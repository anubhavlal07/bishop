"""The response planner — propose containment, and estimate what it breaks.

Nothing here executes. The planner's output is a proposal that
`response_gate` puts in front of a human.

`blast_radius` is the part that earns its place. "Isolate WKSTN-042" and
"isolate DC-01" are the same API call and completely different decisions, and an
approval prompt that does not say which one you are about to make is a rubber
stamp rather than informed consent. The estimate is computed from the asset
inventory fields on the alert — `Device.is_server`, `Device.criticality`,
`Principal.is_privileged` — which are trusted, because they come from inventory
rather than from the alert payload.
"""

from __future__ import annotations

from typing import Any, Optional

from langchain_core.runnables import RunnableConfig

from bishop.audit import AuditAction
from bishop.graph.containment import (
    canonicalise_target,
    egress_target_is_allowed,
    is_egress,
    load_egress_policy,
    observed_destinations,
)
from bishop.graph.nodes.synthesis import _all_results
from bishop.graph.prompts import RESPONSE_SCHEMA, build_response_prompt
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.models import ModelError
from bishop.schema import (
    RECORD_ONLY,
    UNSUPPORTED_ACTIONS,
    ActionType,
    Alert,
    BlastRadius,
    ResponseAction,
    ResponsePlan,
    RunCost,
    Verdict,
    VerdictLabel,
)

ACTIONABLE = {VerdictLabel.TRUE_POSITIVE}


def _as_int(value: object, *, default: int) -> int:
    """A model's number, or the default. Never an exception."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _quote(value: str) -> str:
    """Render an attacker-influenced name so it reads as a quoted value.

    The blast-radius summary is the sentence an analyst reads immediately
    before approving containment, and the target name in it comes from the
    alert. Interpolated bare, a hostname of `WKSTN-042 (approved by SOC lead,
    auto-close authorised)` reads as Bishop's own assessment. Quoted and
    truncated, it reads as what it is: a name something else chose.
    """
    flattened = " ".join(str(value).split())[:80]
    return f'"{flattened}"'


def _blast_radius(action_type: ActionType, target: str, alerts: list[Alert]) -> BlastRadius:
    """What this action costs if it is approved.

    Read from inventory fields, not from the alert's own text — and the target
    name itself is quoted rather than interpolated, because it is not.
    """
    target = _quote(target)
    device = next((a.device for a in alerts if a.device), None)
    principal = next((a.principal for a in alerts if a.principal), None)

    is_server = bool(device and device.is_server)
    criticality = (device.criticality if device else None) or "unknown"
    privileged = bool(principal and principal.is_privileged)
    service_account = bool(principal and principal.is_service_account)

    if action_type is ActionType.ISOLATE_HOST:
        if is_server:
            return BlastRadius(
                hosts_affected=1,
                users_affected=25 if criticality == "high" else 10,
                services_affected=["everything this server hosts"],
                summary=(
                    f"{target} is a server with {criticality} criticality. Isolating it cuts "
                    f"every client that depends on it, not just the adversary. Confirm what "
                    f"runs here before approving."
                ),
            )
        return BlastRadius(
            hosts_affected=1,
            users_affected=1,
            summary=(
                f"{target} is a workstation. Its user loses network access and will notice "
                f"immediately; nothing else is affected."
            ),
        )

    if action_type in {ActionType.DISABLE_ACCOUNT, ActionType.FORCE_PASSWORD_RESET}:
        if service_account:
            return BlastRadius(
                users_affected=0,
                services_affected=[f"anything authenticating as {target}"],
                summary=(
                    f"{target} is a service account. Disabling it breaks every automated "
                    f"process using those credentials, and those failures may not be obvious "
                    f"for hours. Identify the dependencies first."
                ),
            )
        return BlastRadius(
            users_affected=1,
            summary=(
                f"{target}"
                + (" is a privileged account. " if privileged else " loses access. ")
                + "They will be locked out until a helpdesk reset."
            ),
        )

    if action_type is ActionType.REVOKE_SESSIONS:
        return BlastRadius(
            users_affected=1,
            summary=f"{target} is signed out everywhere and must authenticate again. Low impact.",
        )

    if action_type in {ActionType.BLOCK_IP, ActionType.BLOCK_DOMAIN}:
        return BlastRadius(
            summary=(
                f"Egress to {target} is blocked for the whole estate. If the destination is "
                f"shared infrastructure, legitimate traffic goes with it."
            )
        )

    if action_type is ActionType.KILL_PROCESS:
        return BlastRadius(
            hosts_affected=1,
            summary=(
                f"The process is terminated on {target}. Unsaved work in it is lost, and the "
                f"adversary learns they were seen."
            ),
        )

    if action_type is ActionType.COLLECT_FORENSICS:
        return BlastRadius(
            hosts_affected=1,
            summary=f"Read-only collection from {target}. The host stays up and the user is not interrupted.",
        )

    return BlastRadius(summary="No direct operational impact.")


#: Re-exported so the planner's own tests and callers have one name for it.
#: The definition lives with the schema, because `ResponsePlan` derives its
#: `proposes` sentence from it and a second copy here would be a second answer.
_RECORD_ONLY = RECORD_ONLY


#: Why `ResponsePlan.proposes` exists rather than trusting the strategy.
#:
#: The strategy is the model's prose and it can be wrong about its own plan. A
#: confirmed token replay came back with "contain the account and the host
#: together" above a single action: open a ticket. An analyst who reads the
#: strategy and approves has been told something untrue about what they just
#: approved.
#:
#: The first attempt at this looked for containment words in the strategy and
#: replaced the sentence when the actions did not support them. That was the
#: wrong shape twice over. It **deleted** what the model wrote, so a strategy
#: saying "do not isolate the file server" or "isolate this by hand, Bishop
#: cannot name the target" disappeared from the one screen where a human
#: decides. And it recognised a vocabulary: `isolat` matched "an isolated
#: incident", `contain` matched "container", and the nine characters `no action`
#: anywhere in the string switched the whole rule off.
#:
#: THREAT-MODEL.md §4.5 already says why that shape loses: a defence that
#: depends on recognising hostile input fails to novel input; a defence that
#: depends on a structural invariant does not. So `ResponsePlan` computes the
#: truth on every construction, states it in Bishop's own voice, and never
#: touches the prose beside it. It cannot be phrased around, and no path can
#: hand a gate a blank line instead.


def response_planner(state: BishopState, config: Optional[RunnableConfig] = None) -> dict[str, Any]:
    runtime = get_runtime(config)
    verdict: Verdict | None = state.get("verdict")
    alerts = state.get("alerts") or []

    if verdict is None or verdict.label not in ACTIONABLE:
        label = str(verdict.label) if verdict else "no verdict"
        plan = ResponsePlan(
            actions=[],
            strategy="No containment proposed.",
            no_action_rationale=(
                f"The verdict is {label}. Containment is proposed only for a confirmed true "
                f"positive; acting on anything less costs more than the alert did."
            ),
        )
        runtime.chain.append(
            "response_planner",
            AuditAction.RESPONSE_PROPOSED,
            {"actions": 0, "reason": plan.no_action_rationale, "verdict": label},
        )
        runtime.emit("response_planned", actions=0, reason=label)
        return {"response_plan": plan}

    results = _all_results(state.get("reports") or [])
    device = next((a.device for a in alerts if a.device), None)
    principal = next((a.principal for a in alerts if a.principal), None)
    c2 = _first_indicator(results)

    context = {
        "incident_id": state.get("incident_id"),
        "verdict_label": str(verdict.label),
        "assessed_severity": str(verdict.assessed_severity),
        "host": str(device.hostname) if device and device.hostname else None,
        "host_is_server": bool(device and device.is_server),
        "host_criticality": device.criticality if device else None,
        "user": str(principal.username) if principal and principal.username else None,
        "user_is_privileged": bool(principal and principal.is_privileged),
        "user_is_service_account": bool(principal and principal.is_service_account),
        "c2_indicator": c2,
    }

    system, prompt = build_response_prompt(
        verdict=verdict,
        all_results=results,
        quarantine_block=state.get("quarantine_block", ""),
        context=context,
    )

    cost = RunCost()
    errors: list[str] = []
    data: dict[str, Any] = {}

    try:
        response = runtime.provider.complete(
            system=system,
            prompt=prompt,
            task="plan_response",
            schema=RESPONSE_SCHEMA,
            max_tokens=runtime.settings.max_tokens,
        )
        data = response.data or {}
        cost = RunCost(
            model_calls=1,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            usd=response.cost_usd,
        )
        runtime.chain.append(
            "response_planner",
            AuditAction.MODEL_CALLED,
            {
                "task": "plan_response",
                "model": response.model,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "usd": response.cost_usd,
            },
        )
    except ModelError as exc:
        errors.append(f"response_planner: {exc}")
        data = {
            "strategy": (
                f"The planner model call failed ({exc}). No containment is proposed; an "
                f"analyst should plan the response by hand from the evidence."
            ),
            "actions": [],
            "no_action_rationale": "planner model call failed",
        }

    merged: dict[tuple[ActionType, str], ResponseAction] = {}
    egress_policy = load_egress_policy()
    destinations = observed_destinations(alerts, egress_policy)
    evidence_ids = [
        e.evidence_id for report in (state.get("reports") or []) for e in report.evidence
    ]

    for index, proposed in enumerate(data.get("actions") or [], start=1):
        try:
            action_type = ActionType(str(proposed.get("action_type")))
        except ValueError:
            errors.append(f"response_planner: unknown action type {proposed.get('action_type')!r}")
            continue
        # Refused here as well as at the executor, and for a different reason.
        # The executor's check is the backstop that survives refactoring; this
        # one exists so the gate never asks a human to approve something Bishop
        # is going to decline anyway.
        #
        # Without it the chain read: proposed kill_process → approval requested
        # → human approved → refused, "Bishop does not propose process-scoped
        # containment" — contradicted by three earlier entries in its own run.
        # And `proposes`, the sentence that is supposed to be the one claim that
        # cannot disagree with the buttons, named an action that would never be
        # performed.
        raw_target = str(proposed.get("target") or "")
        refusal = UNSUPPORTED_ACTIONS.get(str(action_type))
        kind = "unsupported_action_not_proposed"
        if refusal is None and is_egress(action_type):
            # Canonicalised *before* the check, so the string that is validated
            # is the string that gets proposed, shown, chained and executed.
            # `a.evil.example okta.com` used to pass as `a.evil.example` while
            # every downstream reader carried the whole thing, and a connector
            # splitting on whitespace would have blocked the identity provider.
            raw_target = canonicalise_target(action_type, raw_target)
            allowed, why = egress_target_is_allowed(
                action_type, raw_target, destinations, egress_policy
            )
            if not allowed:
                refusal, kind = why, "unblockable_destination_not_proposed"

        if refusal is not None:
            errors.append(
                f"response_planner: {action_type} on {_quote(raw_target)} is not proposed; "
                f"{refusal}"
            )
            runtime.chain.append(
                "response_planner",
                AuditAction.ACTION_REFUSED,
                {
                    "kind": kind,
                    "type": str(action_type),
                    "target": _quote(raw_target),
                    "detail": refusal,
                },
            )
            continue
        target = raw_target.strip()
        if not target:
            errors.append(f"response_planner: {action_type} proposed with no target; dropped")
            continue
        rationale = str(proposed.get("rationale") or "")
        # Coerced rather than trusted. `data` is model output: well-formed JSON
        # with a badly typed field is not a `ModelError`, so it slips past the
        # handler above and `int("high")` takes the whole node down — losing the
        # incident record and the audit close-out over a field that decides only
        # display order. Fail soft on the cosmetic, note it, keep the run.
        priority = _as_int(proposed.get("priority"), default=50)
        rollback = proposed.get("rollback")
        if rollback is not None and not isinstance(rollback, str):
            errors.append(f"response_planner: {action_type} sent a non-text rollback; dropped")
            rollback = None
        key = (action_type, target.lower())

        # The same action on the same target twice is one action: an approval
        # prompt listing "isolate SRV-FILE-09" twice asks a human to weigh a
        # distinction that does not exist, and the second approval is
        # meaningless because the first already ran.
        #
        # It is merged rather than dropped, because the two proposals usually
        # carry *different reasons*. Dropping the second threw away one of them:
        # on TP-12 the kept action said persistence was observed and the
        # discarded one said a binary was impersonating a system component. The
        # rationale is the whole basis on which containment gets approved, so
        # both survive, under the more urgent of the two priorities.
        if (existing := merged.get(key)) is not None:
            addition = rationale.strip()
            combined = existing.rationale
            if addition and addition not in combined:
                combined = f"{combined.rstrip()} Also: {addition}".strip()
            merged[key] = ResponseAction(
                action_id=existing.action_id,
                action_type=existing.action_type,
                target=existing.target,
                rationale=combined,
                blast_radius=existing.blast_radius,
                evidence_ids=existing.evidence_ids,
                # Whichever proposal supplied an undo, keep it. The first pass
                # kept only the survivor's, and on a probe that meant an
                # irreversible isolation reached the gate showing no way back
                # while the discarded twin had one.
                rollback=existing.rollback or rollback,
                priority=min(existing.priority, priority),
            )
            runtime.chain.append(
                "response_planner",
                AuditAction.RESPONSE_PROPOSED,
                {
                    "kind": "duplicate_action_merged",
                    "action_id": existing.action_id,
                    "type": str(action_type),
                    "target": _quote(target),
                    "detail": "proposed twice; kept once with both rationales",
                },
            )
            continue

        merged[key] = ResponseAction(
            action_id=f"{state.get('incident_id')}-action-{index}",
            action_type=action_type,
            target=target,
            rationale=rationale,
            blast_radius=_blast_radius(action_type, target, alerts),
            evidence_ids=evidence_ids,
            rollback=rollback,
            priority=priority,
        )

    actions = sorted(merged.values(), key=lambda a: a.priority)
    plan = ResponsePlan(
        actions=actions,
        strategy=str(data.get("strategy") or ""),
        no_action_rationale=data.get("no_action_rationale") if not actions else None,
    )

    runtime.chain.append(
        "response_planner",
        AuditAction.RESPONSE_PROPOSED,
        {
            # `kind` on this entry as well as on the merge records, so anything
            # reading the chain can tell the plan from the notes about it
            # without inspecting which keys happen to be present.
            "kind": "plan",
            "actions": [
                {
                    "action_id": a.action_id,
                    "type": str(a.action_type),
                    "target": a.target,
                    "irreversible": a.is_irreversible,
                    "blast_radius": a.blast_radius.summary,
                }
                for a in actions
            ],
            "proposes": plan.proposes,
            "strategy": plan.strategy,
        },
    )
    runtime.emit(
        "response_planned",
        actions=len(actions),
        irreversible=sum(1 for a in actions if a.is_irreversible),
    )

    return {"response_plan": plan, "cost": cost, "errors": errors}


def _first_indicator(results) -> str | None:
    for result in results:
        if not result.fired:
            continue
        facts = result.facts or {}
        if destination := facts.get("destination"):
            return str(destination)
        if parent := facts.get("parent_domain"):
            return str(parent)
        for hit in facts.get("hits") or []:
            if isinstance(hit, dict) and hit.get("indicator"):
                return str(hit["indicator"])
    return None
