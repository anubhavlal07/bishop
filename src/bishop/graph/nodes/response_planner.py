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
from bishop.graph.nodes.synthesis import _all_results
from bishop.graph.prompts import RESPONSE_SCHEMA, build_response_prompt
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.models import ModelError
from bishop.schema import (
    ActionType,
    Alert,
    BlastRadius,
    ResponseAction,
    ResponsePlan,
    RunCost,
    Verdict,
    VerdictLabel,
)

#: Verdicts that may carry a containment proposal at all. A false positive with
#: a containment plan attached is how an automated SOC takes the estate down.
ACTIONABLE = {VerdictLabel.TRUE_POSITIVE}


def _blast_radius(action_type: ActionType, target: str, alerts: list[Alert]) -> BlastRadius:
    """What this action costs if it is approved.

    Read from inventory fields, not from the alert's own text.
    """
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

    actions: list[ResponseAction] = []
    evidence_ids = [
        e.evidence_id for report in (state.get("reports") or []) for e in report.evidence
    ]

    for index, proposed in enumerate(data.get("actions") or [], start=1):
        try:
            action_type = ActionType(str(proposed.get("action_type")))
        except ValueError:
            errors.append(f"response_planner: unknown action type {proposed.get('action_type')!r}")
            continue
        target = str(proposed.get("target") or "").strip()
        if not target:
            errors.append(f"response_planner: {action_type} proposed with no target; dropped")
            continue
        actions.append(
            ResponseAction(
                action_id=f"{state.get('incident_id')}-action-{index}",
                action_type=action_type,
                target=target,
                rationale=str(proposed.get("rationale") or ""),
                blast_radius=_blast_radius(action_type, target, alerts),
                evidence_ids=evidence_ids,
                rollback=proposed.get("rollback"),
                priority=int(proposed.get("priority") or 50),
            )
        )

    actions.sort(key=lambda a: a.priority)
    plan = ResponsePlan(
        actions=actions,
        strategy=str(data.get("strategy") or ""),
        no_action_rationale=data.get("no_action_rationale") if not actions else None,
    )

    runtime.chain.append(
        "response_planner",
        AuditAction.RESPONSE_PROPOSED,
        {
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
