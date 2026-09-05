"""The human gate. Nothing irreversible happens on the other side of this
without a recorded decision.

`CLAUDE.md` §3: *no autonomous containment, ever.* This node is where that rule
lives. It calls LangGraph's `interrupt()`, which suspends the run and
checkpoints it; the graph only resumes when a human supplies a decision. There
is no timeout that auto-approves, no severity above which the gate is skipped,
and no configuration flag that disables it — because the first thing anyone
would do with such a flag is turn it on at 2am during an incident, which is
precisely when nobody should be trusting an unattended machine to disable
accounts.

The gate is deliberately *not* conditional on the actions being irreversible.
Every plan with anything in it stops here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Optional

from langchain_core.runnables import RunnableConfig
from langgraph.types import interrupt

from bishop.audit import AuditAction, hash_payload
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.schema import Decision, HumanDecision, ResponsePlan


def _approval_request(plan: ResponsePlan, state: BishopState) -> dict[str, Any]:
    """What the analyst is shown. Everything needed to decide, nothing else."""
    verdict = state.get("verdict")
    return {
        "kind": "approval_request",
        "incident_id": state.get("incident_id"),
        "entity": state.get("entity_key"),
        "verdict": {
            "label": str(verdict.label) if verdict else None,
            "confidence": verdict.confidence if verdict else None,
            "rationale": verdict.rationale if verdict else "",
            "counter_arguments": verdict.counter_arguments if verdict else [],
            "technique_ids": verdict.technique_ids if verdict else [],
        },
        "strategy": plan.strategy,
        "actions": [
            {
                "action_id": action.action_id,
                "action_type": str(action.action_type),
                "target": action.target,
                "rationale": action.rationale,
                "irreversible": action.is_irreversible,
                "rollback": action.rollback,
                "blast_radius": {
                    "summary": action.blast_radius.summary,
                    "users_affected": action.blast_radius.users_affected,
                    "hosts_affected": action.blast_radius.hosts_affected,
                    "services_affected": action.blast_radius.services_affected,
                },
            }
            for action in plan.actions
        ],
        "instructions": (
            "Approve, reject, or approve a subset. Reply with "
            "{'decision': 'approved'|'rejected'|'modified', "
            "'approved_action_ids': [...], 'decided_by': '...', 'note': '...'}. "
            "`approved_action_ids` is required for an approval: an approval that "
            "names no action approves nothing."
        ),
    }


def response_gate(state: BishopState, config: Optional[RunnableConfig] = None) -> dict[str, Any]:
    runtime = get_runtime(config)
    plan: ResponsePlan | None = state.get("response_plan")

    if plan is None or not plan.actions:
        # Nothing to approve. Recorded explicitly so the audit log distinguishes
        # "nobody was asked" from "somebody said no".
        runtime.chain.append(
            "response_gate",
            AuditAction.HUMAN_DECIDED,
            {
                "decision": "not_required",
                "reason": "no actions were proposed",
            },
        )
        return {
            "human_decision": HumanDecision(
                decided_by="system",
                decision=Decision.REJECTED,
                approved_action_ids=[],
                note="no actions were proposed, so no approval was sought",
                decided_at=datetime.now(UTC).isoformat(),
            )
        }

    request = _approval_request(plan, state)
    # LangGraph re-runs a node from the top when a run resumes, so this line is
    # reached twice for every approval: once when the request is raised and once
    # when the human answers. Both are recorded — the chain is append-only and
    # deleting the first would be a lie about what happened — but the second is
    # labelled, so a reader is not left thinking two approvals were sought.
    replay = any(
        entry.payload.get("action_ids") == [a.action_id for a in plan.actions]
        for entry in runtime.chain.by_action(AuditAction.APPROVAL_REQUESTED)
    )
    # The hash commits to *what the analyst was shown* — targets, blast radii,
    # the verdict — not just to the action ids. Without it the chain can prove
    # someone approved `INC-X-action-1` and cannot prove what action-1 was.
    request_hash = hash_payload(request)
    runtime.chain.append(
        "response_gate",
        AuditAction.APPROVAL_REQUESTED,
        {
            "action_ids": [a.action_id for a in plan.actions],
            "irreversible": [a.action_id for a in plan.actions if a.is_irreversible],
            "targets": {a.action_id: a.target[:120] for a in plan.actions},
            "blast_radii": {a.action_id: a.blast_radius.summary[:200] for a in plan.actions},
            "request_hash": request_hash,
            "replayed_after_resume": replay,
        },
    )
    runtime.emit("approval_requested", actions=len(plan.actions))

    # Suspends the run. The graph resumes here when a human answers.
    answer = interrupt(request)

    decision = _parse_decision(answer, plan)

    runtime.chain.append(
        "response_gate",
        AuditAction.HUMAN_DECIDED,
        {
            "decided_by": decision.decided_by,
            "decision": str(decision.decision),
            "approved_action_ids": decision.approved_action_ids,
            "rejected_action_ids": [
                a.action_id for a in plan.actions if a.action_id not in decision.approved_action_ids
            ],
            "note": decision.note,
            "decided_at": decision.decided_at,
            # Same hash as the APPROVAL_REQUESTED entry above: this is what they
            # were looking at when they decided.
            "approved_request_hash": request_hash,
        },
    )
    runtime.emit(
        "human_decided",
        decision=str(decision.decision),
        approved=len(decision.approved_action_ids),
    )

    return {"human_decision": decision, "audit_head": runtime.chain.head}


def _parse_decision(answer: Any, plan: ResponsePlan) -> HumanDecision:
    """Turn whatever the human sent into a decision record.

    Unrecognised input is treated as a rejection. Defaulting the other way
    would mean a malformed resume payload could isolate a host.
    """
    now = datetime.now(UTC).isoformat()
    valid_ids = {a.action_id for a in plan.actions}

    if isinstance(answer, str):
        answer = {"decision": answer}
    if not isinstance(answer, dict):
        return HumanDecision(
            decided_by="unknown",
            decision=Decision.REJECTED,
            approved_action_ids=[],
            note=f"unparseable approval response ({type(answer).__name__}); treated as a rejection",
            decided_at=now,
        )

    raw = str(answer.get("decision", "")).strip().lower()
    decided_by = str(answer.get("decided_by") or "unknown")
    note = str(answer.get("note") or "")

    if raw in {"approved", "approve", "yes", "y"}:
        # An approval names what it approves. `[] or valid_ids` used to mean
        # everything, which made `{"decision": "approved"}` — a body naming no
        # actions at all — approve five, two of them irreversible, through an
        # unauthenticated endpoint. An omitted list and an empty one were
        # indistinguishable, and both meant "all".
        #
        # Both now mean none. Every caller Bishop ships sends the ids
        # explicitly, so nothing loses a capability it was using, and the
        # failure direction is the one that does not disable an account.
        approved = [str(i) for i in (answer.get("approved_action_ids") or [])]
        approved = [i for i in approved if i in valid_ids]
        if not approved:
            return HumanDecision(
                decided_by=decided_by,
                decision=Decision.REJECTED,
                approved_action_ids=[],
                note=(
                    (note + " ").strip()
                    + "[approval named no valid action ids; treated as a rejection]"
                ).strip(),
                decided_at=now,
            )
        return HumanDecision(
            decided_by=decided_by,
            decision=Decision.APPROVED,
            approved_action_ids=approved,
            note=note,
            decided_at=now,
        )

    if raw in {"modified", "modify", "partial", "subset"}:
        approved = [str(i) for i in (answer.get("approved_action_ids") or [])]
        unknown = [i for i in approved if i not in valid_ids]
        approved = [i for i in approved if i in valid_ids]
        if unknown:
            note = (note + f" [ignored unknown action ids: {', '.join(unknown)}]").strip()
        return HumanDecision(
            decided_by=decided_by,
            decision=Decision.MODIFIED,
            approved_action_ids=approved,
            note=note,
            decided_at=now,
        )

    return HumanDecision(
        decided_by=decided_by,
        decision=Decision.REJECTED,
        approved_action_ids=[],
        note=note or f"decision {raw!r} was not an approval",
        decided_at=now,
    )
