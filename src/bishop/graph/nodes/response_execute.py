"""The executor. Mocked, and it refuses anything a human did not approve.

Two layers, because one is not enough for a control that matters:

1. `response_gate` will not let the graph past it without a `HumanDecision`.
2. This node checks for that decision *again*, per action, and refuses anything
   not named in it — including when the graph is invoked directly, a state is
   restored from a checkpoint, or someone wires a new edge that skips the gate.

The second check is the one that survives refactoring. A control that lives
only in the graph topology is one edge away from being gone, and nobody would
notice until an account got disabled.

**Everything here is a mock.** `Executor` is an interface with one
implementation, `MockExecutor`, which records what it would have done and
performs no side effects. `PLAN.md` §6 puts real connectors explicitly out of
scope: Bishop investigates and proposes. Shipping a real isolate-host call would
change what this project is.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Optional, Protocol

from langchain_core.runnables import RunnableConfig

from bishop.audit import AuditAction
from bishop.graph.containment import (
    Destinations,
    EgressPolicy,
    egress_target_is_allowed,
    is_egress,
    load_egress_policy,
    observed_destinations,
)
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.schema import (
    UNSUPPORTED_ACTIONS,
    Decision,
    HumanDecision,
    ResponseAction,
    ResponsePlan,
)


class ExecutionRefused(RuntimeError):
    """An action reached the executor without an approval covering it.

    Raised rather than logged. This is a stop-the-line condition: it means a
    code path exists that can act without a human, and that is the one bug in
    Bishop that must never be recovered from quietly.
    """


class Executor(Protocol):
    """The seam a real connector would implement. Nothing does, deliberately."""

    name: str

    def execute(self, action: ResponseAction) -> dict[str, Any]: ...


class MockExecutor:
    """Records intent. Performs nothing."""

    name = "mock"

    def __init__(self) -> None:
        self.performed: list[ResponseAction] = []

    def execute(self, action: ResponseAction) -> dict[str, Any]:
        self.performed.append(action)
        return {
            "action_id": action.action_id,
            "action_type": str(action.action_type),
            "target": action.target,
            "status": "simulated",
            "executor": self.name,
            "detail": (
                f"MOCK: would {str(action.action_type).replace('_', ' ')} "
                f"on {action.target}. No side effect was performed."
            ),
            "irreversible": action.is_irreversible,
            "at": datetime.now(UTC).isoformat(),
        }


#: Actions that act on a named machine or account. `open_ticket`, `notify_owner`
#: and `monitor` take a reference rather than a target and are not checked here.
_TARGETED_ACTIONS = {
    "isolate_host",
    "disable_account",
    "revoke_sessions",
    "force_password_reset",
    "kill_process",
    "quarantine_file",
}

#: Refused as policy, whatever they name. The set and the reasons live with
#: the schema so the planner refuses at proposal time from the same source:
#: a gate that asks a human to approve something Bishop will then decline is
#: a worse failure than either answer on its own.
_UNSUPPORTED_ACTIONS = UNSUPPORTED_ACTIONS


def _known_entities(alerts: list[Any]) -> set[str]:
    """Every host and account the alerts actually name, lowercased."""
    known: set[str] = set()
    for alert in alerts or []:
        device = getattr(alert, "device", None)
        if device is not None:
            for value in (device.hostname, device.ip):
                if value:
                    known.add(str(value).strip().lower())
        principal = getattr(alert, "principal", None)
        if principal is not None:
            for value in (principal.username, principal.upn, principal.sid):
                if value:
                    known.add(str(value).strip().lower())
        for event in getattr(alert, "auth_events", []) or []:
            if event.username:
                known.add(str(event.username).strip().lower())
    return known


def _targets_a_known_entity(
    action: ResponseAction,
    known: set[str],
    destinations: Destinations,
    policy: EgressPolicy,
) -> tuple[bool, str]:
    """Refuse to act on something the alert never mentioned.

    The containment target reaches here from the response plan, which a model
    wrote from prompt context that includes attacker-controlled fields. Nothing
    upstream ties it back to the incident, so a laundered hostname could name a
    machine the alert has nothing to do with — pointing the one irreversible
    capability Bishop has at a third party, with a human approving what looked
    like a reasonable plan.

    Scanning the hostname cannot fix this: `DC-01` is a perfectly ordinary name
    and there is nothing in it to detect. What is checkable is the relationship
    — you cannot isolate a host that is not in the incident.

    Two action types have no such relationship to check and are refused as
    policy first, so the refusal says *why* rather than reading like a gap in
    the entity list that someone should go and fill.
    """
    if (refusal := _UNSUPPORTED_ACTIONS.get(str(action.action_type))) is not None:
        return False, refusal

    kind = str(action.action_type)
    if is_egress(kind):
        return egress_target_is_allowed(kind, action.target, destinations, policy)

    if kind not in _TARGETED_ACTIONS:
        return True, ""
    target = (action.target or "").strip().lower()
    if not target:
        return False, "the action names no target"
    if target not in known:
        return False, (
            f"{action.target!r} is not a host or account named by this incident. An "
            f"action may only touch an entity the alerts actually mention."
        )
    return True, ""


def _authorised(action: ResponseAction, decision: HumanDecision | None) -> tuple[bool, str]:
    """The independent re-check. See the module docstring for why it exists."""
    if decision is None:
        return False, "no human decision is recorded for this run"
    if decision.decision is Decision.REJECTED:
        return False, f"the plan was rejected by {decision.decided_by}"
    if action.action_id not in decision.approved_action_ids:
        return False, (
            f"action {action.action_id} is not in the set approved by {decision.decided_by}"
        )
    return True, ""


def response_execute(
    state: BishopState,
    config: Optional[RunnableConfig] = None,
    *,
    executor: Executor | None = None,
) -> dict[str, Any]:
    runtime = get_runtime(config)
    plan: ResponsePlan | None = state.get("response_plan")
    decision: HumanDecision | None = state.get("human_decision")
    engine = executor or MockExecutor()

    if plan is None or not plan.actions:
        runtime.chain.append(
            "response_execute",
            AuditAction.ACTION_REFUSED,
            {"kind": "nothing_to_execute", "reason": "no actions were proposed"},
        )
        return {"execution_log": []}

    log: list[dict[str, Any]] = []

    alerts = state.get("alerts") or []
    known = _known_entities(alerts)
    policy = load_egress_policy()
    destinations = observed_destinations(alerts, policy)

    for action in plan.actions:
        allowed, reason = _authorised(action, decision)
        if allowed:
            allowed, reason = _targets_a_known_entity(action, known, destinations, policy)
        if not allowed:
            record = {
                "action_id": action.action_id,
                "action_type": str(action.action_type),
                "target": action.target,
                "status": "refused",
                "reason": reason,
                "at": datetime.now(UTC).isoformat(),
            }
            log.append(record)
            runtime.chain.append("response_execute", AuditAction.ACTION_REFUSED, record)
            runtime.emit("action_refused", action_id=action.action_id, reason=reason)
            continue

        record = engine.execute(action)
        record["approved_by"] = decision.decided_by if decision else None
        log.append(record)
        runtime.chain.append("response_execute", AuditAction.ACTION_EXECUTED, record)
        runtime.emit(
            "action_executed",
            action_id=action.action_id,
            action_type=str(action.action_type),
            target=action.target,
        )

    return {"execution_log": log, "audit_head": runtime.chain.head}
