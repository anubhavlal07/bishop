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
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.schema import Decision, HumanDecision, ResponseAction, ResponsePlan


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
        return {"execution_log": []}

    log: list[dict[str, Any]] = []

    for action in plan.actions:
        allowed, reason = _authorised(action, decision)
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
