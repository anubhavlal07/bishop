"""Report — assemble the incident and close the audit chain.

The last node. It does not summarise anything; every field it writes was
produced upstream. Its one job is to bind the run together and record the
chain head, so a reader can verify afterwards that the incident they are looking
at is the one Bishop actually produced.
"""

from __future__ import annotations

from typing import Any, Optional

from langchain_core.runnables import RunnableConfig

from bishop.audit import AuditAction
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.schema import Incident, InvestigatorReport, VerdictLabel


def report(state: BishopState, config: Optional[RunnableConfig] = None) -> dict[str, Any]:
    runtime = get_runtime(config)
    verdict = state.get("verdict")

    runtime.chain.append(
        "report",
        AuditAction.RUN_COMPLETED,
        {
            "incident_id": state.get("incident_id"),
            "verdict": str(verdict.label) if verdict else None,
            "confidence": verdict.confidence if verdict else None,
            "actions_executed": sum(
                1 for e in (state.get("execution_log") or []) if e.get("status") == "simulated"
            ),
            "actions_refused": sum(
                1 for e in (state.get("execution_log") or []) if e.get("status") == "refused"
            ),
            "errors": state.get("errors") or [],
        },
    )
    runtime.emit("completed", verdict=str(verdict.label) if verdict else None)

    return {
        "audit_head": runtime.chain.head,
        "escalated": bool(verdict and verdict.label is VerdictLabel.ESCALATE),
    }


def build_incident(state: BishopState, *, audit_head: str | None = None) -> Incident:
    """Assemble the `Incident` the API and CLI render.

    Kept out of the node so the same assembly runs on a partial state — a run
    that failed halfway still produces a readable incident.
    """
    alerts = state.get("alerts") or []
    reports: list[InvestigatorReport] = list(state.get("reports") or [])

    # Quarantine findings are their own report so the console can show which
    # component raised them, and so they survive a run where nothing else fired.
    injections = state.get("quarantine_evidence") or []
    if injections:
        reports = [
            InvestigatorReport(
                investigator="quarantine",
                summary=(
                    f"{len(injections)} field(s) in this alert carried text aimed at steering "
                    f"Bishop's own analysis. Preserved verbatim and escalated as indicators."
                ),
                evidence=injections,
            ),
            *reports,
        ]

    return Incident(
        incident_id=state.get("incident_id") or "unknown",
        entity_key=state.get("entity_key") or "unknown|unknown",
        alerts=alerts,
        reports=reports,
        verdict=state.get("verdict"),
        response_plan=state.get("response_plan"),
        human_decision=state.get("human_decision"),
        execution_log=list(state.get("execution_log") or []),
        cost=state.get("cost"),
        audit_head=audit_head or state.get("audit_head"),
    )
