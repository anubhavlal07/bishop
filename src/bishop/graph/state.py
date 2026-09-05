"""The graph state.

One object flows through every node. Two things about its shape are load-bearing:

**`reports` is a reducer field.** Investigators run in parallel via `Send`, so
their writes must merge rather than overwrite. Everything else is written by
exactly one node, which is what keeps the concurrency comprehensible.

**Quarantine evidence has its own field, not a slot in `reports`.** The
injection findings come out of the boundary at ingest, before any investigator
runs, and synthesis reads them directly. That matters: an alert whose only
notable feature is an injection attempt produces no detector hits at all, and if
injection evidence travelled with the investigator reports it would arrive empty
and the finding would vanish. `tests/graph/` pins that path.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from bishop.schema import (
    Alert,
    Evidence,
    HumanDecision,
    InvestigatorReport,
    ResponsePlan,
    RunCost,
    Verdict,
)


def merge_cost(left: RunCost, right: RunCost) -> RunCost:
    """Sum costs across parallel investigators."""
    return RunCost(
        model_calls=left.model_calls + right.model_calls,
        input_tokens=left.input_tokens + right.input_tokens,
        output_tokens=left.output_tokens + right.output_tokens,
        usd=round(left.usd + right.usd, 8),
        wall_ms=max(left.wall_ms, right.wall_ms),
    )


class BishopState(TypedDict, total=False):
    """Everything one run knows."""

    run_id: str
    alerts: list[Alert]
    incident_id: str
    entity_key: str

    quarantine_block: str
    quarantine_evidence: list[Evidence]
    quarantine_summary: dict[str, Any]

    dispatch: list[str]
    dispatch_rationale: str

    reports: Annotated[list[InvestigatorReport], operator.add]
    cost: Annotated[RunCost, merge_cost]

    verdict: Verdict | None
    critic_rounds: int
    critique: list[str]

    response_plan: ResponsePlan | None
    human_decision: HumanDecision | None
    execution_log: list[dict[str, Any]]

    audit_head: str
    errors: Annotated[list[str], operator.add]
    escalated: bool


class InvestigatorTask(TypedDict):
    """The payload one `Send` carries to one investigator."""

    run_id: str
    surface: str
    alerts: list[Alert]
    quarantine_block: str
    incident_id: str


def initial_state(*, run_id: str, alerts: list[Alert], incident_id: str) -> BishopState:
    return BishopState(
        run_id=run_id,
        alerts=alerts,
        incident_id=incident_id,
        entity_key=alerts[0].entity_key() if alerts else "unknown|unknown",
        quarantine_block="",
        quarantine_evidence=[],
        quarantine_summary={},
        dispatch=[],
        dispatch_rationale="",
        reports=[],
        cost=RunCost(),
        verdict=None,
        critic_rounds=0,
        critique=[],
        response_plan=None,
        human_decision=None,
        execution_log=[],
        audit_head="",
        errors=[],
        escalated=False,
    )
