"""The incident — everything Bishop learned about one correlated event.

This is the object the console renders, the eval harness scores, and the audit
chain covers. It is assembled across the run rather than written at the end, so
a run that fails partway still leaves a readable, partial incident behind.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from bishop.schema.alert import Alert, BishopModel
from bishop.schema.evidence import Evidence
from bishop.schema.response import HumanDecision, ResponsePlan
from bishop.schema.verdict import Verdict


class InvestigatorReport(BishopModel):
    """One investigator's contribution, kept separate on purpose.

    Fusing these too early loses the ability to say *which* specialist found
    what — which is exactly what an analyst asks first when they disagree with
    a verdict.
    """

    investigator: str
    summary: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    examined: list[str] = Field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None
    duration_ms: int = 0
    tokens_used: int = 0


class RunCost(BishopModel):
    """Measured, not estimated. Zero on the mock model, which is the point."""

    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    wall_ms: int = 0


class Incident(BishopModel):
    incident_id: str
    entity_key: str
    alerts: list[Alert] = Field(default_factory=list)
    reports: list[InvestigatorReport] = Field(default_factory=list)
    verdict: Verdict | None = None
    response_plan: ResponsePlan | None = None
    human_decision: HumanDecision | None = None
    execution_log: list[dict[str, Any]] = Field(default_factory=list)
    cost: RunCost = Field(default_factory=RunCost)
    audit_head: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def all_evidence(self) -> list[Evidence]:
        return [e for report in self.reports for e in report.evidence]

    def evidence_by_id(self, evidence_id: str) -> Evidence | None:
        return next((e for e in self.all_evidence if e.evidence_id == evidence_id), None)
