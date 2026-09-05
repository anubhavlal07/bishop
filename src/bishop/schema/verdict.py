"""Verdict, confidence, and the abstention that matters more than either.

Three labels plus an explicit fourth state. Most SOC tooling collapses
`benign_true_positive` into `false_positive`, which is wrong and expensive: the
activity really happened, the detection was correct, and someone authorised it.
An analyst needs to know which of those two they are looking at, because one is
a tuning problem and the other is a paperwork problem.

`ESCALATE` is not a label Bishop assigns to activity. It is Bishop declining to
assign one. A tool that guesses under low confidence is worse than a tool that
says so, because the guess is indistinguishable from a real answer downstream.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from bishop.schema.alert import BishopModel, Severity


class VerdictLabel(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    ESCALATE = "escalate"


class ConfidenceBand(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def of(cls, confidence: float) -> ConfidenceBand:
        if confidence >= 0.75:
            return cls.HIGH
        if confidence >= 0.5:
            return cls.MEDIUM
        return cls.LOW


class AttackStage(BishopModel):
    """One step in the reconstructed narrative, in observed order."""

    order: int
    tactic: str
    technique_id: str
    technique_name: str
    summary: str
    evidence_ids: list[str] = Field(default_factory=list)


class Verdict(BishopModel):
    label: VerdictLabel
    confidence: float = 0.0
    rationale: str = ""
    narrative: str = ""
    stages: list[AttackStage] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    assessed_severity: Severity = Severity.MEDIUM
    counter_arguments: list[str] = Field(default_factory=list)
    escalation_reason: str | None = None

    @property
    def band(self) -> ConfidenceBand:
        return ConfidenceBand.of(self.confidence)

    @property
    def is_escalation(self) -> bool:
        return self.label is VerdictLabel.ESCALATE
