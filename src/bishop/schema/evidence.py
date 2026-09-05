"""Evidence — the only thing a verdict is allowed to rest on.

There are two kinds and the difference is the whole design:

`DetectorResult` comes out of a deterministic, unit-tested function in
`bishop.detectors`. It carries numbers a reader can check by hand: an implied
travel velocity, a jitter coefficient, a Shannon entropy. No model touches it.

`Evidence` is what an investigator writes down. An investigator may add context
and correlation, but the `signals` it cites are detector results, and a verdict
that cites no detector signal is an abstention by construction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, model_validator

from bishop.schema.alert import BishopModel


class EvidenceKind(StrEnum):
    DETECTOR = "detector"
    OBSERVATION = "observation"
    INTEL = "intel"
    INJECTION = "injection"
    MITIGATING = "mitigating"


class DetectorResult(BishopModel):
    """The output of one deterministic detector.

    `score` is the detector's own confidence that what it measured is
    suspicious, on 0..1. It is not a probability and it is not a verdict — the
    synthesis step weighs it against everything else.
    """

    detector: str
    fired: bool
    score: float = 0.0
    facts: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    mitigating: bool = False
    technique_hints: list[str] = Field(default_factory=list)
    examined: bool = False

    @model_validator(mode="after")
    def _firing_implies_examining(self) -> DetectorResult:
        if self.fired and not self.examined:
            object.__setattr__(self, "examined", True)
        return self

    def __bool__(self) -> bool:
        return self.fired


class Evidence(BishopModel):
    """One finding, attributable to a named producer."""

    evidence_id: str
    producer: str
    kind: EvidenceKind
    title: str
    detail: str = ""
    confidence: float = 0.5
    signals: list[DetectorResult] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    facts: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_grounded(self) -> bool:
        """True if at least one deterministic detector backs this finding."""
        return any(s.fired for s in self.signals)
