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

from pydantic import Field

from bishop.schema.alert import BishopModel


class EvidenceKind(StrEnum):
    #: A deterministic detector fired.
    DETECTOR = "detector"
    #: An investigator's reading of the detector output plus alert context.
    OBSERVATION = "observation"
    #: A cached threat-intelligence match.
    INTEL = "intel"
    #: An attempt to manipulate Bishop through an alert field. Always escalated.
    INJECTION = "injection"
    #: A reason the activity may be legitimate. Weighed against the rest.
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
    #: Every number the detector computed. This is what makes a finding checkable.
    facts: dict[str, Any] = Field(default_factory=dict)
    #: One sentence, plain English, no hedging.
    rationale: str = ""
    #: True when firing *argues against* malice rather than for it — an
    #: authorised actor, a signed vendor binary, a sanctioned destination.
    #: Without this, a detector could only ever add suspicion, and Bishop could
    #: never reach `benign_true_positive` at all.
    mitigating: bool = False
    #: Techniques this detector *suggests*. Validated before any of them ship.
    technique_hints: list[str] = Field(default_factory=list)

    def __bool__(self) -> bool:
        return self.fired


class Evidence(BishopModel):
    """One finding, attributable to a named producer."""

    evidence_id: str
    #: Detector name, investigator name, or intel feed name.
    producer: str
    kind: EvidenceKind
    title: str
    detail: str = ""
    confidence: float = 0.5
    #: Detector results this finding rests on. Empty for pure observations.
    signals: list[DetectorResult] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    facts: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_grounded(self) -> bool:
        """True if at least one deterministic detector backs this finding."""
        return any(s.fired for s in self.signals)
