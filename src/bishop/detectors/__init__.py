"""Deterministic detection primitives.

Every signal that contributes to a verdict originates here, in a pure function
with a unit test beside it. Agents interpret and correlate these results; they
do not invent signals. `docs/DETECTORS.md` documents each one — what it
measures, the maths, and where the thresholds came from.

Importing this package registers every detector. `run_surface` then dispatches
by investigator.
"""

from bishop.detectors import context, endpoint, identity, intel, network
from bishop.detectors.base import (
    Baseline,
    DetectorSpec,
    Surface,
    clear,
    for_surface,
    haversine_km,
    miss,
    register,
    registry,
    run_surface,
    scale,
    shannon_entropy,
)

#: The investigator surfaces, in dispatch order. `context` runs on every alert:
#: it is the only surface that can argue *against* malice, and an alert with no
#: exculpatory evidence looked at is one where nobody checked.
SURFACES: tuple[str, ...] = ("identity", "endpoint", "network", "threatintel", "context")

__all__ = [
    "SURFACES",
    "Baseline",
    "DetectorSpec",
    "Surface",
    "clear",
    "context",
    "endpoint",
    "for_surface",
    "haversine_km",
    "identity",
    "intel",
    "miss",
    "network",
    "register",
    "registry",
    "run_surface",
    "scale",
    "shannon_entropy",
]
