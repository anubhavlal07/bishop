"""The detector contract, the registry, and the maths they share.

A detector is a pure function from an `Alert` to a `DetectorResult`. Pure means
what it says: no model call, no network, no database, no clock read, no
randomness. Given the same alert it returns the same result on any machine, in
any year, which is what makes `pytest tests/detectors` a meaningful gate and
what lets an analyst re-derive a finding by hand.

The clock rule is the one that gets broken by accident. A detector that calls
`datetime.now()` produces a different answer when the golden set is replayed
next week, and the eval scorecard quietly rots. Every time reference comes out
of the alert.

Registration exists so the coverage matrix in `docs/COVERAGE.md` can be
generated from the code rather than maintained beside it, and so nobody has to
remember to wire a new detector into an investigator.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from math import asin, cos, radians, sin, sqrt
from statistics import median

from bishop.schema.alert import Alert
from bishop.schema.evidence import DetectorResult

Surface = str

DetectorFn = Callable[[Alert], DetectorResult]


@dataclass(frozen=True, slots=True)
class DetectorSpec:
    name: str
    fn: DetectorFn
    surface: Surface
    summary: str
    techniques: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


_REGISTRY: dict[str, DetectorSpec] = {}


def register(
    *,
    surface: Surface,
    summary: str,
    techniques: Sequence[str] = (),
    references: Sequence[str] = (),
) -> Callable[[DetectorFn], DetectorFn]:
    """Register a detector under its function name."""

    def decorator(fn: DetectorFn) -> DetectorFn:
        name = fn.__name__
        if name in _REGISTRY:
            raise ValueError(f"detector {name!r} is already registered")
        _REGISTRY[name] = DetectorSpec(
            name=name,
            fn=fn,
            surface=surface,
            summary=summary,
            techniques=tuple(techniques),
            references=tuple(references),
        )
        return fn

    return decorator


def registry() -> dict[str, DetectorSpec]:
    """Every registered detector, keyed by name."""
    return dict(_REGISTRY)


def for_surface(surface: Surface) -> list[DetectorSpec]:
    return [spec for spec in _REGISTRY.values() if spec.surface == surface]


def run_surface(surface: Surface, alert: Alert) -> list[DetectorResult]:
    """Run every detector for one investigator's surface.

    Returns all results, fired or not. A detector that looked and found nothing
    is information — it is the difference between "no beaconing" and "nobody
    checked for beaconing", and an analyst reading a verdict needs to know
    which of those they are looking at.
    """
    return [spec.fn(alert) for spec in for_surface(surface)]


def miss(detector: str, reason: str) -> DetectorResult:
    """A detector that had nothing to work with.

    Distinct from a detector that ran and found nothing suspicious: `rationale`
    records why there was no answer, so the report can say so.
    """
    return DetectorResult(detector=detector, fired=False, score=0.0, rationale=reason)


def clear(detector: str, rationale: str, **facts) -> DetectorResult:
    """A detector that ran and found nothing suspicious.

    `examined=True` is the load-bearing part. A verdict of "false positive"
    means someone looked; this is the record that someone did.
    """
    return DetectorResult(
        detector=detector,
        fired=False,
        score=0.0,
        rationale=rationale,
        facts=facts,
        examined=True,
    )


EARTH_RADIUS_KM = 6371.0088


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres.

    Great-circle rather than driving distance on purpose: it is a strict lower
    bound on how far someone actually travelled, so the implied velocity it
    feeds is a lower bound too. A detector that under-claims is one an analyst
    can trust.
    """
    p1, p2 = radians(lat1), radians(lat2)
    dphi = p2 - p1
    dlambda = radians(lon2 - lon1)
    a = sin(dphi / 2) ** 2 + cos(p1) * cos(p2) * sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * asin(sqrt(min(1.0, a)))


def seconds_between(earlier: datetime, later: datetime) -> float:
    """Signed seconds between two timestamps, tolerant of naive/aware mixes."""
    if (earlier.tzinfo is None) != (later.tzinfo is None):
        from datetime import UTC

        earlier = earlier.replace(tzinfo=UTC) if earlier.tzinfo is None else earlier
        later = later.replace(tzinfo=UTC) if later.tzinfo is None else later
    return (later - earlier).total_seconds()


def coefficient_of_variation(values: Sequence[float]) -> float:
    """Standard deviation over mean. Scale-free, so 60 s and 3600 s compare."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return sqrt(variance) / mean


def median_absolute_deviation(values: Sequence[float]) -> float:
    """Robust spread. Unlike stddev, one outlier does not swamp it.

    Beaconing detection needs this: a single missed check-in in an otherwise
    metronomic pattern would wreck a stddev-based score, and missed check-ins
    are normal on a laptop that sleeps.
    """
    if not values:
        return 0.0
    centre = median(values)
    return median([abs(v - centre) for v in values])


def shannon_entropy(text: str) -> float:
    """Bits per character."""
    if not text:
        return 0.0
    from collections import Counter
    from math import log2

    counts = Counter(text)
    length = len(text)
    return abs(-sum((c / length) * log2(c / length) for c in counts.values()))


def scale(value: float, low: float, high: float) -> float:
    """Map `value` onto 0..1 across the band `low..high`, clamped.

    Detector scores are graded rather than binary so that synthesis can weigh a
    marginal signal differently from an unambiguous one.
    """
    if high <= low:
        return 1.0 if value >= high else 0.0
    return max(0.0, min(1.0, (value - low) / (high - low)))


def ordered_by_time[T](items: Iterable[T], key: Callable[[T], datetime]) -> list[T]:
    """Sort by timestamp. Detectors must never assume input order."""
    return sorted(items, key=key)


@dataclass(slots=True)
class Baseline:
    """Environment knowledge a detector is allowed to assume.

    Committed to the repo, loaded from disk, never fetched. In a real
    deployment this is the asset inventory and a process-frequency baseline; here
    it is a small honest stand-in, and `docs/DETECTORS.md` says so.
    """

    common_parents: dict[str, set[str]] = field(default_factory=dict)
    admin_tools: set[str] = field(default_factory=set)
    known_good_paths: dict[str, set[str]] = field(default_factory=dict)
