"""Threat-intelligence detectors — reputation lookups against a cached corpus.

Bishop never calls a feed during a run. Intelligence is fetched ahead of time by
`scripts/fetch_intel.py` and the detector reads the resulting file. Three
reasons, in order:

1. A detector that makes a network call is not reproducible, so the eval
   scorecard stops meaning anything.
2. A SOC tool that resolves attacker infrastructure at triage time tells the
   attacker their payload was received.
3. `just demo` has to run on a machine with no credentials.

Two caches, and which one is loaded matters to how a hit should be read. A
fetched cache under `data/` wins when present; otherwise the committed one
under `fixtures/` is used, which is synthetic and says so in its own metadata
and in every rationale the detector produces from it. abuse.ch's terms permit
use but not redistribution, which is why the real one is gitignored.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from bishop.detectors.base import clear, miss, register
from bishop.schema.alert import Alert
from bishop.schema.evidence import DetectorResult

_REPO_ROOT = Path(__file__).resolve().parents[3]

#: A real cache fetched by `just intel`. Gitignored, so it is absent on a fresh
#: clone and present after someone runs the fetch script.
FETCHED_CACHE_PATH = _REPO_ROOT / "data" / "intel" / "ioc_cache.json"

#: The committed synthetic cache. Always present, and honest about being made up.
SYNTHETIC_CACHE_PATH = _REPO_ROOT / "fixtures" / "intel" / "ioc_cache.json"


def default_cache_path() -> Path:
    """Prefer a fetched cache over the synthetic one, when it exists."""
    return FETCHED_CACHE_PATH if FETCHED_CACHE_PATH.exists() else SYNTHETIC_CACHE_PATH


@dataclass(frozen=True, slots=True)
class IocRecord:
    indicator: str
    kind: str  # ip | domain | url | sha256
    verdict: str  # malicious | suspicious | benign
    #: Feed name and first-seen date, so a stale hit can be recognised as stale.
    source: str = "unknown"
    first_seen: str = ""
    last_seen: str = ""
    malware_family: str = ""
    confidence: float = 0.5
    note: str = ""


@dataclass(slots=True)
class IntelCache:
    """An immutable snapshot of indicator reputation."""

    records: dict[str, IocRecord] = field(default_factory=dict)
    snapshot_taken: str = ""
    synthetic: bool = True

    def lookup(self, indicator: str) -> IocRecord | None:
        return self.records.get(indicator.strip().lower())

    def __len__(self) -> int:
        return len(self.records)


@lru_cache(maxsize=4)
def load_cache(path: Path | None = None) -> IntelCache:
    """Load and memoise the indicator cache.

    Missing file is not an error: Bishop runs without intelligence and the
    detector says so, rather than failing the investigation.
    """
    resolved = path or default_cache_path()
    if not resolved.exists():
        return IntelCache(snapshot_taken="", synthetic=True)
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    records: dict[str, IocRecord] = {}
    for entry in payload.get("indicators", []):
        record = IocRecord(**entry)
        records[record.indicator.strip().lower()] = record
    return IntelCache(
        records=records,
        snapshot_taken=payload.get("snapshot_taken", ""),
        synthetic=bool(payload.get("synthetic", True)),
    )


def _indicators_in(alert: Alert) -> list[tuple[str, str, str]]:
    """Every indicator worth looking up, as `(where, kind, value)`."""
    found: list[tuple[str, str, str]] = []

    for index, connection in enumerate(alert.connections):
        if connection.dest_ip:
            found.append((f"connections[{index}].dest_ip", "ip", connection.dest_ip))
        if connection.hostname:
            found.append((f"connections[{index}].hostname", "domain", str(connection.hostname)))
        if connection.url:
            found.append((f"connections[{index}].url", "url", str(connection.url)))

    for index, event in enumerate(alert.dns_events):
        found.append((f"dns_events[{index}].query", "domain", str(event.query)))

    for label, process in (
        ("process", alert.process),
        ("parent_process", alert.parent_process),
        ("grandparent_process", alert.grandparent_process),
    ):
        if process and process.sha256:
            found.append((f"{label}.sha256", "sha256", process.sha256))
    for index, child in enumerate(alert.child_processes):
        if child.sha256:
            found.append((f"child_processes[{index}].sha256", "sha256", child.sha256))

    if alert.file and alert.file.sha256:
        found.append(("file.sha256", "sha256", alert.file.sha256))

    if alert.email:
        for index, link in enumerate(alert.email.links):
            found.append((f"email.links[{index}]", "url", str(link)))

    for index, event in enumerate(alert.auth_events):
        if event.source_ip:
            found.append((f"auth_events[{index}].source_ip", "ip", event.source_ip))

    return found


def _is_private(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


@register(
    surface="threatintel",
    summary=(
        "Reputation lookup for every IP, domain, URL and hash in the alert, against "
        "an indicator cache fetched ahead of the run."
    ),
    techniques=[],
    references=["https://abuse.ch/"],
)
def ioc_reputation(alert: Alert) -> DetectorResult:
    """Match alert indicators against known-bad reputation.

    A hit here is one of the few near-conclusive signals Bishop has, so the
    facts carry the feed and the first-seen date: an indicator that was
    malicious in 2019 and has since been reclaimed is a different thing from one
    seen last week, and the analyst gets to make that call.
    """
    cache = load_cache()
    indicators = _indicators_in(alert)
    checked = [(where, kind, value) for where, kind, value in indicators if not _is_private(value)]

    if not checked:
        return miss("ioc_reputation", "the alert contained no public indicators to look up")
    if not len(cache):
        return miss(
            "ioc_reputation",
            "no indicator cache is present; run `just intel` to populate one before relying on this",
        )

    hits: list[dict[str, object]] = []
    for where, kind, value in checked:
        record = cache.lookup(value)
        if record is None and kind == "url":
            # A URL misses on the full string but its host may be listed.
            host = value.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            record = cache.lookup(host)
        if record is None or record.verdict == "benign":
            continue
        hits.append(
            {
                "where": where,
                "indicator": value[:200],
                "kind": record.kind,
                "verdict": record.verdict,
                "source": record.source,
                "malware_family": record.malware_family,
                "first_seen": record.first_seen,
                "last_seen": record.last_seen,
                "confidence": record.confidence,
                "note": record.note,
            }
        )

    facts: dict[str, object] = {
        "indicators_checked": len(checked),
        "cache_size": len(cache),
        "cache_snapshot": cache.snapshot_taken,
        "cache_is_synthetic": cache.synthetic,
        "hits": hits,
    }

    if not hits:
        return clear(
            "ioc_reputation",
            f"none of the {len(checked)} indicators in this alert appear in the cache",
            **facts,
        )

    malicious = [h for h in hits if h["verdict"] == "malicious"]
    strongest = max(hits, key=lambda h: float(h["confidence"]))  # type: ignore[arg-type]
    score = min(0.95, float(strongest["confidence"]) + 0.05 * (len(hits) - 1))  # type: ignore[arg-type]
    if not malicious:
        score = min(score, 0.5)

    family = strongest["malware_family"] or "an unattributed campaign"
    rationale = (
        f"{strongest['indicator']} ({strongest['where']}) is listed as {strongest['verdict']} "
        f"by {strongest['source']}, associated with {family}"
    )
    if cache.synthetic:
        rationale += "; note the committed cache is synthetic — see docs/DETECTORS.md"

    return DetectorResult(
        detector="ioc_reputation",
        fired=True,
        score=round(score, 3),
        facts=facts,
        rationale=rationale,
        technique_hints=[],
    )
