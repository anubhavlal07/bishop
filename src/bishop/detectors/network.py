"""Network detectors — the shape of traffic rather than its content.

Both detectors here work on timing and structure, not payload, because that is
what survives TLS. Beaconing is a rhythm; DNS tunnelling is a distribution of
label entropy. Neither needs to see inside a packet, and neither reads a clock:
every timestamp comes from the alert.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import pairwise

from bishop.detectors.base import (
    clear,
    coefficient_of_variation,
    median_absolute_deviation,
    miss,
    ordered_by_time,
    register,
    scale,
    seconds_between,
    shannon_entropy,
)
from bishop.schema.alert import Alert
from bishop.schema.evidence import DetectorResult

#: Below this, inter-arrival times are too regular to be a human at a keyboard.
#: Automated software also beacons regularly — the detector says "automation",
#: and synthesis decides whose.
REGULAR_CV_THRESHOLD = 0.25

#: Fewer than this and any apparent rhythm is coincidence.
MIN_BEACON_SAMPLES = 5

#: Public suffixes get one extra label before the interesting part.
_TWO_PART_TLDS = frozenset({"co.uk", "com.au", "co.jp", "co.nz", "com.br", "co.in", "org.uk"})


def _without_missed_checkins(gaps: list[float]) -> tuple[list[float], int]:
    """Drop the largest few intervals before measuring regularity.

    A laptop that sleeps through three check-ins leaves one enormous gap in an
    otherwise metronomic series, and including it would make a textbook beacon
    look irregular. Dropping the top fifth — at most two — removes that without
    letting a genuinely irregular series through, because trimming two values
    out of a scattered series leaves it just as scattered.

    Median absolute deviation was the obvious tool here and is the wrong one: it
    tolerates a *majority* of irregular values, so browsing traffic with gaps of
    5 s, 900 s and 3600 s scores as a clean beacon. Both measures are still
    reported in the facts, because they are informative to a reader even though
    the decision no longer rests on them.
    """
    if len(gaps) < 4:
        return list(gaps), 0
    drop = min(2, len(gaps) // 5)
    if not drop:
        return list(gaps), 0
    return sorted(gaps)[:-drop], drop


@register(
    surface="network",
    summary=(
        "Inter-arrival regularity across repeated connections to one destination, "
        "measured as coefficient of variation after dropping missed check-ins."
    ),
    techniques=["T1071.001", "T1573"],
    references=["https://attack.mitre.org/techniques/T1071/001/"],
)
def beaconing(alert: Alert) -> DetectorResult:
    """Callbacks on a schedule.

    Regularity is the coefficient of variation of the inter-arrival times,
    measured after `_without_missed_checkins` removes the largest few gaps. That
    trimming is what lets a sleeping laptop still look like a beacon without
    letting ordinary bursty browsing look like one.

    Small jitter is *more* suspicious than none, not less: modern C2 frameworks
    randomise the interval by design, so a perfectly flat series often means a
    cron job and a 10-20% wobble often means an implant.
    """
    if len(alert.connections) < MIN_BEACON_SAMPLES:
        return miss(
            "beaconing",
            f"only {len(alert.connections)} connections in the alert; "
            f"at least {MIN_BEACON_SAMPLES} are needed to judge a rhythm",
        )

    by_destination: dict[str, list] = defaultdict(list)
    for connection in alert.connections:
        key = str(connection.hostname or connection.dest_ip or "unknown")
        by_destination[key].append(connection)

    best: dict[str, object] | None = None
    best_score = 0.0

    for destination, group in by_destination.items():
        if len(group) < MIN_BEACON_SAMPLES:
            continue
        ordered = ordered_by_time(group, key=lambda c: c.timestamp)
        gaps = [seconds_between(a.timestamp, b.timestamp) for a, b in pairwise(ordered)]
        gaps = [g for g in gaps if g > 0]
        if len(gaps) < MIN_BEACON_SAMPLES - 1:
            continue

        mean_gap = sum(gaps) / len(gaps)
        cv = coefficient_of_variation(gaps)
        mad = median_absolute_deviation(gaps)
        mad_ratio = mad / mean_gap if mean_gap else 0.0

        kept, dropped = _without_missed_checkins(gaps)
        regularity = coefficient_of_variation(kept)
        if regularity > REGULAR_CV_THRESHOLD:
            continue

        payloads = [c.bytes_out for c in ordered if c.bytes_out is not None]
        uniform_payload = bool(payloads) and len(set(payloads)) <= max(2, len(payloads) // 4)

        score = 0.45 + 0.35 * (1.0 - scale(regularity, 0.0, REGULAR_CV_THRESHOLD))
        if uniform_payload:
            # Near-identical request sizes on a fixed schedule is a check-in,
            # not a person browsing.
            score += 0.15
        if 0.02 <= regularity <= 0.2:
            # The deliberate-jitter band: too regular for a human, too irregular
            # for a scheduler.
            score += 0.05
        score = min(0.93, score)

        if score <= best_score:
            continue
        best_score = score
        best = {
            "destination": destination,
            "connections": len(ordered),
            "mean_interval_seconds": round(mean_gap, 2),
            "coefficient_of_variation": round(cv, 4),
            "trimmed_coefficient_of_variation": round(regularity, 4),
            "median_absolute_deviation_seconds": round(mad, 2),
            "mad_ratio": round(mad_ratio, 4),
            "gaps_dropped_as_missed_checkins": dropped,
            "jitter_percent": round(regularity * 100, 1),
            "uniform_payload_size": uniform_payload,
            "bytes_out_values": sorted(set(payloads))[:5],
            "first_seen": ordered[0].timestamp.isoformat(),
            "last_seen": ordered[-1].timestamp.isoformat(),
            "threshold_cv": REGULAR_CV_THRESHOLD,
        }

    if best is None:
        return clear(
            "beaconing",
            "no destination showed a regular enough inter-arrival pattern to be a beacon",
            destinations_examined=len(by_destination),
            connections=len(alert.connections),
        )

    interval = float(best["mean_interval_seconds"])  # type: ignore[arg-type]
    rationale = (
        f"{best['connections']} connections to {best['destination']} every "
        f"{interval:.0f} s ± {best['jitter_percent']}% — regular enough to be automated"
    )
    if best["uniform_payload_size"]:
        rationale += ", with near-identical request sizes"

    hints = ["T1071.001"]
    if _mostly_tls(alert.connections, str(best["destination"])):
        # A beacon over 443 is an encrypted channel, which is the property that
        # makes the payload unavailable and the rhythm the only thing left.
        hints.append("T1573")

    return DetectorResult(
        detector="beaconing",
        fired=True,
        score=round(best_score, 3),
        facts=best,
        rationale=rationale,
        technique_hints=hints,
    )


def _mostly_tls(connections, destination: str) -> bool:
    matching = [
        c
        for c in connections
        if str(c.hostname or c.dest_ip or "unknown") == destination and c.dest_port
    ]
    if not matching:
        return False
    return sum(1 for c in matching if c.dest_port in (443, 8443)) >= len(matching) * 0.8


def _registrable_parts(query: str) -> tuple[str, list[str]]:
    """Split a hostname into `(registrable domain, subdomain labels)`.

    Deliberately simple — no public-suffix list dependency. It handles the
    common two-part TLDs and treats everything else as `domain.tld`, which is
    accurate enough for a tunnelling heuristic and honest about its limits.
    """
    labels = [label for label in str(query).lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return ".".join(labels), []
    tail = ".".join(labels[-2:])
    take = 3 if tail in _TWO_PART_TLDS and len(labels) >= 3 else 2
    return ".".join(labels[-take:]), labels[:-take]


@register(
    surface="network",
    summary=(
        "DNS used as a transport: high-entropy labels, unusual label lengths, and "
        "many unique subdomains under one parent."
    ),
    techniques=["T1071.004", "T1048.003"],
    references=["https://attack.mitre.org/techniques/T1071/004/"],
)
def dns_exfiltration(alert: Alert) -> DetectorResult:
    """Data encoded into DNS query names.

    Three signals combined: the subdomain labels look encoded rather than
    written (high Shannon entropy), they are close to the 63-character limit,
    and there are many distinct ones under a single parent domain. Any one of
    those alone has benign causes — CDNs generate high-entropy hostnames all
    day — so the detector requires the combination.
    """
    if len(alert.dns_events) < 3:
        return miss(
            "dns_exfiltration",
            f"only {len(alert.dns_events)} DNS queries in the alert; too few to judge a pattern",
        )

    by_parent: dict[str, list[str]] = defaultdict(list)
    for event in alert.dns_events:
        parent, subdomains = _registrable_parts(str(event.query))
        if subdomains:
            by_parent[parent].append(".".join(subdomains))

    if not by_parent:
        return clear(
            "dns_exfiltration",
            "every query was for a bare domain with no subdomain labels to carry data",
            queries=len(alert.dns_events),
        )

    best: dict[str, object] | None = None
    best_score = 0.0

    for parent, subdomains in by_parent.items():
        unique = sorted(set(subdomains))
        if len(unique) < 3:
            continue

        entropies = [shannon_entropy(s.replace(".", "")) for s in unique]
        mean_entropy = sum(entropies) / len(entropies)
        longest = max(len(s) for s in unique)
        mean_length = sum(len(s) for s in unique) / len(unique)
        uniqueness = len(unique) / len(subdomains)

        # Encoded data sits above ~3.5 bits/char; English hostnames sit below.
        entropy_signal = scale(mean_entropy, 3.2, 4.3)
        length_signal = scale(mean_length, 20, 55)
        volume_signal = scale(len(unique), 5, 50)

        if entropy_signal < 0.2 or length_signal < 0.15:
            continue

        score = min(
            0.92,
            0.3 * entropy_signal + 0.3 * length_signal + 0.25 * volume_signal + 0.15 * uniqueness,
        )
        # Two weak legs and one strong one is not a tunnel.
        if sum(1 for s in (entropy_signal, length_signal, volume_signal) if s > 0.35) < 2:
            continue
        if score <= best_score:
            continue

        best_score = score
        best = {
            "parent_domain": parent,
            "unique_subdomains": len(unique),
            "total_queries": len(subdomains),
            "mean_entropy_bits_per_char": round(mean_entropy, 3),
            "mean_subdomain_length": round(mean_length, 1),
            "longest_subdomain_length": longest,
            "uniqueness_ratio": round(uniqueness, 3),
            "examples": unique[:3],
        }

    if best is None:
        return clear(
            "dns_exfiltration",
            "subdomain entropy and length stayed within the range of ordinary hostnames",
            parents_examined=len(by_parent),
            queries=len(alert.dns_events),
        )

    return DetectorResult(
        detector="dns_exfiltration",
        fired=True,
        score=round(best_score, 3),
        facts=best,
        rationale=(
            f"{best['unique_subdomains']} distinct subdomains under {best['parent_domain']}, "
            f"averaging {best['mean_subdomain_length']} characters at "
            f"{best['mean_entropy_bits_per_char']} bits per character — that is encoded data, "
            f"not hostnames"
        ),
        # DNS carrying data out is exfiltration over a non-C2 protocol as much
        # as it is application-layer C2; which one it is depends on direction,
        # and the volume here says data is leaving.
        technique_hints=["T1071.004", "T1048.003"],
    )


@register(
    surface="network",
    summary="Large outbound transfers relative to what came back, to a single destination.",
    techniques=["T1041", "T1030"],
    references=["https://attack.mitre.org/techniques/T1041/"],
)
def outbound_volume(alert: Alert) -> DetectorResult:
    """Asymmetry between bytes sent and bytes received.

    Browsing is inbound-heavy. A session that sends far more than it receives is
    an upload, and an upload nobody scheduled is worth a look.
    """
    with_bytes = [
        c for c in alert.connections if c.bytes_out is not None and c.bytes_in is not None
    ]
    if not with_bytes:
        return miss("outbound_volume", "no connection in the alert carried byte counts")

    by_destination: dict[str, list] = defaultdict(list)
    for connection in with_bytes:
        by_destination[str(connection.hostname or connection.dest_ip or "unknown")].append(
            connection
        )

    worst_key, worst_group = max(
        by_destination.items(), key=lambda kv: sum(c.bytes_out or 0 for c in kv[1])
    )
    sent = sum(c.bytes_out or 0 for c in worst_group)
    received = sum(c.bytes_in or 0 for c in worst_group)
    ratio = sent / received if received else float(sent)

    sizes = [c.bytes_out for c in worst_group if c.bytes_out]
    # Near-identical transfer sizes across many connections is a deliberate
    # chunk size, which is what T1030 describes — data split to stay under a
    # threshold rather than sent in one stream.
    uniform_chunks = len(sizes) >= 5 and len(set(sizes)) <= max(2, len(sizes) // 5)

    facts = {
        "destination": worst_key,
        "uniform_chunk_size": uniform_chunks,
        "bytes_out": sent,
        "bytes_in": received,
        "out_in_ratio": round(ratio, 2) if received else None,
        "connections": len(worst_group),
        "megabytes_out": round(sent / 1_000_000, 2),
    }

    #: 10 MB and 10:1. Below either, ordinary application traffic explains it.
    if sent < 10_000_000 or ratio < 10:
        return clear(
            "outbound_volume",
            (
                f"{facts['megabytes_out']} MB sent to {worst_key} at a {facts['out_in_ratio']}:1 "
                f"ratio — within the range of ordinary application traffic"
            ),
            **facts,
        )

    return DetectorResult(
        detector="outbound_volume",
        fired=True,
        score=round(
            min(
                0.85,
                0.4 + 0.25 * scale(sent, 10_000_000, 1_000_000_000) + 0.2 * scale(ratio, 10, 200),
            ),
            3,
        ),
        facts=facts,
        rationale=(
            f"{facts['megabytes_out']} MB uploaded to {worst_key} against "
            f"{round(received / 1_000_000, 2)} MB received — a {facts['out_in_ratio']}:1 "
            f"outbound ratio, which is an upload rather than a session"
        ),
        technique_hints=["T1041"] + (["T1030"] if uniform_chunks else []),
    )
