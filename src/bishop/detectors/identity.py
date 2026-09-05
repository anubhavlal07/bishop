"""Identity detectors — what the account did, and whether a human could have.

These run against `alert.auth_events`, which the normaliser fills from the
identity provider. Nothing here reads the clock or the network.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from itertools import pairwise

from bishop.detectors.base import (
    clear,
    haversine_km,
    miss,
    ordered_by_time,
    register,
    scale,
    seconds_between,
)
from bishop.schema.alert import Alert, AuthEvent
from bishop.schema.evidence import DetectorResult

#: Cruising speed of a commercial airliner, rounded down. Below this, "they
#: flew" is an ordinary explanation and the detector should stay quiet.
PLAUSIBLE_TRAVEL_KMH = 900.0

#: Above this, no combination of aircraft and time zones explains it.
IMPOSSIBLE_TRAVEL_KMH = 1200.0

#: Under this gap, no travel explains the distance at any speed, so the pair is
#: a change of network egress rather than a person moving. Reported, not fired.
NETWORK_ARTEFACT_SECONDS = 300.0

#: Consumer geolocation is accurate to a city at best. Below this, apparent
#: movement is database imprecision.
SAME_METRO_KM = 50.0

SUCCESS_OUTCOMES = {"success", "mfa_success"}
FAILURE_OUTCOMES = {"failure", "denied", "mfa_denied"}


def _located_by_principal(events: list[AuthEvent]) -> dict[str, list[tuple[int, AuthEvent]]]:
    """Successful, geolocated logins grouped by account.

    Grouping is the whole correctness of this detector. One alert routinely
    carries events for several accounts, and comparing a login by `alice` in
    London against one by `bob` in Singapore manufactures travel that nobody
    did. The index travels with the event so a finding can point at the exact
    entry rather than a city name.
    """
    grouped: dict[str, list[tuple[int, AuthEvent]]] = defaultdict(list)
    for index, event in enumerate(events):
        if event.outcome not in SUCCESS_OUTCOMES:
            continue
        if event.geo is None or not event.geo.has_coordinates:
            continue
        grouped[str(event.username).strip().lower()].append((index, event))
    return grouped


@register(
    surface="identity",
    summary=(
        "Great-circle distance between one account's consecutive successful logins "
        "over the time between them, compared against airliner cruising speed."
    ),
    techniques=["T1078"],
    references=["https://attack.mitre.org/techniques/T1078/"],
)
def impossible_travel(alert: Alert) -> DetectorResult:
    """Two successful logins too far apart for the same person to have made both.

    The velocity is a lower bound twice over: great-circle distance understates
    real travel, and the detector uses the shortest gap between the two
    sightings. If it says 4,000 km/h, the true implied speed is higher.

    Three cases are separated rather than collapsed, because they mean different
    things and a single "impossible travel" label would be wrong for two of them:

    - **A gap under `NETWORK_ARTEFACT_SECONDS`** cannot be travel at any speed,
      so it is not reported as travel. It is a VPN or proxy egress change, and
      the detector deliberately does *not* fire — this is the single largest
      source of false positives in real deployments, and firing on it would put
      grounded evidence behind an explanation the detector itself disbelieves.
    - **A non-positive gap** is concurrent sessions, which is a genuine signal
      but is just as often duplicated events or clock skew between collectors.
      It fires at a capped score rather than the maximum, because an infinite
      implied velocity is an artefact of dividing by zero, not a measurement.
    - **A positive gap implying superhuman speed** is the real finding.
    """
    grouped = _located_by_principal(alert.auth_events)
    comparable = {user: events for user, events in grouped.items() if len(events) >= 2}
    if not comparable:
        return miss(
            "impossible_travel",
            "no single account had two successful logins carrying geolocation, "
            "so no pair could be compared",
        )

    best: dict[str, object] | None = None
    best_rank = (-1.0, 0.0)  # (case weight, velocity) — concurrent ranks below travel
    pairs_compared = 0
    suppressed: list[dict[str, object]] = []

    for username, events in comparable.items():
        ordered = ordered_by_time(events, key=lambda pair: pair[1].timestamp)
        for (earlier_index, earlier), (later_index, later) in pairwise(ordered):
            assert earlier.geo and later.geo  # guarded by _located_by_principal
            distance = haversine_km(
                float(earlier.geo.latitude),
                float(earlier.geo.longitude),
                float(later.geo.latitude),
                float(later.geo.longitude),
            )
            if distance < SAME_METRO_KM:
                continue  # geolocation is not precise enough to call this movement
            pairs_compared += 1
            gap = seconds_between(earlier.timestamp, later.timestamp)

            observation: dict[str, object] = {
                "username": username,
                "from_event_index": earlier_index,
                "to_event_index": later_index,
                "from_field": f"auth_events[{earlier_index}].geo",
                "to_field": f"auth_events[{later_index}].geo",
                "from_city": earlier.geo.city,
                "from_country": earlier.geo.country,
                "to_city": later.geo.city,
                "to_country": later.geo.country,
                "from_ip": earlier.source_ip,
                "to_ip": later.source_ip,
                "distance_km": round(distance, 1),
                "elapsed_seconds": round(gap, 1),
                "threshold_kmh": PLAUSIBLE_TRAVEL_KMH,
            }

            if 0 < gap <= NETWORK_ARTEFACT_SECONDS:
                observation["case"] = "network_artefact"
                observation["implied_kmh"] = round(distance / (gap / 3600.0), 1)
                suppressed.append(observation)
                continue

            if gap <= 0:
                observation["case"] = "concurrent_sessions"
                observation["implied_kmh"] = None
                rank = (1.0, 0.0)
            else:
                velocity = distance / (gap / 3600.0)
                observation["case"] = "travel"
                observation["implied_kmh"] = round(velocity, 1)
                if velocity < PLAUSIBLE_TRAVEL_KMH:
                    continue
                rank = (2.0, velocity)

            if rank > best_rank:
                best_rank = rank
                best = observation

    if best is None:
        if suppressed:
            worst = max(suppressed, key=lambda o: float(o["distance_km"]))  # type: ignore[arg-type]
            return clear(
                "impossible_travel",
                (
                    f"{worst['username']} was seen in {worst['from_city']} and "
                    f"{worst['to_city']} {float(worst['elapsed_seconds']) / 60:.1f} minutes "
                    f"apart. No travel explains that, and nothing does except a change of "
                    f"network egress — a VPN or proxy, not a second person"
                ),
                pairs_compared=pairs_compared,
                accounts_examined=len(comparable),
                suppressed_as_network_artefact=suppressed,
            )
        return clear(
            "impossible_travel",
            "every account's successive logins were close enough together to be one person",
            pairs_compared=pairs_compared,
            accounts_examined=len(comparable),
        )

    facts = dict(best)
    facts["pairs_compared"] = pairs_compared
    facts["accounts_examined"] = len(comparable)
    if suppressed:
        facts["suppressed_as_network_artefact"] = suppressed

    if best["case"] == "concurrent_sessions":
        return DetectorResult(
            detector="impossible_travel",
            fired=True,
            # Capped: duplicated events and collector clock skew produce this
            # too, and neither is an intrusion.
            score=0.55,
            facts=facts,
            rationale=(
                f"{best['username']} authenticated successfully from {best['from_city']} and "
                f"{best['to_city']} at the same instant, {best['distance_km']} km apart — "
                f"concurrent sessions, or two collectors whose clocks disagree"
            ),
            technique_hints=["T1078"],
        )

    velocity = float(best["implied_kmh"])  # type: ignore[arg-type]
    minutes = float(best["elapsed_seconds"]) / 60  # type: ignore[arg-type]
    return DetectorResult(
        detector="impossible_travel",
        fired=True,
        # A near-threshold value is a weaker signal than a physically absurd one.
        score=round(
            0.55 + 0.45 * scale(velocity, PLAUSIBLE_TRAVEL_KMH, IMPOSSIBLE_TRAVEL_KMH * 3), 3
        ),
        facts=facts,
        rationale=(
            f"{best['username']} authenticated from {best['from_city']} then "
            f"{best['to_city']} {minutes:.1f} minutes later — {best['distance_km']} km apart, "
            f"implying {velocity:,.0f} km/h against a {PLAUSIBLE_TRAVEL_KMH:,.0f} km/h ceiling"
        ),
        technique_hints=["T1078"],
    )


@register(
    surface="identity",
    summary=(
        "A burst of denied MFA prompts followed by an approval, which is what "
        "push-bombing looks like from the log side."
    ),
    techniques=["T1621"],
    references=["https://attack.mitre.org/techniques/T1621/"],
)
def mfa_fatigue(alert: Alert) -> DetectorResult:
    """Repeated MFA denials ending in an acceptance.

    The signal is not the denials — users misfire prompts all the time. It is
    the shape: several denials close together, then an approval, meaning the
    person eventually gave in or stopped paying attention.
    """
    events = ordered_by_time(alert.auth_events, key=lambda e: e.timestamp)
    mfa_events = [e for e in events if e.outcome in {"mfa_denied", "mfa_success"}]
    if len(mfa_events) < 2:
        return miss("mfa_fatigue", "fewer than two MFA events in the alert")

    denials = [e for e in mfa_events if e.outcome == "mfa_denied"]
    approvals = [e for e in mfa_events if e.outcome == "mfa_success"]

    if not denials:
        return clear("mfa_fatigue", "no MFA prompts were denied", mfa_events=len(mfa_events))

    window_seconds = seconds_between(mfa_events[0].timestamp, mfa_events[-1].timestamp)
    denials_before_approval = 0
    approved_after_burst = False
    if approvals:
        first_approval = approvals[0].timestamp
        denials_before_approval = sum(1 for e in denials if e.timestamp < first_approval)
        approved_after_burst = denials_before_approval >= 3

    facts = {
        "denials": len(denials),
        "approvals": len(approvals),
        "denials_before_approval": denials_before_approval,
        "window_seconds": round(window_seconds, 1),
        "source_ips": sorted({e.source_ip for e in mfa_events if e.source_ip}),
    }

    if not approved_after_burst:
        if len(denials) >= 5 and window_seconds <= 900:
            return DetectorResult(
                detector="mfa_fatigue",
                fired=True,
                score=0.5,
                facts=facts,
                rationale=(
                    f"{len(denials)} MFA prompts denied within {window_seconds / 60:.1f} minutes "
                    f"and none approved — push-bombing that the user held out against"
                ),
                technique_hints=["T1621"],
            )
        return clear(
            "mfa_fatigue",
            f"{len(denials)} MFA denials, which is below the burst threshold",
            **facts,
        )

    return DetectorResult(
        detector="mfa_fatigue",
        fired=True,
        score=round(min(0.95, 0.6 + 0.07 * denials_before_approval), 3),
        facts=facts,
        rationale=(
            f"{denials_before_approval} MFA prompts denied in "
            f"{window_seconds / 60:.1f} minutes, then one approved — the pattern of a user "
            f"worn down by repeated pushes"
        ),
        technique_hints=["T1621"],
    )


@register(
    surface="identity",
    summary=(
        "One source trying a few passwords against many accounts — the inverse of "
        "brute force, and invisible to per-account lockout."
    ),
    techniques=["T1110.003"],
    references=["https://attack.mitre.org/techniques/T1110/003/"],
)
def password_spray(alert: Alert) -> DetectorResult:
    """Many accounts, few attempts each, one origin.

    Per-account lockout does not fire on this by design, which is why it needs
    a detector that counts across accounts rather than within one.
    """
    failures = [e for e in alert.auth_events if e.outcome in FAILURE_OUTCOMES]
    if len(failures) < 5:
        return miss("password_spray", "fewer than five failed authentications in the alert")

    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in failures:
        by_ip[event.source_ip or "unknown"].append(event)

    worst_ip, worst_events = max(by_ip.items(), key=lambda kv: len({e.username for e in kv[1]}))
    targets = {str(e.username).lower() for e in worst_events}
    per_account = Counter(str(e.username).lower() for e in worst_events)
    max_per_account = max(per_account.values())

    successes_after = sorted(
        {
            str(e.username).lower()
            for e in alert.auth_events
            if e.outcome in SUCCESS_OUTCOMES
            and str(e.username).lower() in targets
            and e.source_ip == worst_ip
        }
    )

    facts = {
        "source_ip": worst_ip,
        "distinct_accounts": len(targets),
        "failed_attempts": len(worst_events),
        "max_attempts_per_account": max_per_account,
        "compromised_accounts": successes_after,
    }

    #: Spraying is wide and shallow. Deep and narrow is brute force, which is a
    #: different technique and would be a different detector.
    if len(targets) < 5 or max_per_account > 5:
        return clear(
            "password_spray",
            (
                f"{len(worst_events)} failures against {len(targets)} accounts from {worst_ip} — "
                f"too narrow or too deep to be spraying"
            ),
            **facts,
        )

    score = 0.5 + 0.3 * scale(len(targets), 5, 40)
    if successes_after:
        score = min(0.95, score + 0.25)

    rationale = (
        f"{worst_ip} failed against {len(targets)} distinct accounts with at most "
        f"{max_per_account} attempts each — wide and shallow, which per-account lockout misses"
    )
    if successes_after:
        rationale += f"; {len(successes_after)} of those accounts then authenticated successfully"

    return DetectorResult(
        detector="password_spray",
        fired=True,
        score=round(score, 3),
        facts=facts,
        rationale=rationale,
        technique_hints=["T1110.003"],
    )


#: Binaries that can actually change group membership or create accounts. The
#: detector will not infer a group change from a command line unless the process
#: being run is one of these — see `account_manipulation` for why.
GROUP_MANAGEMENT_TOOLS: frozenset[str] = frozenset(
    {
        "net.exe",
        "net1.exe",
        "net",
        "dsadd.exe",
        "dsmod.exe",
        "powershell.exe",
        "pwsh.exe",
        "wmic.exe",
        "usermod",
        "useradd",
        "adduser",
        "gpasswd",
        "dscl",
    }
)

PRIVILEGED_GROUPS: tuple[str, ...] = (
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "backup operators",
    "remote desktop users",
    "account operators",
    "sudo",
    "wheel",
    "admin",
)


def _basename(value: object) -> str:
    if not value:
        return ""
    return str(value).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip().lower()


@register(
    surface="identity",
    summary=(
        "Privileged group membership and account creation, read from the directory's "
        "own change events where available and from group-management command lines "
        "otherwise."
    ),
    techniques=["T1098", "T1136"],
    references=["https://attack.mitre.org/techniques/T1098/"],
)
def account_manipulation(alert: Alert) -> DetectorResult:
    """Privileged group additions and account creation.

    **On trusting command lines.** A process command line is attacker-authored,
    which cuts both ways. The obvious risk is an attacker hiding a real change;
    the subtler one is an attacker *manufacturing* a finding — writing
    `net localgroup administrators /add` into a filename so that a lexical match
    reports a privilege escalation that never happened. That direction is not
    harmless: fabricated evidence pointed at an innocent account wastes an
    analyst's night and, if Bishop proposed containment on it, disables the
    wrong person.

    Two things bound it. The directory's own change events are preferred when
    the source provides them, because those are written by the domain
    controller rather than by whoever started the process. Where the command
    line is the only source, the *executable* must actually be a group
    management tool — `notepad.exe "…administrators /add.txt"` no longer
    matches — and the finding is scored lower and labelled with its source, so
    a reader knows which kind of evidence they are looking at.

    Neither makes the command-line path trustworthy. It makes it bounded, and
    the facts say which path produced the finding.
    """
    hits: list[dict[str, object]] = []

    # Preferred source: the directory's own audit events, normalised into `raw`
    # by the collector. Windows writes these as 4728/4732/4756.
    for index, change in enumerate(alert.raw.get("group_changes") or []):
        if not isinstance(change, dict):
            continue
        group = str(change.get("group", "")).lower()
        action = str(change.get("action", "add")).lower()
        if action not in {"add", "added"}:
            continue
        if not any(privileged in group for privileged in PRIVILEGED_GROUPS):
            continue
        hits.append(
            {
                "where": f"raw.group_changes[{index}]",
                "kind": "privileged_group_add",
                "group": str(change.get("group", "")),
                "member": str(change.get("member", "")),
                "evidence_source": "directory_event",
                "weight": 0.75,
            }
        )

    for index, account in enumerate(alert.raw.get("accounts_created") or []):
        hits.append(
            {
                "where": f"raw.accounts_created[{index}]",
                "kind": "account_created",
                "group": "",
                "member": str(account),
                "evidence_source": "directory_event",
                "weight": 0.6,
            }
        )

    # Fallback source: command lines, and only from a binary that could actually
    # have made the change.
    haystacks: list[tuple[str, str, str]] = []
    for label, process in (("process", alert.process), ("parent_process", alert.parent_process)):
        if process and process.command_line:
            haystacks.append(
                (
                    label,
                    _basename(process.name) or _basename(process.path),
                    str(process.command_line),
                )
            )
    for index, child in enumerate(alert.child_processes):
        if child.command_line:
            haystacks.append(
                (
                    f"child_processes[{index}]",
                    _basename(child.name) or _basename(child.path),
                    str(child.command_line),
                )
            )

    examined = 0
    for where, image, command_line in haystacks:
        if image not in GROUP_MANAGEMENT_TOOLS:
            continue
        examined += 1
        text = command_line.lower()
        adds = "/add" in text or " -a " in text or "-ag " in text or "add-localgroupmember" in text
        if adds and ("localgroup" in text or "group" in text or "usermod" in text):
            for group in PRIVILEGED_GROUPS:
                if group in text:
                    hits.append(
                        {
                            "where": where,
                            "kind": "privileged_group_add",
                            "group": group,
                            "image": image,
                            "command_line": command_line[:300],
                            "evidence_source": "command_line",
                            "weight": 0.55,
                        }
                    )
                    break
        if "net user" in text and "/add" in text:
            hits.append(
                {
                    "where": where,
                    "kind": "account_created",
                    "group": "",
                    "image": image,
                    "command_line": command_line[:300],
                    "evidence_source": "command_line",
                    "weight": 0.45,
                }
            )

    facts: dict[str, object] = {
        "observations": hits,
        "command_lines_examined": examined,
        "command_lines_skipped_wrong_binary": len(haystacks) - examined,
        "directory_events_available": bool(alert.raw.get("group_changes")),
    }

    if not haystacks and not alert.raw.get("group_changes"):
        return miss(
            "account_manipulation",
            "the alert carries neither directory change events nor process command lines",
        )
    if not hits:
        return clear(
            "account_manipulation",
            "no privileged group additions or account creations in the available evidence",
            **facts,
        )

    strongest = max(hits, key=lambda h: float(h["weight"]))  # type: ignore[arg-type]
    kinds = {str(h["kind"]) for h in hits}
    score = float(strongest["weight"])  # type: ignore[arg-type]
    if len(kinds) > 1:
        score = min(0.85, score + 0.15)

    described = ", ".join(
        f"{str(h['kind']).replace('_', ' ')}{f' ({h["group"]})' if h['group'] else ''}"
        for h in hits[:3]
    )
    rationale = f"observed {described}"
    if strongest["evidence_source"] == "directory_event":
        rationale += ", from the directory's own change events"
    else:
        rationale += (
            f", inferred from a {strongest.get('image')} command line — note that command "
            f"lines are written by whoever started the process, so this is weaker evidence "
            f"than a directory event"
        )

    return DetectorResult(
        detector="account_manipulation",
        fired=True,
        score=round(score, 3),
        facts=facts,
        rationale=rationale,
        technique_hints=["T1098"] + (["T1136"] if "account_created" in kinds else []),
    )
