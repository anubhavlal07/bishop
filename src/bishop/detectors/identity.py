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

PLAUSIBLE_TRAVEL_KMH = 900.0

IMPOSSIBLE_TRAVEL_KMH = 1200.0

NETWORK_ARTEFACT_SECONDS = 300.0

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
        if grouped:
            plural = "" if len(grouped) == 1 else "s"
            return clear(
                "impossible_travel",
                f"{len(grouped)} account{plural} had geolocated logins, but no single "
                f"account had two, so no journey is implied by this alert",
                accounts_with_geolocation=sorted(grouped),
            )
        return miss(
            "impossible_travel",
            "no single account had two successful logins carrying geolocation, "
            "so no pair could be compared",
        )

    best: dict[str, object] | None = None
    best_rank = (-1.0, 0.0)
    pairs_compared = 0
    suppressed: list[dict[str, object]] = []

    for username, events in comparable.items():
        ordered = ordered_by_time(events, key=lambda pair: pair[1].timestamp)
        for (earlier_index, earlier), (later_index, later) in pairwise(ordered):
            assert earlier.geo and later.geo
            distance = haversine_km(
                float(earlier.geo.latitude),
                float(earlier.geo.longitude),
                float(later.geo.latitude),
                float(later.geo.longitude),
            )
            if distance < SAME_METRO_KM:
                continue
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
        technique_hints=["T1621", "T1078"],
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
        technique_hints=["T1110.003"] + (["T1078"] if successes_after else []),
    )


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


#: Kerberos encryption types, as Windows event 4769 reports them. RC4 is the
#: one an attacker wants: the resulting ticket is encrypted with the service
#: account's NTLM hash and can be cracked offline at speed. AES tickets are far
#: more expensive to attack, so a request that asks for RC4 on a domain capable
#: of AES is asking for the crackable version on purpose.
_WEAK_TICKET_ENCRYPTION = {"0x17", "0x18", "rc4", "rc4-hmac", "rc4_hmac_md5", "rc4-hmac-md5"}

#: Field spellings for the same thing across sensors. Windows writes
#: `TicketEncryptionType`; normalised pipelines tend to write snake_case.
_TICKET_ENCRYPTION_KEYS = ("ticket_encryption", "TicketEncryptionType", "ticket_encryption_type")
_TICKET_COUNT_KEYS = ("service_tickets_requested", "ticket_count", "tgs_requests")
_TICKET_WINDOW_KEYS = ("window_seconds", "window_s", "interval_seconds")
_SERVICE_NAME_KEYS = ("service_names", "ServiceName", "spns", "service_principal_names")


def _first_raw(alert: Alert, keys: tuple[str, ...]) -> object:
    for key in keys:
        if key in alert.raw and alert.raw[key] not in (None, "", [], {}):
            return alert.raw[key]
    return None


@register(
    surface="identity",
    summary=(
        "Bulk Kerberos service-ticket requests, weighted by whether the weak "
        "RC4 encryption an offline crack needs was asked for."
    ),
    techniques=["T1558.003"],
    references=[
        "https://attack.mitre.org/techniques/T1558/003/",
        "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4769",
    ],
)
def kerberoasting(alert: Alert) -> DetectorResult:
    """Harvesting service tickets to crack offline.

    Written because the held-out set caught Bishop escalating a Kerberoasting
    alert with nothing measured: no detector had jurisdiction, so a real
    intrusion arrived at a human with an empty evidence table.

    **The rate is the signal, not the request.** Every workstation requests
    service tickets constantly; that is how Kerberos works. What no ordinary
    client does is ask for dozens in a couple of minutes, because a client
    requests a ticket for a service it is about to use, and it does not
    suddenly need forty.

    **RC4 is the part that shows intent.** A ticket encrypted with RC4 is
    encrypted with the service account's NTLM hash and can be cracked offline;
    an AES ticket is far more expensive to attack. A modern domain issues AES,
    so a request that specifically asks for RC4 is asking for the crackable
    version — which is why the same rate scores higher with it than without.

    **What this does not do.** It reads a summary the sensor already computed
    rather than counting raw 4769 events, because the alert schema carries no
    ticket-event type. A sensor that reports no count leaves nothing to measure
    and this returns a miss rather than pretending otherwise.
    """
    encryption = _first_raw(alert, _TICKET_ENCRYPTION_KEYS)
    count = _first_raw(alert, _TICKET_COUNT_KEYS)
    window = _first_raw(alert, _TICKET_WINDOW_KEYS)
    services = _first_raw(alert, _SERVICE_NAME_KEYS)

    if count is None and encryption is None:
        return miss(
            "kerberoasting",
            "the alert carries no service-ticket counts or encryption types to examine",
        )

    try:
        requested = int(str(count)) if count is not None else 0
    except (TypeError, ValueError):
        requested = 0

    try:
        seconds = float(str(window)) if window is not None else 0.0
    except (TypeError, ValueError):
        seconds = 0.0

    weak = str(encryption).strip().lower() in _WEAK_TICKET_ENCRYPTION if encryption else False
    distinct_services = len(services) if isinstance(services, list) else 0

    # A handful of tickets is ordinary Kerberos. The threshold is deliberately
    # well above what a client does in a burst at logon.
    if requested < 10 and not (weak and distinct_services >= 10):
        return clear(
            "kerberoasting",
            f"{requested} service tickets requested, which is ordinary Kerberos traffic",
            tickets_requested=requested,
            weak_encryption=weak,
        )

    per_minute = (requested / (seconds / 60)) if seconds > 0 else float(requested)

    score = 0.45
    if requested >= 20:
        score = 0.6
    if per_minute >= 10:
        score = 0.7
    if weak:
        # The downgrade is what separates harvesting from a busy client.
        score = min(0.9, score + 0.2)
    if distinct_services >= 10:
        score = min(0.95, score + 0.05)

    facts = {
        "tickets_requested": requested,
        "window_seconds": seconds or None,
        "tickets_per_minute": round(per_minute, 1) if seconds > 0 else None,
        "weak_encryption": weak,
        "encryption_reported": str(encryption) if encryption else None,
        "distinct_services": distinct_services or None,
        "account": str(alert.principal.username) if alert.principal else None,
    }

    rate = f" in {seconds:.0f} s ({per_minute:.0f}/min)" if seconds > 0 else ""
    reason = (
        " requested with RC4, which encrypts the ticket under the service account's "
        "NTLM hash and can be cracked offline — a modern domain issues AES, so asking "
        "for RC4 is asking for the crackable version"
        if weak
        else ". No weak encryption was reported, so this is volume alone"
    )
    return DetectorResult(
        detector="kerberoasting",
        fired=True,
        score=round(score, 3),
        facts=facts,
        rationale=f"{requested} Kerberos service tickets{rate}{reason}",
        technique_hints=["T1558.003"],
    )


#: User-agent fragments that identify a scripted or library HTTP client. A
#: person's browser never becomes one of these; tooling replaying a stolen
#: token usually is one, because the attacker is driving a script rather than
#: a browser.
_SCRIPTED_CLIENTS = (
    "python-requests",
    "python-urllib",
    "httpx",
    "aiohttp",
    "curl/",
    "wget/",
    "go-http-client",
    "okhttp",
    "axios",
    "node-fetch",
    "libwww-perl",
    "java/",
    "apache-httpclient",
    "restsharp",
    "postmanruntime",
    "insomnia",
    "powershell",
    "guzzlehttp",
    "msgraph-sdk",
    "azurecli",
    "boto3",
    "aws-cli",
)

#: Fragments that identify an interactive browser. Every mainstream browser
#: sends `Mozilla/5.0` for historical reasons, so a family marker is what
#: separates a real browser from something merely borrowing the prefix.
_BROWSER_CLIENTS = (
    "chrome/",
    "safari/",
    "firefox/",
    "edg/",
    "edge/",
    "gecko",
    "webkit",
    "opr/",
    "trident",
)

#: A client-class change is only evidence when it happens inside one session's
#: lifetime. Over days it is a person getting a new laptop.
TOKEN_REPLAY_WINDOW_SECONDS = 3600.0

#: Inside this, the two clients overlap rather than succeed each other.
TOKEN_REPLAY_TIGHT_SECONDS = 900.0


def _client_class(user_agent: object) -> str:
    """Sort a user agent into browser, scripted, or unknown.

    Scripted is tested first on purpose. PowerShell and several SDK clients
    send the `Mozilla/5.0` prefix with their own name appended, so a
    browser-first test would call them browsers.
    """
    text = str(user_agent or "").strip().lower()
    if not text:
        return "unknown"
    if any(marker in text for marker in _SCRIPTED_CLIENTS):
        return "scripted"
    if text.startswith("mozilla/") or any(marker in text for marker in _BROWSER_CLIENTS):
        return "browser"
    return "unknown"


@register(
    surface="identity",
    summary=(
        "A cloud session credential presented by a materially different client "
        "than the one that obtained it — a browser session continuing as a script."
    ),
    techniques=["T1550.001", "T1528"],
    references=[
        "https://attack.mitre.org/techniques/T1550/001/",
        "https://attack.mitre.org/techniques/T1528/",
    ],
)
def token_replay(alert: Alert) -> DetectorResult:
    """A session credential used by something that is not the user's browser.

    Written because the held-out set caught Bishop closing a refresh-token
    replay as a false positive at 0.95 confidence — the worst outcome
    available. No detector had jurisdiction over a cloud alert, so the empty
    evidence table read as nothing to see.

    **Impossible travel deliberately misses this.** Both logins were from
    Dublin, ten minutes apart, so distance and speed have nothing to say.
    Geography is not the signal when a token is replayed from the victim's own
    city, or from a hosting provider that geolocates to it.

    **The signal is the client, not the place.** A browser session does not
    become `python-requests/2.31.0`. When one account succeeds twice inside a
    session's lifetime and the second success comes from a scripted client
    where the first came from a browser, the credential is being presented by
    something other than the thing that obtained it.

    Two facts raise it. A changed source IP means the second client is not the
    first one on a new tab. A dropped MFA factor means no fresh
    authentication happened — re-authenticating would have produced a new
    factor, and its absence is what makes this reuse rather than a second
    login.

    **What defeats it.** A user agent is attacker-controlled, and tooling that
    sends a browser string evades this completely. That is a bound on what it
    catches rather than a bug: it cannot be tightened by reading the same field
    harder, only by an ASN or token-binding field the alert schema does not
    carry. The inverse abuse is not available — manufacturing a finding
    would mean controlling the victim's own browser string. It caps at 0.85 for
    the same reason: one lexical read of one attacker-influenced field should
    not carry a verdict alone.
    """
    events = ordered_by_time(alert.auth_events, key=lambda event: event.timestamp)
    successes = [event for event in events if event.outcome in SUCCESS_OUTCOMES]
    identified = [event for event in successes if _client_class(event.user_agent) != "unknown"]
    if len(identified) < 2:
        return miss(
            "token_replay",
            "fewer than two successful logins carry a recognisable client, "
            "so there is no session to compare against",
        )

    by_account: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in identified:
        by_account[str(event.username).lower()].append(event)

    handovers: list[tuple[str, AuthEvent, AuthEvent, float]] = []
    for account, account_events in by_account.items():
        for earlier, later in pairwise(account_events):
            if _client_class(earlier.user_agent) != "browser":
                continue
            if _client_class(later.user_agent) != "scripted":
                continue
            gap = seconds_between(earlier.timestamp, later.timestamp)
            if gap <= TOKEN_REPLAY_WINDOW_SECONDS:
                handovers.append((account, earlier, later, gap))

    if not handovers:
        return clear(
            "token_replay",
            "no account handed a session from a browser to a scripted client",
            accounts_examined=sorted(by_account),
            logins_with_a_recognisable_client=len(identified),
        )

    account, earlier, later, gap = min(handovers, key=lambda handover: handover[3])

    ip_changed = bool(
        earlier.source_ip and later.source_ip and earlier.source_ip != later.source_ip
    )
    factor_dropped = bool(earlier.mfa_method) and not later.mfa_method

    score = 0.6
    if ip_changed:
        score += 0.15
    if gap <= TOKEN_REPLAY_TIGHT_SECONDS:
        score += 0.1
    if factor_dropped:
        score += 0.1

    facts = {
        "account": account,
        "seconds_between": round(gap),
        "client_before": str(earlier.user_agent)[:200],
        "client_after": str(later.user_agent)[:200],
        "source_ip_before": earlier.source_ip,
        "source_ip_after": later.source_ip,
        "source_ip_changed": ip_changed,
        "mfa_factor_dropped": factor_dropped,
        "handovers_found": len(handovers),
    }

    movement = "from a different address" if ip_changed else "from the same address"
    factor = ", with no new MFA factor to show a fresh login" if factor_dropped else ""
    return DetectorResult(
        detector="token_replay",
        fired=True,
        score=round(min(0.85, score), 3),
        facts=facts,
        rationale=(
            f"{account} signed in from a browser; {round(gap)} s later, {movement}, "
            f"the same session continued from a scripted client{factor}"
        ),
        technique_hints=["T1550.001", "T1528"],
    )
