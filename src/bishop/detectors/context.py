"""Context detectors — the evidence that argues *against* malice.

Every other detector in Bishop can only add suspicion. Without something that
can subtract it, `benign_true_positive` is a label the system can define but
never reach, and an authorised red-team exercise reads as a genuine intrusion.
The first scorecard run showed exactly that: all four benign true positives came
back as true positives, because nothing in the pipeline could represent
"this happened, and someone approved it".

Two detectors, because they support different verdicts and conflating them
would lose the distinction that makes the label worth having:

`authorised_activity` says *the technique really was used, by someone entitled
to use it* — the red team on their range, the platform admin inside a change
window, the automation account doing its documented job. That is a
`benign_true_positive`: the detection was correct and the activity was approved.

`routine_software` says *the rule's premise is wrong* — a signed vendor binary
in a trusted install path, a sanctioned monitoring destination. That is a
`false_positive`: a tuning problem, not a paperwork one.

**Where the trust comes from.** These read `fixtures/environment/policy.json`,
which is inventory data — CMDB, identity provider, change calendar. It is not
attacker-controlled, which is the whole reason it can be used to exonerate. An
attacker who can write into the alert cannot add themselves to the automation
account list. Anything sourced from the alert itself gets no exculpatory weight
here; note that `authorised_activity` matches accounts against policy keys
rather than against claims made in the payload.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from bishop.detectors.base import clear, miss, register
from bishop.schema.alert import Alert
from bishop.schema.evidence import DetectorResult

POLICY_PATH = Path(__file__).resolve().parents[3] / "fixtures" / "environment" / "policy.json"


@lru_cache(maxsize=2)
def load_policy(path: Path | None = None) -> dict[str, Any]:
    """Load environment policy. Absent is not an error — it is less context."""
    resolved = path or POLICY_PATH
    if not resolved.exists():
        return {}
    return json.loads(resolved.read_text(encoding="utf-8"))


def _basename(value: object) -> str:
    if not value:
        return ""
    return str(value).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip().lower()


def _username(alert: Alert) -> str:
    if alert.principal and alert.principal.username:
        return str(alert.principal.username).strip().lower()
    if alert.process and alert.process.user:
        return str(alert.process.user).strip().lower()
    return ""


def _all_processes(alert: Alert):
    for label, process in (
        ("grandparent_process", alert.grandparent_process),
        ("parent_process", alert.parent_process),
        ("process", alert.process),
    ):
        if process is not None:
            yield label, process
    for index, child in enumerate(alert.child_processes):
        yield f"child_processes[{index}]", child


#: Privilege tiers, least to most. Authorisation at one tier does not imply the
#: next: an account permitted to add a local administrator is not thereby
#: permitted to add a Domain Admin.
_PRIVILEGE_ORDER = ("none", "local", "domain")

_DOMAIN_GROUPS = ("domain admins", "enterprise admins", "schema admins", "account operators")
_LOCAL_GROUPS = ("administrators", "backup operators", "remote desktop users", "sudo", "wheel")


def _observed_privilege(alert: Alert) -> str:
    """The highest privilege tier this alert shows being touched.

    Read from the directory's change events where available, and from the
    command line otherwise. Note the asymmetry: this is used to *withhold*
    exculpation, so reading it from an attacker-controlled command line is safe
    in the direction that matters — the worst an attacker can do by writing
    "domain admins" into a command line is deny themselves a mitigation.
    """
    haystacks: list[str] = []
    for change in alert.raw.get("group_changes") or []:
        if isinstance(change, dict):
            haystacks.append(str(change.get("group", "")).lower())
    for _, process in _all_processes(alert):
        if process.command_line:
            haystacks.append(str(process.command_line).lower())

    text = " ".join(haystacks)
    if any(group in text for group in _DOMAIN_GROUPS):
        return "domain"
    if any(group in text for group in _LOCAL_GROUPS):
        return "local"
    return "none"


def _within_scope(observed: str, granted: str) -> bool:
    try:
        return _PRIVILEGE_ORDER.index(observed) <= _PRIVILEGE_ORDER.index(granted)
    except ValueError:
        return False


@register(
    surface="context",
    summary=(
        "Whether the actor was entitled to do this — red-team range, approved change "
        "window, or an automation account performing its documented function."
    ),
    techniques=[],
    references=[],
)
def authorised_activity(alert: Alert) -> DetectorResult:
    """Authorisation for activity that genuinely happened.

    Supports `benign_true_positive`, never `false_positive`. The distinction
    matters to whoever owns the detection rule: a benign true positive means the
    rule is working and the paperwork explains it, and tuning the rule away
    would blind them to the real thing.
    """
    policy = load_policy()
    if not policy:
        return miss(
            "authorised_activity",
            "no environment policy is loaded, so Bishop cannot tell authorised "
            "activity from unauthorised — see fixtures/environment/policy.json",
        )

    findings: list[dict[str, object]] = []
    out_of_scope: list[dict[str, object]] = []
    username = _username(alert)
    hostname = (
        str(alert.device.hostname).strip().upper() if alert.device and alert.device.hostname else ""
    )
    host_ip = alert.device.ip if alert.device else None

    for entry in policy.get("authorised_test_ranges", []):
        prefix = str(entry.get("prefix") or "")
        host_prefix = str(entry.get("hostname_prefix") or "")
        in_range = bool(prefix and host_ip and str(host_ip).startswith(prefix))
        named = bool(host_prefix and hostname.startswith(host_prefix.upper()))
        if in_range or named:
            findings.append(
                {
                    "kind": "authorised_test_range",
                    "note": str(entry.get("note") or ""),
                    "authorised_by": str(entry.get("authorised_by") or "unknown"),
                    "matched_on": "ip" if in_range else "hostname",
                    "weight": 0.8,
                }
            )

    observed = _observed_privilege(alert)
    accounts = {
        **{
            k.lower(): ("automation_account", v)
            for k, v in (policy.get("automation_accounts") or {}).items()
        },
        **{
            k.lower(): ("privileged_admin", v)
            for k, v in (policy.get("privileged_admins") or {}).items()
        },
    }
    if username and username in accounts:
        kind, entry = accounts[username]
        granted = str(entry.get("max_privilege", "none")).lower()
        note = str(entry.get("note", ""))
        if _within_scope(observed, granted):
            findings.append(
                {
                    "kind": kind,
                    "account": username,
                    "note": note,
                    "granted_privilege": granted,
                    "observed_privilege": observed,
                    "weight": 0.6 if kind == "automation_account" else 0.55,
                }
            )
        else:
            # Recorded, but as an aggravating observation rather than a
            # mitigating one. A known account exceeding its remit is a worse
            # signal than an unknown account doing the same thing.
            out_of_scope.append(
                {
                    "account": username,
                    "granted_privilege": granted,
                    "observed_privilege": observed,
                    "note": note,
                }
            )

    windows = {str(w.get("name")): w for w in (policy.get("change_windows") or [])}
    for index, task in enumerate(alert.scheduled_tasks):
        name = str(task.name)
        if name in windows:
            findings.append(
                {
                    "kind": "approved_change_window",
                    "where": f"scheduled_tasks[{index}]",
                    "change": name,
                    "note": str(windows[name].get("note") or ""),
                    "approved_by": str(windows[name].get("approved_by") or "unknown"),
                    "weight": 0.75,
                }
            )

    if not findings:
        if out_of_scope:
            entry = out_of_scope[0]
            return DetectorResult(
                detector="authorised_activity",
                fired=True,
                mitigating=False,  # this one argues *for* concern, not against
                score=0.65,
                facts={"out_of_scope": out_of_scope, "account": username},
                rationale=(
                    f"{entry['account']} is a known account but is only authorised to "
                    f"{entry['granted_privilege']} privilege, and this alert shows a "
                    f"{entry['observed_privilege']}-privilege change. A recognised account "
                    f"exceeding its remit is worse than an unrecognised one, not better"
                ),
                technique_hints=[],
            )
        return clear(
            "authorised_activity",
            "nothing in the environment policy authorises this actor for this activity",
            account_examined=username or None,
            host_examined=hostname or None,
        )

    strongest = max(findings, key=lambda f: float(f["weight"]))  # type: ignore[arg-type]
    score = min(0.9, float(strongest["weight"]) + 0.05 * (len(findings) - 1))  # type: ignore[arg-type]

    return DetectorResult(
        detector="authorised_activity",
        fired=True,
        mitigating=True,
        score=round(score, 3),
        facts={
            "findings": findings,
            "account": username,
            "host": hostname,
            "observed_privilege": observed,
        },
        rationale=(
            f"{str(strongest['kind']).replace('_', ' ')}: {strongest['note']} "
            f"(from environment policy, not from the alert)"
        ),
        technique_hints=[],
    )


@register(
    surface="context",
    summary=(
        "Whether the activity is ordinary vendor software behaving normally — signed "
        "by a trusted publisher, running from a trusted install path, or talking to a "
        "sanctioned destination."
    ),
    techniques=[],
    references=[],
)
def routine_software(alert: Alert) -> DetectorResult:
    """Evidence that the rule's premise is wrong rather than its subject approved.

    Supports `false_positive`. Signature and install path together are what
    carry the weight: a signed binary in `%TEMP%` is a stolen certificate or a
    legitimate installer mid-run, and neither exonerates it.

    Each finding names the detectors it *explains*, in `facts["explains"]`. That
    is how an analyst actually reasons — "the beaconing is the monitoring agent
    checking in" is a specific rebuttal of a specific observation, and it is
    much stronger than a general sense that the host looks fine. Synthesis uses
    it to decide whether every suspicious signal has an innocent account of it,
    rather than comparing two aggregate scores that measure different things.
    """
    policy = load_policy()
    if not policy:
        return miss("routine_software", "no environment policy is loaded")

    publishers = {p.lower() for p in policy.get("trusted_publishers", [])}
    paths = [p.lower() for p in policy.get("trusted_install_paths", [])]
    destinations = {k.lower(): v for k, v in (policy.get("sanctioned_destinations") or {}).items()}

    findings: list[dict[str, object]] = []

    for where, process in _all_processes(alert):
        path = str(process.path or "").lower().replace("/", "\\")
        signer = str(process.signer or "").strip().lower()
        trusted_path = any(path.startswith(p.replace("/", "\\")) for p in paths)
        trusted_signer = bool(signer and signer in publishers)

        if trusted_path and (process.signed is True or trusted_signer):
            findings.append(
                {
                    "kind": "signed_binary_in_trusted_path",
                    "where": where,
                    "path": str(process.path or "")[:200],
                    "signer": str(process.signer or ""),
                    "note": (
                        f"{_basename(process.path) or _basename(process.name)} is signed and "
                        f"runs from a trusted install path"
                    ),
                    "explains": [
                        "encoded_command",
                        "suspicious_execution_path",
                        "masquerading",
                        "lolbin_abuse",
                        "data_staging",
                        "suspicious_parent_child",
                    ],
                    "weight": 0.6 if trusted_signer else 0.45,
                }
            )

    # Persistence that points back into a trusted install path is an installer
    # registering its own updater. Persistence pointing at %TEMP% is not, and
    # this is the difference between the two.
    persistence_targets: list[tuple[str, str]] = []
    for index, change in enumerate(alert.registry_changes):
        persistence_targets.append((f"registry_changes[{index}]", str(change.value_data or "")))
    for index, service in enumerate(alert.service_installs):
        persistence_targets.append((f"service_installs[{index}]", str(service.image_path or "")))
    for index, task in enumerate(alert.scheduled_tasks):
        persistence_targets.append((f"scheduled_tasks[{index}]", str(task.action or "")))

    for where, target in persistence_targets:
        cleaned = target.strip().strip('"').lower().replace("/", "\\")
        if cleaned and any(cleaned.startswith(p.replace("/", "\\")) for p in paths):
            findings.append(
                {
                    "kind": "persistence_into_trusted_path",
                    "where": where,
                    "target": target[:200],
                    "note": (
                        "the persistence entry points at a trusted install path, which is what "
                        "an installer registering its own updater looks like"
                    ),
                    "explains": ["persistence"],
                    "weight": 0.65,
                }
            )

    scanners = {k: v for k, v in (policy.get("scanner_sources") or {}).items()}
    scanner_ips = {e.source_ip for e in alert.auth_events if e.source_ip} & set(scanners)
    for ip in sorted(scanner_ips):
        findings.append(
            {
                "kind": "known_scanner_source",
                "source_ip": ip,
                "note": scanners[ip],
                "explains": ["password_spray", "mfa_fatigue", "impossible_travel"],
                "weight": 0.8,
            }
        )

    seen_destinations: set[str] = set()
    for index, connection in enumerate(alert.connections):
        for candidate in (connection.hostname, connection.dest_ip):
            key = str(candidate or "").strip().lower()
            if key and key in destinations and key not in seen_destinations:
                seen_destinations.add(key)
                findings.append(
                    {
                        "kind": "sanctioned_destination",
                        "where": f"connections[{index}]",
                        "destination": key,
                        "note": destinations[key],
                        "explains": [
                            "beaconing",
                            "outbound_volume",
                            "abused_hosting_contact",
                            "dns_exfiltration",
                            "ioc_reputation",
                        ],
                        "weight": 0.8,
                    }
                )

    for _, process in _all_processes(alert):
        command = str(process.command_line or "").lower()
        for destination, note in destinations.items():
            if destination in command and destination not in seen_destinations:
                seen_destinations.add(destination)
                findings.append(
                    {
                        "kind": "sanctioned_destination",
                        "where": "process.command_line",
                        "destination": destination,
                        "note": note,
                        "explains": ["lolbin_abuse", "abused_hosting_contact"],
                        "weight": 0.5,
                    }
                )

    if not findings:
        nothing_named = not any(
            (p.command_line or p.name or p.path) for _, p in _all_processes(alert)
        )
        if nothing_named and not alert.connections and alert.file is None:
            return miss(
                "routine_software",
                "the alert names no software, path or destination to recognise",
            )
        return clear(
            "routine_software",
            "nothing here matches a trusted publisher, install path or sanctioned destination",
        )

    strongest = max(findings, key=lambda f: float(f["weight"]))  # type: ignore[arg-type]
    score = min(0.85, float(strongest["weight"]) + 0.08 * (len(findings) - 1))  # type: ignore[arg-type]

    explains: list[str] = []
    for finding in findings:
        for detector in finding.get("explains", []):  # type: ignore[union-attr]
            if detector not in explains:
                explains.append(str(detector))

    return DetectorResult(
        detector="routine_software",
        fired=True,
        mitigating=True,
        score=round(score, 3),
        facts={"findings": findings, "explains": explains},
        rationale=str(strongest["note"]),
        technique_hints=[],
    )
