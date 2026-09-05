"""Turning somebody else's alert into Bishop's alert.

Until this module existed, Bishop could only triage the thirty fixtures in
`fixtures/alerts/`. That makes a demo, not a tool: the one thing a person wants
to do — point it at an alert *they* have and see what it says — was the one
thing it could not do.

The problem is that "a security alert" has no agreed shape. A Sysmon event, an
Elastic document, a Defender incident and a Splunk row describe the same
process execution with four different sets of field names. So this is a
best-effort mapper over the shapes that are actually common, and the emphasis
is on *best-effort*: it maps what it recognises and reports what it did not.

**The report is the point, not a nicety.** A security tool that silently drops
half of your data and then hands you a confident verdict is worse than one that
refuses, because you cannot see what it failed to read. Every normalisation
returns a `MappingReport` saying which fields were read, which were ignored,
what was defaulted and why — and, most usefully, which detectors actually have
jurisdiction over what survived. If that last list is empty, Bishop is going to
escalate no matter what the alert says, and you should know that before you
wait for a run rather than after.

**What this deliberately does not do.** It does not guess at semantics. If a
field is not recognised it goes to `raw` untouched, where it is still scanned
for injection but is not interpreted as a hostname or a command line. Inventing
a mapping to make the input look richer than it is would put unearned evidence
behind a verdict, which is the failure this whole project is arranged against.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from bishop.schema import (
    Alert,
    AlertCategory,
    AuthEvent,
    Device,
    DnsEvent,
    FileObject,
    NetworkConnection,
    Principal,
    Process,
    RegistryChange,
    Severity,
)

__all__ = [
    "MappingReport",
    "detect_format",
    "normalise",
    "supported_formats",
]


# ── the mapping report ──────────────────────────────────────────────────────


@dataclass(slots=True)
class MappingReport:
    """What the normaliser understood, and what it did not.

    Read `detectors_with_jurisdiction` first. It is computed by actually
    running the detectors and asking which of them had data in their remit, so
    it is a fact about your alert rather than a promise about the tool. Empty
    means Bishop will escalate whatever else is in the payload, because it has
    nothing it can measure.
    """

    detected_format: str
    #: `(source field, Bishop field)` for everything that was understood.
    mapped: list[tuple[str, str]] = field(default_factory=list)
    #: Top-level keys that were not recognised. They are kept in `raw`, where
    #: they are still injection-scanned, but nothing interprets them.
    ignored: list[str] = field(default_factory=list)
    #: `(field, value, why)` — required fields that were not supplied.
    defaulted: list[tuple[str, str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    detectors_with_jurisdiction: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected_format": self.detected_format,
            "mapped": [{"from": a, "to": b} for a, b in self.mapped],
            "ignored": self.ignored,
            "defaulted": [{"field": f, "value": v, "why": w} for f, v, w in self.defaulted],
            "warnings": self.warnings,
            "detectors_with_jurisdiction": self.detectors_with_jurisdiction,
        }

    @property
    def usable(self) -> bool:
        """Whether any detector can examine this alert at all."""
        return bool(self.detectors_with_jurisdiction)


def supported_formats() -> dict[str, str]:
    """The shapes this understands, for the console and `--help`."""
    return {
        "bishop": "Bishop's own alert schema — passed through unchanged.",
        "ecs": "Elastic Common Schema. Elastic, and anything that exports ECS.",
        "sysmon": "Sysmon / Windows Security event JSON, by EventID.",
        "generic": "Flat or nested JSON matched on common field-name aliases.",
    }


# ── field aliases ───────────────────────────────────────────────────────────
#
# Ordered by preference: the first alias that resolves wins. Dotted names are
# tried both as a nested path and as a literal flat key, because exporters
# disagree about which they emit and a user should not have to care.

_HOSTNAME = (
    "host.hostname",
    "host.name",
    "device.hostname",
    "agent.hostname",
    "endpoint.name",
    "ComputerName",
    "Computer",
    "computer_name",
    "hostname",
    "host",
    "dest_host",
    "src_host",
    "machine_name",
    "MachineName",
)
_HOST_IP = ("host.ip", "device.ip", "local_ip", "ComputerIP", "ip", "host_ip")
_HOST_OS = ("host.os.full", "host.os.name", "os.name", "os", "OperatingSystem")

_USERNAME = (
    "user.name",
    "principal.username",
    "SubjectUserName",
    "TargetUserName",
    "AccountName",
    "User",
    "username",
    "user",
    "account",
    "account_name",
    "user_name",
    "actor",
    "UserName",
)
_DOMAIN = (
    "user.domain",
    "SubjectDomainName",
    "TargetDomainName",
    "domain",
    "user_domain",
    "dns_domain",
)
_UPN = ("user.email", "user_principal_name", "upn", "UserPrincipalName")

_PROC_PATH = (
    "process.executable",
    "process.path",
    "Image",
    "NewProcessName",
    "ImagePath",
    "process_path",
    "ProcessPath",
    "process_image",
    "image",
)
_PROC_NAME = ("process.name", "ProcessName", "process_name", "proc_name")
_PROC_CMD = (
    "process.command_line",
    "CommandLine",
    "ProcessCommandLine",
    "command_line",
    "process_command_line",
    "cmdline",
    "commandline",
)
_PROC_PID = ("process.pid", "ProcessId", "process_id", "pid")
_PROC_SIGNER = (
    "process.code_signature.subject_name",
    "Signature",
    "signer",
    "publisher",
)
_PROC_SIGNED = ("process.code_signature.signed", "Signed", "signed")

_PARENT_PATH = (
    "process.parent.executable",
    "process.parent.path",
    "ParentImage",
    "ParentProcessName",
    "parent_process_path",
    "parent_image",
)
_PARENT_NAME = ("process.parent.name", "parent_process_name", "ParentProcessName")
_PARENT_CMD = (
    "process.parent.command_line",
    "ParentCommandLine",
    "parent_command_line",
)

_FILE_PATH = (
    "file.path",
    "TargetFilename",
    "file_path",
    "FilePath",
    "TargetFile",
)
_FILE_NAME = ("file.name", "FileName", "file_name")
_FILE_SIZE = ("file.size", "FileSize", "file_size", "size_bytes")

_RULE_NAME = (
    "rule.name",
    "rule_name",
    "RuleName",
    "signature",
    "alert_name",
    "detection_name",
    "title",
    "DisplayName",
    "search_name",
    "Description",
)
_RULE_ID = ("rule.id", "rule_id", "RuleId", "signature_id", "detection_id")
_ALERT_ID = (
    "alert_id",
    "event.id",
    "alert.id",
    "AlertId",
    "id",
    "_id",
    "incident_id",
    "EventRecordID",
)
_SOURCE = (
    "source",
    "event.module",
    "event.provider",
    "Provider",
    "product",
    "vendor",
    "data_source",
    "Channel",
    "sourcetype",
)
_TIMESTAMP = (
    "detected_at",
    "@timestamp",
    "event.created",
    "timestamp",
    "TimeCreated",
    "UtcTime",
    "EventTime",
    "_time",
    "time",
    "created_at",
    "eventTime",
)
_SEVERITY = (
    "severity",
    "event.severity",
    "rule.level",
    "Severity",
    "AlertSeverity",
    "priority",
    "risk_score",
    "urgency",
)
_DESCRIPTION = ("description", "message", "Message", "event.original", "summary")

_DEST_IP = ("destination.ip", "DestinationIp", "dest_ip", "remote_ip", "dst_ip")
_DEST_PORT = (
    "destination.port",
    "DestinationPort",
    "dest_port",
    "remote_port",
    "dst_port",
)
_DEST_HOST = (
    "destination.domain",
    "DestinationHostname",
    "dest_hostname",
    "url.domain",
)
_BYTES_OUT = ("source.bytes", "network.bytes_out", "bytes_out", "SentBytes")
_BYTES_IN = ("destination.bytes", "network.bytes_in", "bytes_in", "ReceivedBytes")

_DNS_QUERY = ("dns.question.name", "QueryName", "query", "dns_query", "domain_name")
_DNS_TYPE = ("dns.question.type", "QueryType", "query_type", "record_type")

#: Keys consumed by the mapper. Anything else is reported as ignored and kept
#: in `raw`, so the user can see exactly what Bishop did not interpret.
_ALL_ALIASES: tuple[tuple[str, ...], ...] = (
    _HOSTNAME,
    _HOST_IP,
    _HOST_OS,
    _USERNAME,
    _DOMAIN,
    _UPN,
    _PROC_PATH,
    _PROC_NAME,
    _PROC_CMD,
    _PROC_PID,
    _PROC_SIGNER,
    _PROC_SIGNED,
    _PARENT_PATH,
    _PARENT_NAME,
    _PARENT_CMD,
    _FILE_PATH,
    _FILE_NAME,
    _FILE_SIZE,
    _RULE_NAME,
    _RULE_ID,
    _ALERT_ID,
    _SOURCE,
    _TIMESTAMP,
    _SEVERITY,
    _DESCRIPTION,
    _DEST_IP,
    _DEST_PORT,
    _DEST_HOST,
    _BYTES_OUT,
    _BYTES_IN,
    _DNS_QUERY,
    _DNS_TYPE,
)


# ── reading values out of an arbitrary payload ──────────────────────────────


def _dig(payload: dict[str, Any], path: str) -> Any:
    """Resolve `a.b.c` as a nested path, then as a literal flat key.

    Exporters disagree about which of those they emit — Elastic writes nested
    objects, most CSV-to-JSON pipelines write `"host.hostname"` as one key —
    and a user should not have to know which theirs did.
    """
    if path in payload:
        return payload[path]
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _first(
    payload: dict[str, Any], aliases: tuple[str, ...], report: MappingReport, target: str
) -> Any:
    """The first alias that resolves to something non-empty, recorded."""
    for alias in aliases:
        value = _dig(payload, alias)
        if value not in (None, "", [], {}):
            report.mapped.append((alias, target))
            return value
    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "valid", "signed"}:
            return True
        if lowered in {"false", "no", "0", "invalid", "unsigned"}:
            return False
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _basename(path: str) -> str:
    return re.split(r"[\\/]", str(path).strip())[-1]


# ── severity and time, which every vendor spells differently ────────────────

_SEVERITY_WORDS = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "emergency": Severity.CRITICAL,
    "high": Severity.HIGH,
    "important": Severity.HIGH,
    "error": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    "information": Severity.INFORMATIONAL,
    "notice": Severity.INFORMATIONAL,
}


def _severity_from(value: Any) -> Severity | None:
    """Map a word or a number onto Bishop's five levels.

    Numeric scales are the awkward half: 1-10, 0-100 and Windows' inverted
    1-5 (where 1 is *most* severe) are all in the wild. Only the two
    unambiguous ranges are mapped; an inverted scale would need to be told
    apart from a normal one by guessing, and guessing severity silently is
    how a critical alert becomes a low one.
    """
    if value is None:
        return None
    if isinstance(value, str):
        word = _SEVERITY_WORDS.get(value.strip().lower())
        if word is not None:
            return word
    number = _as_int(value)
    if number is None:
        return None
    if 0 <= number <= 10:
        return (
            Severity.CRITICAL
            if number >= 9
            else Severity.HIGH
            if number >= 7
            else Severity.MEDIUM
            if number >= 4
            else Severity.LOW
            if number >= 2
            else Severity.INFORMATIONAL
        )
    if 11 <= number <= 100:
        return (
            Severity.CRITICAL
            if number >= 90
            else Severity.HIGH
            if number >= 70
            else Severity.MEDIUM
            if number >= 40
            else Severity.LOW
        )
    return None


def _timestamp_from(value: Any) -> datetime | None:
    """Parse the formats that actually turn up, without dateutil."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float):
        # Epoch seconds or milliseconds. The boundary is around the year 2001
        # in seconds, which no security alert predates.
        seconds = float(value)
        if seconds > 1e11:
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        pass
    for pattern in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p"):
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


_CATEGORY_HINTS = (
    (AlertCategory.IDENTITY, ("logon", "login", "auth", "credential", "mfa", "kerberos")),
    (AlertCategory.EMAIL, ("email", "mail", "phish", "attachment")),
    (AlertCategory.NETWORK, ("network", "dns", "proxy", "firewall", "beacon", "c2")),
    (AlertCategory.CLOUD, ("cloud", "aws", "azure", "gcp", "s3", "iam")),
    (AlertCategory.ENDPOINT, ("process", "file", "registry", "endpoint", "sysmon")),
)


def _category_from(alert_fields: dict[str, Any], rule_name: str, source: str) -> AlertCategory:
    """Structure first, words second.

    What data the alert actually carries is a far better signal than what its
    title says — a rule called "Suspicious activity" tells you nothing, but a
    payload with a process tree is an endpoint alert whatever it is called.
    """
    if alert_fields.get("email"):
        return AlertCategory.EMAIL
    if alert_fields.get("auth_events"):
        return AlertCategory.IDENTITY
    if (
        alert_fields.get("process")
        or alert_fields.get("parent_process")
        or alert_fields.get("registry_changes")
        or alert_fields.get("file")
    ):
        return AlertCategory.ENDPOINT
    if alert_fields.get("connections") or alert_fields.get("dns_events"):
        return AlertCategory.NETWORK

    haystack = f"{rule_name} {source}".lower()
    for category, needles in _CATEGORY_HINTS:
        if any(needle in haystack for needle in needles):
            return category
    return AlertCategory.OTHER


# ── format detection ────────────────────────────────────────────────────────


def detect_format(payload: dict[str, Any]) -> str:
    """Guess which shape this is. Advisory — the mapper tries everything anyway."""
    if "alert_id" in payload and "rule_name" in payload and "detected_at" in payload:
        return "bishop"
    if any(key in payload for key in ("EventID", "event_id", "EventCode")) or (
        "Image" in payload and "ParentImage" in payload
    ):
        return "sysmon"
    if "@timestamp" in payload or isinstance(payload.get("event"), dict):
        return "ecs"
    return "generic"


# ── the mapper ──────────────────────────────────────────────────────────────


def normalise(
    payload: dict[str, Any], *, alert_id: str | None = None
) -> tuple[Alert, MappingReport]:
    """Map an arbitrary alert payload onto Bishop's schema.

    Returns the alert and a report of what was understood. The alert is always
    constructible — missing required fields are defaulted and the defaults are
    listed in the report — because refusing to build it would leave the caller
    with nothing to look at, and the report already says what is missing.
    """
    if not isinstance(payload, dict):
        raise TypeError("an alert payload must be a JSON object")

    detected = detect_format(payload)
    report = MappingReport(detected_format=detected)

    if detected == "bishop":
        return _passthrough(payload, report, alert_id=alert_id)

    # ── identity of the alert itself ────────────────────────────────────────
    resolved_id = alert_id or _first(payload, _ALERT_ID, report, "alert_id")
    if not resolved_id:
        resolved_id = f"user-{uuid.uuid4().hex[:12]}"
        report.defaulted.append(
            ("alert_id", str(resolved_id), "the payload carried no recognisable id")
        )

    rule_name = _first(payload, _RULE_NAME, report, "rule_name")
    if not rule_name:
        rule_name = "Untitled alert"
        report.defaulted.append(
            (
                "rule_name",
                "Untitled alert",
                "no rule name found. Bishop treats the rule name as trusted text "
                "written by a detection engineer, so it is never invented from "
                "attacker-controlled fields.",
            )
        )

    source = _first(payload, _SOURCE, report, "source")
    if not source and detected in {"sysmon", "ecs"}:
        # The shape itself names the sensor when nothing else does.
        source = detected
        report.defaulted.append(
            ("source", detected, f"inferred from the payload shape ({detected})")
        )
    elif not source:
        source = "user-submitted"
        report.defaulted.append(("source", "user-submitted", "no sensor or product name found"))

    detected_at = _timestamp_from(_first(payload, _TIMESTAMP, report, "detected_at"))
    if detected_at is None:
        detected_at = datetime.now(UTC)
        report.defaulted.append(
            (
                "detected_at",
                detected_at.isoformat(),
                "no parseable timestamp found, so the time of submission was used. "
                "Detectors that reason about intervals — beaconing, impossible "
                "travel — need real event times and will not be meaningful here.",
            )
        )

    severity = _severity_from(_first(payload, _SEVERITY, report, "severity"))
    if severity is None:
        severity = Severity.MEDIUM
        report.defaulted.append(
            ("severity", "medium", "no recognisable severity. Bishop assesses its own anyway.")
        )

    # ── the structured objects ──────────────────────────────────────────────
    device = _device(payload, report)
    principal = _principal(payload, report)
    process = _process(payload, report, _PROC_PATH, _PROC_NAME, _PROC_CMD, "process")
    parent = _process(payload, report, _PARENT_PATH, _PARENT_NAME, _PARENT_CMD, "parent_process")
    file_object = _file(payload, report)
    connections = _connections(payload, report, detected_at)
    dns_events = _dns(payload, report, detected_at)
    auth_events = _auth(payload, report, detected_at)
    registry = _registry(payload, report)

    description = _first(payload, _DESCRIPTION, report, "description")

    alert = Alert(
        alert_id=str(resolved_id),
        source=str(source),
        rule_id=(lambda v: str(v) if v else None)(_first(payload, _RULE_ID, report, "rule_id")),
        rule_name=str(rule_name),
        detected_at=detected_at,
        severity=severity,
        category=_category_from(
            {
                "process": process,
                "parent_process": parent,
                "file": file_object,
                "auth_events": auth_events,
                "connections": connections,
                "dns_events": dns_events,
                "registry_changes": registry,
            },
            str(rule_name),
            str(source),
        ),
        description=str(description) if description else None,
        device=device,
        principal=principal,
        process=process,
        parent_process=parent,
        file=file_object,
        connections=connections,
        dns_events=dns_events,
        auth_events=auth_events,
        registry_changes=registry,
        # Everything, including what was mapped. `raw` is injection-scanned in
        # full, and dropping the recognised keys from it would mean a payload
        # hidden in a mapped field escaped that scan.
        raw={k: v for k, v in payload.items() if k != "labels"},
    )

    _record_ignored(payload, report)
    report.detectors_with_jurisdiction = _jurisdiction(alert)
    _warn_about_thin_input(alert, report)
    return alert, report


def _passthrough(
    payload: dict[str, Any], report: MappingReport, *, alert_id: str | None
) -> tuple[Alert, MappingReport]:
    """A payload already in Bishop's schema. Validate it and say nothing else.

    `labels` is stripped. It is the ground-truth block the eval corpus carries,
    and a submitted alert that could set it would be telling Bishop the answer.
    """
    body = {k: v for k, v in payload.items() if k != "labels"}
    if alert_id:
        body["alert_id"] = alert_id
    if "labels" in payload:
        report.warnings.append(
            "a `labels` block was present and has been dropped — it is the eval "
            "corpus's ground-truth field, and Bishop never reads it during a run."
        )
    alert = Alert.model_validate(body)
    report.mapped.append(("(whole document)", "Alert"))
    report.detectors_with_jurisdiction = _jurisdiction(alert)
    _warn_about_thin_input(alert, report)
    return alert, report


# ── per-object mappers ──────────────────────────────────────────────────────


def _device(payload: dict[str, Any], report: MappingReport) -> Device | None:
    hostname = _first(payload, _HOSTNAME, report, "device.hostname")
    ip = _first(payload, _HOST_IP, report, "device.ip")
    os_name = _first(payload, _HOST_OS, report, "device.os")
    if not any((hostname, ip, os_name)):
        return None
    name = str(hostname or "")
    return Device(
        hostname=name or None,
        ip=str(ip) if ip else None,
        os=str(os_name) if os_name else None,
        # A naming convention is a guess, not a fact, so it only ever sets the
        # flag — never the criticality, which drives containment blast radius.
        is_server=bool(re.match(r"(?i)^(srv|dc|sql|web|app|db)[-_]", name)),
    )


def _principal(payload: dict[str, Any], report: MappingReport) -> Principal | None:
    username = _first(payload, _USERNAME, report, "principal.username")
    domain = _first(payload, _DOMAIN, report, "principal.domain")
    upn = _first(payload, _UPN, report, "principal.upn")
    if not any((username, domain, upn)):
        return None
    name = str(username or "")

    # Windows writes the account as `DOMAIN\user` in most log sources. Leaving
    # the two joined breaks the entity key that correlation groups on, so two
    # alerts about the same person from two sensors would never be linked.
    if "\\" in name:
        left, _, right = name.partition("\\")
        if left and right:
            name, domain = right, domain or left
            report.mapped.append((r"(DOMAIN\user split)", "principal.domain"))

    # `user@domain` is the same account written the other way round.
    elif "@" in name and not upn:
        upn, name = name, name.split("@", 1)[0]

    return Principal(
        username=name or None,
        domain=str(domain) if domain else None,
        upn=str(upn) if upn else None,
        is_service_account=bool(re.match(r"(?i)^(svc|srv|service)[-_.]", name))
        or name.endswith("$"),
    )


def _process(
    payload: dict[str, Any],
    report: MappingReport,
    paths: tuple[str, ...],
    names: tuple[str, ...],
    commands: tuple[str, ...],
    label: str,
) -> Process | None:
    path = _first(payload, paths, report, f"{label}.path")
    name = _first(payload, names, report, f"{label}.name")
    command = _first(payload, commands, report, f"{label}.command_line")
    if not any((path, name, command)):
        return None
    # Sysmon's `Image` is a full path; the name is its basename. Deriving it
    # matters because `masquerading` reads the name, and a detector that never
    # sees a name cannot notice a right-to-left override in one.
    resolved_name = str(name) if name else (_basename(str(path)) if path else None)
    fields: dict[str, Any] = {
        "name": resolved_name,
        "path": str(path) if path else None,
        "command_line": str(command) if command else None,
        "pid": _as_int(_first(payload, _PROC_PID, report, f"{label}.pid")),
    }
    if label == "process":
        fields["signed"] = _as_bool(_first(payload, _PROC_SIGNED, report, "process.signed"))
        signer = _first(payload, _PROC_SIGNER, report, "process.signer")
        fields["signer"] = str(signer) if signer else None
    return Process(**fields)


def _file(payload: dict[str, Any], report: MappingReport) -> FileObject | None:
    path = _first(payload, _FILE_PATH, report, "file.path")
    name = _first(payload, _FILE_NAME, report, "file.name")
    if not any((path, name)):
        return None
    return FileObject(
        name=str(name) if name else (_basename(str(path)) if path else None),
        path=str(path) if path else None,
        size_bytes=_as_int(_first(payload, _FILE_SIZE, report, "file.size_bytes")),
    )


def _connections(
    payload: dict[str, Any], report: MappingReport, when: datetime
) -> list[NetworkConnection]:
    """One connection from top-level fields, or a list if the payload has one.

    A single alert rarely carries the dozens of connections that `beaconing`
    needs, which is why the report warns when a rhythm detector has one sample.
    """
    existing = payload.get("connections")
    if isinstance(existing, list) and existing:
        report.mapped.append(("connections", "connections[]"))
        out: list[NetworkConnection] = []
        for item in existing:
            if isinstance(item, dict):
                try:
                    out.append(NetworkConnection.model_validate({"timestamp": when, **item}))
                except Exception:
                    report.warnings.append(
                        "a row in `connections` did not validate and was skipped"
                    )
        return out

    dest_ip = _first(payload, _DEST_IP, report, "connections[0].dest_ip")
    dest_host = _first(payload, _DEST_HOST, report, "connections[0].hostname")
    port = _as_int(_first(payload, _DEST_PORT, report, "connections[0].dest_port"))
    if not any((dest_ip, dest_host, port)):
        return []
    return [
        NetworkConnection(
            timestamp=when,
            dest_ip=str(dest_ip) if dest_ip else None,
            hostname=str(dest_host) if dest_host else None,
            dest_port=port,
            bytes_out=_as_int(_first(payload, _BYTES_OUT, report, "connections[0].bytes_out")),
            bytes_in=_as_int(_first(payload, _BYTES_IN, report, "connections[0].bytes_in")),
        )
    ]


def _dns(payload: dict[str, Any], report: MappingReport, when: datetime) -> list[DnsEvent]:
    existing = payload.get("dns_events")
    if isinstance(existing, list) and existing:
        report.mapped.append(("dns_events", "dns_events[]"))
        out: list[DnsEvent] = []
        for item in existing:
            if isinstance(item, dict):
                try:
                    out.append(DnsEvent.model_validate({"timestamp": when, **item}))
                except Exception:
                    report.warnings.append("a row in `dns_events` did not validate and was skipped")
        return out

    query = _first(payload, _DNS_QUERY, report, "dns_events[0].query")
    if not query:
        return []
    query_type = _first(payload, _DNS_TYPE, report, "dns_events[0].query_type")
    return [
        DnsEvent(
            timestamp=when,
            query=str(query),
            query_type=str(query_type).upper() if query_type else "A",
        )
    ]


def _auth(payload: dict[str, Any], report: MappingReport, when: datetime) -> list[AuthEvent]:
    existing = payload.get("auth_events")
    if not isinstance(existing, list) or not existing:
        return []
    report.mapped.append(("auth_events", "auth_events[]"))
    out: list[AuthEvent] = []
    for item in existing:
        if isinstance(item, dict):
            try:
                out.append(AuthEvent.model_validate({"timestamp": when, **item}))
            except Exception:
                report.warnings.append("a row in `auth_events` did not validate and was skipped")
    return out


def _registry(payload: dict[str, Any], report: MappingReport) -> list[RegistryChange]:
    existing = payload.get("registry_changes")
    if isinstance(existing, list) and existing:
        report.mapped.append(("registry_changes", "registry_changes[]"))
        out: list[RegistryChange] = []
        for item in existing:
            if isinstance(item, dict):
                try:
                    out.append(RegistryChange.model_validate(item))
                except Exception:
                    report.warnings.append(
                        "a row in `registry_changes` did not validate and was skipped"
                    )
        return out

    # Sysmon events 12/13 carry the key in `TargetObject` and the value in
    # `Details`, which is how a Run-key payload actually arrives.
    target = _dig(payload, "TargetObject") or _dig(payload, "registry.key")
    if not target:
        return []
    report.mapped.append(("TargetObject", "registry_changes[0].key"))
    details = _dig(payload, "Details") or _dig(payload, "registry.data.strings")
    if isinstance(details, list):
        details = details[0] if details else None
    return [
        RegistryChange(
            key=str(target),
            value_data=str(details) if details else None,
        )
    ]


# ── reporting ───────────────────────────────────────────────────────────────


def _record_ignored(payload: dict[str, Any], report: MappingReport) -> None:
    consumed = {alias.split(".")[0] for group in _ALL_ALIASES for alias in group}
    consumed |= {alias for group in _ALL_ALIASES for alias in group}
    consumed |= {
        "connections",
        "dns_events",
        "auth_events",
        "registry_changes",
        "scheduled_tasks",
        "service_installs",
        "child_processes",
        "labels",
    }
    report.ignored = sorted(key for key in payload if key not in consumed)


def _jurisdiction(alert: Alert) -> list[str]:
    """Which detectors can actually examine this alert.

    Computed by running them, because the honest answer is a property of the
    data rather than of the tool. This is the same `examined` flag the verdict
    layer uses to decide whether an alert can be closed at all, so what the
    preview reports and what the run does cannot drift apart.

    The context surface is excluded for the same reason synthesis excludes it:
    `authorised_activity` reaches a conclusion on any alert naming an account,
    but finding that nothing authorises an actor argues *towards* suspicion
    rather than away from it. Counting it would make every payload look usable,
    including ones where Bishop can measure nothing at all — which is precisely
    the case this list exists to warn about.
    """
    from bishop.detectors import SURFACES, run_surface
    from bishop.graph.nodes.synthesis import _MITIGATING_INVESTIGATOR

    mitigating_surface = _MITIGATING_INVESTIGATOR.removesuffix("_investigator")
    names: list[str] = []
    for surface in SURFACES:
        if surface == mitigating_surface:
            continue
        for result in run_surface(surface, alert):
            if result.examined:
                names.append(result.detector)
    return sorted(set(names))


def _warn_about_thin_input(alert: Alert, report: MappingReport) -> None:
    """Say what will be weak about this run, before it is run."""
    if not report.detectors_with_jurisdiction:
        report.warnings.append(
            "No detector has anything to work with in this alert. Bishop will "
            "escalate it rather than reach a verdict — which is the correct "
            "behaviour, but means the run will not tell you much. Adding a "
            "command line, a set of connections or a list of auth events is "
            "what gives it something to measure."
        )
    if len(alert.connections) == 1:
        report.warnings.append(
            "Only one network connection. `beaconing` needs at least five to "
            "judge an interval, so a rhythm cannot be assessed from this."
        )
    if len(alert.dns_events) == 1:
        report.warnings.append(
            "Only one DNS query. Tunnelling is a property of a set of queries, not of one."
        )
    if len(alert.auth_events) == 1:
        report.warnings.append(
            "Only one authentication event. Impossible travel, spraying and MFA "
            "fatigue all need several."
        )


def load_payload(text: str) -> dict[str, Any]:
    """Parse submitted text into one alert payload.

    Accepts a JSON object, a single-element array, or NDJSON — all three turn
    up when someone exports one alert from a SIEM, and failing on the wrapper
    would be a pointless obstacle.
    """
    stripped = text.strip()
    if not stripped:
        raise ValueError("nothing to parse")
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        lines = [line for line in stripped.splitlines() if line.strip()]
        if len(lines) == 1:
            raise
        parsed = [json.loads(line) for line in lines]
    if isinstance(parsed, list):
        if not parsed:
            raise ValueError("the array was empty")
        if len(parsed) > 1:
            raise ValueError(
                f"{len(parsed)} alerts were supplied. Bishop triages one at a time here — "
                f"submit them individually, or use the correlation view to see how a set "
                f"of alerts groups."
            )
        parsed = parsed[0]
    if not isinstance(parsed, dict):
        raise ValueError("expected a JSON object describing one alert")
    return parsed
