"""The normalised alert.

Every source — Sysmon, EDR, an identity provider, a proxy — is normalised into
this shape before Bishop looks at it. The shape borrows OCSF's vocabulary
(actor / process / device separation, a coarse activity category) without
dragging in the whole specification; Bishop needs a schema its detectors can
rely on, not a standards-compliance exercise.

Fields typed `Untrusted` are attacker-influenced. That is not a judgement about
a particular alert — it is a statement about who gets to write that field in the
general case. A process command line is written by whoever started the process.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from bishop.schema.untrusted import Untrusted


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class AlertCategory(StrEnum):
    """Coarse routing category. Decides which investigators get dispatched."""

    IDENTITY = "identity"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    EMAIL = "email"
    CLOUD = "cloud"
    OTHER = "other"


class BishopModel(BaseModel):
    """Base for every Bishop model: strict, no silent extra fields."""

    model_config = ConfigDict(extra="forbid")


class GeoLocation(BishopModel):
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None

    @field_validator("latitude")
    @classmethod
    def _valid_lat(cls, v: float | None) -> float | None:
        if v is not None and not -90.0 <= v <= 90.0:
            raise ValueError("latitude out of range")
        return v

    @field_validator("longitude")
    @classmethod
    def _valid_lon(cls, v: float | None) -> float | None:
        if v is not None and not -180.0 <= v <= 180.0:
            raise ValueError("longitude out of range")
        return v

    @property
    def has_coordinates(self) -> bool:
        return self.latitude is not None and self.longitude is not None


class Device(BishopModel):
    hostname: Untrusted | None = None
    ip: str | None = None
    os: str | None = None
    #: From asset inventory, not from the alert payload. Trusted.
    criticality: str | None = None
    is_server: bool = False


class Principal(BishopModel):
    """A user or service account.

    `username` is untrusted whenever it originates outside the identity
    provider — a Sysmon `User` field is whatever the process reported.
    """

    username: Untrusted | None = None
    upn: Untrusted | None = None
    domain: Untrusted | None = None
    sid: str | None = None
    #: From HR/IdP inventory, not the alert. Trusted.
    is_privileged: bool = False
    is_service_account: bool = False


class Process(BishopModel):
    name: Untrusted | None = None
    path: Untrusted | None = None
    command_line: Untrusted | None = None
    pid: int | None = None
    sha256: str | None = None
    signed: bool | None = None
    signer: Untrusted | None = None
    integrity_level: str | None = None
    user: Untrusted | None = None
    started_at: datetime | None = None

    @field_validator("sha256")
    @classmethod
    def _valid_sha(cls, v: str | None) -> str | None:
        if v is None:
            return None
        candidate = v.strip().lower()
        if len(candidate) != 64 or any(c not in "0123456789abcdef" for c in candidate):
            raise ValueError("sha256 must be a 64-character hex digest")
        return candidate


class FileObject(BishopModel):
    name: Untrusted | None = None
    path: Untrusted | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    created_at: datetime | None = None


class RegistryChange(BishopModel):
    key: Untrusted
    value_name: Untrusted | None = None
    value_data: Untrusted | None = None
    operation: str = "set"


class ScheduledTask(BishopModel):
    name: Untrusted
    action: Untrusted | None = None
    trigger: Untrusted | None = None
    run_as: Untrusted | None = None


class ServiceInstall(BishopModel):
    name: Untrusted
    image_path: Untrusted | None = None
    start_type: Untrusted | None = None


class AuthEvent(BishopModel):
    """One authentication attempt, from the identity provider."""

    timestamp: datetime
    username: Untrusted
    #: success | failure | denied | mfa_denied | mfa_success
    outcome: str
    source_ip: str | None = None
    geo: GeoLocation | None = None
    user_agent: Untrusted | None = None
    mfa_method: str | None = None
    application: Untrusted | None = None


class DnsEvent(BishopModel):
    timestamp: datetime
    query: Untrusted
    query_type: str = "A"
    answer: Untrusted | None = None
    resolver: str | None = None


class NetworkConnection(BishopModel):
    timestamp: datetime
    source_ip: str | None = None
    source_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str = "tcp"
    bytes_out: int | None = None
    bytes_in: int | None = None
    #: The Host header and SNI are whatever the client chose to send.
    hostname: Untrusted | None = None
    user_agent: Untrusted | None = None
    url: Untrusted | None = None


class EmailMessage(BishopModel):
    sender: Untrusted | None = None
    recipient: Untrusted | None = None
    subject: Untrusted | None = None
    body_excerpt: Untrusted | None = None
    attachment_names: list[Untrusted] = Field(default_factory=list)
    links: list[Untrusted] = Field(default_factory=list)


class Alert(BishopModel):
    """A normalised security alert. Bishop's unit of work."""

    alert_id: str
    source: str
    rule_id: str | None = None
    #: The detection rule's own title, written by a detection engineer. Trusted.
    rule_name: str
    detected_at: datetime
    severity: Severity = Severity.MEDIUM
    category: AlertCategory = AlertCategory.OTHER

    #: Free text from the sensor. Vendors interpolate attacker data into these.
    description: Untrusted | None = None

    device: Device | None = None
    principal: Principal | None = None
    process: Process | None = None
    parent_process: Process | None = None
    grandparent_process: Process | None = None
    file: FileObject | None = None
    email: EmailMessage | None = None

    auth_events: list[AuthEvent] = Field(default_factory=list)
    dns_events: list[DnsEvent] = Field(default_factory=list)
    connections: list[NetworkConnection] = Field(default_factory=list)
    registry_changes: list[RegistryChange] = Field(default_factory=list)
    scheduled_tasks: list[ScheduledTask] = Field(default_factory=list)
    service_installs: list[ServiceInstall] = Field(default_factory=list)
    child_processes: list[Process] = Field(default_factory=list)

    #: Sensor-specific leftovers. Never rendered into a prompt un-quarantined.
    raw: dict[str, Any] = Field(default_factory=dict)

    #: Populated only in fixtures and eval. Never read by the graph.
    labels: dict[str, Any] = Field(default_factory=dict)

    def entity_key(self) -> str:
        """A stable key for correlating alerts into one incident.

        Deliberately coarse — host plus principal. Correlation that is too
        clever merges unrelated activity, and a wrongly merged incident is
        worse than two separate ones.
        """
        host = (self.device.hostname if self.device else None) or "unknown-host"
        user = (self.principal.username if self.principal else None) or "unknown-user"
        return f"{str(host).lower()}|{str(user).lower()}"
