"""Builders for detector tests.

Detectors are pure functions over an `Alert`, so the tests need a cheap way to
construct alerts that carry exactly one interesting thing. Everything here
takes explicit timestamps — no test may depend on the wall clock, for the same
reason no detector may.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from bishop.schema import (
    Alert,
    AuthEvent,
    Device,
    DnsEvent,
    GeoLocation,
    NetworkConnection,
    Principal,
    Process,
    RegistryChange,
    ScheduledTask,
    ServiceInstall,
    Severity,
)

T0 = datetime(2026, 3, 1, 9, 0, 0, tzinfo=UTC)

CITIES: dict[str, tuple[float, float]] = {
    "london": (51.5074, -0.1278),
    "manchester": (53.4808, -2.2426),
    "new_york": (40.7128, -74.0060),
    "singapore": (1.3521, 103.8198),
    "sydney": (-33.8688, 151.2093),
}


def at(seconds: float = 0.0) -> datetime:
    return T0 + timedelta(seconds=seconds)


def alert(**overrides) -> Alert:
    base: dict = {
        "alert_id": "TEST-1",
        "source": "test",
        "rule_name": "Test rule",
        "detected_at": T0,
        "severity": Severity.MEDIUM,
    }
    base.update(overrides)
    return Alert(**base)


def proc(name: str, command_line: str | None = None, **kwargs) -> Process:
    return Process(name=name, command_line=command_line, **kwargs)


def auth(
    seconds: float,
    username: str = "alice",
    outcome: str = "success",
    city: str | None = None,
    source_ip: str | None = None,
    **kwargs,
) -> AuthEvent:
    geo = None
    if city:
        latitude, longitude = CITIES[city]
        geo = GeoLocation(city=city, latitude=latitude, longitude=longitude)
    return AuthEvent(
        timestamp=at(seconds),
        username=username,
        outcome=outcome,
        geo=geo,
        source_ip=source_ip,
        **kwargs,
    )


def conn(seconds: float, host: str = "c2.example", **kwargs) -> NetworkConnection:
    return NetworkConnection(timestamp=at(seconds), hostname=host, **kwargs)


def dns(seconds: float, query: str, **kwargs) -> DnsEvent:
    return DnsEvent(timestamp=at(seconds), query=query, **kwargs)


def beacon_series(
    count: int, interval: float, jitter: float = 0.0, host: str = "c2.example", **kwargs
) -> list[NetworkConnection]:
    """A deterministic series of connections with a fixed proportional jitter.

    The jitter alternates sign rather than being random, because a detector
    test that uses randomness is a flaky test.
    """
    connections = []
    elapsed = 0.0
    for index in range(count):
        connections.append(conn(elapsed, host=host, **kwargs))
        wobble = interval * jitter * (1 if index % 2 == 0 else -1)
        elapsed += interval + wobble
    return connections


@pytest.fixture
def registry_run_key() -> RegistryChange:
    return RegistryChange(
        key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        value_name="Updater",
        value_data=r"C:\Users\Public\update.exe",
    )


@pytest.fixture
def scheduled_task() -> ScheduledTask:
    return ScheduledTask(
        name="SystemUpdate",
        action=r"powershell.exe -w hidden -enc SQBFAFgAKAAoAA==",
        trigger="daily",
    )


@pytest.fixture
def service_install() -> ServiceInstall:
    return ServiceInstall(
        name="WinUpdateSvc", image_path=r"C:\ProgramData\svc.exe", start_type="auto"
    )


@pytest.fixture
def workstation() -> Device:
    return Device(hostname="WKSTN-042", ip="10.20.30.40", os="Windows 11")


@pytest.fixture
def analyst() -> Principal:
    return Principal(username="alice", domain="CORP", sid="S-1-5-21-1-2-3-1104")
