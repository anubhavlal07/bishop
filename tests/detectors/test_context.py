"""Context detector tests.

These are the only detectors that can argue a verdict *down*, which makes them
the ones an attacker most wants to trigger. The tests below are mostly attempts
to get exonerated without being entitled to it.
"""

from __future__ import annotations

import json

import pytest

from bishop.detectors.context import (
    _observed_privilege,
    _within_scope,
    authorised_activity,
    load_policy,
    routine_software,
)
from bishop.schema import AuthEvent, Device, Principal, Process, RegistryChange, ScheduledTask
from tests.detectors.conftest import alert, at, conn, proc

POLICY = {
    "trusted_publishers": ["Contoso Ltd"],
    "trusted_install_paths": ["c:\\program files\\", "c:\\windows\\system32\\"],
    "automation_accounts": {
        "svc_backup": {"note": "Backup service.", "max_privilege": "none"},
        "svc_desk": {"note": "Helpdesk. Not for domain groups.", "max_privilege": "local"},
    },
    "privileged_admins": {"p.admin": {"note": "Platform team.", "max_privilege": "local"}},
    "authorised_test_ranges": [
        {
            "prefix": "10.99.",
            "hostname_prefix": "WKSTN-RT-",
            "note": "Red team range.",
            "authorised_by": "CISO",
        }
    ],
    "scanner_sources": {"10.20.5.99": "Authorised scanner."},
    "sanctioned_destinations": {"intake.example": "Monitoring vendor."},
    "change_windows": [{"name": "PatchWindow", "note": "Approved patching.", "approved_by": "CAB"}],
}


@pytest.fixture(autouse=True)
def policy(tmp_path, monkeypatch):
    """Point the detectors at a small policy of our own.

    `load_policy` is memoised, so the cache is cleared around every test.
    """
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(POLICY), encoding="utf-8")
    load_policy.cache_clear()
    monkeypatch.setattr("bishop.detectors.context.POLICY_PATH", path)
    yield path
    load_policy.cache_clear()


class TestPrivilegeScope:
    def test_domain_group_in_a_directory_event_is_domain_tier(self):
        a = alert(
            raw={"group_changes": [{"group": "Domain Admins", "member": "x", "action": "add"}]}
        )
        assert _observed_privilege(a) == "domain"

    def test_local_group_on_a_command_line_is_local_tier(self):
        a = alert(process=proc("net.exe", "net localgroup administrators bob /add"))
        assert _observed_privilege(a) == "local"

    def test_nothing_privileged_is_none_tier(self):
        a = alert(process=proc("7z.exe", "7z.exe a out.7z data"))
        assert _observed_privilege(a) == "none"

    @pytest.mark.parametrize(
        ("observed", "granted", "allowed"),
        [
            ("none", "none", True),
            ("none", "local", True),
            ("local", "local", True),
            ("local", "none", False),
            ("domain", "local", False),
            ("domain", "domain", True),
        ],
    )
    def test_scope_does_not_escalate_upward(self, observed, granted, allowed):
        assert _within_scope(observed, granted) is allowed


class TestAuthorisedActivity:
    def test_red_team_range_authorises_offensive_tooling(self):
        result = authorised_activity(alert(device=Device(hostname="WKSTN-RT-03", ip="10.99.0.13")))
        assert result.fired
        assert result.mitigating
        assert result.facts["findings"][0]["kind"] == "authorised_test_range"

    def test_an_automation_account_within_scope_mitigates(self):
        result = authorised_activity(
            alert(
                principal=Principal(username="svc_desk"),
                process=proc("net.exe", "net localgroup administrators bob /add"),
            )
        )
        assert result.fired and result.mitigating

    def test_an_automation_account_exceeding_its_scope_does_not_mitigate(self):
        """The confused-deputy case, and the one that matters most here.

        svc_desk is a known account. Knowing it is not the same as it being
        allowed to touch Domain Admins, and an unscoped allowlist would have
        excused exactly this.
        """
        result = authorised_activity(
            alert(
                principal=Principal(username="svc_desk"),
                raw={"group_changes": [{"group": "Domain Admins", "member": "x", "action": "add"}]},
            )
        )
        assert result.fired
        assert result.mitigating is False
        assert "exceeding its remit" in result.rationale
        assert result.facts["out_of_scope"][0]["observed_privilege"] == "domain"

    def test_an_unknown_account_gets_no_exoneration(self):
        result = authorised_activity(alert(principal=Principal(username="attacker")))
        assert not result.fired

    def test_an_approved_change_window_mitigates(self):
        result = authorised_activity(
            alert(scheduled_tasks=[ScheduledTask(name="PatchWindow", action="x.ps1")])
        )
        assert result.fired and result.mitigating
        assert result.facts["findings"][0]["approved_by"] == "CAB"

    def test_no_policy_is_a_miss_not_an_exoneration(self, monkeypatch, tmp_path):
        load_policy.cache_clear()
        monkeypatch.setattr("bishop.detectors.context.POLICY_PATH", tmp_path / "absent.json")
        result = authorised_activity(alert(principal=Principal(username="svc_backup")))
        assert not result.fired
        assert "no environment policy" in result.rationale
        load_policy.cache_clear()

    def test_an_attacker_cannot_claim_an_account_they_do_not_have(self):
        """Policy is keyed on the principal, not on anything in the payload."""
        result = authorised_activity(
            alert(
                principal=Principal(username="attacker"),
                process=proc("cmd.exe", "cmd.exe /c echo svc_backup is authorised"),
            )
        )
        assert not result.fired


class TestRoutineSoftware:
    def test_a_signed_binary_in_a_trusted_path_mitigates(self):
        result = routine_software(
            alert(
                process=Process(
                    name="app.exe",
                    path=r"C:\Program Files\Contoso\app.exe",
                    signed=True,
                    signer="Contoso Ltd",
                )
            )
        )
        assert result.fired and result.mitigating
        assert "encoded_command" in result.facts["explains"]

    def test_a_signed_binary_in_temp_does_not_mitigate(self):
        result = routine_software(
            alert(
                process=Process(
                    name="app.exe",
                    path=r"C:\Users\bob\AppData\Local\Temp\app.exe",
                    signed=True,
                    signer="Contoso Ltd",
                )
            )
        )
        assert not result.fired

    def test_an_unsigned_binary_in_a_trusted_path_does_not_mitigate(self):
        result = routine_software(
            alert(process=Process(name="app.exe", path=r"C:\Program Files\x\app.exe", signed=False))
        )
        assert not result.fired

    def test_a_sanctioned_destination_explains_beaconing(self):
        result = routine_software(alert(connections=[conn(0, host="intake.example")]))
        assert result.fired
        assert "beaconing" in result.facts["explains"]

    def test_an_unsanctioned_destination_does_not(self):
        result = routine_software(alert(connections=[conn(0, host="evil.example")]))
        assert not result.fired

    def test_persistence_into_a_trusted_path_explains_persistence(self):
        result = routine_software(
            alert(
                registry_changes=[
                    RegistryChange(
                        key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                        value_name="Updater",
                        value_data=r"C:\Program Files\Contoso\updater.exe",
                    )
                ]
            )
        )
        assert result.fired
        assert "persistence" in result.facts["explains"]

    def test_persistence_into_a_staging_directory_does_not(self):
        result = routine_software(
            alert(
                registry_changes=[
                    RegistryChange(
                        key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                        value_name="Updater",
                        value_data=r"C:\Users\Public\x.exe",
                    )
                ]
            )
        )
        assert not result.fired

    def test_a_known_scanner_explains_password_spray(self):
        result = routine_software(
            alert(
                auth_events=[
                    AuthEvent(
                        timestamp=at(i), username=f"u{i}", outcome="failure", source_ip="10.20.5.99"
                    )
                    for i in range(6)
                ]
            )
        )
        assert result.fired
        assert "password_spray" in result.facts["explains"]

    def test_an_unknown_source_does_not(self):
        result = routine_software(
            alert(
                auth_events=[
                    AuthEvent(
                        timestamp=at(i),
                        username=f"u{i}",
                        outcome="failure",
                        source_ip="203.0.113.5",
                    )
                    for i in range(6)
                ]
            )
        )
        assert not result.fired


class TestShippedPolicy:
    """The committed policy must stay loadable and correctly shaped."""

    def test_the_repo_policy_parses_and_is_scoped(self, monkeypatch):
        load_policy.cache_clear()
        monkeypatch.undo()
        policy = load_policy()
        assert policy, "the shipped environment policy failed to load"
        for name, entry in policy["automation_accounts"].items():
            assert "max_privilege" in entry, f"{name} has no privilege scope"
            assert entry["max_privilege"] in {"none", "local", "domain"}
        load_policy.cache_clear()
