"""Tests for `recovery_destruction`.

Written because the held-out set caught Bishop closing a shadow-copy deletion
as a false positive — no detector had jurisdiction, so the evidence table came
back empty and ransomware preparation read as nothing to see.

The tests that matter are the ones separating maintenance from intent. A single
`vssadmin delete shadows` is something an administrator genuinely runs; three
different recovery mechanisms destroyed in one command line is not.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from bishop.detectors.endpoint import recovery_destruction
from bishop.schema import Alert, Process, ScheduledTask


def alert_with(command: str = "", *, task: str = "") -> Alert:
    return Alert(
        alert_id="REC-1",
        source="edr",
        rule_name="Suspicious command",
        detected_at=datetime(2026, 3, 14, tzinfo=UTC),
        process=Process(name="cmd.exe", command_line=command) if command else None,
        scheduled_tasks=[ScheduledTask(name="t", action=task)] if task else [],
    )


class TestTheRansomwareSweep:
    def test_three_mechanisms_in_one_command_scores_near_certain(self):
        result = recovery_destruction(
            alert_with(
                "cmd.exe /c vssadmin delete shadows /all /quiet & wbadmin delete catalog "
                "-quiet & bcdedit /set recoveryenabled No"
            )
        )
        assert result.fired
        assert result.score >= 0.9
        assert set(result.facts["mechanisms"]) == {
            "shadow copies",
            "backup catalogue",
            "boot recovery",
        }

    def test_the_technique_is_inhibit_system_recovery(self):
        result = recovery_destruction(alert_with("vssadmin delete shadows /all /quiet"))
        assert "T1490" in result.technique_hints

    def test_clearing_the_event_log_adds_indicator_removal(self):
        result = recovery_destruction(
            alert_with("cmd.exe /c wevtutil cl Security & vssadmin delete shadows /all")
        )
        assert "T1070.001" in result.technique_hints


class TestOneMechanismIsSuspicionNotIntent:
    def test_a_single_deletion_scores_below_a_sweep(self):
        """An administrator reclaiming disk on a server genuinely runs this."""
        one = recovery_destruction(alert_with("vssadmin delete shadows /for=C: /oldest"))
        many = recovery_destruction(
            alert_with("vssadmin delete shadows /all & wbadmin delete catalog")
        )
        assert one.fired
        assert one.score < many.score

    def test_the_rationale_says_why_it_is_not_a_conclusion(self):
        result = recovery_destruction(alert_with("vssadmin delete shadows /for=C: /oldest"))
        assert "administrative use" in result.rationale

    def test_suppressing_the_prompt_raises_it(self):
        """`/quiet` exists to skip the confirmation. Nobody at a console needs it."""
        loud = recovery_destruction(alert_with("vssadmin delete shadows /for=C: /oldest"))
        quiet = recovery_destruction(alert_with("vssadmin delete shadows /all /quiet"))
        assert quiet.score > loud.score
        assert quiet.facts["unattended"] is True


class TestItLooksWhereCommandsActuallyRun:
    def test_a_scheduled_task_action_is_examined(self):
        """Persistence runs the command later; the task action is the carrier."""
        result = recovery_destruction(alert_with(task="vssadmin delete shadows /all /quiet"))
        assert result.fired

    @pytest.mark.parametrize(
        "command",
        [
            "wmic shadowcopy delete",
            "powershell -c Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }",
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
            "wbadmin delete systemstatebackup -keepversions:0",
            "powershell Disable-ComputerRestore -Drive C:\\",
        ],
    )
    def test_the_other_spellings_are_covered(self, command):
        assert recovery_destruction(alert_with(command)).fired


class TestItStaysQuietOtherwise:
    @pytest.mark.parametrize(
        "command",
        [
            r"cmd.exe /c dir C:\Users",
            r"vssadmin list shadows",
            r"wbadmin start backup -backupTarget:E: -include:C:",
            r"bcdedit /enum",
            "robocopy C:\\data E:\\backup /mir",
        ],
    )
    def test_ordinary_administration_does_not_fire(self, command):
        """Listing shadows, taking a backup and enumerating boot config are the
        legitimate neighbours of every pattern here."""
        assert not recovery_destruction(alert_with(command)).fired

    def test_an_alert_with_no_commands_is_a_miss_not_a_clear(self):
        """Nothing to read is not the same as read-and-found-nothing — the
        difference decides whether the alert can be closed at all."""
        result = recovery_destruction(alert_with())
        assert not result.fired
        assert not result.examined

    def test_an_alert_with_commands_is_examined(self):
        result = recovery_destruction(alert_with("cmd.exe /c dir"))
        assert not result.fired
        assert result.examined


class TestPurity:
    def test_the_same_alert_gives_the_same_answer(self):
        alert = alert_with("vssadmin delete shadows /all /quiet")
        first, second = recovery_destruction(alert), recovery_destruction(alert)
        assert first.score == second.score
        assert first.facts == second.facts
