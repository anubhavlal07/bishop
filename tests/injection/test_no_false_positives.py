"""The other half of the job: ordinary telemetry must not flag.

A detector that screams at every PowerShell command line is not a defence, it is
a way of teaching an analyst to ignore the one alert that mattered. These are
real-shaped SOC inputs — encoded commands, LOLBins, base64 in URLs, prose that
happens to contain the words "ignore" and "previous" — and every one of them
must stay under the threshold.
"""

from __future__ import annotations

import pytest

from bishop.quarantine import INJECTION_THRESHOLD, scan_text
from tests.injection.conftest import benign_corpus, make_alert
from bishop.quarantine import quarantine_alert
from bishop.schema import Process

BENIGN = benign_corpus()


@pytest.mark.parametrize("entry", [pytest.param(e, id=e["id"]) for e in BENIGN])
def test_benign_telemetry_stays_under_the_threshold(entry):
    risk = scan_text(entry["value"], field=entry["field"])
    assert not risk.is_injection, (
        f"{entry['id']} is ordinary telemetry and scored {risk.score} "
        f"({risk.techniques}): {entry['note']}"
    )


@pytest.mark.parametrize("entry", [pytest.param(e, id=e["id"]) for e in BENIGN])
def test_benign_telemetry_does_not_drift_upward(entry):
    """Score creep is how a precise detector becomes a noisy one.

    The ledger records what each benign sample scored. A change that pushes any
    of them up is worth seeing even when it stays under the threshold, because
    two harmless increments combine over the probabilistic OR into a flag.
    """
    risk = scan_text(entry["value"], field=entry["field"])
    assert risk.score <= max(entry["score"], 0.3) + 1e-9, (
        f"{entry['id']} scored {risk.score}, up from {entry['score']} in the ledger"
    )


def test_a_whole_benign_alert_raises_no_injection_evidence():
    alert = make_alert(
        process=Process(
            name="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=(
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
                r"C:\ProgramData\Corp\Scripts\Set-Baseline.ps1 -Ring pilot"
            ),
        ),
        description=(
            "Detection rule guidance: analysts should ignore previous alerts from this rule "
            "when the host is in the pilot ring; see runbook RB-14."
        ),
    )
    report = quarantine_alert(alert, run_id="run-benign")
    assert report.fields, "the boundary should still quarantine the fields"
    assert not report.has_injection
    assert report.max_score < INJECTION_THRESHOLD


def test_the_false_positive_rate_is_reported():
    flagged = [e for e in BENIGN if scan_text(e["value"], field=e["field"]).is_injection]
    print(f"\nbenign corpus false positives: {len(flagged)}/{len(BENIGN)}")
    assert not flagged
