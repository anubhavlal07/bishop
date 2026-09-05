"""Corpus loading and the helpers the attack tests share."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
from bishop.schema import Alert

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "injection"
PAYLOADS_PATH = FIXTURES / "payloads.json"
BENIGN_PATH = FIXTURES / "benign.json"
ALERTS_DIR = FIXTURES / "alerts"

RUN_ID = "run-injection-corpus"


#: Findings filed against the current build that change a verdict, drop a
#: containment action, or put attacker text outside the fence. Every id here has
#: a strict-xfail test asserting the behaviour Bishop should have; when one is
#: fixed the test reports XPASS and fails, which is the signal to clear the id
#: from this list. An entry here means the review is not passed.
#: Findings that would stop a ship. Empty is the only acceptable value here;
#: an entry means a demonstrated path from an attacker-controlled field to a
#: changed verdict or a dropped containment action.
OPEN_BLOCKERS: tuple[str, ...] = ()


def _load(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def payload_corpus() -> list[dict[str, Any]]:
    return _load(PAYLOADS_PATH)


def benign_corpus() -> list[dict[str, Any]]:
    return _load(BENIGN_PATH)


def load_attack_alert(name: str) -> Alert:
    """One of the end-to-end envelopes in `fixtures/injection/alerts/`."""
    path = next(ALERTS_DIR.glob(f"{name}*.json"))
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    payload.pop("labels", None)
    return Alert(**payload)


def attack_alert_labels(name: str) -> dict[str, Any]:
    path = next(ALERTS_DIR.glob(f"{name}*.json"))
    with path.open(encoding="utf-8") as handle:
        return json.load(handle).get("labels", {})


@dataclass
class RunResult:
    """What one offline pipeline run produced, in the shape the tests ask about."""

    state: dict[str, Any]

    @property
    def label(self) -> str:
        verdict = self.state.get("verdict")
        return str(verdict.label) if verdict else "none"

    @property
    def confidence(self) -> float:
        verdict = self.state.get("verdict")
        return verdict.confidence if verdict else 0.0

    @property
    def flagged_fields(self) -> int:
        return int((self.state.get("quarantine_summary") or {}).get("fields_flagged", 0))

    @property
    def injection_evidence(self) -> list[Any]:
        return list(self.state.get("quarantine_evidence") or [])

    @property
    def actions(self) -> list[tuple[str, str]]:
        plan = self.state.get("response_plan")
        if plan is None:
            return []
        return [(str(a.action_type), a.target) for a in plan.actions]

    @property
    def action_types(self) -> set[str]:
        return {kind for kind, _ in self.actions}


def run_pipeline(alert: Alert, *, run_id: str = RUN_ID) -> RunResult:
    """Run the whole graph offline against the deterministic mock provider.

    The mock is Bishop's default provider, not a test double: `just demo` and
    `just eval` use it, and the scorecard numbers come from it. A verdict that
    moves here is a verdict that moves in the shipped offline configuration.
    """
    runtime = build_runtime(run_id=run_id)
    config = runtime_config(runtime)
    state = initial_state(run_id=run_id, alerts=[alert], incident_id=f"INC-{alert.alert_id}")
    return RunResult(build_graph().invoke(state, config=config))


def make_alert(**overrides: Any) -> Alert:
    base: dict[str, Any] = {
        "alert_id": "INJ-UNIT",
        "source": "sysmon",
        "rule_name": "Test rule",
        "detected_at": "2026-03-14T02:48:00Z",
    }
    base.update(overrides)
    return Alert(**base)


def blocker_xfail(finding_id: str, detail: str) -> pytest.MarkDecorator:
    """Mark a test that asserts behaviour Bishop does not yet have.

    Strict, so closing the hole turns the XPASS into a failure and whoever fixed
    it has to remove the marker and the entry in `OPEN_BLOCKERS`. A red-team
    ledger that quietly goes stale is worse than no ledger.
    """
    return pytest.mark.xfail(strict=True, reason=f"OPEN BLOCKER {finding_id}: {detail}")
