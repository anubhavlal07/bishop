"""Detector purity, enforced rather than asserted in a docstring.

`docs/DETECTORS.md` claims every detector is a pure function of its alert: no
model call, no network, no database, no clock read, no randomness. That claim is
what makes the golden set reproducible and the scorecard meaningful, and it is
exactly the kind of claim that quietly stops being true.

These tests check it two ways — by reading the source for the calls that would
break it, and by running every detector twice and comparing.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

import bishop.detectors  # importing registers every detector
from bishop.detectors.base import registry
from bishop.eval import load_corpus

DETECTOR_DIR = Path(inspect.getfile(bishop.detectors)).parent

FORBIDDEN_MODULES = {
    "random": "randomness",
    "requests": "network",
    "httpx": "network",
    "urllib": "network",
    "socket": "network",
    "aiohttp": "network",
}


def detector_sources() -> list[tuple[str, str]]:
    return [
        (path.name, path.read_text(encoding="utf-8")) for path in sorted(DETECTOR_DIR.glob("*.py"))
    ]


class TestSourcePurity:
    @pytest.mark.parametrize(("name", "source"), detector_sources(), ids=lambda v: v[:24])
    def test_no_impure_imports(self, name: str, source: str):
        tree = ast.parse(source)
        offenders: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in FORBIDDEN_MODULES:
                        offenders.append(f"import {alias.name} ({FORBIDDEN_MODULES[root]})")
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root in FORBIDDEN_MODULES:
                    offenders.append(f"from {node.module} ({FORBIDDEN_MODULES[root]})")
        assert offenders == [], f"{name} imports impure modules: {offenders}"

    @pytest.mark.parametrize(("name", "source"), detector_sources(), ids=lambda v: v[:24])
    def test_no_clock_reads(self, name: str, source: str):
        """A detector that reads the clock gives a different answer next week."""
        tree = ast.parse(source)
        offenders: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            attribute = func.attr if isinstance(func, ast.Attribute) else None
            if attribute in {"now", "utcnow", "today", "monotonic", "perf_counter"}:
                offenders.append(f"line {node.lineno}: .{attribute}()")
        assert offenders == [], f"{name} reads the clock: {offenders}"


class TestRuntimePurity:
    """Run every detector twice over the whole corpus and compare."""

    def test_every_detector_is_deterministic(self):
        corpus = load_corpus()
        specs = registry()
        differences: list[str] = []

        for item in corpus:
            for spec in specs.values():
                first = spec.fn(item.alert)
                second = spec.fn(item.alert)
                if first.model_dump() != second.model_dump():
                    differences.append(f"{spec.name} on {item.alert_id}")

        assert differences == [], f"non-deterministic detectors: {differences}"

    def test_no_detector_mutates_the_alert(self):
        """A detector that edits its input corrupts every detector after it."""
        corpus = load_corpus()
        specs = registry()
        mutated: list[str] = []

        for item in corpus:
            before = item.alert.model_dump_json()
            for spec in specs.values():
                spec.fn(item.alert)
                if item.alert.model_dump_json() != before:
                    mutated.append(f"{spec.name} on {item.alert_id}")
                    break

        assert mutated == [], f"detectors mutated their input: {mutated}"

    def test_every_detector_survives_a_nearly_empty_alert(self):
        """A missing field must produce a miss, not an exception."""
        from bishop.schema import Alert

        bare = Alert(
            alert_id="BARE", source="test", rule_name="nothing", detected_at="2026-01-01T00:00:00Z"
        )
        for spec in registry().values():
            result = spec.fn(bare)
            assert result.detector == spec.name
            assert result.fired is False
