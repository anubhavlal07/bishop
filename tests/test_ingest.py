"""Tests for the alert normaliser.

Two properties matter more than the field mapping itself.

The normaliser must never *invent* structure. A field it does not recognise
goes to `raw` uninterpreted; it does not become a hostname because it looked
like one. Unearned evidence behind a verdict is the failure this project is
arranged against, and a lenient mapper is the easiest place to introduce it.

And the mapping report must be honest about what was dropped, because a
security tool that silently reads half your alert and then sounds confident is
worse than one that refuses.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from bishop.ingest import detect_format, load_payload, normalise
from bishop.schema import AlertCategory, Severity

BACKSLASH = chr(92)


def sysmon_process_create() -> dict:
    """A Sysmon EventID 1, in the shape the Windows event log actually emits."""
    return {
        "EventID": 1,
        "UtcTime": "2026-09-05 11:22:33.123",
        "Computer": "WKSTN-903",
        "User": f"CORP{BACKSLASH}a.smith",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "ParentImage": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        "ProcessId": 4242,
        "RuleName": "Office application spawned PowerShell",
        "Hashes": "SHA256=abc123",
    }


def ecs_document() -> dict:
    """Elastic Common Schema, nested the way Elastic writes it."""
    return {
        "@timestamp": "2026-09-05T11:22:33.000Z",
        "event": {"module": "endpoint", "severity": 73},
        "host": {"hostname": "SRV-APP-11", "ip": "10.0.0.11", "os": {"name": "Windows"}},
        "user": {"name": "svc_worker", "domain": "CORP"},
        "process": {
            "name": "rundll32.exe",
            "executable": r"C:\Windows\System32\rundll32.exe",
            "command_line": "rundll32.exe comsvcs.dll, MiniDump 908 out.dmp full",
            "pid": 900,
        },
        "rule": {"name": "Credential access attempt", "id": "R-114"},
    }


class TestFormatDetection:
    def test_bishop_native_is_recognised(self):
        payload = {
            "alert_id": "A-1",
            "rule_name": "x",
            "detected_at": "2026-01-01T00:00:00Z",
            "source": "s",
        }
        assert detect_format(payload) == "bishop"

    def test_sysmon_is_recognised(self):
        assert detect_format(sysmon_process_create()) == "sysmon"

    def test_ecs_is_recognised(self):
        assert detect_format(ecs_document()) == "ecs"

    def test_anything_else_is_generic(self):
        assert detect_format({"hostname": "H", "cmdline": "x"}) == "generic"


class TestSysmon:
    def test_the_process_tree_maps(self):
        alert, _ = normalise(sysmon_process_create())
        assert alert.process.name == "powershell.exe"
        assert alert.parent_process.name == "WINWORD.EXE"
        assert "-enc" in alert.process.command_line

    def test_the_name_is_derived_from_the_path(self):
        """Sysmon sends `Image` as a full path and no separate name.

        `masquerading` reads the *name*, so a detector that never sees one
        cannot notice a right-to-left override in it.
        """
        alert, _ = normalise(sysmon_process_create())
        assert alert.process.name == "powershell.exe"
        assert alert.process.path.endswith("powershell.exe")

    def test_a_windows_account_splits_into_domain_and_user(self):
        """`DOMAIN\\user` left joined breaks the entity key correlation uses."""
        alert, _ = normalise(sysmon_process_create())
        assert alert.principal.username == "a.smith"
        assert alert.principal.domain == "CORP"

    def test_the_timestamp_is_parsed_not_defaulted(self):
        alert, report = normalise(sysmon_process_create())
        assert alert.detected_at == datetime(2026, 9, 5, 11, 22, 33, 123000, tzinfo=UTC)
        assert not any(f == "detected_at" for f, _, _ in report.defaulted)

    def test_the_category_comes_from_the_data(self):
        alert, _ = normalise(sysmon_process_create())
        assert alert.category is AlertCategory.ENDPOINT


class TestEcs:
    def test_nested_paths_resolve(self):
        alert, _ = normalise(ecs_document())
        assert alert.device.hostname == "SRV-APP-11"
        assert alert.principal.username == "svc_worker"
        assert alert.process.name == "rundll32.exe"

    def test_a_dotted_key_resolves_the_same_as_a_nested_one(self):
        """Exporters disagree; the user should not have to care."""
        flat = {
            "@timestamp": "2026-09-05T11:22:33Z",
            "host.hostname": "SRV-APP-11",
            "process.command_line": "whoami",
        }
        alert, _ = normalise(flat)
        assert alert.device.hostname == "SRV-APP-11"
        assert alert.process.command_line == "whoami"

    def test_a_numeric_severity_maps_onto_the_scale(self):
        alert, _ = normalise(ecs_document())
        assert alert.severity is Severity.HIGH

    def test_a_service_account_is_flagged_by_convention(self):
        alert, _ = normalise(ecs_document())
        assert alert.principal.is_service_account


class TestTheReportIsHonest:
    def test_unrecognised_keys_are_reported_as_ignored(self):
        alert, report = normalise(sysmon_process_create())
        assert "Hashes" in report.ignored
        assert "EventID" in report.ignored

    def test_an_ignored_key_is_still_kept_in_raw(self):
        """Ignored means uninterpreted, not discarded — `raw` is still scanned
        for injection, so a payload cannot hide in an unmapped field."""
        alert, report = normalise(sysmon_process_create())
        assert alert.raw["Hashes"] == "SHA256=abc123"

    def test_defaults_are_declared_with_a_reason(self):
        alert, report = normalise({"CommandLine": "whoami"})
        names = {f for f, _, _ in report.defaulted}
        assert "alert_id" in names
        assert "rule_name" in names
        assert all(why for _, _, why in report.defaulted)

    def test_a_missing_timestamp_says_which_detectors_it_breaks(self):
        _, report = normalise({"CommandLine": "whoami"})
        why = next(w for f, _, w in report.defaulted if f == "detected_at")
        assert "beaconing" in why or "interval" in why

    def test_jurisdiction_is_computed_by_running_the_detectors(self):
        _, report = normalise(sysmon_process_create())
        assert "encoded_command" in report.detectors_with_jurisdiction
        assert report.usable

    def test_an_alert_nothing_can_read_says_so(self):
        """The most useful thing the preview does: tell you the run is pointless
        before you wait for it."""
        _, report = normalise({"some_vendor_field": "value", "another": 12})
        assert not report.usable
        assert any("No detector has anything to work with" in w for w in report.warnings)

    def test_a_single_connection_warns_that_rhythm_cannot_be_judged(self):
        _, report = normalise(
            {"destination.ip": "203.0.113.5", "destination.port": 443, "host.hostname": "H"}
        )
        assert any("beaconing" in w for w in report.warnings)


class TestItDoesNotInventStructure:
    def test_an_unknown_field_does_not_become_a_hostname(self):
        alert, _ = normalise({"weird_host_like_thing": "SRV-01"})
        assert alert.device is None

    def test_an_empty_payload_produces_no_objects(self):
        alert, _ = normalise({})
        assert alert.device is None
        assert alert.principal is None
        assert alert.process is None
        assert alert.connections == []

    def test_labels_are_never_accepted_from_a_submitted_alert(self):
        """`labels` is the eval corpus's ground truth. A submitted alert that
        could set it would be handing Bishop the answer."""
        alert, _ = normalise({"CommandLine": "whoami", "labels": {"verdict": "false_positive"}})
        assert alert.labels == {}

    def test_labels_are_stripped_from_a_native_payload_too(self):
        payload = {
            "alert_id": "A-1",
            "source": "s",
            "rule_name": "r",
            "detected_at": "2026-01-01T00:00:00Z",
            "labels": {"verdict": "false_positive"},
        }
        alert, report = normalise(payload)
        assert alert.labels == {}
        assert any("labels" in w for w in report.warnings)

    def test_an_unmappable_severity_is_not_guessed(self):
        """Windows' inverted 1-5 scale cannot be told from a normal one without
        guessing, and guessing severity silently turns a critical into a low."""
        alert, report = normalise({"severity": "wibble", "CommandLine": "x"})
        assert alert.severity is Severity.MEDIUM
        assert any(f == "severity" for f, _, _ in report.defaulted)


class TestNativePassthrough:
    def test_a_bishop_alert_is_validated_not_remapped(self):
        payload = {
            "alert_id": "MINE-1",
            "source": "edr",
            "rule_name": "Credential dumping",
            "detected_at": "2026-09-05T10:00:00Z",
            "severity": "critical",
            "process": {"name": "mimikatz.exe", "command_line": "sekurlsa::logonpasswords"},
        }
        alert, report = normalise(payload)
        assert report.detected_format == "bishop"
        assert alert.alert_id == "MINE-1"
        assert alert.severity is Severity.CRITICAL
        assert alert.process.name == "mimikatz.exe"


class TestLoadPayload:
    def test_a_plain_object_parses(self):
        assert load_payload('{"a": 1}') == {"a": 1}

    def test_a_single_element_array_is_unwrapped(self):
        """Exporting one alert from a SIEM usually yields a one-element array."""
        assert load_payload('[{"a": 1}]') == {"a": 1}

    def test_ndjson_with_one_row_parses(self):
        assert load_payload('{"a": 1}\n') == {"a": 1}

    def test_several_alerts_are_refused_with_an_explanation(self):
        with pytest.raises(ValueError, match="one at a time"):
            load_payload('[{"a": 1}, {"b": 2}]')

    def test_empty_input_is_refused(self):
        with pytest.raises(ValueError):
            load_payload("   ")

    def test_a_bare_scalar_is_refused(self):
        with pytest.raises(ValueError, match="one alert"):
            load_payload("42")


class TestEndToEnd:
    def test_a_sysmon_event_reaches_a_grounded_verdict(self):
        """The whole point: somebody else's alert, triaged.

        The encoded command decodes, `encoded_command` fires, and the verdict
        rests on a detector rather than on the model's reading.
        """
        from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
        from bishop.schema import VerdictLabel

        payload = sysmon_process_create()
        payload["CommandLine"] = (
            "powershell.exe -nop -w hidden -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
        )
        alert, report = normalise(payload)
        assert report.usable

        runtime = build_runtime(run_id="test-ingest")
        result = build_graph().invoke(
            initial_state(run_id="test-ingest", alerts=[alert], incident_id="INC-ING"),
            config=runtime_config(runtime),
        )
        verdict = result["verdict"]
        assert verdict.label is VerdictLabel.TRUE_POSITIVE
        assert "T1027" in verdict.technique_ids

    def test_an_unreadable_alert_escalates_rather_than_closing(self):
        """The grounding rule and the preview agree: nothing examined means
        nothing can be closed."""
        from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
        from bishop.schema import VerdictLabel

        alert, report = normalise({"vendor_specific": "nothing Bishop reads"})
        assert not report.usable

        runtime = build_runtime(run_id="test-thin")
        result = build_graph().invoke(
            initial_state(run_id="test-thin", alerts=[alert], incident_id="INC-THIN"),
            config=runtime_config(runtime),
        )
        assert result["verdict"].label is VerdictLabel.ESCALATE
