"""Technique validation tests.

The rule under test is `CLAUDE.md` §3: an ID reaches a report only if it is in
the bundle. The most important test in this file is
`test_plausible_invented_id_is_rejected` — a hallucinated technique ID is the
one wrong answer Bishop can produce that looks exactly like a right one.
"""

from __future__ import annotations

import pytest

from bishop.attck import (
    ATLAS_TECHNIQUES,
    TechniqueRejected,
    atlas_for_signals,
    build_matrix,
    is_atlas_id,
    load_catalogue,
    validate_atlas,
    validate_techniques,
)
from bishop.detectors.base import registry


@pytest.fixture(scope="module")
def catalogue():
    return load_catalogue()


class TestCatalogue:
    def test_bundle_loaded_with_a_named_version(self, catalogue):
        assert len(catalogue) > 500
        assert catalogue.attack_version
        assert "T1059.001" in catalogue

    def test_known_technique_carries_its_tactics(self, catalogue):
        technique = catalogue.get("T1003.001")
        assert technique is not None
        assert technique.name == "LSASS Memory"
        assert "credential-access" in technique.tactics
        assert technique.is_subtechnique
        assert technique.parent == "T1003"


class TestValidation:
    def test_valid_id_is_accepted(self):
        result = validate_techniques(["T1078"])
        assert result.ok
        assert result.ids == ["T1078"]

    def test_plausible_invented_id_is_rejected(self):
        result = validate_techniques(["T9999"])
        assert not result.ok
        assert result.ids == []
        assert result.rejected[0].reason == "not_in_bundle"
        assert "invented" in result.rejected[0].detail

    def test_invented_subtechnique_of_a_real_technique_is_rejected(self):
        result = validate_techniques(["T1059.099"])
        assert not result.ok
        assert result.rejected[0].reason == "not_in_bundle"

    def test_prose_around_an_id_is_tolerated(self):
        result = validate_techniques(["T1059.001 - PowerShell"])
        assert result.ok
        assert result.ids == ["T1059.001"]

    def test_lowercase_and_short_subtechnique_are_normalised(self):
        result = validate_techniques(["t1059.1"])
        assert result.ok
        assert result.ids == ["T1059.001"]
        assert result.normalised[0][1] == "T1059.001"

    def test_text_with_no_id_is_malformed(self):
        result = validate_techniques(["lateral movement"])
        assert not result.ok
        assert result.rejected[0].reason == "malformed"

    def test_duplicates_collapse(self):
        result = validate_techniques(["T1078", "T1078", "t1078"])
        assert result.ids == ["T1078"]

    def test_mixed_batch_keeps_the_good_and_reports_the_bad(self):
        result = validate_techniques(["T1078", "T9999", "T1003.001"])
        assert result.ids == ["T1078", "T1003.001"]
        assert len(result.rejected) == 1
        assert "1 rejected" in result.summary()

    def test_require_raises_rather_than_degrading(self):
        with pytest.raises(TechniqueRejected):
            load_catalogue().require(["T9999"])

    def test_empty_input_is_valid_and_empty(self):
        result = validate_techniques([])
        assert result.ok
        assert result.ids == []


class TestDetectorHints:
    def test_every_detector_hint_is_a_real_technique(self):
        """A detector shipping an invalid ID is a bug, and this is the gate."""
        bad: list[str] = []
        for spec in registry().values():
            result = validate_techniques(list(spec.techniques))
            bad.extend(f"{spec.name} -> {r.proposed} ({r.reason})" for r in result.rejected)
        assert bad == [], (
            "detectors propose technique IDs that are not in the bundle: " + "; ".join(bad)
        )

    def test_no_detector_hint_is_deprecated(self, catalogue):
        deprecated = [
            f"{spec.name} -> {hint}"
            for spec in registry().values()
            for hint in spec.techniques
            if (t := catalogue.get(hint)) is not None and t.deprecated
        ]
        assert deprecated == []


class TestAtlas:
    def test_indirect_prompt_injection_is_the_base_mapping(self):
        techniques = atlas_for_signals(["instruction_override"])
        ids = [t.id for t in techniques]
        assert ids[:2] == ["AML.T0051", "AML.T0051.001"]
        assert "AML.T0054" in ids

    def test_encoding_signals_add_the_obfuscation_technique(self):
        ids = [t.id for t in atlas_for_signals(["encoding_evasion"])]
        assert "AML.T0068" in ids

    def test_unknown_atlas_id_is_rejected(self):
        known, unknown = validate_atlas(["AML.T0051", "AML.T9999"])
        assert known == ["AML.T0051"]
        assert unknown == ["AML.T9999"]

    def test_atlas_ids_are_not_mistaken_for_attack_ids(self):
        assert not validate_techniques(["AML.T0051"]).ok
        assert is_atlas_id("AML.T0051")
        assert not is_atlas_id("T1059")

    def test_every_mapped_atlas_id_is_in_the_catalogue(self):
        from bishop.attck.atlas import BASE_INJECTION_TECHNIQUES, SIGNAL_TO_ATLAS

        mapped = {i for ids in SIGNAL_TO_ATLAS.values() for i in ids}
        mapped.update(BASE_INJECTION_TECHNIQUES)
        assert mapped <= set(ATLAS_TECHNIQUES)

    def test_every_injection_signal_has_a_mapping_entry(self):
        from bishop.attck.atlas import SIGNAL_TO_ATLAS
        from bishop.quarantine.signals import InjectionTechnique

        assert {t.value for t in InjectionTechnique} == set(SIGNAL_TO_ATLAS)


class TestCoverageMatrix:
    def test_matrix_builds_from_the_registry(self):
        matrix = build_matrix()
        assert matrix.invalid_hints == []
        assert len(matrix.entries) > 20
        assert all(entry.detectors for entry in matrix.entries)

    def test_a_technique_with_no_fixture_is_untested_not_covered(self):
        matrix = build_matrix()
        assert matrix.covered == []
        assert len(matrix.untested) == len(matrix.entries)

    def test_fixture_labels_promote_a_technique_to_covered(self):
        matrix = build_matrix({"ALERT-1": ["T1078"]})
        entry = next(e for e in matrix.entries if e.technique.id == "T1078")
        assert entry.status == "covered"
        assert entry.fixtures == ["ALERT-1"]
