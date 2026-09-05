"""The payload corpus, one test per payload.

`fixtures/injection/payloads.json` is a ledger, not a wish list. Every entry
records what `scan_text` did to it on the day the finding was filed:

- `status: caught` — the scanner flags it. The test asserts it still does, and
  that the techniques the ledger recorded are still among the ones that match,
  so a pattern rewrite that catches the payload by accident for a different
  reason shows up as a change rather than passing quietly.
- `status: evades` — the scanner does not flag it. The test asserts the payload
  *is* caught and is marked strict-xfail, so it stays red-in-the-ledger while
  the gap is open and fails loudly the moment somebody closes it.

Adding a payload that already gets caught is worth very little. Adding one that
evades is the point of the file.
"""

from __future__ import annotations

import pytest

from bishop.quarantine import INJECTION_THRESHOLD, scan_text
from tests.injection.conftest import payload_corpus

CORPUS = payload_corpus()


def _params():
    for entry in CORPUS:
        marks = []
        if entry["status"] == "evades":
            marks.append(
                pytest.mark.xfail(
                    strict=True,
                    reason=f"{entry['id']} evades the scanner ({entry['score']:.2f} < "
                    f"{INJECTION_THRESHOLD}): {entry['note']}",
                )
            )
        yield pytest.param(entry, id=entry["id"], marks=marks)


@pytest.mark.parametrize("entry", list(_params()))
def test_payload_is_flagged_as_an_injection_attempt(entry):
    risk = scan_text(entry["payload"], field=entry["field"])
    assert risk.is_injection, (
        f"{entry['id']} ({entry['class']}) scored {risk.score} in {entry['field']} "
        f"and reached the model unflagged"
    )


@pytest.mark.parametrize(
    "entry",
    [pytest.param(e, id=e["id"]) for e in CORPUS if e["status"] == "caught"],
)
def test_caught_payloads_are_caught_for_the_recorded_reason(entry):
    """A catch that changes technique is a change in the defence, not a bug.

    It still has to be visible: the ledger records why each payload was caught,
    and losing that reason usually means a pattern was narrowed by accident.
    """
    risk = scan_text(entry["payload"], field=entry["field"])
    missing = set(entry["techniques"]) - set(risk.techniques)
    assert not missing, (
        f"{entry['id']} no longer matches {sorted(missing)}; it now matches "
        f"{risk.techniques}. Update fixtures/injection/payloads.json if that is intended."
    )


def test_every_payload_has_a_unique_id_and_a_note():
    ids = [entry["id"] for entry in CORPUS]
    assert len(ids) == len(set(ids))
    assert all(entry["note"].strip() for entry in CORPUS)


def test_the_corpus_covers_every_attack_class_the_threat_model_names():
    classes = {entry["class"] for entry in CORPUS}
    assert {
        "instruction_override",
        "role_hijack",
        "delimiter_break",
        "confused_deputy",
        "verdict_manipulation",
        "tool_coercion",
        "exfiltration_lure",
        "encoding_evasion",
        "homoglyph",
        "invisible_text",
        "multilingual_instruction",
        "oversized_field",
    } <= classes


def test_recall_is_reported_rather_than_asserted(record_property):
    """Print the score so the README number comes from a run, not from memory."""
    caught = sum(1 for entry in CORPUS if scan_text(entry["payload"], field=entry["field"]).is_injection)
    record_property("corpus_caught", caught)
    record_property("corpus_total", len(CORPUS))
    print(f"\ninjection corpus recall: {caught}/{len(CORPUS)}")
    assert caught > 0
