"""The scorecard has to say which model produced it.

`CLAUDE.md` §3: no accuracy claim without a scorecard run. A card that names the
wrong model is worse than no card — it is a reproducible-looking number nobody
can reproduce, and the caveats printed underneath it are wrong too.

This existed as a bug. `cmd_eval` called `run_scorecard()` with no provider, so
the card labelled itself `mock`, while `build_runtime` resolved the provider
from the environment and ran the whole corpus live. A run against Gemini —
178 model calls, 21 s a triage — produced a card headed `provider mock (mock)`
carrying the note "cost is genuinely $0.00".
"""

from __future__ import annotations

import pytest

from bishop.eval.scorecard import run_scorecard


class NamedProvider:
    """A provider that answers nothing, so the card can be built without cost."""

    def __init__(self, name: str, model_id: str) -> None:
        self.name = name
        self.model_id = model_id

    def complete(self, **_kwargs):
        from bishop.models import ModelError

        raise ModelError("this provider exists only to be named")


@pytest.fixture
def one_alert(tmp_path):
    """A corpus of one, so the card is cheap to produce."""
    import json
    import shutil
    from pathlib import Path

    source = sorted((Path("fixtures") / "alerts").glob("FP-*.json"))[0]
    target = tmp_path / source.name
    shutil.copy(source, target)
    assert json.loads(target.read_text(encoding="utf-8"))["labels"]
    return tmp_path


class TestTheCardNamesTheModelThatAnsweredIt:
    def test_an_explicit_provider_is_recorded(self, one_alert):
        card = run_scorecard(
            provider=NamedProvider("gemini", "gemini-3.8-flash"), corpus_dir=one_alert
        )
        assert card.provider == "gemini"
        assert card.model == "gemini-3.8-flash"

    def test_the_environment_provider_is_recorded_when_none_is_passed(self, one_alert, monkeypatch):
        """The bug in one line: the harness took the environment's provider and
        the card did not."""
        monkeypatch.setenv("BISHOP_MODEL_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "AQ." + "x" * 30)

        card = run_scorecard(corpus_dir=one_alert)
        assert card.provider == "gemini", "the card named a model that did not answer"
        assert card.model == "gemini-3.8-flash"

    def test_the_offline_default_still_says_mock(self, one_alert, monkeypatch):
        monkeypatch.delenv("BISHOP_MODEL_PROVIDER", raising=False)
        card = run_scorecard(corpus_dir=one_alert)
        assert card.provider == "mock"
        assert any("mock provider" in note for note in card.notes)

    def test_a_live_card_does_not_claim_the_run_was_free(self, one_alert, monkeypatch):
        """The zero-cost note is true of the mock and a lie about anything else."""
        monkeypatch.setenv("BISHOP_MODEL_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "AQ." + "x" * 30)

        card = run_scorecard(corpus_dir=one_alert)
        assert not any("genuinely $0.00" in note for note in card.notes)

    def test_a_model_with_no_published_price_says_so(self, one_alert, monkeypatch):
        """`cost_usd` returns 0 for a model it has no rates for, and its
        docstring has always claimed the scorecard would say so. Nothing did, so
        a live run printed "$0.000000 per alert" and read as free."""
        monkeypatch.setenv("BISHOP_MODEL_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "AQ." + "x" * 30)

        card = run_scorecard(corpus_dir=one_alert)
        assert any("not because the run was free" in note for note in card.notes)

    def test_a_priced_model_gets_no_such_note(self, one_alert):
        card = run_scorecard(
            provider=NamedProvider("anthropic", "claude-sonnet-5"), corpus_dir=one_alert
        )
        assert not any("not because the run was free" in note for note in card.notes)
