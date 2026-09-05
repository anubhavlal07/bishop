"""Persistence tests.

Two things matter here. An incident must survive the process that produced it
with its evidence intact, and a stored chain must still be verifiable — with
truncation detectable, which is the whole reason the head is stored beside the
incident rather than only inside the chain.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete

from bishop.audit import AuditAction, AuditChain
from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
from bishop.graph.nodes.report import build_incident
from bishop.schema import EvidenceKind, VerdictLabel
from bishop.store import (
    get_engine,
    health,
    init_db,
    list_incidents,
    load_chain,
    load_incident,
    prune,
    save_incident,
    verify_stored_chain,
)
from bishop.store.database import audit_entries
from tests.graph.conftest import credential_theft_alert, injection_only_alert


@pytest.fixture
def engine(tmp_path):
    return init_db(get_engine(f"sqlite:///{tmp_path / 'test.db'}"))


def run_and_store(alert, engine, *, incident_id="INC-1", run_id="run-1"):
    runtime = build_runtime(run_id=run_id)
    config = runtime_config(runtime)
    state = initial_state(run_id=run_id, alerts=[alert], incident_id=incident_id)
    result = build_graph().invoke(state, config=config)
    incident = build_incident(result, audit_head=runtime.chain.head)
    save_incident(incident, chain=runtime.chain, engine=engine)
    return incident, runtime


class TestRoundTrip:
    def test_an_incident_survives_the_process(self, engine):
        original, _ = run_and_store(credential_theft_alert(), engine)
        restored = load_incident("INC-1", engine=engine)

        assert restored is not None
        assert restored.incident_id == original.incident_id
        assert restored.verdict.label is VerdictLabel.TRUE_POSITIVE
        assert restored.verdict.technique_ids == original.verdict.technique_ids

    def test_the_evidence_survives_with_its_detector_signals(self, engine):
        """A stored incident that lost its signals cannot be re-checked."""
        run_and_store(credential_theft_alert(), engine)
        restored = load_incident("INC-1", engine=engine)

        signals = [s for e in restored.all_evidence for s in e.signals]
        assert signals, "detector signals did not survive storage"
        assert all(s.detector for s in signals)
        assert any(s.facts for s in signals)

    def test_injection_evidence_survives(self, engine):
        run_and_store(injection_only_alert(), engine, incident_id="INC-INJ", run_id="run-inj")
        restored = load_incident("INC-INJ", engine=engine)
        injections = [e for e in restored.all_evidence if e.kind is EvidenceKind.INJECTION]
        assert injections
        assert "ignore all previous instructions" in injections[0].facts["raw_value"]

    def test_an_unknown_incident_is_none_not_an_error(self, engine):
        assert load_incident("nope", engine=engine) is None

    def test_saving_twice_replaces_rather_than_duplicates(self, engine):
        run_and_store(credential_theft_alert(), engine)
        run_and_store(credential_theft_alert(), engine)
        assert len(list_incidents(engine=engine)) == 1

    def test_the_listing_carries_what_a_console_needs(self, engine):
        run_and_store(credential_theft_alert(), engine)
        row = list_incidents(engine=engine)[0]
        assert row["verdict"] == "true_positive"
        assert row["alert_count"] == 1
        assert row["audit_head"]
        assert row["run_id"] == "run-1"


class TestStoredChain:
    def test_the_chain_is_stored_and_verifies(self, engine):
        _, runtime = run_and_store(credential_theft_alert(), engine)
        stored = load_chain("run-1", engine=engine)
        assert len(stored) == len(runtime.chain)

        intact, detail = verify_stored_chain("INC-1", engine=engine)
        assert intact, detail

    def test_an_edited_payload_is_caught(self, engine):
        run_and_store(credential_theft_alert(), engine)
        with engine.begin() as conn:
            from sqlalchemy import update

            conn.execute(
                update(audit_entries)
                .where(audit_entries.c.run_id == "run-1", audit_entries.c.seq == 2)
                .values(payload={"tampered": True})
            )
        intact, detail = verify_stored_chain("INC-1", engine=engine)
        assert not intact
        assert "payload" in detail

    def test_a_truncated_tail_is_caught(self, engine):
        """Deleting the record of what executed is the cheapest tamper.

        Verifying from genesis forwards cannot see it — the remaining chain is
        a shorter valid chain. The head stored with the incident is what makes
        it detectable.
        """
        run_and_store(credential_theft_alert(), engine)
        with engine.begin() as conn:
            conn.execute(
                delete(audit_entries).where(
                    audit_entries.c.run_id == "run-1", audit_entries.c.seq >= 30
                )
            )
        intact, detail = verify_stored_chain("INC-1", engine=engine)
        assert not intact
        assert "removed from the end" in detail or "truncated" in detail

    def test_an_incident_stored_without_a_chain_says_so(self, engine):
        incident, _ = run_and_store(credential_theft_alert(), engine)
        save_incident(incident, chain=None, engine=engine)
        intact, detail = verify_stored_chain("INC-1", engine=engine)
        assert not intact
        assert "no audit entries" in detail


class TestHousekeeping:
    def test_prune_removes_old_incidents(self, engine):
        run_and_store(credential_theft_alert(), engine)
        assert prune(datetime.now(UTC) - timedelta(days=1), engine=engine) == 0
        assert prune(datetime.now(UTC) + timedelta(days=1), engine=engine) == 1
        assert list_incidents(engine=engine) == []

    def test_pruning_an_incident_leaves_its_chain(self, engine):
        """Retention for a triage result and for a chain of custody are not the
        same decision, and defaulting them together makes the second one by
        accident."""
        run_and_store(credential_theft_alert(), engine)
        prune(datetime.now(UTC) + timedelta(days=1), engine=engine)
        assert load_chain("run-1", engine=engine)

    def test_health_reports_the_dialect_and_a_count(self, engine):
        run_and_store(credential_theft_alert(), engine)
        report = health(engine)
        assert report["connected"] is True
        assert report["dialect"] == "sqlite"
        assert report["incidents"] == 1

    def test_health_reports_a_broken_connection_rather_than_raising(self):
        broken = get_engine("sqlite:///Z:/nonexistent/path/to.db")
        report = health(broken)
        assert report["connected"] is False
        assert report["error"]


class TestUrlResolution:
    def test_a_bare_postgres_scheme_gets_a_driver(self, monkeypatch):
        from bishop.store import database_url

        monkeypatch.setenv("DATABASE_URL", "postgres://u:p@host:5432/bishop")
        assert database_url().startswith("postgresql+psycopg://")

    def test_an_explicit_driver_is_left_alone(self, monkeypatch):
        from bishop.store import database_url

        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host/bishop")
        assert database_url() == "postgresql+psycopg://u:p@host/bishop"

    def test_no_url_falls_back_to_sqlite(self, monkeypatch):
        from bishop.store import database_url

        monkeypatch.delenv("DATABASE_URL", raising=False)
        assert database_url().startswith("sqlite:///")


class TestChainReload:
    def test_a_reloaded_chain_can_be_verified_by_the_audit_module(self, engine):
        _, runtime = run_and_store(credential_theft_alert(), engine)
        entries = load_chain("run-1", engine=engine)

        chain = AuditChain(run_id="run-1")
        chain._entries = entries
        chain.verify(expected_head=runtime.chain.head, expected_length=len(runtime.chain))
        assert chain.by_action(AuditAction.VERDICT_REACHED)
