"""Correlation tests.

The join is the finding, so the tests are mostly about joins that must *not*
happen. A wrongly merged incident buries a real alert inside a larger story that
explains it away, and an analyst who spots one bad join stops trusting all of
them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from bishop.correlate import DEFAULT_WINDOW, correlate, incident_for
from bishop.eval import load_corpus
from bishop.schema import Alert, AuthEvent, Device, Principal, Severity

T0 = datetime(2026, 3, 14, 12, 0, tzinfo=UTC)


def alert(
    alert_id: str, *, minutes: float = 0, host: str | None = None, user: str | None = None, **kw
) -> Alert:
    return Alert(
        alert_id=alert_id,
        source="test",
        rule_name="test",
        detected_at=T0 + timedelta(minutes=minutes),
        severity=Severity.MEDIUM,
        device=Device(hostname=host) if host else None,
        principal=Principal(username=user) if user else None,
        **kw,
    )


class TestJoining:
    def test_a_shared_host_joins(self):
        incidents = correlate([alert("A", host="H1"), alert("B", minutes=5, host="H1")])
        assert len(incidents) == 1
        assert {a.alert_id for a in incidents[0].alerts} == {"A", "B"}

    def test_a_shared_account_joins(self):
        incidents = correlate([alert("A", user="alice"), alert("B", minutes=5, user="alice")])
        assert len(incidents) == 1

    def test_joining_is_transitive(self):
        """The lateral-movement case, and the reason correlation is worth having.

        A and C share nothing directly; B links them. Following that chain is
        what a tier-2 analyst does by hand.
        """
        incidents = correlate(
            [
                alert("A", host="WKSTN", user="alice"),
                alert("B", minutes=10, host="SRV", user="alice"),
                alert("C", minutes=20, host="SRV", user="svc_backup"),
            ]
        )
        assert len(incidents) == 1
        assert {a.alert_id for a in incidents[0].alerts} == {"A", "B", "C"}

    def test_an_auth_event_username_counts_as_an_entity(self):
        incidents = correlate(
            [
                alert("A", user="alice"),
                alert(
                    "B",
                    minutes=5,
                    auth_events=[AuthEvent(timestamp=T0, username="alice", outcome="failure")],
                ),
            ]
        )
        assert len(incidents) == 1


class TestNotJoining:
    def test_different_entities_stay_apart(self):
        incidents = correlate([alert("A", host="H1"), alert("B", minutes=5, host="H2")])
        assert len(incidents) == 2

    def test_the_window_bounds_transitivity(self):
        """Without a window, one host accumulates a month-long 'incident'."""
        incidents = correlate(
            [
                alert("A", host="H1"),
                alert("B", minutes=DEFAULT_WINDOW.total_seconds() / 60 + 5, host="H1"),
            ]
        )
        assert len(incidents) == 2

    def test_a_hostname_cannot_collide_with_a_username(self):
        """Entities are namespaced, so `host:web01` and `user:web01` differ."""
        incidents = correlate([alert("A", host="web01"), alert("B", minutes=1, user="web01")])
        assert len(incidents) == 2

    def test_alerts_with_no_entity_do_not_all_merge(self):
        incidents = correlate([alert("A"), alert("B", minutes=1), alert("C", minutes=2)])
        assert len(incidents) == 3

    def test_case_and_whitespace_do_not_prevent_a_join(self):
        incidents = correlate([alert("A", host="WKSTN-1"), alert("B", minutes=1, host=" wkstn-1 ")])
        assert len(incidents) == 1


class TestOrdering:
    def test_input_order_does_not_change_the_result(self):
        alerts = [
            alert("A", host="WKSTN", user="alice"),
            alert("B", minutes=10, host="SRV", user="alice"),
            alert("C", minutes=20, host="SRV", user="svc"),
        ]
        forwards = correlate(alerts)
        backwards = correlate(list(reversed(alerts)))
        assert [sorted(a.alert_id for a in i.alerts) for i in forwards] == [
            sorted(a.alert_id for a in i.alerts) for i in backwards
        ]

    def test_every_alert_lands_in_exactly_one_incident(self):
        corpus = [item.alert for item in load_corpus()]
        incidents = correlate(corpus)
        placed = [a.alert_id for i in incidents for a in i.alerts]
        assert sorted(placed) == sorted(a.alert_id for a in corpus)
        assert len(placed) == len(set(placed))


class TestTheShippedCorpus:
    def test_the_chain_correlates_into_one_incident(self):
        group = incident_for("CHAIN-02-lateral-movement", [i.alert for i in load_corpus()])
        assert group is not None
        assert {a.alert_id for a in group.alerts} == {
            "CHAIN-01-initial-access",
            "CHAIN-02-lateral-movement",
            "CHAIN-03-collection",
        }

    def test_the_chain_rationale_names_what_linked_it(self):
        group = incident_for("CHAIN-01-initial-access", [i.alert for i in load_corpus()])
        assert group is not None
        assert "n.adeyemi" in group.rationale()
        assert "srv-file-07" in group.rationale()

    def test_unrelated_corpus_alerts_are_not_merged_into_it(self):
        group = incident_for("CHAIN-01-initial-access", [i.alert for i in load_corpus()])
        assert group is not None
        assert len(group.alerts) == 3


class TestTheGraphAcceptsAGroup:
    def test_a_correlated_group_produces_one_verdict(self):
        from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
        from bishop.schema import VerdictLabel

        group = incident_for("CHAIN-01-initial-access", [i.alert for i in load_corpus()])
        assert group is not None

        runtime = build_runtime(run_id="run-chain")
        config = runtime_config(runtime)
        state = initial_state(run_id="run-chain", alerts=group.alerts, incident_id="INC-CHAIN")
        result = build_graph().invoke(state, config=config)

        verdict = result["verdict"]
        assert verdict.label is VerdictLabel.TRUE_POSITIVE
        # Techniques spanning the whole chain, not just one alert's worth.
        assert {"T1566.001", "T1543.003", "T1560.001"} <= set(verdict.technique_ids)

    def test_the_supervisor_says_how_many_alerts_it_had(self):
        from bishop.graph import build_graph, build_runtime, initial_state, runtime_config

        group = incident_for("CHAIN-01-initial-access", [i.alert for i in load_corpus()])
        assert group is not None
        runtime = build_runtime(run_id="run-chain-2")
        config = runtime_config(runtime)
        state = initial_state(run_id="run-chain-2", alerts=group.alerts, incident_id="INC-C2")
        result = build_graph().invoke(state, config=config)
        assert "3 correlated alerts" in result["dispatch_rationale"]
