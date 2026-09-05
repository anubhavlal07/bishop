"""API surface tests.

The important ones are in `TestApprovalFlow`: the API is the path a console
takes to the human gate, and it must not become a way around it.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from bishop.api import app


@pytest.fixture
def client():
    return TestClient(app)


def wait_for(client, run_id: str, status: str, timeout: float = 20.0) -> dict:
    """Poll until the run reaches a status. Runs execute on a worker thread."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/runs/{run_id}").json()
        if body["status"] == status:
            return body
        if body["status"] == "failed":
            raise AssertionError(f"run failed: {body['error']}")
        time.sleep(0.05)
    raise AssertionError(f"run {run_id} did not reach {status}; last was {body['status']}")


class TestReadOnly:
    def test_health_reports_the_provider(self, client):
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert body["offline"] is True

    def test_alerts_lists_the_corpus(self, client):
        body = client.get("/alerts").json()
        assert body["count"] == 20
        assert all(a["synthetic"] for a in body["alerts"])

    def test_a_single_alert_carries_its_ground_truth(self, client):
        body = client.get("/alerts/TP-01-credential-dumping").json()
        assert body["labels"]["verdict"] == "true_positive"
        assert body["labels"]["why"]

    def test_an_unknown_alert_is_404(self, client):
        assert client.get("/alerts/nope").status_code == 404

    def test_detectors_are_listed_with_their_surfaces(self, client):
        body = client.get("/detectors").json()
        assert body["count"] >= 19
        assert "context" in body["surfaces"]

    def test_coverage_distinguishes_covered_from_untested(self, client):
        body = client.get("/coverage").json()
        statuses = {e["status"] for e in body["entries"]}
        assert statuses <= {"covered", "untested", "none"}
        assert body["attack_version"]

    def test_the_scorecard_ships_its_caveats(self, client):
        body = client.get("/scorecard").json()
        assert body["notes"], "the scorecard must carry its own limitations"
        assert any("synthetic" in note for note in body["notes"])


class TestRunLifecycle:
    def test_starting_an_unknown_alert_is_404(self, client):
        assert client.post("/runs", json={"alert_id": "nope"}).status_code == 404

    def test_a_quiet_alert_runs_to_completion_without_a_gate(self, client):
        started = client.post("/runs", json={"alert_id": "FP-07-cdn-dns"})
        assert started.status_code == 202
        run_id = started.json()["run_id"]
        body = wait_for(client, run_id, "done")
        assert body["incident"]["verdict"]["label"] == "false_positive"
        assert body["audit_intact"] is True

    def test_the_audit_chain_is_exposed_and_verifies(self, client):
        run_id = client.post("/runs", json={"alert_id": "FP-07-cdn-dns"}).json()["run_id"]
        wait_for(client, run_id, "done")
        audit = client.get(f"/runs/{run_id}/audit").json()
        assert audit["intact"] is True
        assert len(audit["entries"]) > 10
        assert audit["entries"][0]["prev_hash"] == "0" * 64

    def test_events_replay_for_a_late_subscriber(self, client):
        run_id = client.post("/runs", json={"alert_id": "FP-07-cdn-dns"}).json()["run_id"]
        wait_for(client, run_id, "done")
        with client.stream("GET", f"/runs/{run_id}/events") as response:
            assert response.status_code == 200
            body = "".join(chunk for chunk in response.iter_text())
        assert "event: verdict" in body
        assert "event: done" in body


class TestApprovalFlow:
    """The API must not become a way around the human gate."""

    def _run_to_gate(self, client) -> str:
        run_id = client.post("/runs", json={"alert_id": "TP-01-credential-dumping"}).json()[
            "run_id"
        ]
        wait_for(client, run_id, "awaiting_approval")
        return run_id

    def test_a_true_positive_suspends_for_approval(self, client):
        run_id = self._run_to_gate(client)
        body = client.get(f"/runs/{run_id}").json()
        request = body["approval_request"]
        assert request["actions"]
        assert any(a["irreversible"] for a in request["actions"])
        assert all(a["blast_radius"]["summary"] for a in request["actions"])
        # Nothing has run.
        assert not body["incident"]["execution_log"]

    def test_rejecting_executes_nothing(self, client):
        run_id = self._run_to_gate(client)
        client.post(
            f"/runs/{run_id}/decision",
            json={"decision": "rejected", "decided_by": "test-analyst"},
        )
        body = wait_for(client, run_id, "done")
        log = body["incident"]["execution_log"]
        assert log and all(entry["status"] == "refused" for entry in log)

    def test_a_subset_approval_executes_only_that_subset(self, client):
        run_id = self._run_to_gate(client)
        request = client.get(f"/runs/{run_id}").json()["approval_request"]
        keep = [a["action_id"] for a in request["actions"] if not a["irreversible"]]

        client.post(
            f"/runs/{run_id}/decision",
            json={
                "decision": "modified",
                "approved_action_ids": keep,
                "decided_by": "test-analyst",
            },
        )
        body = wait_for(client, run_id, "done")
        executed = {
            e["action_id"] for e in body["incident"]["execution_log"] if e["status"] == "simulated"
        }
        assert executed == set(keep)

    def test_an_action_id_the_run_never_proposed_is_ignored(self, client):
        """A console bug must not be able to name an action into existence."""
        run_id = self._run_to_gate(client)
        client.post(
            f"/runs/{run_id}/decision",
            json={
                "decision": "modified",
                "approved_action_ids": ["fabricated-action-id"],
                "decided_by": "test-analyst",
            },
        )
        body = wait_for(client, run_id, "done")
        assert all(e["status"] == "refused" for e in body["incident"]["execution_log"])

    def test_deciding_twice_is_rejected(self, client):
        run_id = self._run_to_gate(client)
        first = client.post(
            f"/runs/{run_id}/decision", json={"decision": "rejected", "decided_by": "a"}
        )
        assert first.status_code == 200
        wait_for(client, run_id, "done")
        second = client.post(
            f"/runs/{run_id}/decision", json={"decision": "approved", "decided_by": "b"}
        )
        assert second.status_code == 409

    def test_deciding_on_an_unknown_run_is_404(self, client):
        response = client.post(
            "/runs/run-does-not-exist/decision",
            json={"decision": "approved", "decided_by": "a"},
        )
        assert response.status_code == 404

    def test_the_decision_appears_in_the_audit_chain(self, client):
        run_id = self._run_to_gate(client)
        client.post(
            f"/runs/{run_id}/decision",
            json={"decision": "rejected", "decided_by": "test-analyst", "note": "not now"},
        )
        wait_for(client, run_id, "done")
        entries = client.get(f"/runs/{run_id}/audit").json()["entries"]
        decisions = [e for e in entries if e["action"] == "human_decided"]
        assert len(decisions) == 1
        assert decisions[0]["payload"]["decided_by"] == "test-analyst"


class TestInjectionThroughTheApi:
    def test_the_injection_alert_surfaces_its_finding(self, client):
        run_id = client.post("/runs", json={"alert_id": "INJ-02-encoded-fence-break"}).json()[
            "run_id"
        ]
        body = wait_for(client, run_id, "done")
        evidence = [
            e
            for report in body["incident"]["reports"]
            for e in report["evidence"]
            if e["kind"] == "injection"
        ]
        assert evidence, "the injection finding did not reach the API response"
        assert body["incident"]["verdict"]["label"] == "escalate"
