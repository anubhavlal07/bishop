"""The human gate and the executor. The controls that must not be theatre.

`CLAUDE.md` §3: *no autonomous containment, ever.* Every test in this file is
an attempt to get an action executed without a human approving it. If any of
them ever passes, the control is gone.
"""

from __future__ import annotations

import pytest
from langgraph.types import Command

from bishop.audit import AuditAction
from bishop.graph import EXECUTOR_NODE, GATE_NODE, build_graph
from bishop.graph.nodes.response_execute import MockExecutor, response_execute
from bishop.graph.nodes.response_gate import _parse_decision
from bishop.graph.runtime import build_runtime, runtime_config
from bishop.schema import (
    ActionType,
    BlastRadius,
    Decision,
    HumanDecision,
    ResponseAction,
    ResponsePlan,
)
from tests.graph.conftest import credential_theft_alert


def isolate_action(action_id: str = "act-1") -> ResponseAction:
    return ResponseAction(
        action_id=action_id,
        action_type=ActionType.ISOLATE_HOST,
        target="WKSTN-042",
        rationale="credential theft observed",
        blast_radius=BlastRadius(hosts_affected=1, summary="one workstation"),
    )


def plan_with(*actions: ResponseAction) -> ResponsePlan:
    return ResponsePlan(actions=list(actions), strategy="test")


class TestTopology:
    def test_the_gate_is_the_only_way_into_the_executor(self):
        """A second edge into the executor would route around the human.

        The executor re-checks the decision itself, so this is defence in depth
        rather than the only control — but a stray edge is exactly the kind of
        change that gets made without anyone noticing.
        """
        graph = build_graph().get_graph()
        predecessors = {e.source for e in graph.edges if e.target == EXECUTOR_NODE}
        assert predecessors == {GATE_NODE}

    def test_the_gate_cannot_be_bypassed_by_the_planner(self):
        graph = build_graph().get_graph()
        successors = {e.target for e in graph.edges if e.source == "response_planner"}
        assert successors == {GATE_NODE}


class TestExecutorRefusal:
    """The executor's own check, exercised by calling it directly.

    Calling the node directly is the point: it simulates every way the gate
    could be skipped — a new edge, a restored checkpoint, a caller invoking the
    node by hand.
    """

    def _run(self, state):
        runtime = build_runtime(run_id="run-gate")
        executor = MockExecutor()
        # A real state always carries the alerts, and the executor now checks a
        # containment target against the entities they name. `isolate_action`
        # targets WKSTN-042, which is the host in `credential_theft_alert`.
        state = {"alerts": [credential_theft_alert()], **state}
        result = response_execute(state, runtime_config(runtime), executor=executor)
        return result, executor, runtime

    def test_no_decision_at_all_refuses_everything(self):
        state = {"response_plan": plan_with(isolate_action()), "human_decision": None}
        result, executor, runtime = self._run(state)
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"
        assert "no human decision" in result["execution_log"][0]["reason"]
        assert len(runtime.chain.by_action(AuditAction.ACTION_REFUSED)) == 1

    def test_a_rejection_refuses_everything(self):
        state = {
            "response_plan": plan_with(isolate_action()),
            "human_decision": HumanDecision(
                decided_by="analyst", decision=Decision.REJECTED, approved_action_ids=["act-1"]
            ),
        }
        result, executor, _ = self._run(state)
        assert executor.performed == []
        assert "rejected by analyst" in result["execution_log"][0]["reason"]

    def test_an_action_outside_the_approved_set_is_refused(self):
        state = {
            "response_plan": plan_with(isolate_action("act-1"), isolate_action("act-2")),
            "human_decision": HumanDecision(
                decided_by="analyst",
                decision=Decision.MODIFIED,
                approved_action_ids=["act-1"],
            ),
        }
        result, executor, _ = self._run(state)
        assert [a.action_id for a in executor.performed] == ["act-1"]
        statuses = {e["action_id"]: e["status"] for e in result["execution_log"]}
        assert statuses == {"act-1": "simulated", "act-2": "refused"}

    def test_an_approval_naming_no_actions_executes_nothing(self):
        state = {
            "response_plan": plan_with(isolate_action()),
            "human_decision": HumanDecision(
                decided_by="analyst", decision=Decision.APPROVED, approved_action_ids=[]
            ),
        }
        _, executor, _ = self._run(state)
        assert executor.performed == []

    def test_execution_is_always_simulated(self):
        state = {
            "response_plan": plan_with(isolate_action()),
            "human_decision": HumanDecision(
                decided_by="analyst", decision=Decision.APPROVED, approved_action_ids=["act-1"]
            ),
        }
        result, executor, _ = self._run(state)
        assert result["execution_log"][0]["status"] == "simulated"
        assert result["execution_log"][0]["executor"] == "mock"
        assert "No side effect was performed" in result["execution_log"][0]["detail"]


class TestDecisionParsing:
    """Anything unrecognised must fail closed."""

    plan = plan_with(isolate_action("act-1"), isolate_action("act-2"))

    @pytest.mark.parametrize(
        "answer",
        [None, 42, [], "", "maybe", {"decision": "later"}, {"decision": ""}, object()],
    )
    def test_unrecognised_answers_are_rejections(self, answer):
        decision = _parse_decision(answer, self.plan)
        assert decision.decision is Decision.REJECTED
        assert decision.approved_action_ids == []

    def test_an_approval_naming_no_action_approves_nothing(self):
        """This used to approve everything, and it is the API's default body.

        `approved_action_ids` defaults to `[]` on the request model, so
        `{"decision": "approved"}` is a valid body that named no actions — and
        `[] or valid_ids` made it mean all of them. Against an unauthenticated
        endpoint that was one request from isolating a host, with an audit entry
        recording a human approval nobody gave.
        """
        decision = _parse_decision({"decision": "approved", "decided_by": "a"}, self.plan)
        assert decision.decision is Decision.REJECTED
        assert decision.approved_action_ids == []
        assert "named no valid action ids" in decision.note

    def test_an_approval_naming_actions_approves_exactly_those(self):
        decision = _parse_decision(
            {"decision": "approved", "approved_action_ids": ["act-1", "act-2"], "decided_by": "a"},
            self.plan,
        )
        assert decision.decision is Decision.APPROVED
        assert set(decision.approved_action_ids) == {"act-1", "act-2"}

    def test_a_subset_approval_keeps_only_the_named_actions(self):
        decision = _parse_decision(
            {"decision": "modified", "approved_action_ids": ["act-2"], "decided_by": "a"},
            self.plan,
        )
        assert decision.decision is Decision.MODIFIED
        assert decision.approved_action_ids == ["act-2"]

    def test_an_action_id_that_is_not_in_the_plan_is_discarded(self):
        """Otherwise a crafted resume payload could name an action into existence."""
        decision = _parse_decision(
            {"decision": "approved", "approved_action_ids": ["act-1", "act-99"]}, self.plan
        )
        assert decision.approved_action_ids == ["act-1"]

    def test_an_unknown_id_in_a_subset_is_dropped_and_noted(self):
        decision = _parse_decision(
            {"decision": "modified", "approved_action_ids": ["act-99"]}, self.plan
        )
        assert decision.approved_action_ids == []
        assert "act-99" in decision.note


class TestEndToEndGate:
    def test_the_run_suspends_at_the_gate(self, run):
        graph, state, config, runtime = run(credential_theft_alert())
        result = graph.invoke(state, config=config)

        assert result.get("__interrupt__"), "the run should have suspended for approval"
        request = result["__interrupt__"][0].value
        assert request["kind"] == "approval_request"
        assert request["actions"], "the analyst was shown no actions"
        assert all("blast_radius" in a for a in request["actions"])
        assert not result.get("execution_log")

    def test_rejecting_executes_nothing(self, run):
        graph, state, config, runtime = run(credential_theft_alert())
        graph.invoke(state, config=config)
        result = graph.invoke(
            Command(resume={"decision": "rejected", "decided_by": "analyst"}), config=config
        )
        assert all(e["status"] == "refused" for e in result["execution_log"])
        assert runtime.chain.by_action(AuditAction.ACTION_EXECUTED) == []

    def test_a_partial_approval_is_honoured_exactly(self, run):
        graph, state, config, runtime = run(credential_theft_alert())
        first = graph.invoke(state, config=config)
        actions = first["__interrupt__"][0].value["actions"]
        keep = [a["action_id"] for a in actions if a["action_type"] != "isolate_host"]

        result = graph.invoke(
            Command(
                resume={
                    "decision": "modified",
                    "approved_action_ids": keep,
                    "decided_by": "analyst@corp",
                }
            ),
            config=config,
        )
        executed = {e["action_id"] for e in result["execution_log"] if e["status"] == "simulated"}
        refused = {e["action_id"] for e in result["execution_log"] if e["status"] == "refused"}
        assert executed == set(keep)
        assert refused and not (refused & executed)

    def test_the_decision_is_written_to_the_audit_chain(self, run):
        graph, state, config, runtime = run(credential_theft_alert())
        first = graph.invoke(state, config=config)
        request = first["__interrupt__"][0].value
        ids = [a["action_id"] for a in request["actions"]]
        graph.invoke(
            Command(
                resume={
                    "decision": "approved",
                    "approved_action_ids": ids,
                    "decided_by": "analyst@corp",
                    "note": "go",
                }
            ),
            config=config,
        )
        decisions = runtime.chain.by_action(AuditAction.HUMAN_DECIDED)
        assert len(decisions) == 1
        assert decisions[0].payload["decided_by"] == "analyst@corp"
        assert decisions[0].payload["decision"] == "approved"

        requested = runtime.chain.by_action(AuditAction.APPROVAL_REQUESTED)
        assert decisions[0].payload["approved_request_hash"] == requested[0].payload["request_hash"]
        assert requested[0].payload["targets"]
        assert requested[0].payload["blast_radii"]
        runtime.chain.verify()

    def test_the_approval_replay_is_labelled_not_hidden(self, run):
        """LangGraph re-runs the node on resume. The chain says so."""
        graph, state, config, runtime = run(credential_theft_alert())
        graph.invoke(state, config=config)
        graph.invoke(Command(resume={"decision": "approved", "decided_by": "a"}), config=config)
        requests = runtime.chain.by_action(AuditAction.APPROVAL_REQUESTED)
        assert len(requests) == 2
        assert requests[0].payload["replayed_after_resume"] is False
        assert requests[1].payload["replayed_after_resume"] is True

    def test_a_verdict_that_is_not_a_true_positive_proposes_nothing(self, run):
        from tests.graph.conftest import quiet_alert

        graph, state, config, runtime = run(quiet_alert())
        result = graph.invoke(state, config=config)
        assert not result.get("__interrupt__")
        assert result["response_plan"].actions == []
        assert result["execution_log"] == []


class TestAnActionMayOnlyTouchTheIncident:
    """The containment target must be an entity the alerts actually name.

    The target reaches the executor from a plan a model wrote, using prompt
    context that includes attacker-controlled fields. Nothing upstream ties it
    back to the incident, so a laundered hostname could point Bishop's one
    irreversible capability at a third party — with a human approving what
    looked like an entirely reasonable plan.

    Scanning cannot fix this: `DC-01` is an ordinary hostname with nothing in it
    to detect. The checkable thing is the relationship.
    """

    def _run(self, action, alerts=None):
        runtime = build_runtime(run_id="run-target")
        executor = MockExecutor()
        state = {
            "alerts": alerts if alerts is not None else [credential_theft_alert()],
            "response_plan": plan_with(action),
            "human_decision": HumanDecision(
                decision=Decision.APPROVED,
                approved_action_ids=[action.action_id],
                decided_by="analyst",
            ),
        }
        result = response_execute(state, runtime_config(runtime), executor=executor)
        return result, executor, runtime

    def other_host(self, hostname: str) -> ResponseAction:
        return ResponseAction(
            action_id="act-x",
            action_type=ActionType.ISOLATE_HOST,
            target=hostname,
            rationale="laundered target",
            blast_radius=BlastRadius(hosts_affected=1, summary="one host"),
        )

    def test_the_incidents_own_host_is_isolated(self):
        result, executor, _ = self._run(isolate_action())
        assert [a.action_id for a in executor.performed] == ["act-1"]
        assert result["execution_log"][0]["status"] == "simulated"

    def test_a_host_the_alert_never_mentioned_is_refused(self):
        """TOL-07: a hostname laundered through an attacker-controlled field."""
        result, executor, _ = self._run(self.other_host("DC-01"))
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"
        assert (
            "not a host or account named by this incident" in (result["execution_log"][0]["reason"])
        )

    def test_the_refusal_is_audited(self):
        _, _, runtime = self._run(self.other_host("DC-01"))
        assert runtime.chain.by_action(AuditAction.ACTION_REFUSED)

    def test_matching_ignores_case_and_padding(self):
        """A real plan writes the hostname back in whatever case the model used."""
        result, executor, _ = self._run(self.other_host("  wkstn-042  "))
        assert result["execution_log"][0]["status"] == "simulated"

    def test_an_account_action_checks_the_principal(self):
        action = ResponseAction(
            action_id="act-a",
            action_type=ActionType.DISABLE_ACCOUNT,
            target="someone.else",
            rationale="laundered account",
            blast_radius=BlastRadius(users_affected=1, summary="one account"),
        )
        result, executor, _ = self._run(action)
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    def test_an_untargeted_action_is_not_blocked(self):
        """`open_ticket` names a reference, not a machine."""
        action = ResponseAction(
            action_id="act-t",
            action_type=ActionType.OPEN_TICKET,
            target="INC-1234",
            rationale="record it",
            blast_radius=BlastRadius(summary="no operational impact"),
        )
        result, _, _ = self._run(action)
        assert result["execution_log"][0]["status"] == "simulated"

    def test_no_alerts_means_nothing_may_be_touched(self):
        """Fail closed: not knowing what the incident is about is not a reason
        to allow an irreversible action."""
        result, executor, _ = self._run(isolate_action(), alerts=[])
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"
