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
    DnsEvent,
    HumanDecision,
    NetworkConnection,
    ResponseAction,
    ResponsePlan,
)
from tests.graph.conftest import T0, credential_theft_alert, make_alert


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
        assert not result["response_plan"].actions
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


class TestProcessAndFileActionsAreRefusedAsPolicy:
    """The two action types whose target cannot be checked against anything.

    A process name and a file path both come out of the alert payload, so
    checking one against the incident means checking a string the attacker wrote
    against itself. Widening `_known_entities` to admit them is the obvious
    repair and it is the wrong one: it turns a relationship test into a
    self-consistency test.

    Before this was explicit they were *mostly* refused, and only by accident —
    a process name is rarely also a hostname. `quarantine_file` on the alert's
    own IP passed the check and executed. That is worse than either refusing
    them or supporting them, and the refusal message read like a missing entity
    rather than a decision, which invites exactly the widening that must not
    happen.
    """

    def _refuse(self, action_type: ActionType, target: str):
        action = ResponseAction(
            action_id="act-p",
            action_type=action_type,
            target=target,
            rationale="stop it",
            blast_radius=BlastRadius(summary="one process"),
        )
        runtime = build_runtime(run_id="run-policy")
        executor = MockExecutor()
        state = {
            "alerts": [credential_theft_alert()],
            "response_plan": plan_with(action),
            "human_decision": HumanDecision(
                decision=Decision.APPROVED,
                approved_action_ids=["act-p"],
                decided_by="analyst",
            ),
        }
        result = response_execute(state, runtime_config(runtime), executor=executor)
        return result, executor

    @pytest.mark.parametrize(
        ("action_type", "target"),
        [
            (ActionType.KILL_PROCESS, "rundll32.exe"),
            (ActionType.KILL_PROCESS, r"C:\Users\Public\x.dll"),
            (ActionType.QUARANTINE_FILE, r"C:\Users\Public\x.dmp"),
        ],
        ids=["process-name", "process-path", "file-path"],
    )
    def test_a_process_or_file_target_is_refused(self, action_type, target):
        result, executor = self._refuse(action_type, target)
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    @pytest.mark.parametrize(
        ("action_type", "target"),
        [
            (ActionType.KILL_PROCESS, "10.20.30.40"),
            (ActionType.QUARANTINE_FILE, "10.20.30.40"),
            (ActionType.QUARANTINE_FILE, "WKSTN-042"),
            (ActionType.KILL_PROCESS, "j.okafor"),
        ],
        ids=["kill-an-ip", "quarantine-an-ip", "quarantine-a-host", "kill-an-account"],
    )
    def test_naming_a_host_or_account_does_not_smuggle_it_through(self, action_type, target):
        """The membership test passed on these, because the alert really does
        name that IP. "Quarantine the file 10.20.30.40" is not a coherent
        action and it executed."""
        result, executor = self._refuse(action_type, target)
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    def test_the_refusal_says_it_is_a_decision_not_a_gap(self):
        """The next person to read "is not a host or account named by this
        incident" fixes it by widening the entity list. That is the change that
        must not happen, so the reason has to say why instead."""
        result, _ = self._refuse(ActionType.KILL_PROCESS, "rundll32.exe")
        reason = result["execution_log"][0]["reason"]
        assert "does not propose process-scoped containment" in reason
        assert "by hand" in reason


class TestAnEgressBlockMustNameSomethingTheIncidentContacted:
    """The other target class that does not come from inventory.

    `block_domain` was unchecked on the assumption that a containment target is
    always an asset the organisation owns. It is not: the target comes from a
    fired detector's facts, which come from DNS queries and connection
    destinations. Blocking egress is estate-wide, so a laundered destination is
    a denial-of-service on the organisation carrying an analyst's approval.
    """

    def _run(self, target: str, alert):
        action = ResponseAction(
            action_id="act-b",
            action_type=ActionType.BLOCK_DOMAIN,
            target=target,
            rationale="cut the channel",
            blast_radius=BlastRadius(summary="estate-wide egress"),
        )
        runtime = build_runtime(run_id="run-egress")
        executor = MockExecutor()
        state = {
            "alerts": [alert],
            "response_plan": plan_with(action),
            "human_decision": HumanDecision(
                decision=Decision.APPROVED,
                approved_action_ids=["act-b"],
                decided_by="analyst",
            ),
        }
        result = response_execute(state, runtime_config(runtime), executor=executor)
        return result, executor

    def beaconing_alert(self):
        return make_alert(
            dns_events=[
                DnsEvent(timestamp=T0, query="a1b2.tun.example"),
                DnsEvent(timestamp=T0, query="c3d4.tun.example"),
            ],
            connections=[
                NetworkConnection(timestamp=T0, dest_ip="203.0.113.9", hostname="tun.example")
            ],
        )

    def test_a_destination_the_incident_contacted_is_blocked(self):
        result, executor = self._run("tun.example", self.beaconing_alert())
        assert [a.action_id for a in executor.performed] == ["act-b"]

    def test_the_parent_of_an_observed_name_is_blocked(self):
        """A detector summarising sixty subdomain queries reports the parent.
        Blocking the parent is the right answer to the children."""
        alert = make_alert(dns_events=[DnsEvent(timestamp=T0, query="a1b2.tun.example")])
        result, executor = self._run("tun.example", alert)
        assert [a.action_id for a in executor.performed] == ["act-b"]

    def test_a_destination_the_incident_never_contacted_is_refused(self):
        """The laundering case: an attacker-authored field naming somewhere the
        organisation actually needs."""
        result, executor = self._run("windowsupdate.example", self.beaconing_alert())
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"
        assert "not a destination this incident contacted" in result["execution_log"][0]["reason"]

    def test_a_suffix_that_is_not_a_label_boundary_is_refused(self):
        """`un.example` is not a parent of `tun.example`, and treating it as one
        would block a domain nobody observed."""
        result, executor = self._run("un.example", self.beaconing_alert())
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    def test_an_alert_with_no_traffic_blocks_nothing(self):
        """Fail closed: nothing observed means nothing to block."""
        result, executor = self._run("tun.example", make_alert())
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    @pytest.mark.parametrize(
        ("observed", "target"),
        [
            ("a1b2.cdn-telemetry.com", "com"),
            ("a1b2.node7.co.za", "co.za"),
            ("a1b2.node7.co.za", "za"),
            ("a1b2.svc7.ac.uk", "ac.uk"),
            ("a1b2.svc7.ac.uk", "uk"),
            ("a1b2.svc.com.mx", "com.mx"),
            ("a1b2.svc.net.au", "net.au"),
            ("a1b2.svc.co.kr", "co.kr"),
            ("com", "com"),
            ("wpad", "wpad"),
        ],
    )
    def test_a_public_suffix_is_refused_even_when_it_was_observed(self, observed, target):
        """Three attempts to get this right, and the first two shipped.

        A label-boundary suffix rule let `com` through. Replacing it with the
        tunnelling detector's parent heuristic — seven two-part TLDs — let
        `co.za` and `ac.uk` through, because `x.y.co.za` parents to `co.za` and
        the parent goes into the accepted set. Blocking a national registry is
        not a containment action.

        The suffix list is now consulted to *permit*: a target must have a label
        of its own beneath a known suffix. An incomplete list over-refuses,
        which is the direction that costs an analyst a click rather than an
        estate its internet.
        """
        alert = make_alert(dns_events=[DnsEvent(timestamp=T0, query=observed)])
        result, executor = self._run(target, alert)
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    @pytest.mark.parametrize(
        "suffix",
        [
            # Every one of these executed against a hand-written 127-entry
            # list. They are the whole reason the committed Public Suffix List
            # exists: a subset consulted to *derive* a parent over-permits,
            # because a missing `com.pl` makes the parent of `a.evil.com.pl`
            # come out as `com.pl` rather than `evil.com.pl`.
            "com.pl",
            "nhs.uk",
            "co.il",
            "com.tr",
            "com.sg",
            "com.hk",
            "net.mx",
            "ac.nz",
            "co.ke",
            "id.au",
            "web.za",
            "github.io",
            "pages.dev",
            "workers.dev",
            "netlify.app",
            "vercel.app",
            "herokuapp.com",
            "blogspot.com",
            "azurewebsites.net",
        ],
    )
    def test_a_registry_outside_any_hand_written_list_is_refused(self, suffix):
        alert = make_alert(
            dns_events=[DnsEvent(timestamp=T0, query=f"{n:040x}.evil.{suffix}") for n in range(5)]
        )
        result, executor = self._run(suffix, alert)
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    @pytest.mark.parametrize(
        "suffix",
        [
            # The Public Suffix List writes IDN suffixes in Unicode form only,
            # with no punycode alongside. A parser that skipped non-ASCII lines
            # — on the stated belief that punycode was there — dropped 459
            # rules, 260 of them second-level registries under an ASCII TLD.
            # Punycode is what a resolver logs, so every one of these passed the
            # hostname check and blocked a national namespace.
            "xn--55qx5d.cn",  # 公司.cn
            "xn--io0a7i.cn",  # 网络.cn
            "xn--55qx5d.hk",
            "xn--mgba3a4f16a.ir",  # ایران.ir
        ],
    )
    def test_an_internationalised_registry_is_refused(self, suffix):
        alert = make_alert(
            dns_events=[DnsEvent(timestamp=T0, query=f"{n:040x}.evil.{suffix}") for n in range(5)]
        )
        result, executor = self._run(suffix, alert)
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    @pytest.mark.parametrize(
        "namespace",
        ["kobe.jp", "kawasaki.jp", "nagoya.jp", "yokohama.jp", "sapporo.jp", "sendai.jp"],
    )
    def test_a_wildcard_registry_namespace_is_refused(self, namespace):
        """The Public Suffix List's exception rules are the prevailing rule.

        `!city.kobe.jp` means the public suffix of `foo.city.kobe.jp` is
        `kobe.jp` and the registrable domain is `city.kobe.jp`. Treating the
        exception as merely "not a suffix" and walking further right derived
        `kobe.jp` — a whole municipal namespace, five DNS queries from any host
        the adversary already owns.
        """
        alert = make_alert(
            dns_events=[
                DnsEvent(timestamp=T0, query=f"{n:040x}.city.{namespace}") for n in range(5)
            ]
        )
        result, executor = self._run(namespace, alert)
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    def test_the_domain_an_exception_rule_carves_out_is_blockable(self):
        """Refusing the namespace must not cost the answer. `city.kobe.jp` is
        the registrable domain the exception exists to name."""
        alert = make_alert(
            dns_events=[DnsEvent(timestamp=T0, query=f"{n:040x}.city.kobe.jp") for n in range(5)]
        )
        _, executor = self._run("city.kobe.jp", alert)
        assert [a.action_id for a in executor.performed] == ["act-b"]

    @pytest.mark.parametrize(
        "suffix",
        [
            "com.pl",
            "co.il",
            "github.io",
            "herokuapp.com",
            "netlify.app",
            "web.za",
            "xn--55qx5d.cn",
        ],
    )
    def test_the_attackers_own_domain_under_one_is_still_blockable(self, suffix):
        """Refusing the registry must not cost the answer. `evil.github.io` is
        the tenant; `github.io` is every tenant."""
        alert = make_alert(
            dns_events=[DnsEvent(timestamp=T0, query=f"{n:040x}.evil.{suffix}") for n in range(5)]
        )
        _, executor = self._run(f"evil.{suffix}", alert)
        assert [a.action_id for a in executor.performed] == ["act-b"]

    @pytest.mark.parametrize(
        ("observed", "target"),
        [
            ("a1b2.node7.co.za", "node7.co.za"),
            ("a1b2.svc7.ac.uk", "svc7.ac.uk"),
            ("a1b2.tun.example", "tun.example"),
        ],
    )
    def test_the_real_registrable_parent_is_still_blockable(self, observed, target):
        """The attacker's own infrastructure remains reachable. Refusing the
        registry must not cost the answer."""
        alert = make_alert(dns_events=[DnsEvent(timestamp=T0, query=observed)])
        _, executor = self._run(target, alert)
        assert [a.action_id for a in executor.performed] == ["act-b"]

    def test_without_a_policy_no_egress_block_is_allowed(self):
        """Not knowing what the organisation depends on is not a licence to
        guess. `load_policy` returns `{}` when the file is missing, and the
        first version of this read an empty never-block list out of that and
        carried on."""
        from bishop.graph.containment import egress_target_is_allowed, load_egress_policy
        from bishop.graph.containment import observed_destinations as observed

        empty = load_egress_policy({})
        alert = make_alert(dns_events=[DnsEvent(timestamp=T0, query="a.tun.example")])
        allowed, reason = egress_target_is_allowed(
            "block_domain", "tun.example", observed([alert], empty), empty
        )
        assert not allowed
        assert "no environment policy is loaded" in reason

    @pytest.mark.parametrize(
        "entry",
        ["*.okta.com", "okta.com microsoftonline.com", "not a host!", "okta .com", "-lead.com"],
    )
    def test_an_entry_that_does_not_round_trip_refuses_the_whole_policy(self, entry):
        """A trusted list must not be leniently repaired.

        `normalise_name` is deliberately forgiving because it reads
        attacker-authored alert fields. On this list that forgiveness silently
        rewrote entries: `"okta.com microsoftonline.com"` — a plausible CMDB
        export — protected the first name and lost the identity-provider tenant
        domain, while the policy still reported itself usable.
        """
        from bishop.graph.containment import load_egress_policy

        policy = load_egress_policy({"never_block": [entry], "public_suffixes": []})
        assert policy.usable is False

    @pytest.mark.parametrize(
        "entry",
        ["*.lab.internal", "lab.internal extra.internal", "not a host!", "lab..internal", None],
    )
    def test_a_suffix_entry_that_does_not_round_trip_refuses_too(self, entry):
        """The other list, validated the same way.

        `never_block` got the round trip and this one did not, which is the half
        that fails *open*: `*.lab.internal` was silently dropped, so
        `lab.internal` stopped being a declared registry and became blockable —
        a boundary the operator wrote down, removed by a typo nothing reported.
        """
        from bishop.graph.containment import load_egress_policy

        policy = load_egress_policy({"never_block": [], "public_suffixes": [entry]})
        assert policy.usable is False

    def test_an_address_range_protects_the_addresses_in_it(self):
        """Names do not cover their addresses — Bishop does not resolve. A CIDR
        entry is the remedy, so the limitation has a lever rather than a shrug."""
        from bishop.graph.containment import load_egress_policy

        policy = load_egress_policy({"never_block": ["198.51.100.0/24"], "public_suffixes": []})
        assert policy.protects_address("198.51.100.240") == "198.51.100.0/24"
        assert policy.protects_address("203.0.113.9") is None

    def test_a_truncated_suffix_list_refuses_everything(self, monkeypatch):
        """Missing and unparseable already failed closed. Valid JSON holding six
        rules did not, and a short list authorises blocking most of the
        internet's registries."""
        import bishop.graph.containment as containment
        from bishop.graph.containment import load_egress_policy

        monkeypatch.setattr(
            containment, "_suffix_rules", lambda: (frozenset({"com"}), frozenset(), frozenset())
        )
        assert load_egress_policy({"never_block": [], "public_suffixes": []}).usable is False

    def test_a_broken_policy_file_does_not_take_the_run_down(self, tmp_path, monkeypatch):
        """Fail closed, but keep the incident record and the audit close-out."""
        import bishop.detectors.context as context
        from bishop.graph.containment import load_egress_policy

        broken = tmp_path / "policy.json"
        broken.write_text("{ not json", encoding="utf-8")
        monkeypatch.setattr(context, "POLICY_PATH", broken)
        context.load_policy.cache_clear()
        try:
            assert load_egress_policy().usable is False
        finally:
            context.load_policy.cache_clear()

    def test_a_destination_on_the_never_block_list_is_refused(self):
        """The attack no string rule closes.

        An adversary who wants the estate cut off from its identity provider
        does not need to own `okta.com` — they make a host they already control
        emit thirty high-entropy queries under it. The detector fires, correctly
        names the registrable parent, and the plan proposes blocking it. Every
        step is working as designed, and an analyst reading thirty encoded
        queries approves. The only bound is a list the adversary cannot write
        into an alert.
        """
        alert = make_alert(
            dns_events=[DnsEvent(timestamp=T0, query=f"{n:040x}.okta.com") for n in range(30)]
        )
        result, executor = self._run("okta.com", alert)
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"
        assert "never-block list" in result["execution_log"][0]["reason"]

    def test_a_subdomain_of_a_protected_domain_is_refused_too(self):
        alert = make_alert(dns_events=[DnsEvent(timestamp=T0, query="sso.okta.com")])
        result, executor = self._run("sso.okta.com", alert)
        assert executor.performed == []
        assert "never-block list" in result["execution_log"][0]["reason"]

    def test_a_superdomain_of_a_protected_entry_is_refused_too(self):
        """The direction that was missed. `update.microsoft.com` was listed and
        `microsoft.com` was not — and `microsoft.com` is exactly what a detector
        reports. Blocking a parent cuts every child, so the match runs both
        ways. Suffix matching is safe here precisely because it only ever
        refuses more."""
        alert = make_alert(dns_events=[DnsEvent(timestamp=T0, query="a.svc.update.microsoft.com")])
        result, executor = self._run("microsoft.com", alert)
        assert executor.performed == []
        assert "never-block list" in result["execution_log"][0]["reason"]

    def test_a_protected_address_is_refused(self):
        """The never-block list was consulted for names and not for addresses,
        so blocking the observed address of a protected name executed."""
        alert = make_alert(connections=[NetworkConnection(timestamp=T0, dest_ip="192.0.2.50")])
        action = ResponseAction(
            action_id="act-b",
            action_type=ActionType.BLOCK_IP,
            target="192.0.2.50",
            rationale="cut the channel",
            blast_radius=BlastRadius(summary="estate-wide egress"),
        )
        runtime = build_runtime(run_id="run-protected-ip")
        executor = MockExecutor()
        state = {
            "alerts": [alert],
            "response_plan": plan_with(action),
            "human_decision": HumanDecision(
                decision=Decision.APPROVED,
                approved_action_ids=["act-b"],
                decided_by="analyst",
            ),
        }
        result = response_execute(state, runtime_config(runtime), executor=executor)
        assert executor.performed == []
        assert "never-block list" in result["execution_log"][0]["reason"]

    def test_an_ip_target_is_not_a_domain(self):
        alert = make_alert(connections=[NetworkConnection(timestamp=T0, dest_ip="203.0.113.9")])
        result, executor = self._run("203.0.113.9", alert)
        assert executor.performed == []
        assert "use `block_ip`" in result["execution_log"][0]["reason"]


class TestBlockingAnAddressComparesExactly:
    """An address has no hierarchy a suffix test can read.

    Routing `block_ip` through the domain rule meant an observed `203.0.113.9`
    admitted the targets `9`, `113.9` and `0.113.9`. IP hierarchy runs left to
    right; a right-anchored label match is meaningless on an address.
    """

    def _run(self, target: str):
        action = ResponseAction(
            action_id="act-i",
            action_type=ActionType.BLOCK_IP,
            target=target,
            rationale="cut the channel",
            blast_radius=BlastRadius(summary="estate-wide egress"),
        )
        runtime = build_runtime(run_id="run-ip")
        executor = MockExecutor()
        state = {
            "alerts": [
                make_alert(connections=[NetworkConnection(timestamp=T0, dest_ip="203.0.113.9")])
            ],
            "response_plan": plan_with(action),
            "human_decision": HumanDecision(
                decision=Decision.APPROVED,
                approved_action_ids=["act-i"],
                decided_by="analyst",
            ),
        }
        result = response_execute(state, runtime_config(runtime), executor=executor)
        return result, executor

    def test_the_observed_address_is_blocked(self):
        _, executor = self._run("203.0.113.9")
        assert [a.action_id for a in executor.performed] == ["act-i"]

    def test_a_non_canonical_spelling_of_it_is_refused_here(self):
        """`::ffff:203.0.113.9` is the same address, and the executor still
        refuses it — because what it validates has to be what it executes.

        Canonicalising is the planner's job, done before the action is built,
        so an ordinary run never reaches here with an alternative spelling. A
        plan that does came from somewhere else, and the executor is the
        backstop for exactly that.
        """
        result, executor = self._run("::ffff:203.0.113.9")
        assert executor.performed == []
        assert "canonical" in result["execution_log"][0]["reason"]

    @pytest.mark.parametrize("target", ["9", "0.113.9", "113.9", "203.0.113.0/24", "203.0.113.10"])
    def test_a_partial_or_neighbouring_address_is_refused(self, target):
        result, executor = self._run(target)
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    def test_a_leading_zero_form_is_refused(self):
        """Whether `0203` is octal or decimal depends on who parses it. A target
        that means two addresses to two libraries does not reach a block list."""
        result, executor = self._run("0203.0.113.9")
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"

    def test_a_hostname_is_not_an_address(self):
        result, executor = self._run("cdn-telemetry.com")
        assert executor.performed == []
        assert result["execution_log"][0]["status"] == "refused"
