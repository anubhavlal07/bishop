"""The plan has to describe itself honestly — structurally, not lexically.

Three defects live here, all found on real output.

**The strategy lied about the plan.** A confirmed token replay came back with
"contain the account and the host together" above a list containing one action,
`open_ticket`. An analyst who reads the strategy and approves has been told
something untrue about what they just approved.

**The first fix was worse than the defect.** It looked for containment words in
the strategy and replaced the sentence when the actions did not support them.
That deleted what the model wrote — so a strategy saying "do not isolate the
file server", or "isolate this by hand, Bishop cannot name the target", vanished
from the one screen where a human decides. It also matched "an isolated
incident", "the kill chain" and "container", while the nine characters `no
action` anywhere in the string switched the whole rule off. Recognising a
vocabulary loses to a vocabulary you did not think of, which is the lesson
`safe_block()` already learnt.

So `ResponsePlan.proposes` is computed from the actions and always present, and
`strategy` is never touched. The honesty property then holds regardless of what
anything wrote. Most of this file is the difference between those two.

**The dedupe threw away a reason.** Two branches proposing the same isolation
for different reasons left the analyst reading one of them.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from bishop.audit import AuditAction
from bishop.eval.corpus import load_corpus
from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
from bishop.graph.nodes.response_planner import _RECORD_ONLY, response_planner
from bishop.schema import ResponsePlan, Verdict, VerdictLabel
from tests.graph.conftest import credential_theft_alert


class StubPlanner:
    """A model that returns exactly the plan a test needs."""

    name = "stub"
    model_id = "stub"

    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def complete(self, **_kwargs):
        from bishop.models.base import ModelResponse, Usage

        return ModelResponse(
            data=self.payload,
            text="",
            model="mock",
            usage=Usage(input_tokens=0, output_tokens=0),
        )


def ticket(**overrides) -> dict:
    action = {
        "action_type": "open_ticket",
        "target": "INC-TEST",
        "rationale": "Record it.",
        "priority": 90,
    }
    action.update(overrides)
    return action


def isolation(target: str = "WKSTN-042", rationale: str = "Stop it.", priority: int = 10) -> dict:
    return {
        "action_type": "isolate_host",
        "target": target,
        "rationale": rationale,
        "priority": priority,
    }


def plan_from(strategy: str, actions: list[dict]):
    runtime = build_runtime(
        run_id="planner-test",
        provider=StubPlanner({"strategy": strategy, "actions": actions}),
    )
    state = initial_state(
        run_id="planner-test", alerts=[credential_theft_alert()], incident_id="INC-TEST"
    )
    state["verdict"] = Verdict(
        label=VerdictLabel.TRUE_POSITIVE,
        confidence=0.9,
        rationale="test",
        technique_ids=[],
    )
    result = response_planner(state, runtime_config(runtime))
    return result["response_plan"], runtime


class TestTheComputedSentenceCannotDisagreeWithThePlan:
    def test_it_names_what_the_plan_proposes(self):
        plan, _ = plan_from("Contain the host.", [isolation(), ticket()])
        assert plan.proposes == (
            "This plan proposes: isolate host and open ticket. 1 of 2 is irreversible."
        )

    def test_it_counts_repeated_actions(self):
        """Thirty-nine isolations and one isolation must not read the same. The
        sentence exists to say what is being approved, and a bare type name is
        the summary an analyst was already not supposed to trust."""
        plan, _ = plan_from(
            "Contain them all.",
            [isolation(target=f"WKSTN-{n:03d}", rationale=f"Host {n}.") for n in range(39)]
            + [ticket()],
        )
        assert "39 x isolate host" in plan.proposes
        assert "39 of 40 are irreversible" in plan.proposes

    def test_it_counts_the_irreversible_ones(self):
        plan, _ = plan_from("Contain the host.", [isolation(), ticket()])
        assert "1 of 2 is irreversible." in plan.proposes

    def test_a_record_only_plan_claims_nothing_irreversible(self):
        plan, _ = plan_from("Open a ticket.", [ticket()])
        assert "irreversible" not in plan.proposes

    def test_a_plan_that_contains_nothing_says_so(self):
        plan, _ = plan_from("Contain the account and the host together.", [ticket()])
        assert "No containment action is included." in plan.proposes

    def test_a_plan_that_contains_something_does_not_say_so(self):
        plan, _ = plan_from("Contain the host.", [isolation()])
        assert "No containment action" not in plan.proposes

    def test_forensics_alone_is_not_containment(self):
        """Collection is read-only. A plan holding nothing but a collection has
        contained nothing and must not imply otherwise."""
        plan, _ = plan_from(
            "Capture the host.",
            [
                {
                    "action_type": "collect_forensics",
                    "target": "WKSTN-042",
                    "rationale": "Image it.",
                    "priority": 5,
                }
            ],
        )
        assert "No containment action is included." in plan.proposes

    def test_it_is_written_to_the_audit_chain(self):
        _, runtime = plan_from("Contain the account.", [ticket()])
        proposed = [
            entry
            for entry in runtime.chain.entries()
            if entry.action is AuditAction.RESPONSE_PROPOSED and "proposes" in entry.payload
        ]
        assert proposed
        assert "No containment action is included." in proposed[-1].payload["proposes"]


class TestTheModelsOwnWordsAreNeverEdited:
    @pytest.mark.parametrize(
        "strategy",
        [
            "Contain the account and the host together.",
            "Do not isolate the file server. Open a ticket and collect forensics.",
            "Isolate the host manually via the EDR console; Bishop cannot name the target.",
            "This appears to be an isolated incident; open a ticket and monitor.",
            "The activity sits early in the kill chain. Open a ticket and keep watching.",
            "The container image is the artefact of interest; record and monitor.",
            "A terminated employee's account. Open a ticket for HR.",
        ],
    )
    def test_the_strategy_survives_verbatim(self, strategy):
        """The first three are the ones that matter. A rule that replaced prose
        it read as an unsupported claim deleted a safety instruction, a
        recommendation to act by hand, and four ordinary sentences whose only
        crime was containing the letters of a containment word."""
        plan, _ = plan_from(strategy, [ticket()])
        assert plan.strategy == strategy

    def test_nothing_is_refused_for_writing_prose(self):
        _, runtime = plan_from("Do not isolate the file server. Open a ticket.", [ticket()])
        assert not [
            entry for entry in runtime.chain.entries() if entry.action is AuditAction.ACTION_REFUSED
        ]

    def test_no_phrase_can_switch_the_check_off(self):
        """The lexical version was disabled by `no action` appearing anywhere.
        The computed sentence has no such switch: it is not reading prose."""
        plan, _ = plan_from(
            "Contain the account and the host together. No action on the DMZ hosts.",
            [ticket()],
        )
        assert "No containment action is included." in plan.proposes
        assert plan.strategy.startswith("Contain the account")


class TestTheSameActionTwiceIsOneActionWithBothReasons:
    def duplicate_isolation(self):
        return plan_from(
            "Contain the host.",
            [
                isolation(rationale="Persistence was observed here.", priority=40),
                isolation(
                    target="wkstn-042",
                    rationale="A binary is impersonating a system component.",
                    priority=10,
                ),
            ],
        )

    def test_it_appears_once(self):
        plan, _ = self.duplicate_isolation()
        assert len(plan.actions) == 1

    def test_both_reasons_survive(self):
        """The rationale is the whole basis on which containment is approved.
        Dropping the second proposal dropped one of two independent reasons."""
        plan, _ = self.duplicate_isolation()
        assert "Persistence was observed here." in plan.actions[0].rationale
        assert "A binary is impersonating a system component." in plan.actions[0].rationale

    def test_the_more_urgent_priority_wins(self):
        plan, _ = self.duplicate_isolation()
        assert plan.actions[0].priority == 10

    def test_an_identical_rationale_is_not_repeated(self):
        plan, _ = plan_from("Contain the host.", [isolation(), isolation()])
        assert plan.actions[0].rationale == "Stop it."

    def test_the_merge_is_recorded(self):
        _, runtime = self.duplicate_isolation()
        merges = [
            entry
            for entry in runtime.chain.entries()
            if entry.payload.get("kind") == "duplicate_action_merged"
        ]
        assert merges, "the chain has to show what the model actually proposed"

    def test_the_same_action_on_a_different_target_is_kept(self):
        plan, _ = plan_from(
            "Contain both hosts.",
            [isolation(rationale="One."), isolation(target="SRV-FILE-09", rationale="Two.")],
        )
        assert len(plan.actions) == 2


def run_plan(item, prefix: str):
    run_id = f"{prefix}-{item.alert_id}"
    runtime = build_runtime(run_id=run_id, provider=None)
    result = build_graph().invoke(
        initial_state(run_id=run_id, alerts=[item.alert], incident_id="INC-COH"),
        config=runtime_config(runtime),
    )
    return result.get("verdict"), result["response_plan"], runtime


class TestEveryCorpusPlanIsCoherent:
    """The regression that keeps this fixed as detectors are added.

    A new detector routed to no containment branch produces exactly the defect
    this file exists for: a confirmed true positive whose plan promises
    containment and opens a ticket.
    """

    @pytest.mark.parametrize("item", load_corpus(), ids=lambda item: item.alert_id)
    def test_the_computed_sentence_matches_the_actions(self, item):
        _, plan, _ = run_plan(item, "coh")
        contains = [a for a in plan.actions if a.action_type not in _RECORD_ONLY]
        says_none = "No containment action is included." in plan.proposes
        assert says_none == (not contains and bool(plan.actions)), (
            f"{item.alert_id}: proposes={plan.proposes!r} against "
            f"{len(contains)} containment actions"
        )

    @pytest.mark.parametrize("item", load_corpus(), ids=lambda item: item.alert_id)
    def test_every_action_is_named_in_the_computed_sentence(self, item):
        _, plan, _ = run_plan(item, "named")
        for action in plan.actions:
            assert str(action.action_type).replace("_", " ") in plan.proposes

    @pytest.mark.parametrize("item", load_corpus(), ids=lambda item: item.alert_id)
    def test_every_true_positive_proposes_some_containment(self, item):
        """A confirmed intrusion whose whole plan is a ticket is a coverage gap
        in the planner, not a considered decision."""
        verdict, plan, _ = run_plan(item, "con")
        if verdict is None or verdict.label is not VerdictLabel.TRUE_POSITIVE:
            pytest.skip("containment is proposed only for a confirmed true positive")
        contains = [a for a in plan.actions if a.action_type not in _RECORD_ONLY]
        assert contains, f"{item.alert_id} is a true positive whose plan only keeps records"

    def test_the_readme_number_of_irreversible_plans_is_current(self):
        """The README says 17 of the 20 confirmed true positives propose at
        least one irreversible action. It was true when written and nothing
        pinned it, which is how the badge got to 1050 while 1355 passed."""
        readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
        confirmed = irreversible = 0
        for item in load_corpus():
            verdict, plan, _ = run_plan(item, "irr")
            if verdict is None or verdict.label is not VerdictLabel.TRUE_POSITIVE:
                continue
            confirmed += 1
            irreversible += any(action.is_irreversible for action in plan.actions)
        assert f"**{irreversible} of the {confirmed} confirmed true positives" in readme, (
            f"the README claim does not match the corpus: {irreversible} of {confirmed}"
        )

    @pytest.mark.parametrize("item", load_corpus(), ids=lambda item: item.alert_id)
    def test_the_mock_proposes_no_duplicate_action(self, item):
        """The merge path is a backstop for a model that repeats itself, not
        something Bishop's own default planner should be leaning on."""
        _, _, runtime = run_plan(item, "dup")
        merges = [
            entry
            for entry in runtime.chain.entries()
            if entry.payload.get("kind") == "duplicate_action_merged"
        ]
        assert not merges, f"{item.alert_id}: the mock proposed the same action twice"


class TestActionsBishopWillNotPerformAreNotProposed:
    """Refused at proposal time, not only at the executor.

    With the check only downstream, a run's chain read: proposed `kill_process`
    → approval requested → human approved → refused, "Bishop does not propose
    process-scoped containment". The refusal was contradicted by three earlier
    entries in its own run, and `proposes` — the sentence that is supposed to be
    the one claim that cannot disagree with the buttons — named an action that
    was never going to be performed.
    """

    def unsupported(self, action_type: str = "kill_process", target: str = "rundll32.exe"):
        return plan_from(
            "Stop it.",
            [
                {
                    "action_type": action_type,
                    "target": target,
                    "rationale": "stop it",
                    "priority": 10,
                },
                ticket(),
            ],
        )

    def test_the_action_never_reaches_the_plan(self):
        plan, _ = self.unsupported()
        assert [str(a.action_type) for a in plan.actions] == ["open_ticket"]

    def test_the_computed_sentence_does_not_name_it(self):
        plan, _ = self.unsupported()
        assert "kill process" not in plan.proposes
        assert "No containment action is included." in plan.proposes

    def test_the_refusal_is_recorded_with_its_reason(self):
        _, runtime = self.unsupported()
        refusals = [
            entry
            for entry in runtime.chain.entries()
            if entry.payload.get("kind") == "unsupported_action_not_proposed"
        ]
        assert refusals
        assert "process-scoped containment" in refusals[0].payload["detail"]

    def test_the_rest_of_the_plan_survives(self):
        """One refused proposal must not discard the others."""
        plan, _ = self.unsupported()
        assert len(plan.actions) == 1

    def test_quarantine_file_is_refused_too(self):
        plan, _ = self.unsupported("quarantine_file", "C:/Users/Public/x.dmp")
        assert [str(a.action_type) for a in plan.actions] == ["open_ticket"]


class TestThePlanCannotDriftFromItsSentence:
    def test_the_plan_is_frozen(self):
        """`proposes` is derived at construction. A mutable plan could be edited
        afterwards and leave the two disagreeing, which is the whole failure."""
        plan, _ = plan_from("Contain the host.", [isolation()])
        with pytest.raises(ValidationError):
            plan.proposes = "something else entirely"

    def test_the_actions_are_not_a_list_that_can_be_appended_to(self):
        plan, _ = plan_from("Contain the host.", [isolation()])
        assert isinstance(plan.actions, tuple)

    def test_a_rehydrated_plan_recomputes_its_sentence(self):
        """A row written before this field existed, or a payload carrying a
        different sentence, must not reach a gate with either."""
        plan, _ = plan_from("Contain the host.", [isolation(), ticket()])
        raw = plan.model_dump(mode="json")

        raw["proposes"] = "This plan proposes: nothing at all."
        assert ResponsePlan.model_validate(raw).proposes == plan.proposes

        del raw["proposes"]
        assert ResponsePlan.model_validate(raw).proposes == plan.proposes
