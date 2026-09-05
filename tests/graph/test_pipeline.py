"""End-to-end graph behaviour.

The tests that matter most here are the ones about what Bishop *refuses* to do:
assert a verdict nothing measured, carry a technique ID that does not exist, or
let an injection-laced alert come back clean because no detector fired on it.
"""

from __future__ import annotations

from bishop.audit import AuditAction
from bishop.graph import build_runtime, initial_state, runtime_config
from bishop.graph.nodes.investigators import _ground
from bishop.graph.nodes.report import build_incident
from bishop.graph.nodes.synthesis import _accusatory_examination
from bishop.graph.runtime import Settings
from bishop.schema import DetectorResult, EvidenceKind, VerdictLabel
from tests.graph.conftest import (
    credential_theft_alert,
    injection_only_alert,
    quiet_alert,
    uncovered_alert,
)


class TestHappyPath:
    def test_a_true_positive_produces_a_grounded_verdict(self, run):
        graph, state, config, runtime = run(credential_theft_alert())
        result = graph.invoke(state, config=config)
        verdict = result["verdict"]

        assert verdict.label is VerdictLabel.TRUE_POSITIVE
        assert 0 < verdict.confidence <= 0.95
        assert verdict.technique_ids
        assert verdict.rationale

    def test_confidence_never_reads_as_certain(self, run):
        graph, state, config, runtime = run(credential_theft_alert())
        result = graph.invoke(state, config=config)
        assert result["verdict"].confidence < 1.0

    def test_every_technique_in_the_verdict_is_real(self, run):
        from bishop.attck import load_catalogue

        catalogue = load_catalogue()
        graph, state, config, runtime = run(credential_theft_alert())
        result = graph.invoke(state, config=config)
        for technique_id in result["verdict"].technique_ids:
            assert technique_id in catalogue, f"{technique_id} is not in the ATT&CK bundle"

    def test_investigators_run_in_parallel_and_all_report(self, run):
        graph, state, config, runtime = run(credential_theft_alert())
        result = graph.invoke(state, config=config)
        names = {r.investigator for r in result["reports"]}
        assert "endpoint_investigator" in names
        assert len(names) == len(result["dispatch"])

    def test_the_audit_chain_covers_the_whole_run_and_verifies(self, run):
        graph, state, config, runtime = run(credential_theft_alert())
        graph.invoke(state, config=config)
        runtime.chain.verify()
        actions = {str(e.action) for e in runtime.chain}
        assert {
            "run_started",
            "alert_ingested",
            "quarantine_applied",
            "investigator_dispatched",
            "detector_ran",
            "evidence_recorded",
            "verdict_reached",
            "response_proposed",
            "approval_requested",
        } <= actions

    def test_cost_is_measured_not_estimated(self, run):
        graph, state, config, runtime = run(credential_theft_alert())
        result = graph.invoke(state, config=config)
        cost = result["cost"]
        assert cost.model_calls >= 3
        assert cost.input_tokens > 0
        assert cost.usd == 0.0


class TestQuietAlert:
    def test_nothing_fired_means_no_true_positive(self, run):
        graph, state, config, runtime = run(quiet_alert())
        result = graph.invoke(state, config=config)
        assert result["verdict"].label is not VerdictLabel.TRUE_POSITIVE

    def test_no_containment_is_proposed(self, run):
        graph, state, config, runtime = run(quiet_alert())
        result = graph.invoke(state, config=config)
        assert not result["response_plan"].actions
        assert result["response_plan"].no_action_rationale


class TestInjectionOnlyAlert:
    """An alert whose only notable feature is a payload in a field.

    No detector fires on it. If quarantine evidence travelled with the
    investigator reports it would arrive empty and this alert would come back
    clean — which is the failure this whole design exists to prevent.
    """

    def test_the_injection_is_caught_even_though_no_detector_fires(self, run):
        graph, state, config, runtime = run(injection_only_alert())
        result = graph.invoke(state, config=config)

        assert result["quarantine_evidence"], "the payload was not raised as evidence"
        fired = [
            signal
            for report in result["reports"]
            for evidence in report.evidence
            for signal in evidence.signals
            if signal.fired
        ]
        assert fired == [], "no ordinary detector should have fired on this alert"

    def test_the_finding_reaches_the_incident(self, run):
        graph, state, config, runtime = run(injection_only_alert())
        result = graph.invoke(state, config=config)
        incident = build_incident(result)

        injections = [e for e in incident.all_evidence if e.kind is EvidenceKind.INJECTION]
        assert injections, "the injection finding did not reach the incident"
        assert injections[0].is_grounded

    def test_the_payload_is_preserved_verbatim(self, run):
        graph, state, config, runtime = run(injection_only_alert())
        result = graph.invoke(state, config=config)
        raw = result["quarantine_evidence"][0].facts["raw_value"]
        assert "ignore all previous instructions" in raw

    def test_the_attempt_is_audited(self, run):
        graph, state, config, runtime = run(injection_only_alert())
        graph.invoke(state, config=config)
        detected = runtime.chain.by_action(AuditAction.INJECTION_DETECTED)
        assert len(detected) == 1
        assert detected[0].payload["field"] == "process.command_line"

    def test_the_verdict_is_not_benign(self, run):
        """The payload asked to be marked benign. It must not have worked."""
        graph, state, config, runtime = run(injection_only_alert())
        result = graph.invoke(state, config=config)
        verdict = result["verdict"]
        assert verdict.label is not VerdictLabel.FALSE_POSITIVE
        assert "no further action is required" not in verdict.rationale.lower()

    def test_an_injection_escalates_an_otherwise_identical_alert(self, run):
        """The payload is the only difference, and it changes the outcome.

        Asserted on the label rather than on `confidence`, because confidence is
        confidence *in the assigned label* — a confident false positive and a
        hesitant escalation are not on the same scale and comparing their
        numbers would mean nothing.
        """
        clean = run(quiet_alert(), run_id="r1")
        laced = run(injection_only_alert(), run_id="r2")
        clean_result = clean[0].invoke(clean[1], config=clean[2])
        laced_result = laced[0].invoke(laced[1], config=laced[2])

        assert clean_result["verdict"].label is VerdictLabel.FALSE_POSITIVE
        assert laced_result["verdict"].label is VerdictLabel.ESCALATE
        assert laced_result["verdict"].escalation_reason


class TestGrounding:
    """A model may not introduce a finding no detector produced."""

    def test_a_finding_citing_a_detector_that_did_not_fire_is_dropped(self):
        results = [DetectorResult(detector="beaconing", fired=False, score=0.0)]
        findings = [
            {"title": "C2 beacon", "detail": "invented", "confidence": 0.9, "detector": "beaconing"}
        ]
        evidence, dropped = _ground(findings, results, surface="network", alert_id="A-1")
        assert evidence == []
        assert len(dropped) == 1
        assert "did not fire" in dropped[0]

    def test_a_finding_citing_no_detector_is_dropped(self):
        evidence, dropped = _ground(
            [{"title": "x", "detail": "y"}], [], surface="endpoint", alert_id="A"
        )
        assert evidence == []
        assert dropped

    def test_a_grounded_finding_survives(self):
        results = [DetectorResult(detector="beaconing", fired=True, score=0.8, rationale="regular")]
        findings = [{"title": "Beacon", "detail": "d", "confidence": 0.7, "detector": "beaconing"}]
        evidence, dropped = _ground(findings, results, surface="network", alert_id="A-1")
        assert dropped == []
        assert len(evidence) == 1
        assert evidence[0].is_grounded

    def test_a_model_may_not_claim_more_confidence_than_the_detector(self):
        results = [DetectorResult(detector="beaconing", fired=True, score=0.4)]
        findings = [{"title": "x", "detail": "y", "confidence": 0.99, "detector": "beaconing"}]
        evidence, _ = _ground(findings, results, surface="network", alert_id="A-1")
        assert evidence[0].confidence <= 0.4

    def test_dropping_a_finding_is_audited(self, run):
        """A dropped finding is a model trying to invent a signal. Record it."""
        graph, state, config, runtime = run(quiet_alert())
        graph.invoke(state, config=config)
        refusals = [
            e
            for e in runtime.chain.by_action(AuditAction.ACTION_REFUSED)
            if e.payload.get("kind") == "ungrounded_finding_dropped"
        ]
        assert refusals == []


class TestClosingIsAlsoAClaim:
    """`false_positive` needs grounding too — the third direction.

    Bishop already refused to *accuse* without a detector, and refused to
    *clear as authorised* without a mitigating detector. Closing an alert as a
    false positive needed nothing at all, which meant an alert type Bishop has
    no coverage for came back "nothing wrong" rather than "I cannot see this".
    The held-out set found it; this is what keeps it found.
    """

    def test_an_alert_nothing_examined_is_escalated_not_closed(self, run):
        graph, state, config, runtime = run(uncovered_alert())
        result = graph.invoke(state, config=config)

        verdict = result["verdict"]
        assert verdict.label is VerdictLabel.ESCALATE
        assert "no detector had anything to work with" in (verdict.escalation_reason or "")

    def test_the_reason_blames_bishop_rather_than_the_alert(self, run):
        """Wording matters here. An analyst reading "no coverage" triages it
        themselves; one reading "nothing suspicious" does not look again."""
        graph, state, config, runtime = run(uncovered_alert())
        result = graph.invoke(state, config=config)
        reason = result["verdict"].escalation_reason or ""
        assert "gap in Bishop" in reason

    def test_an_examined_alert_can_still_be_closed(self, run):
        """The rule must not turn every false positive into an escalation."""
        graph, state, config, runtime = run(quiet_alert())
        result = graph.invoke(state, config=config)
        assert result["verdict"].label is VerdictLabel.FALSE_POSITIVE

    def test_a_cleared_detector_counts_as_examination(self, run):
        graph, state, config, runtime = run(quiet_alert())
        result = graph.invoke(state, config=config)
        examined = {name for report in result["reports"] for name in report.examined}
        assert examined, "a quiet alert should still have been looked at"

    def test_no_accusing_detector_examines_an_uncovered_alert(self, run):
        """Context is excluded deliberately.

        `authorised_activity` reaches a conclusion on any alert naming an
        account, but "nothing authorises this actor" argues towards suspicion,
        not away from it. Letting it count would make the rule fire almost
        never, which is the same as not having it.
        """
        graph, state, config, runtime = run(uncovered_alert())
        result = graph.invoke(state, config=config)

        assert _accusatory_examination(result["reports"]) == []
        context = [r for r in result["reports"] if r.investigator == "context_investigator"]
        assert context and context[0].examined, "context did look; it just cannot clear"


class TestEscalation:
    def test_a_high_threshold_forces_abstention(self, run):
        """Bishop declines rather than guessing when the bar is not met."""
        graph, state, config, runtime = run(
            credential_theft_alert(), settings=Settings(escalation_threshold=0.99)
        )
        result = graph.invoke(state, config=config)
        assert result["verdict"].label is VerdictLabel.ESCALATE
        assert result["verdict"].escalation_reason
        assert not result["response_plan"].actions

    def test_the_critic_runs_and_records_counter_arguments(self, run):
        graph, state, config, runtime = run(credential_theft_alert())
        result = graph.invoke(state, config=config)
        assert runtime.chain.by_action(AuditAction.CRITIQUE_APPLIED)
        assert result["verdict"].counter_arguments

    def test_the_critic_loop_is_bounded(self, run):
        graph, state, config, runtime = run(
            credential_theft_alert(), settings=Settings(max_critic_rounds=1)
        )
        result = graph.invoke(state, config=config)
        assert result["critic_rounds"] <= 1


class TestTheCriticMustBackItsOwnEscalation:
    """A critic that asks to escalate while leaving confidence untouched is
    contradicting itself, and an unsupported flag does not decide a verdict.

    Found against a live model, not the deterministic one: on TP-01 the critic
    wrote "the verdict easily survives adversarial critique", named a red-team
    hypothesis it then dismissed, left confidence at 0.98 — and still set
    `should_escalate`. Honouring that escalates every true positive, because a
    competent critic can always name some alternative, and a tool that
    escalates everything has perfect recall and is useless.
    """

    def critique(self, *, should_escalate, adjustment, base_confidence=0.95):
        """Drive `adversarial_critic` with one scripted critic response."""
        from bishop.graph.nodes.adversarial_critic import adversarial_critic
        from bishop.models.base import ModelResponse, Usage
        from bishop.schema import Verdict
        from tests.graph.conftest import credential_theft_alert

        class ScriptedCritic:
            name = "scripted"
            model_id = "scripted"

            def complete(self, **_):
                return ModelResponse(
                    text="",
                    data={
                        "counter_arguments": ["an authorised red team could explain this"],
                        "confidence_adjustment": adjustment,
                        "should_escalate": should_escalate,
                    },
                    usage=Usage(input_tokens=1, output_tokens=1),
                    model="scripted",
                    stop_reason="end_turn",
                )

        runtime = build_runtime(
            run_id="critic-coherence", provider=ScriptedCritic(), settings=Settings()
        )
        verdict = Verdict(
            label=VerdictLabel.TRUE_POSITIVE,
            confidence=base_confidence,
            rationale="detectors fired",
            assessed_severity="high",
        )
        state = initial_state(
            run_id="critic-coherence",
            alerts=[credential_theft_alert()],
            incident_id="INC-CC",
        )
        state["verdict"] = verdict
        result = adversarial_critic(state, runtime_config(runtime))
        return result["verdict"], runtime

    def test_an_unsupported_escalation_is_refused(self):
        verdict, _ = self.critique(should_escalate=True, adjustment=-0.02)
        assert verdict.label is VerdictLabel.TRUE_POSITIVE

    def test_a_supported_escalation_is_honoured(self):
        """Real doubt, expressed as a real confidence drop, still escalates."""
        verdict, _ = self.critique(should_escalate=True, adjustment=-0.3)
        assert verdict.label is VerdictLabel.ESCALATE
        assert "does not rule out" in (verdict.escalation_reason or "")

    def test_escalation_still_happens_when_confidence_falls_below_threshold(self):
        verdict, _ = self.critique(should_escalate=True, adjustment=-0.05, base_confidence=0.46)
        assert verdict.label is VerdictLabel.ESCALATE

    def test_the_counter_arguments_survive_a_refused_escalation(self):
        """The critique is still shown — only the label change is refused."""
        verdict, _ = self.critique(should_escalate=True, adjustment=-0.02)
        assert verdict.counter_arguments

    def test_the_refusal_is_audited(self):
        """A refused label change is a decision, and decisions go in the chain."""
        _, runtime = self.critique(should_escalate=True, adjustment=-0.02)
        refusals = [
            e
            for e in runtime.chain.by_action(AuditAction.ACTION_REFUSED)
            if e.payload.get("kind") == "unsupported_escalation_refused"
        ]
        assert refusals, "an unsupported escalation must be recorded, not silently dropped"
