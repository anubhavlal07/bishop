"""The deterministic model. Bishop's default, not a test double.

`just demo`, the whole test suite, and the eval harness all run against this. It
takes no key, makes no network call, and returns the same bytes for the same
input on any machine.

**How it can produce a real verdict without a model.** Bishop's hard rule is
that detection is deterministic and the model only interprets and narrates. The
prompt therefore already contains every signal the verdict rests on, in a
machine-readable `<detector-results>` block. This provider parses that block and
composes the same structured output a real model would be asked for — the
weighing is arithmetic over detector scores rather than reasoning, and the prose
is assembled from the detectors' own rationales.

So the offline demo is not a puppet show. The verdict is real, the evidence is
real, and the numbers are checkable. What is missing is the model's judgement:
the narrative reads like a report generator, correlation across signals is
crude, and it will not notice the thing nobody wrote a detector for. That gap
is exactly what the live provider is for, and `docs/ARCHITECTURE.md` says so.
"""

from __future__ import annotations

import json
import re
from typing import Any

from bishop.models.base import ModelResponse, Usage

#: Nodes embed detector output here. Trusted data — it is Bishop's own, not the
#: alert's — so unlike the quarantine block it is parsed rather than fenced.
DETECTOR_BLOCK = re.compile(r"<detector-results>\s*(.*?)\s*</detector-results>", re.DOTALL)
INJECTION_BLOCK = re.compile(r"<injection-findings>\s*(.*?)\s*</injection-findings>", re.DOTALL)
CONTEXT_BLOCK = re.compile(r"<incident-context>\s*(.*?)\s*</incident-context>", re.DOTALL)


def _parse_block(pattern: re.Pattern[str], prompt: str) -> Any:
    match = pattern.search(prompt)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def _fired(results: list[dict], *, mitigating: bool = False) -> list[dict]:
    """Detectors that fired, strongest first.

    `mitigating` selects which side of the argument to return. Mixing the two
    would let an authorising change record add to a suspicion score, which is
    exactly backwards.
    """
    return sorted(
        (r for r in results if r.get("fired") and bool(r.get("mitigating")) is mitigating),
        key=lambda r: float(r.get("score") or 0.0),
        reverse=True,
    )


#: Nothing Bishop reports is certain, so nothing it reports reads as certain.
#: Four strong detectors combine to 0.9996 under a probabilistic OR, which
#: renders as "1.00 confidence" and is a claim no evidence supports.
MAX_CONFIDENCE = 0.95


def _combine(scores: list[float]) -> float:
    """Probabilistic OR — the same combiner the quarantine scorer uses."""
    remaining = 1.0
    for score in scores:
        remaining *= 1.0 - max(0.0, min(1.0, score))
    return round(min(MAX_CONFIDENCE, 1.0 - remaining), 4)


def _sentence(text: str) -> str:
    text = text.strip()
    if not text:
        return ""
    return text[0].upper() + text[1:] + ("" if text.endswith((".", "!", "?")) else ".")


class MockModel:
    """A deterministic stand-in that composes structured output from detectors."""

    name = "mock"
    model_id = "mock"

    def __init__(self, *, model_id: str = "mock") -> None:
        self.model_id = model_id
        self.calls: list[tuple[str, int]] = []

    # ── provider interface ──────────────────────────────────────────────────

    def complete(
        self,
        *,
        system: str,
        prompt: str,
        task: str,
        schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
    ) -> ModelResponse:
        detectors = _parse_block(DETECTOR_BLOCK, prompt) or []
        injections = _parse_block(INJECTION_BLOCK, prompt) or []
        context = _parse_block(CONTEXT_BLOCK, prompt) or {}

        handler = {
            "investigate": self._investigate,
            "synthesise": self._synthesise,
            "critique": self._critique,
            "plan_response": self._plan_response,
        }.get(task)
        data = (
            handler(detectors, injections, context) if handler else {"note": f"no mock for {task}"}
        )

        text = json.dumps(data, indent=2, sort_keys=False)
        # Token counts are approximate but real measurements of the actual
        # payload — a quarter of a character each, the usual English rule of
        # thumb. Cost is genuinely zero because no request was made.
        usage = Usage(
            input_tokens=(len(system) + len(prompt)) // 4,
            output_tokens=len(text) // 4,
        )
        self.calls.append((task, usage.input_tokens))
        return ModelResponse(text=text, data=data, usage=usage, model=self.model_id)

    # ── per-task composition ────────────────────────────────────────────────

    def _investigate(self, detectors: list[dict], injections: list[dict], context: dict) -> dict:
        # Both sides of the argument. A mitigating detector that fired is a
        # finding — it is the only way an authorising change record reaches
        # synthesis, because evidence is what travels between nodes.
        fired = _fired(detectors) + _fired(detectors, mitigating=True)
        surface = context.get("surface", "unknown")
        findings = [
            {
                "title": self._title_for(result),
                "detail": _sentence(str(result.get("rationale", ""))),
                "confidence": round(min(0.95, float(result.get("score") or 0.0)), 3),
                "detector": result.get("detector"),
                "technique_ids": list(result.get("technique_hints") or []),
            }
            for result in fired
        ]

        for injection in injections:
            findings.append(
                {
                    "title": f"Prompt-injection attempt in {injection.get('field')}",
                    "detail": (
                        "A field in this alert contains text shaped like an instruction to an "
                        "automated analyst. It was fenced as data and is reported as an "
                        "indicator; it did not influence this investigation."
                    ),
                    "confidence": round(float(injection.get("score") or 0.5), 3),
                    "detector": "quarantine.injection_scan",
                    "technique_ids": [],
                }
            )

        if not findings:
            examined = [r.get("detector") for r in detectors]
            summary = (
                f"No {surface} signal fired. {len(examined)} detectors ran and none found "
                f"anything above threshold."
            )
        else:
            leaders = ", ".join(str(f["detector"]) for f in findings[:3])
            summary = (
                f"{len(findings)} {surface} finding{'s' if len(findings) != 1 else ''}, "
                f"led by {leaders}."
            )
            if surface == "context":
                summary = (
                    f"{len(findings)} piece(s) of exculpatory context: {leaders}. "
                    f"These argue against malice and come from environment policy."
                )

        return {"summary": summary, "findings": findings}

    def _synthesise(self, detectors: list[dict], injections: list[dict], context: dict) -> dict:
        fired = _fired(detectors)
        mitigations = _fired(detectors, mitigating=True)
        scores = [float(r.get("score") or 0.0) for r in fired]
        combined = _combine(scores)

        techniques: list[str] = []
        for result in fired:
            for hint in result.get("technique_hints") or []:
                if hint not in techniques:
                    techniques.append(hint)

        # An injection attempt is an aggravating factor, never a mitigating one:
        # somebody targeting the SOC's tooling is not a false positive.
        if injections:
            combined = _combine([combined, 0.5])

        label, escalate_reason = self._label_for(combined, fired, mitigations, injections, context)

        stages = [
            {
                "order": index + 1,
                "tactic": "",
                "technique_id": (result.get("technique_hints") or [""])[0],
                "technique_name": "",
                "summary": _sentence(str(result.get("rationale", ""))),
                "detector": result.get("detector"),
            }
            for index, result in enumerate(fired)
            if result.get("technique_hints")
        ]

        if fired:
            narrative = " ".join(_sentence(str(r.get("rationale", ""))) for r in fired[:4])
        else:
            narrative = ""

        rationale = self._rationale_for(label, fired, mitigations, injections, combined)

        return {
            "label": label,
            "confidence": round(self._confidence_for(label, combined, mitigations, injections), 3),
            "rationale": rationale,
            "narrative": narrative,
            "technique_ids": techniques,
            "stages": stages,
            "assessed_severity": self._severity_for(combined, fired),
            "escalation_reason": escalate_reason,
        }

    def _critique(self, detectors: list[dict], injections: list[dict], context: dict) -> dict:
        """The adversarial pass: what would make this verdict wrong."""
        fired = _fired(detectors)
        arguments: list[str] = []

        weak = [r for r in fired if float(r.get("score") or 0) < 0.45]
        for result in weak:
            arguments.append(
                f"{result.get('detector')} fired at {float(result.get('score') or 0):.2f}, which is "
                f"low enough that ordinary administrative activity would produce it."
            )

        for result in fired:
            detector = str(result.get("detector"))
            facts = result.get("facts") or {}
            if detector == "impossible_travel" and facts.get("likely_vpn_or_proxy"):
                arguments.append(
                    "The two logins are minutes apart, which fits a VPN egress change far "
                    "better than travel. Check whether the user's client reconnected."
                )
            if detector == "beaconing":
                arguments.append(
                    f"Regular check-ins to {facts.get('destination')} are also what update "
                    f"agents, telemetry and monitoring do. Confirm the destination is not "
                    f"a sanctioned service before treating the rhythm as C2."
                )
            if detector == "lolbin_abuse" and not facts.get("with_argument_tells"):
                arguments.append(
                    "The living-off-the-land binary carried no suspicious arguments. On its "
                    "own that is background noise on any Windows estate."
                )
            if detector == "data_staging":
                arguments.append(
                    "Archive creation is what backup software does. Check whether the "
                    "process is a scheduled backup job before reading this as staging."
                )
            if detector == "persistence":
                arguments.append(
                    "Software installers write Run keys and services legitimately. Confirm "
                    "the binary being persisted is not part of a sanctioned deployment."
                )

        if not fired:
            arguments.append(
                "No deterministic detector fired. Any verdict here rests on the sensor's "
                "own rule firing, which is not evidence Bishop has verified."
            )

        grounded = len([r for r in fired if float(r.get("score") or 0) >= 0.6])
        return {
            "counter_arguments": arguments[:6],
            "should_escalate": grounded == 0 and bool(fired),
            "confidence_adjustment": -0.1 if len(weak) > len(fired) / 2 else 0.0,
        }

    def _plan_response(self, detectors: list[dict], injections: list[dict], context: dict) -> dict:
        fired = _fired(detectors)
        label = str(context.get("verdict_label", ""))
        host = context.get("host") or "the affected host"
        user = context.get("user") or "the affected account"

        if label != "true_positive":
            return {
                "strategy": (
                    "No containment proposed. The verdict is not a true positive, and "
                    "containment on a false positive costs more than the alert did."
                ),
                "actions": [],
                "no_action_rationale": (
                    f"Verdict is {label or 'undetermined'}. Bishop proposes monitoring and "
                    f"a record, not disruption."
                ),
            }

        detectors_fired = {str(r.get("detector")) for r in fired}
        actions: list[dict] = []

        if detectors_fired & {"credential_dumping", "persistence", "encoded_command"}:
            actions.append(
                {
                    "action_type": "isolate_host",
                    "target": str(host),
                    "rationale": (
                        "Credential access or persistence was observed on this host. "
                        "Isolation stops lateral movement while the memory image is taken."
                    ),
                    "priority": 10,
                    "rollback": "Remove the network isolation policy from the EDR console.",
                }
            )
            actions.append(
                {
                    "action_type": "collect_forensics",
                    "target": str(host),
                    "rationale": "Capture volatile memory before isolation drops the sessions.",
                    "priority": 5,
                    "rollback": "None needed; collection is read-only.",
                }
            )
        if detectors_fired & {
            "credential_dumping",
            "impossible_travel",
            "password_spray",
            "mfa_fatigue",
        }:
            actions.append(
                {
                    "action_type": "revoke_sessions",
                    "target": str(user),
                    "rationale": (
                        "Credentials for this account should be treated as known to the "
                        "adversary. Revoking sessions invalidates stolen tokens."
                    ),
                    "priority": 20,
                    "rollback": "The user signs in again; no administrative action needed.",
                }
            )
            actions.append(
                {
                    "action_type": "force_password_reset",
                    "target": str(user),
                    "rationale": "Rotate the credential the adversary is presumed to hold.",
                    "priority": 30,
                    "rollback": "Cannot be undone; the user must set a new password.",
                }
            )
        if detectors_fired & {"beaconing", "dns_exfiltration", "ioc_reputation", "outbound_volume"}:
            actions.append(
                {
                    "action_type": "block_domain",
                    "target": str(context.get("c2_indicator") or "the observed destination"),
                    "rationale": "Cut the command-and-control channel at the egress proxy.",
                    "priority": 25,
                    "rollback": "Remove the block-list entry.",
                }
            )

        actions.append(
            {
                "action_type": "open_ticket",
                "target": str(context.get("incident_id") or "incident"),
                "rationale": "Record the incident and the decisions taken against it.",
                "priority": 90,
                "rollback": "Close the ticket.",
            }
        )

        return {
            "strategy": (
                "Contain the account and the host together. Credential theft that is "
                "answered by isolating the host alone leaves the adversary holding a "
                "working token, and answering it by resetting the password alone leaves "
                "them on the endpoint."
            ),
            "actions": actions,
            "no_action_rationale": None,
        }

    # ── helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _title_for(result: dict) -> str:
        detector = str(result.get("detector", "signal"))
        return detector.replace("_", " ").replace(".", " ").strip().capitalize()

    @staticmethod
    def _label_for(
        combined: float,
        fired: list[dict],
        mitigations: list[dict],
        injections: list[dict],
        context: dict,
    ) -> tuple[str, str | None]:
        """Choose a label from suspicion, mitigation, and injection findings.

        The two mitigating detectors support different labels on purpose.
        `authorised_activity` means the technique really was used by someone
        entitled to use it — a benign true positive, which is a paperwork
        answer. `routine_software` means the rule's premise was wrong — a false
        positive, which is a tuning answer. Collapsing them would throw away the
        distinction the label exists to make.
        """
        by_detector = {str(m.get("detector")): m for m in mitigations}
        authorised = "authorised_activity" in by_detector
        mitigation_strength = _combine([float(m.get("score") or 0.0) for m in mitigations])

        # Which suspicious findings have an innocent account of them.
        explained: set[str] = set()
        for mitigation in mitigations:
            explained.update((mitigation.get("facts") or {}).get("explains") or [])
        suspicious = {str(r.get("detector")) for r in fired}
        all_explained = bool(suspicious) and suspicious <= explained

        # An injection attempt is never excused by context. Someone writing
        # instructions into a log field is not doing authorised work.
        if injections:
            if combined >= 0.7:
                return "true_positive", None
            return (
                "escalate",
                (
                    "A field in this alert carried text aimed at steering the triage. That "
                    "is an indicator in its own right and needs a human, whatever the rest "
                    "of the evidence says."
                ),
            )

        if not fired:
            return "false_positive", None

        # Authorisation is checked before the routine explanation, because when
        # both apply the authorised reading carries more information: it names
        # the party who approved the activity, which a "the rule is noisy"
        # answer does not. An approved change window that also happens to look
        # like ordinary software is still a change somebody signed off.
        #
        # `combined >= 0.5` is what keeps a noisy rule out of this branch: a
        # backup job tripping a weak archive heuristic is a mis-tuned rule, not
        # an authorised intrusion, and calling it a benign true positive would
        # tell the detection engineer their rule is fine when it is not.
        if authorised and mitigation_strength >= 0.5 and combined >= 0.5:
            return "benign_true_positive", None

        # Every suspicious signal has a specific innocent explanation from
        # environment policy, and nobody had to authorise it. The rule fired on
        # ordinary activity: a tuning problem, not a paperwork one.
        if all_explained:
            return "false_positive", None

        if combined >= 0.7:
            return "true_positive", None
        if combined >= 0.45:
            return (
                "escalate",
                (
                    f"Combined detector confidence is {combined:.2f}, which is not enough to "
                    f"stand behind a verdict. A human should look at this rather than have "
                    f"Bishop guess."
                ),
            )
        return "false_positive", None

    @staticmethod
    def _confidence_for(
        label: str, combined: float, mitigations: list[dict], injections: list[dict]
    ) -> float:
        """Confidence in the label that was assigned, not in "something is wrong".

        These are different numbers and conflating them produced a real bug: a
        clean backup job would be labelled benign-true-positive and then given
        the *suspicion* score, 0.35, which is below the escalation threshold —
        so the graph escalated an alert it had correctly explained.
        """
        mitigation_strength = _combine([float(m.get("score") or 0.0) for m in mitigations])
        if label == "true_positive":
            return combined
        if label == "benign_true_positive":
            # How sure we are of the authorisation, not of the malice.
            return mitigation_strength
        if label == "false_positive":
            if mitigations:
                return max(mitigation_strength, 1.0 - combined)
            # Nothing fired at all. That is a confident negative.
            return round(min(MAX_CONFIDENCE, 1.0 - combined), 4)
        # escalate: the confidence is precisely what was not enough.
        return combined

    @staticmethod
    def _severity_for(combined: float, fired: list[dict]) -> str:
        detectors = {str(r.get("detector")) for r in fired}
        if combined >= 0.85 and detectors & {"credential_dumping", "dns_exfiltration"}:
            return "critical"
        if combined >= 0.7:
            return "high"
        if combined >= 0.45:
            return "medium"
        if combined > 0:
            return "low"
        return "informational"

    @staticmethod
    def _rationale_for(
        label: str,
        fired: list[dict],
        mitigations: list[dict],
        injections: list[dict],
        combined: float,
    ) -> str:
        if not fired and not injections:
            base = (
                "No deterministic detector fired against this alert. The sensor's own rule "
                "triggered, but nothing Bishop can verify independently supports it."
            )
            if mitigations:
                base += f" {mitigations[0].get('rationale')}"
            return base
        parts = [
            f"{len(fired)} deterministic detector{'s' if len(fired) != 1 else ''} fired, "
            f"combining to {combined:.2f} suspicion."
        ]
        if fired:
            parts.append(
                f"The strongest is {fired[0].get('detector')}: {fired[0].get('rationale')}."
            )
        if injections:
            fields = ", ".join(str(i.get("field")) for i in injections[:2])
            parts.append(
                f"Separately, {len(injections)} field(s) ({fields}) carried text aimed at "
                f"steering this triage. That raises the priority of the alert rather than "
                f"lowering it."
            )
        if mitigations:
            parts.append(
                f"Against that, {mitigations[0].get('rationale')} That comes from environment "
                f"policy rather than from the alert, so it is not something an attacker could "
                f"have written."
            )
        if label == "benign_true_positive":
            parts.append(
                "The detection is correct and the activity is authorised. This is a benign "
                "true positive rather than a false positive: the rule is working and should "
                "not be tuned away."
            )
        if label == "escalate":
            parts.append("Confidence is too low to stand behind a label, so this goes to a human.")
        return " ".join(parts)
