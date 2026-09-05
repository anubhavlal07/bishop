"""Synthesis — fuse the investigator reports into one verdict.

Three things happen here that do not happen anywhere else, and each is a hard
rule from `CLAUDE.md` §3 made executable:

**Technique validation.** The model proposes technique IDs; they are checked
against the ATT&CK bundle; anything not in it is rejected and the model is
re-prompted once with the rejections named. A rejected ID never reaches the
report with a caveat attached — it does not reach the report at all.

**Grounding.** A verdict of `true_positive` requires at least one deterministic
detector to have fired. The model cannot talk its way to a malicious verdict on
an alert where nothing was measured.

**Abstention.** Below the escalation threshold, Bishop returns `escalate` rather
than a label. That is not the model declining — it is the graph overruling a
confident-sounding answer that the evidence does not support.
"""

from __future__ import annotations

from typing import Any, Optional

from langchain_core.runnables import RunnableConfig

from bishop.attck import atlas_for_signals, load_catalogue, validate_techniques
from bishop.audit import AuditAction
from bishop.graph.prompts import SYNTHESIS_SCHEMA, build_synthesis_prompt
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.models import ModelError
from bishop.schema import (
    AttackStage,
    DetectorResult,
    Evidence,
    InvestigatorReport,
    RunCost,
    Severity,
    Verdict,
    VerdictLabel,
)


def _all_results(reports: list[InvestigatorReport]) -> list[DetectorResult]:
    seen: dict[str, DetectorResult] = {}
    for report in reports:
        for evidence in report.evidence:
            for signal in evidence.signals:
                seen.setdefault(signal.detector, signal)
    return list(seen.values())


def _fired_detectors(reports: list[InvestigatorReport]) -> list[DetectorResult]:
    return [r for r in _all_results(reports) if r.fired]


def synthesis(state: BishopState, config: Optional[RunnableConfig] = None) -> dict[str, Any]:
    runtime = get_runtime(config)
    reports = state.get("reports") or []
    injections: list[Evidence] = state.get("quarantine_evidence") or []
    catalogue = load_catalogue()

    results = _all_results(reports)
    fired = [r for r in results if r.fired]

    context: dict[str, Any] = {
        "incident_id": state.get("incident_id"),
        "entity_key": state.get("entity_key"),
        "investigators_run": [r.investigator for r in reports],
        "detectors_fired": len(fired),
        "injection_attempts": len(injections),
        "attack_version": catalogue.attack_version,
    }

    system, prompt = build_synthesis_prompt(
        reports=reports,
        all_results=results,
        quarantine_block=state.get("quarantine_block", ""),
        injection_evidence=injections,
        context=context,
    )

    cost = RunCost()
    errors: list[str] = []
    data: dict[str, Any] = {}

    try:
        response = runtime.provider.complete(
            system=system,
            prompt=prompt,
            task="synthesise",
            schema=SYNTHESIS_SCHEMA,
            max_tokens=runtime.settings.max_tokens,
        )
        data = response.data or {}
        cost = RunCost(
            model_calls=1,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            usd=response.cost_usd,
        )
        runtime.chain.append(
            "synthesis",
            AuditAction.MODEL_CALLED,
            {
                "task": "synthesise",
                "model": response.model,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "usd": response.cost_usd,
            },
        )

        # ── technique validation, with one re-prompt ────────────────────────
        proposed = [str(t) for t in (data.get("technique_ids") or [])]
        validation = validate_techniques(proposed)

        if validation.rejected:
            for rejection in validation.rejected:
                runtime.chain.append(
                    "synthesis",
                    AuditAction.TECHNIQUE_REJECTED,
                    {
                        "proposed": rejection.proposed,
                        "reason": rejection.reason,
                        "detail": rejection.detail,
                        "attack_version": catalogue.attack_version,
                    },
                )
            runtime.emit(
                "techniques_rejected",
                rejected=[r.proposed for r in validation.rejected],
            )

            retry_prompt = prompt + "\n\n" + _rejection_notice(validation)
            retry = runtime.provider.complete(
                system=system,
                prompt=retry_prompt,
                task="synthesise",
                schema=SYNTHESIS_SCHEMA,
                max_tokens=runtime.settings.max_tokens,
            )
            retry_data = retry.data or {}
            cost = RunCost(
                model_calls=cost.model_calls + 1,
                input_tokens=cost.input_tokens + retry.usage.input_tokens,
                output_tokens=cost.output_tokens + retry.usage.output_tokens,
                usd=round(cost.usd + retry.cost_usd, 8),
            )
            second = validate_techniques([str(t) for t in (retry_data.get("technique_ids") or [])])
            # Whatever survives the second pass is what ships. Nothing that
            # failed validation is carried through with a caveat.
            data = retry_data or data
            validation = second

    except ModelError as exc:
        errors.append(f"synthesis: {exc}")
        runtime.chain.append("synthesis", AuditAction.RUN_FAILED, {"error": str(exc)})
        # Fall back to the deterministic core rather than producing nothing.
        validation = validate_techniques([hint for r in fired for hint in r.technique_hints])
        data = {
            "label": "escalate",
            "confidence": 0.0,
            "rationale": (
                f"The synthesis model call failed ({exc}). {len(fired)} detectors fired and "
                f"their results stand, but Bishop will not assert a verdict it could not "
                f"reason about."
            ),
            "escalation_reason": "synthesis model call failed",
        }

    for technique in validation.accepted:
        runtime.chain.append(
            "synthesis",
            AuditAction.TECHNIQUE_VALIDATED,
            {
                "technique_id": technique.id,
                "name": technique.name,
                "tactics": list(technique.tactics),
            },
        )

    verdict = _build_verdict(
        data=data,
        validation=validation,
        fired=fired,
        injections=injections,
        threshold=runtime.settings.escalation_threshold,
        catalogue=catalogue,
    )

    runtime.chain.append(
        "synthesis",
        AuditAction.VERDICT_REACHED,
        {
            "label": str(verdict.label),
            "confidence": verdict.confidence,
            "assessed_severity": str(verdict.assessed_severity),
            "technique_ids": verdict.technique_ids,
            "detectors_fired": [r.detector for r in fired],
            "escalation_reason": verdict.escalation_reason,
        },
    )
    runtime.emit(
        "verdict",
        label=str(verdict.label),
        confidence=verdict.confidence,
        techniques=verdict.technique_ids,
    )

    return {"verdict": verdict, "cost": cost, "errors": errors, "audit_head": runtime.chain.head}


def _rejection_notice(validation) -> str:
    lines = [
        "<validation-failure>",
        "The following technique IDs you proposed are not in the ATT&CK bundle and have "
        "been rejected. Return the full object again, using only technique IDs you are "
        "certain exist. Do not restate a rejected ID with a caveat — omit it.",
    ]
    lines += [f"- {r.proposed}: {r.detail}" for r in validation.rejected]
    lines.append("</validation-failure>")
    return "\n".join(lines)


def _build_verdict(
    *,
    data: dict[str, Any],
    validation,
    fired: list[DetectorResult],
    injections: list[Evidence],
    threshold: float,
    catalogue,
) -> Verdict:
    raw_label = str(data.get("label") or "escalate")
    try:
        label = VerdictLabel(raw_label)
    except ValueError:
        label = VerdictLabel.ESCALATE

    confidence = float(data.get("confidence") or 0.0)
    escalation_reason = data.get("escalation_reason")

    # Grounding: a malicious verdict needs a measurement behind it. An injection
    # attempt counts — it is a deterministic finding from the quarantine scan.
    if label is VerdictLabel.TRUE_POSITIVE and not fired and not injections:
        label = VerdictLabel.ESCALATE
        escalation_reason = (
            "the model proposed a true positive, but no deterministic detector fired. "
            "Bishop does not assert malice on a model's reading alone."
        )
        confidence = min(confidence, threshold)

    # Abstention: below the threshold Bishop declines rather than guesses.
    if (
        label in {VerdictLabel.TRUE_POSITIVE, VerdictLabel.BENIGN_TRUE_POSITIVE}
        and confidence < threshold
    ):
        escalation_reason = escalation_reason or (
            f"confidence {confidence:.2f} is below the {threshold:.2f} threshold Bishop "
            f"requires before standing behind a verdict"
        )
        label = VerdictLabel.ESCALATE

    severity_raw = str(data.get("assessed_severity") or "medium")
    try:
        severity = Severity(severity_raw)
    except ValueError:
        severity = Severity.MEDIUM

    stages: list[AttackStage] = []
    accepted_ids = {t.id for t in validation.accepted}
    for index, stage in enumerate(data.get("stages") or [], start=1):
        technique_id = str(stage.get("technique_id") or "")
        if technique_id not in accepted_ids:
            continue  # a stage citing an unvalidated technique does not render
        technique = catalogue.get(technique_id)
        stages.append(
            AttackStage(
                order=int(stage.get("order") or index),
                tactic=str(
                    stage.get("tactic")
                    or (technique.tactic_names[0] if technique and technique.tactic_names else "")
                ),
                technique_id=technique_id,
                technique_name=technique.name
                if technique
                else str(stage.get("technique_name") or ""),
                summary=str(stage.get("summary") or ""),
                evidence_ids=[],
            )
        )

    return Verdict(
        label=label,
        confidence=round(max(0.0, min(1.0, confidence)), 3),
        rationale=str(data.get("rationale") or ""),
        narrative=str(data.get("narrative") or ""),
        stages=stages,
        technique_ids=validation.ids,
        assessed_severity=severity,
        counter_arguments=[],
        escalation_reason=escalation_reason,
    )


def atlas_techniques_for(injections: list[Evidence]) -> list[str]:
    """ATLAS IDs for the injection findings, kept out of the ATT&CK list.

    Reported separately in the incident so an ATLAS ID can never be rendered as
    though it were an ATT&CK technique.
    """
    signals: list[str] = []
    for evidence in injections:
        for signal in evidence.signals:
            signals.extend(signal.facts.get("techniques") or [])
    return [t.id for t in atlas_for_signals(signals)]
