"""The specialist investigators.

One node, parameterised by surface, fanned out with `Send`. Four investigators
rather than four prompts to one agent, because the surfaces have genuinely
disjoint inputs: the identity investigator reads `auth_events` and cannot see a
process tree; the endpoint investigator reads the process tree and cannot see a
login. They fail independently, they can be evaluated independently, and they
run in parallel inside one latency budget.

The order inside a node is always the same and it is the hard rule made
concrete: **detectors run first, then the model interprets what they found.**
The model never sees the alert without the detector output alongside it, and it
cannot introduce a finding that no detector produced — `_ground` drops any
finding whose cited detector did not fire.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from langchain_core.runnables import RunnableConfig

from bishop.audit import AuditAction
from bishop.detectors import run_surface
from bishop.graph.prompts import INVESTIGATOR_SCHEMA, build_investigator_prompt
from bishop.graph.runtime import get_runtime
from bishop.graph.state import InvestigatorTask
from bishop.models import ModelError
from bishop.schema import DetectorResult, Evidence, EvidenceKind, InvestigatorReport, RunCost


def _ground(
    findings: list[dict[str, Any]], results: list[DetectorResult], *, surface: str, alert_id: str
) -> tuple[list[Evidence], list[str]]:
    """Attach each reported finding to the detector it claims to rest on.

    A finding citing a detector that did not fire is dropped, not downgraded.
    This is the enforcement point for "no detection verdict originates solely
    from a model" — the model can phrase a finding, choose which to lead with,
    and correlate across signals, but it cannot bring one into existence.
    """
    fired = {r.detector: r for r in results if r.fired}
    evidence: list[Evidence] = []
    dropped: list[str] = []

    for index, finding in enumerate(findings, start=1):
        detector = str(finding.get("detector") or "")
        signal = fired.get(detector)
        if signal is None:
            dropped.append(f"{detector or '(unnamed)'}: cited by the model but did not fire")
            continue
        evidence.append(
            Evidence(
                evidence_id=f"{alert_id}-{surface}-{index}",
                producer=f"{surface}_investigator",
                kind=(EvidenceKind.MITIGATING if signal.mitigating else EvidenceKind.OBSERVATION),
                title=str(finding.get("title") or signal.detector),
                detail=str(finding.get("detail") or signal.rationale),
                # The model may not claim more confidence than the detector had.
                confidence=min(
                    float(finding.get("confidence") or signal.score), max(signal.score, 0.01)
                ),
                signals=[signal],
                technique_ids=[],  # validated later, in synthesis
                facts={
                    "detector_facts": signal.facts,
                    "proposed_techniques": finding.get("technique_ids") or [],
                },
            )
        )
    return evidence, dropped


def investigate(task: InvestigatorTask, config: Optional[RunnableConfig] = None) -> dict[str, Any]:
    """Run one surface. Invoked once per dispatched surface, in parallel."""
    runtime = get_runtime(config)
    surface = task["surface"]
    alerts = task["alerts"]
    alert_id = alerts[0].alert_id if alerts else "unknown"
    started = time.perf_counter()

    # 1. Deterministic detection. No model involved.
    results: list[DetectorResult] = []
    for alert in alerts:
        results.extend(run_surface(surface, alert))

    for result in results:
        runtime.chain.append(
            f"{surface}_investigator",
            AuditAction.DETECTOR_RAN,
            {
                "detector": result.detector,
                "fired": result.fired,
                "score": result.score,
                "rationale": result.rationale,
                "facts": result.facts,
            },
        )
    runtime.emit(
        "detectors_ran",
        surface=surface,
        total=len(results),
        fired=sum(1 for r in results if r.fired),
    )

    # 2. Interpretation. The model sees the detector output and the fenced alert.
    system, prompt = build_investigator_prompt(
        surface=surface,
        results=results,
        quarantine_block=task["quarantine_block"],
        injection_evidence=[],
        context={"incident_id": task["incident_id"], "alert_ids": [a.alert_id for a in alerts]},
    )

    cost = RunCost()
    errors: list[str] = []
    summary = ""
    findings: list[dict[str, Any]] = []

    try:
        response = runtime.provider.complete(
            system=system,
            prompt=prompt,
            task="investigate",
            schema=INVESTIGATOR_SCHEMA,
            max_tokens=runtime.settings.max_tokens,
        )
        data = response.data or {}
        summary = str(data.get("summary") or "")
        findings = list(data.get("findings") or [])
        cost = RunCost(
            model_calls=1,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            usd=response.cost_usd,
        )
        runtime.chain.append(
            f"{surface}_investigator",
            AuditAction.MODEL_CALLED,
            {
                "task": "investigate",
                "model": response.model,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "usd": response.cost_usd,
            },
        )
    except ModelError as exc:
        # The detectors already ran. A failed interpretation degrades the report
        # to its deterministic core rather than losing the surface entirely.
        errors.append(f"{surface}: {exc}")
        summary = (
            f"The {surface} model call failed ({exc}). The detector results below stand on "
            f"their own; only the narrative is missing."
        )
        findings = [
            {
                "title": r.detector,
                "detail": r.rationale,
                "confidence": r.score,
                "detector": r.detector,
            }
            for r in results
            if r.fired
        ]

    evidence, dropped = _ground(findings, results, surface=surface, alert_id=alert_id)

    for reason in dropped:
        runtime.chain.append(
            f"{surface}_investigator",
            AuditAction.ACTION_REFUSED,
            {"kind": "ungrounded_finding_dropped", "detail": reason},
        )
        errors.append(f"{surface}: dropped ungrounded finding — {reason}")

    for item in evidence:
        runtime.chain.append(
            f"{surface}_investigator",
            AuditAction.EVIDENCE_RECORDED,
            {
                "evidence_id": item.evidence_id,
                "title": item.title,
                "confidence": item.confidence,
                "grounded_on": [s.detector for s in item.signals],
            },
        )

    duration_ms = int((time.perf_counter() - started) * 1000)
    report = InvestigatorReport(
        investigator=f"{surface}_investigator",
        summary=summary,
        evidence=evidence,
        skipped=not results,
        skip_reason=None if results else f"no detectors registered for {surface}",
        duration_ms=duration_ms,
        tokens_used=cost.input_tokens + cost.output_tokens,
    )
    runtime.emit(
        "investigator_reported",
        surface=surface,
        findings=len(evidence),
        duration_ms=duration_ms,
    )

    return {
        "reports": [report],
        "cost": RunCost(**{**cost.model_dump(), "wall_ms": duration_ms}),
        "errors": errors,
    }
