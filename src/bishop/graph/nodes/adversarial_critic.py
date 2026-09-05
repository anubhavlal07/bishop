"""The adversarial critic — one bounded pass at proving the verdict wrong.

The failure mode this exists for: a chain of agents that each accept the
previous one's framing and arrive, fluently and unanimously, at a wrong answer.
Nothing upstream of here is incentivised to look for the boring explanation.

Two design choices worth stating:

**Bounded.** `Settings.max_critic_rounds` caps the loop. An unbounded
critic-revise cycle is a way to spend an unbounded amount of money arriving at
the same verdict, and in a triage tool latency is a real cost.

**It can only lower confidence, never raise it.** A critic that could talk a
verdict *up* would be a second synthesis step with fewer inputs. Its counter-
arguments ship in the report either way — an analyst who disagrees with the
verdict gets the strongest case against it in the same document.
"""

from __future__ import annotations

from typing import Any, Optional

from langchain_core.runnables import RunnableConfig

from bishop.audit import AuditAction
from bishop.graph.nodes.synthesis import _all_results
from bishop.graph.prompts import CRITIC_SCHEMA, build_critic_prompt
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.models import ModelError
from bishop.schema import RunCost, Verdict, VerdictLabel


def adversarial_critic(
    state: BishopState, config: Optional[RunnableConfig] = None
) -> dict[str, Any]:
    runtime = get_runtime(config)
    verdict: Verdict | None = state.get("verdict")
    if verdict is None:
        return {"critic_rounds": state.get("critic_rounds", 0) + 1}

    reports = state.get("reports") or []
    results = _all_results(reports)

    context = {
        "incident_id": state.get("incident_id"),
        "entity_key_quoted": f"«{state.get('entity_key')}»",
        "detectors_fired": sum(1 for r in results if r.fired),
    }
    system, prompt = build_critic_prompt(
        verdict=verdict,
        all_results=results,
        quarantine_block=state.get("quarantine_block", ""),
        context=context,
    )

    cost = RunCost()
    errors: list[str] = []
    arguments: list[str] = []
    adjustment = 0.0
    should_escalate = False

    try:
        response = runtime.provider.complete(
            system=system,
            prompt=prompt,
            task="critique",
            schema=CRITIC_SCHEMA,
            max_tokens=runtime.settings.max_tokens,
        )
        data = response.data or {}
        arguments = [str(a) for a in (data.get("counter_arguments") or [])]
        adjustment = float(data.get("confidence_adjustment") or 0.0)
        should_escalate = bool(data.get("should_escalate"))
        cost = RunCost(
            model_calls=1,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            usd=response.cost_usd,
        )
        runtime.chain.append(
            "adversarial_critic",
            AuditAction.MODEL_CALLED,
            {
                "task": "critique",
                "model": response.model,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "usd": response.cost_usd,
            },
        )
    except ModelError as exc:
        errors.append(f"critic: {exc}")
        arguments = [
            f"The adversarial pass did not run ({exc}). This verdict has not been "
            f"challenged, and should be read as less settled than its confidence suggests."
        ]
        adjustment = -0.1

    adjustment = min(0.0, adjustment)
    revised = round(max(0.0, min(1.0, verdict.confidence + adjustment)), 3)

    label = verdict.label
    escalation_reason = verdict.escalation_reason

    #: How far the critic must move confidence for its own escalation flag to
    #: be treated as supported by its analysis rather than as a reflex.
    MATERIAL_DOUBT = 0.1

    if should_escalate and label is VerdictLabel.TRUE_POSITIVE:
        if -adjustment >= MATERIAL_DOUBT or revised < runtime.settings.escalation_threshold:
            label = VerdictLabel.ESCALATE
            escalation_reason = (
                "the adversarial pass found an ordinary explanation that the evidence "
                "does not rule out"
            )
        else:
            # The flag contradicts the critic's own numbers: it asked for
            # escalation while leaving confidence essentially untouched. Seen
            # against a live model on TP-01, where the critic wrote "the verdict
            # easily survives adversarial critique", named a red-team hypothesis
            # it then dismissed, moved confidence to 0.98 — and still set the
            # flag. Honouring that escalates every true positive, because a
            # competent critic can always name *some* alternative; a tool that
            # escalates everything has perfect recall and is useless.
            #
            # Same rule as the grounding checks in synthesis: a model assertion
            # that its own measurements do not support does not decide a verdict.
            # The counter-arguments are still recorded and still shown — only the
            # unsupported label change is refused.
            runtime.chain.append(
                "adversarial_critic",
                AuditAction.ACTION_REFUSED,
                {
                    "kind": "unsupported_escalation_refused",
                    "detail": (
                        f"the critic asked to escalate but moved confidence by only "
                        f"{adjustment:+.2f}, leaving {revised:.2f} — above the "
                        f"{runtime.settings.escalation_threshold:.2f} threshold. Its own "
                        f"analysis does not support the flag."
                    ),
                },
            )
    elif revised < runtime.settings.escalation_threshold and label in {
        VerdictLabel.TRUE_POSITIVE,
        VerdictLabel.BENIGN_TRUE_POSITIVE,
    }:
        label = VerdictLabel.ESCALATE
        escalation_reason = (
            f"the adversarial pass reduced confidence to {revised:.2f}, below the "
            f"{runtime.settings.escalation_threshold:.2f} threshold"
        )

    updated = verdict.model_copy(
        update={
            "confidence": revised,
            "label": label,
            "counter_arguments": arguments,
            "escalation_reason": escalation_reason,
        }
    )

    runtime.chain.append(
        "adversarial_critic",
        AuditAction.CRITIQUE_APPLIED,
        {
            "counter_arguments": arguments,
            "confidence_before": verdict.confidence,
            "confidence_after": revised,
            "label_before": str(verdict.label),
            "label_after": str(label),
        },
    )
    runtime.emit(
        "critique",
        arguments=len(arguments),
        confidence_before=verdict.confidence,
        confidence_after=revised,
    )

    return {
        "verdict": updated,
        "critique": arguments,
        "critic_rounds": state.get("critic_rounds", 0) + 1,
        "cost": cost,
        "errors": errors,
    }
