"""The scorecard.

`CLAUDE.md` §3: *no accuracy claim without a scorecard run.* Every number that
appears in the README, a docstring or a post comes from here, produced by
`just eval` on the committed golden set. Numbers from memory are fabrication.

The metrics are chosen to be the ones a security person actually asks for, in
the order they ask for them:

**False-negative rate on true positives** comes first, not accuracy. A triage
tool that is 95% accurate by calling everything a false positive is worthless,
and overall accuracy hides that. This is the number that says how much real
intrusion the tool missed.

**Escalation precision and recall** measure the abstention, which is the part
most tools do not have. Precision: when Bishop handed something to a human, was
that the right call? Recall: of the cases it should have escalated, how many did
it? A tool that escalates everything has perfect recall and is useless.

**Injection catch rate** is reported separately from verdict accuracy, because
they measure different things. An injection-laced alert has both a correct
verdict *and* a correct handling of the payload, and Bishop can get one right
while getting the other wrong.

Latency and cost are measured, not modelled. On the mock provider the cost is
genuinely zero and the scorecard says so rather than quoting a number nobody
paid.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bishop.eval.corpus import LabelledAlert, load_corpus
from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
from bishop.models import ModelProvider
from bishop.schema import EvidenceKind, VerdictLabel

RESULTS_DIR = Path(__file__).resolve().parents[3] / "eval" / "results"
BASELINE_PATH = RESULTS_DIR / "baseline.json"

#: A human tier-1 analyst on a alert like these. Used only as a stated point of
#: comparison, and labelled as an assumption rather than a measurement.
HUMAN_BASELINE_SECONDS = 20 * 60


@dataclass(slots=True)
class AlertOutcome:
    alert_id: str
    expected: str
    actual: str
    correct: bool
    confidence: float
    #: True when the label is wrong in the direction that matters most.
    missed_true_positive: bool
    escalated: bool
    should_escalate: bool
    techniques_expected: list[str] = field(default_factory=list)
    techniques_reported: list[str] = field(default_factory=list)
    invalid_techniques: list[str] = field(default_factory=list)
    injection_expected: bool = False
    injection_caught: bool = False
    injection_escalated_as_ioc: bool = False
    duration_ms: int = 0
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Scorecard:
    generated_at: str
    provider: str
    model: str
    attack_version: str
    corpus_size: int
    corpus_is_synthetic: bool
    #: Which set this was run on. "golden" is the tuned development corpus;
    #: "holdout" is the set written after the thresholds were fixed and run
    #: once. The two numbers mean different things and are never averaged.
    corpus_name: str = "golden"

    verdict_accuracy: float = 0.0
    false_negative_rate: float = 0.0
    false_positive_rate: float = 0.0
    escalation_precision: float = 0.0
    escalation_recall: float = 0.0
    benign_tp_accuracy: float = 0.0

    injection_caught: int = 0
    injection_total: int = 0
    injection_escalated_as_ioc: int = 0

    invalid_techniques_emitted: int = 0
    technique_recall: float = 0.0

    median_triage_ms: int = 0
    p95_triage_ms: int = 0
    total_usd: float = 0.0
    usd_per_alert: float = 0.0
    total_model_calls: int = 0

    outcomes: list[AlertOutcome] = field(default_factory=list)
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _run_one(item: LabelledAlert, *, provider: ModelProvider | None, index: int) -> AlertOutcome:
    from bishop.attck import validate_techniques

    run_id = f"eval-{item.alert_id}"
    runtime = build_runtime(run_id=run_id, provider=provider)
    graph = build_graph()
    config = runtime_config(runtime)
    state = initial_state(run_id=run_id, alerts=[item.alert], incident_id=f"EVAL-{index:03d}")

    started = time.perf_counter()
    result = graph.invoke(state, config=config)

    # The gate suspends the run. For evaluation, reject: the scorecard measures
    # triage quality, and approving containment on every alert to make the graph
    # finish would be a strange thing to bake into a benchmark.
    if result.get("__interrupt__"):
        from langgraph.types import Command

        result = graph.invoke(
            Command(
                resume={
                    "decision": "rejected",
                    "decided_by": "eval-harness",
                    "note": "eval does not approve containment",
                }
            ),
            config=config,
        )
    duration_ms = int((time.perf_counter() - started) * 1000)

    verdict = result.get("verdict")
    actual = str(verdict.label) if verdict else "none"
    reported = list(verdict.technique_ids) if verdict else []

    # Everything in the verdict should already be valid; check anyway, because
    # this is the number the README claims.
    invalid = [r.proposed for r in validate_techniques(reported).rejected]

    injections = [
        e
        for report in (result.get("reports") or [])
        for e in report.evidence
        if e.kind is EvidenceKind.INJECTION
    ] + list(result.get("quarantine_evidence") or [])

    cost = result.get("cost")
    return AlertOutcome(
        alert_id=item.alert_id,
        expected=item.expected_verdict,
        actual=actual,
        correct=actual == item.expected_verdict,
        confidence=verdict.confidence if verdict else 0.0,
        missed_true_positive=(
            item.expected_verdict == "true_positive"
            and actual in {"false_positive", "benign_true_positive"}
        ),
        escalated=actual == str(VerdictLabel.ESCALATE),
        should_escalate=item.should_escalate or item.expected_verdict == "escalate",
        techniques_expected=list(item.expected_techniques),
        techniques_reported=reported,
        invalid_techniques=invalid,
        injection_expected=item.is_injection_case,
        injection_caught=bool(injections),
        injection_escalated_as_ioc=any(e.is_grounded for e in injections),
        duration_ms=duration_ms,
        model_calls=cost.model_calls if cost else 0,
        input_tokens=cost.input_tokens if cost else 0,
        output_tokens=cost.output_tokens if cost else 0,
        usd=cost.usd if cost else 0.0,
        errors=list(result.get("errors") or []),
    )


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def run_scorecard(
    *,
    provider: ModelProvider | None = None,
    corpus_dir: Path | None = None,
    corpus_name: str = "golden",
) -> Scorecard:
    from bishop.attck import load_catalogue

    corpus = load_corpus(corpus_dir)
    outcomes = [_run_one(item, provider=provider, index=i) for i, item in enumerate(corpus)]

    catalogue = load_catalogue()
    provider_name = getattr(provider, "name", None) or "mock"
    model_id = getattr(provider, "model_id", None) or "mock"

    card = Scorecard(
        generated_at=datetime.now(UTC).isoformat(),
        provider=provider_name,
        model=model_id,
        attack_version=catalogue.attack_version,
        corpus_size=len(corpus),
        corpus_is_synthetic=all(item.synthetic for item in corpus),
        corpus_name=corpus_name,
        outcomes=outcomes,
    )

    card.verdict_accuracy = _rate(sum(1 for o in outcomes if o.correct), len(outcomes))

    true_positives = [o for o in outcomes if o.expected == "true_positive"]
    card.false_negative_rate = _rate(
        sum(1 for o in true_positives if o.missed_true_positive), len(true_positives)
    )

    false_positives = [o for o in outcomes if o.expected == "false_positive"]
    card.false_positive_rate = _rate(
        sum(1 for o in false_positives if o.actual == "true_positive"), len(false_positives)
    )

    benign = [o for o in outcomes if o.expected == "benign_true_positive"]
    card.benign_tp_accuracy = _rate(sum(1 for o in benign if o.correct), len(benign))

    escalated = [o for o in outcomes if o.escalated]
    should = [o for o in outcomes if o.should_escalate]
    card.escalation_precision = _rate(
        sum(1 for o in escalated if o.should_escalate), len(escalated)
    )
    card.escalation_recall = _rate(sum(1 for o in should if o.escalated), len(should))

    injection_cases = [o for o in outcomes if o.injection_expected]
    card.injection_total = len(injection_cases)
    card.injection_caught = sum(1 for o in injection_cases if o.injection_caught)
    card.injection_escalated_as_ioc = sum(
        1 for o in injection_cases if o.injection_escalated_as_ioc
    )

    card.invalid_techniques_emitted = sum(len(o.invalid_techniques) for o in outcomes)
    expected_total = sum(len(o.techniques_expected) for o in outcomes)
    found_total = sum(
        len(set(o.techniques_expected) & set(o.techniques_reported)) for o in outcomes
    )
    card.technique_recall = _rate(found_total, expected_total)

    durations = sorted(o.duration_ms for o in outcomes)
    card.median_triage_ms = int(statistics.median(durations)) if durations else 0
    card.p95_triage_ms = durations[int(len(durations) * 0.95) - 1] if durations else 0

    card.total_usd = round(sum(o.usd for o in outcomes), 6)
    card.usd_per_alert = round(card.total_usd / len(outcomes), 6) if outcomes else 0.0
    card.total_model_calls = sum(o.model_calls for o in outcomes)

    labels = ["true_positive", "false_positive", "benign_true_positive", "escalate", "none"]
    card.confusion = {
        expected: {
            actual: sum(1 for o in outcomes if o.expected == expected and o.actual == actual)
            for actual in labels
        }
        for expected in labels[:-1]
    }

    card.notes = _notes(card)
    return card


def _notes(card: Scorecard) -> list[str]:
    """What the numbers do not say. Written into the scorecard, not around it."""
    notes = []
    if card.corpus_is_synthetic:
        notes.append(
            "The corpus is synthetic. These numbers show the system behaves as designed on "
            "cases whose ground truth is known by construction; they do not show it works "
            "on real-world noise, because the corpus contains none."
        )
    if card.provider == "mock":
        notes.append(
            "Run against the deterministic mock provider, so cost is genuinely $0.00 and "
            "latency measures Bishop's own code rather than a model round trip. Verdicts "
            "come from arithmetic over detector scores — see src/bishop/models/mock.py."
        )
    if card.corpus_size < 50:
        notes.append(
            f"{card.corpus_size} alerts is a smoke test, not a benchmark. One alert moving "
            f"changes accuracy by {100 / card.corpus_size:.0f} points."
        )
    if card.corpus_name == "holdout":
        notes.append(
            "This is the held-out set. It was written after the fusion thresholds were "
            "fixed, nothing here was used to tune anything, and it is run separately from "
            "`just eval` so it cannot leak into the loop by habit. Read this number, not "
            "the golden-set one, when asking whether Bishop generalises."
        )
        notes.append(
            "Several cases here describe techniques Bishop has no detector for — "
            "Kerberoasting, cloud token theft. The correct behaviour on those is to "
            "escalate, so a low accuracy driven by escalations is a different and much "
            "less serious result than one driven by missed true positives. Read the "
            "false-negative rate and the confusion matrix, not the headline."
        )
        notes.append(
            "If a case here gets fixed, it stops being held out — debugging against it "
            "converts it into a development case. The honest move is to move it into "
            "fixtures/alerts/ and write a fresh held-out case, not to keep the label and "
            "the credit."
        )
    elif card.verdict_accuracy >= 1.0:
        notes.append(
            f"{card.verdict_accuracy:.0%} accuracy on {card.corpus_size} alerts is not a "
            "generalisation claim and should not be read as one. This corpus was written "
            "first and the fusion thresholds were then tuned against it, so it measures "
            "internal consistency — the detectors, the mitigating-context rules and the "
            "label definitions agreeing with each other. The held-out set in "
            "fixtures/holdout/ is the number that speaks to unseen data; run it with "
            "`just eval-holdout`."
        )
    if card.technique_recall < 1.0:
        notes.append(
            f"Technique recall is {card.technique_recall:.0%}: some techniques a labelled "
            f"alert should surface are not produced by any detector. That gap is real and "
            f"docs/COVERAGE.md shows exactly where it is."
        )
    if card.invalid_techniques_emitted:
        notes.append(
            f"{card.invalid_techniques_emitted} invalid technique IDs reached a verdict. "
            f"That is a bug — validation should make this impossible."
        )
    return notes


def render_text(card: Scorecard) -> str:
    """The terminal scorecard, for `just eval`."""
    lines: list[str] = []
    add = lines.append

    add("")
    add(
        "  BISHOP SCORECARD — HELD-OUT SET"
        if card.corpus_name == "holdout"
        else "  BISHOP SCORECARD"
    )
    add(
        f"  {card.corpus_size} labelled alerts · provider {card.provider} ({card.model}) · ATT&CK v{card.attack_version}"
    )
    add(f"  generated {card.generated_at}")
    add("")
    add("  DETECTION")
    add(f"    verdict accuracy              {card.verdict_accuracy:>7.1%}")
    add(
        f"    false-negative rate (on TPs)  {card.false_negative_rate:>7.1%}   <- the number that matters"
    )
    add(f"    false-positive rate (on FPs)  {card.false_positive_rate:>7.1%}")
    add(f"    benign-TP accuracy            {card.benign_tp_accuracy:>7.1%}")
    add("")
    add("  ABSTENTION")
    add(f"    escalation precision          {card.escalation_precision:>7.1%}")
    add(f"    escalation recall             {card.escalation_recall:>7.1%}")
    add("")
    add("  INJECTION CORPUS")
    add(f"    caught                        {card.injection_caught:>4} / {card.injection_total}")
    add(
        f"    escalated as an IOC           {card.injection_escalated_as_ioc:>4} / {card.injection_total}"
    )
    add("")
    add("  ATT&CK")
    add(f"    technique recall              {card.technique_recall:>7.1%}")
    add(f"    invalid IDs emitted           {card.invalid_techniques_emitted:>4}")
    add("")
    add("  COST AND LATENCY")
    add(f"    median time to triage         {card.median_triage_ms / 1000:>7.2f} s")
    add(f"    p95 time to triage            {card.p95_triage_ms / 1000:>7.2f} s")
    add(f"    cost per alert                ${card.usd_per_alert:>10.6f}")
    add(f"    model calls                   {card.total_model_calls:>4}")
    add("")

    wrong = [o for o in card.outcomes if not o.correct]
    if wrong:
        add(f"  MISCLASSIFIED ({len(wrong)})")
        for outcome in wrong:
            flag = "  <- MISSED TRUE POSITIVE" if outcome.missed_true_positive else ""
            add(
                f"    {outcome.alert_id:32} expected {outcome.expected:20} got {outcome.actual}{flag}"
            )
        add("")

    if card.notes:
        add("  READ THIS BEFORE QUOTING ANY NUMBER ABOVE")
        for note in card.notes:
            for line in _wrap(note, 76):
                add(f"    {line}")
            add("")

    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    out: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            out.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        out.append(current)
    return out


def save(card: Scorecard, path: Path | None = None) -> Path:
    target = path or (RESULTS_DIR / f"scorecard-{card.generated_at[:10]}.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(card.to_dict(), indent=2) + "\n", encoding="utf-8")
    return target


def load_baseline(path: Path | None = None) -> dict[str, Any] | None:
    target = path or BASELINE_PATH
    if not target.exists():
        return None
    return json.loads(target.read_text(encoding="utf-8"))


#: Metrics where a drop is a regression, and metrics where a rise is.
_HIGHER_IS_BETTER = (
    "verdict_accuracy",
    "escalation_precision",
    "escalation_recall",
    "benign_tp_accuracy",
    "technique_recall",
)
_LOWER_IS_BETTER = ("false_negative_rate", "false_positive_rate", "invalid_techniques_emitted")


def diff_against_baseline(card: Scorecard, baseline: dict[str, Any]) -> list[str]:
    """Regressions against the committed baseline. Empty means no regression."""
    regressions: list[str] = []
    for metric in _HIGHER_IS_BETTER:
        before = float(baseline.get(metric, 0.0))
        after = float(getattr(card, metric))
        if after < before - 1e-9:
            regressions.append(f"{metric}: {before:.1%} -> {after:.1%}")
    for metric in _LOWER_IS_BETTER:
        before = float(baseline.get(metric, 0.0))
        after = float(getattr(card, metric))
        if after > before + 1e-9:
            regressions.append(f"{metric}: {before} -> {after}")
    if card.injection_caught < int(baseline.get("injection_caught", 0)):
        regressions.append(
            f"injection_caught: {baseline.get('injection_caught')} -> {card.injection_caught}"
        )
    return regressions
