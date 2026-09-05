"""Bishop's command line.

Deliberately stdlib-only — `argparse` and hand-rolled ANSI. The terminal report
is a deliverable (`just demo` is how most people will first see this run), and
it is not worth a dependency to draw a box.

Commands:
    bishop alerts              list the labelled corpus
    bishop run <alert-id>      triage one alert and print the incident report
    bishop demo                the showcase run, including the human gate
    bishop eval                the scorecard, against the golden set
    bishop coverage            regenerate docs/COVERAGE.md
    bishop verify <path>       verify a saved audit chain
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

# ── terminal formatting ─────────────────────────────────────────────────────

_COLOUR = (sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and os.name != "nt") or (
    sys.stdout.isatty() and os.environ.get("WT_SESSION") is not None
)


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOUR else text


def bold(text: str) -> str:
    return _c("1", text)


def dim(text: str) -> str:
    return _c("2", text)


def red(text: str) -> str:
    return _c("31", text)


def green(text: str) -> str:
    return _c("32", text)


def yellow(text: str) -> str:
    return _c("33", text)


def cyan(text: str) -> str:
    return _c("36", text)


VERDICT_STYLE = {
    "true_positive": red,
    "false_positive": green,
    "benign_true_positive": cyan,
    "escalate": yellow,
}


def rule(title: str = "", width: int = 78) -> str:
    if not title:
        return dim("─" * width)
    return dim("── ") + bold(title) + " " + dim("─" * max(0, width - len(title) - 4))


def wrap(text: str, width: int = 74, indent: str = "  ") -> list[str]:
    out: list[str] = []
    for paragraph in text.split("\n"):
        line = ""
        for word in paragraph.split():
            if len(line) + len(word) + 1 > width:
                out.append(indent + line)
                line = word
            else:
                line = f"{line} {word}".strip()
        out.append(indent + line)
    return out


# ── commands ────────────────────────────────────────────────────────────────


def cmd_alerts(args: argparse.Namespace) -> int:
    from bishop.eval import distribution, load_corpus

    corpus = load_corpus()
    print()
    print(rule(f"{len(corpus)} labelled alerts"))
    print()
    for item in corpus:
        style = VERDICT_STYLE.get(item.expected_verdict, dim)
        print(
            f"  {item.alert_id:34} {style(item.expected_verdict):>22}  {dim(item.alert.rule_name)}"
        )
    print()
    counts = ", ".join(f"{label} {count}" for label, count in distribution(corpus).items())
    print(dim(f"  {counts}"))
    print(dim("  All synthetic. See scripts/build_corpus.py for why."))
    print()
    return 0


def _load_alert(alert_id: str):
    from bishop.eval import load_corpus

    corpus = load_corpus()
    for item in corpus:
        if item.alert_id == alert_id or item.alert_id.startswith(alert_id):
            return item
    known = "\n".join(f"    {i.alert_id}" for i in corpus)
    raise SystemExit(f"no alert matching {alert_id!r}. Known alerts:\n{known}")


def _print_incident(incident, *, verbose: bool = False) -> None:
    verdict = incident.verdict
    print()
    print(rule("INCIDENT " + incident.incident_id))
    print()
    print(f"  {bold('Entity')}      {incident.entity_key}")
    for alert in incident.alerts:
        print(f"  {bold('Alert')}       {alert.alert_id}  {dim(alert.rule_name)}")
        print(
            f"  {bold('Source')}      {alert.source} · severity {alert.severity} · {alert.detected_at:%Y-%m-%d %H:%M UTC}"
        )
    print()

    if verdict is not None:
        style = VERDICT_STYLE.get(str(verdict.label), dim)
        print(rule("VERDICT"))
        print()
        print(
            f"  {style(bold(str(verdict.label).upper()))}   confidence {verdict.confidence:.2f} ({verdict.band})   severity {verdict.assessed_severity}"
        )
        print()
        for line in wrap(verdict.rationale):
            print(line)
        print()
        if verdict.escalation_reason:
            print(f"  {yellow('ESCALATED')}")
            for line in wrap(verdict.escalation_reason):
                print(line)
            print()
        if verdict.technique_ids:
            print(f"  {bold('ATT&CK')}      {', '.join(verdict.technique_ids)}")
            print()
        if verdict.narrative:
            print(rule("NARRATIVE"))
            print()
            for line in wrap(verdict.narrative):
                print(line)
            print()
        if verdict.counter_arguments:
            print(rule("WHAT WOULD MAKE THIS WRONG"))
            print()
            for argument in verdict.counter_arguments:
                for index, line in enumerate(wrap(argument, indent="    ")):
                    print(("  -" + line[3:]) if index == 0 else line)
            print()

    print(rule("EVIDENCE"))
    print()
    for report in incident.reports:
        marker = dim("(skipped)") if report.skipped else ""
        print(f"  {bold(report.investigator)} {marker}")
        if report.summary:
            for line in wrap(report.summary, indent="    "):
                print(dim(line))
        for evidence in report.evidence:
            tag = {
                "injection": red("[injection]"),
                "mitigating": green("[mitigating]"),
            }.get(str(evidence.kind), "")
            print(f"    · {evidence.title} {dim(f'({evidence.confidence:.2f})')} {tag}")
            if verbose:
                for line in wrap(evidence.detail, indent="        "):
                    print(dim(line))
                for signal in evidence.signals:
                    print(dim(f"        detector {signal.detector} score {signal.score}"))
        print()

    plan = incident.response_plan
    if plan is not None:
        print(rule("PROPOSED RESPONSE"))
        print()
        if plan.actions:
            for line in wrap(plan.strategy):
                print(line)
            print()
            for action in plan.actions:
                flag = red(" IRREVERSIBLE") if action.is_irreversible else ""
                print(f"  {bold(str(action.action_type))} → {action.target}{flag}")
                for line in wrap(action.rationale, indent="      "):
                    print(dim(line))
                for line in wrap("Blast radius: " + action.blast_radius.summary, indent="      "):
                    print(dim(line))
                if action.rollback:
                    for line in wrap("Rollback: " + action.rollback, indent="      "):
                        print(dim(line))
                print()
        else:
            for line in wrap(plan.no_action_rationale or plan.strategy):
                print(line)
            print()

    if incident.execution_log:
        print(rule("EXECUTION (mocked — no side effects)"))
        print()
        for record in incident.execution_log:
            status = record.get("status")
            mark = green("executed") if status == "simulated" else yellow("refused  ")
            detail = record.get("detail") or record.get("reason") or ""
            print(f"  {mark}  {record.get('action_type'):22} {dim(detail[:60])}")
        print()

    decision = incident.human_decision
    if decision is not None and decision.decided_by != "system":
        print(f"  {bold('Decision')}    {decision.decision} by {decision.decided_by}")
        if decision.note:
            print(dim(f"              {decision.note}"))
        print()

    cost = incident.cost
    if cost is not None:
        print(
            dim(
                f"  {cost.model_calls} model calls · {cost.input_tokens + cost.output_tokens} tokens · ${cost.usd:.6f}"
            )
        )
    if incident.audit_head:
        print(dim(f"  audit chain head {incident.audit_head[:32]}…"))
    print()


def _run_alerts(alerts, *, incident_id: str, approve: str | None, audit_path: Path | None):
    """Triage a correlated group. One incident, one audit chain, one verdict."""
    from langgraph.types import Command

    from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
    from bishop.graph.nodes.report import build_incident

    run_id = f"cli-{incident_id}"
    runtime = build_runtime(run_id=run_id, audit_path=audit_path)
    graph = build_graph()
    config = runtime_config(runtime)
    state = initial_state(run_id=run_id, alerts=list(alerts), incident_id=incident_id)

    result = graph.invoke(state, config=config)
    if result.get("__interrupt__"):
        request = result["__interrupt__"][0].value
        _print_gate(request)
        result = graph.invoke(
            Command(resume=_ask_for_decision(request, approve=approve)), config=config
        )
    return build_incident(result, audit_head=runtime.chain.head), runtime, result


def _run_alert(item, *, approve: str | None, verbose: bool, audit_path: Path | None):
    from langgraph.types import Command

    from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
    from bishop.graph.nodes.report import build_incident

    run_id = f"cli-{item.alert_id}"
    runtime = build_runtime(run_id=run_id, audit_path=audit_path)
    graph = build_graph()
    config = runtime_config(runtime)
    state = initial_state(run_id=run_id, alerts=[item.alert], incident_id=f"INC-{item.alert_id}")

    result = graph.invoke(state, config=config)

    if result.get("__interrupt__"):
        request = result["__interrupt__"][0].value
        _print_gate(request)
        answer = _ask_for_decision(request, approve=approve)
        result = graph.invoke(Command(resume=answer), config=config)

    incident = build_incident(result, audit_head=runtime.chain.head)
    return incident, runtime, result


def _print_gate(request: dict[str, Any]) -> None:
    print()
    print(rule("HUMAN APPROVAL REQUIRED"))
    print()
    for line in wrap(request.get("strategy", "")):
        print(line)
    print()
    for action in request["actions"]:
        flag = red(" IRREVERSIBLE") if action["irreversible"] else ""
        print(f"  {bold(action['action_type'])} → {action['target']}{flag}")
        for line in wrap(action["blast_radius"]["summary"], indent="      "):
            print(dim(line))
        print()


def _ask_for_decision(request: dict[str, Any], *, approve: str | None) -> dict[str, Any]:
    ids = [a["action_id"] for a in request["actions"]]
    if approve == "all":
        return {"decision": "approved", "approved_action_ids": ids, "decided_by": "cli --approve"}
    if approve == "none":
        return {"decision": "rejected", "decided_by": "cli --reject"}
    if approve == "reversible":
        keep = [a["action_id"] for a in request["actions"] if not a["irreversible"]]
        return {
            "decision": "modified",
            "approved_action_ids": keep,
            "decided_by": "cli --approve-reversible",
            "note": "irreversible actions held back",
        }

    if not sys.stdin.isatty():
        # Non-interactive and no flag: refuse. Defaulting to approve would be
        # exactly the autonomous containment this project exists not to do.
        print(yellow("  no decision supplied and stdin is not a terminal — rejecting"))
        return {"decision": "rejected", "decided_by": "cli (non-interactive default)"}

    print(
        dim("  [a]pprove all · [r]eject all · [s]ubset (reversible only) · anything else rejects")
    )
    try:
        answer = input("  decision> ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "r"
    who = os.environ.get("USER") or os.environ.get("USERNAME") or "analyst"
    if answer.startswith("a"):
        return {"decision": "approved", "approved_action_ids": ids, "decided_by": who}
    if answer.startswith("s"):
        keep = [a["action_id"] for a in request["actions"] if not a["irreversible"]]
        return {"decision": "modified", "approved_action_ids": keep, "decided_by": who}
    return {"decision": "rejected", "decided_by": who}


def cmd_history(args: argparse.Namespace) -> int:
    """Incidents that outlived the process that produced them."""
    from bishop.store import init_db, list_incidents, verify_stored_chain

    init_db()
    rows = list_incidents(limit=args.limit)
    print()
    print(rule(f"{len(rows)} stored incident{'s' if len(rows) != 1 else ''}"))
    print()
    if not rows:
        print(dim("  Nothing stored yet. `just run TP-01` writes one."))
        print()
        return 0
    for row in rows:
        style = VERDICT_STYLE.get(row["verdict"] or "", dim)
        intact, detail = verify_stored_chain(row["incident_id"])
        mark = green("chain ok") if intact else red("CHAIN BROKEN")
        print(f"  {row['incident_id']:34} {style(row['verdict'] or '-'):>22}  {mark}")
        print(dim(f"    {row['alert_count']} alert(s) · {row['created_at']} · {detail}"))
    print()
    return 0


def cmd_incidents(args: argparse.Namespace) -> int:
    """Show how the corpus correlates into incidents."""
    from bishop.correlate import correlate
    from bishop.eval import load_corpus

    corpus = load_corpus()
    incidents = correlate([item.alert for item in corpus])
    multi = [i for i in incidents if len(i.alerts) > 1]

    print()
    print(rule(f"{len(corpus)} alerts correlate into {len(incidents)} incidents"))
    print()
    for incident in incidents:
        if len(incident.alerts) == 1 and not args.all:
            continue
        marker = (
            bold(f"{len(incident.alerts)} alerts") if len(incident.alerts) > 1 else dim("1 alert")
        )
        print(f"  {marker}")
        for alert in incident.alerts:
            print(f"    {alert.alert_id:34} {dim(alert.rule_name)}")
        for line in wrap(incident.rationale(), indent="    "):
            print(dim(line))
        print()
    if not multi and not args.all:
        print(dim("  No multi-alert incidents. Pass --all to list the singletons."))
        print()
    print(dim("  Correlation is by shared host or account within an hour, transitively."))
    print()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    item = _load_alert(args.alert_id)
    audit_path = Path(args.audit) if args.audit else None

    if getattr(args, "correlate", False):
        from bishop.correlate import incident_for
        from bishop.eval import load_corpus

        group = incident_for(item.alert_id, [i.alert for i in load_corpus()])
        alerts = group.alerts if group else [item.alert]
        if len(alerts) > 1:
            print()
            print(dim(f"  {group.rationale()}"))
        incident, runtime, _ = _run_alerts(
            alerts,
            incident_id=f"INC-{item.alert_id}",
            approve=args.approve,
            audit_path=audit_path,
        )
    else:
        incident, runtime, _ = _run_alert(
            item, approve=args.approve, verbose=args.verbose, audit_path=audit_path
        )
    _print_incident(incident, verbose=args.verbose)

    if item.expected_verdict:
        actual = str(incident.verdict.label) if incident.verdict else "none"
        ok = actual == item.expected_verdict
        mark = green("correct") if ok else red("MISMATCH")
        print(f"  {dim('label:')} expected {item.expected_verdict}, got {actual}  {mark}")
        print(dim(f"  ground truth: {item.why}"))
        print()

    _persist(incident, runtime)
    print(dim(f"  audit chain: {len(runtime.chain)} entries, verified {runtime.chain.is_intact()}"))
    print()
    return 0


def _persist(incident, runtime) -> None:
    """Store the incident. A storage failure is reported, never fatal."""
    try:
        from bishop.store import init_db, save_incident

        init_db()
        save_incident(incident, chain=runtime.chain)
    except Exception as exc:
        print(dim(f"  (not stored: {type(exc).__name__}: {exc})"))


def cmd_demo(args: argparse.Namespace) -> int:
    """The showcase run: a real intrusion with an injection payload in it."""
    from bishop.models import get_provider, is_offline

    provider = get_provider()
    print()
    print(rule("BISHOP"))
    print()
    for line in wrap(
        "An autonomous SOC analyst. It investigates and proposes; it never contains "
        "anything without a human saying so."
    ):
        print(line)
    print()
    if is_offline(provider):
        print(dim("  Running offline against the deterministic mock model. No API key, no"))
        print(dim("  network calls, no cost. Set BISHOP_MODEL_PROVIDER=anthropic for a live run."))
    else:
        print(dim(f"  Running live against {provider.model_id}."))
    print()

    item = _load_alert(args.alert_id or "INJ-01")
    print(
        dim(
            f"  Alert: {item.alert.rule_name} on {item.alert.device.hostname if item.alert.device else 'unknown'}"
        )
    )
    print()

    incident, runtime, _ = _run_alert(
        item, approve=args.approve, verbose=args.verbose, audit_path=None
    )
    _print_incident(incident, verbose=args.verbose)

    injections = [e for e in incident.all_evidence if str(e.kind) == "injection"]
    if injections:
        print(rule("THE INTERESTING PART"))
        print()
        for line in wrap(
            "A field in this alert contained text written to manipulate the analyst "
            "reading it. Bishop fenced it as data, refused to follow it, and reported "
            "it as an indicator in its own right:"
        ):
            print(line)
        print()
        for evidence in injections:
            print(f"  {red(evidence.title)}")
            raw = str(evidence.facts.get("raw_value", ""))
            excerpt = raw[-220:] if len(raw) > 220 else raw
            for line in wrap(f"…{excerpt}" if len(raw) > 220 else excerpt, indent="      "):
                print(dim(line))
            print()

    print(dim(f"  audit chain: {len(runtime.chain)} entries, verified {runtime.chain.is_intact()}"))
    print()
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from bishop.eval import (
        HOLDOUT_DIR,
        diff_against_baseline,
        load_baseline,
        render_text,
        run_scorecard,
        save,
    )

    if getattr(args, "holdout", False):
        return _run_holdout(args, HOLDOUT_DIR, render_text, run_scorecard, save)

    card = run_scorecard()
    print(render_text(card))

    baseline = load_baseline()
    if baseline is None:
        print(dim("  no committed baseline to compare against"))
    else:
        regressions = diff_against_baseline(card, baseline)
        if regressions:
            print(f"  {red('REGRESSION against the committed baseline')}")
            for line in regressions:
                print(f"    {line}")
            print()
            if args.gate:
                return 1
        else:
            print(f"  {green('no regression against the committed baseline')}")
    print()

    if args.save:
        path = save(card)
        print(dim(f"  written to {path}"))
        print()
    return 0


def _run_holdout(args, holdout_dir, render_text, run_scorecard, save) -> int:
    """The held-out run.

    Deliberately different from the golden-set run in two ways.

    There is **no baseline and no gate**. A committed baseline is a regression
    gate, and a regression gate on a held-out set is precisely the mechanism
    that converts it back into a development set: it makes every future change
    optimise against these cases. So the number is printed and recorded, and
    nothing in CI fails because of it.

    And every case is printed, right or wrong, with the label's own
    justification. Fifteen cases is small enough that the individual outcomes
    are the result — the aggregate is a summary of them, not a substitute.
    """
    from bishop.eval import load_corpus

    if not holdout_dir.exists():
        print(red(f"  no held-out set at {holdout_dir}"))
        print(dim("  generate it with: uv run python scripts/build_holdout.py"))
        return 1

    card = run_scorecard(corpus_dir=holdout_dir, corpus_name="holdout")
    print(render_text(card))

    why = {item.alert_id: item.why for item in load_corpus(holdout_dir)}
    print("  EVERY CASE")
    for outcome in card.outcomes:
        mark = green("ok  ") if outcome.correct else red("MISS")
        if outcome.missed_true_positive:
            mark = red("FN  ")
        print(
            f"    {mark} {outcome.alert_id:32} expected {outcome.expected:20} got {outcome.actual}"
        )
        if not outcome.correct:
            for line in _wrap_text(why.get(outcome.alert_id, ""), 68):
                print(dim(f"           {line}"))
    print()
    print(dim("  No baseline and no gate on this set, by design: a regression gate here"))
    print(dim("  would make every future change optimise against these cases, which is"))
    print(dim("  the one thing that would destroy what the set is for."))
    print()

    if args.save:
        path = _holdout_result_path(card)
        if path.exists():
            # Refusing rather than overwriting, because of what this file is.
            # A held-out result is only meaningful the first time; a second run
            # on the same day is a run made after seeing the first, and letting
            # it silently take the same filename would replace the one honest
            # measurement with a flattering one and leave no trace.
            print(red(f"  {path.name} already exists and will not be overwritten"))
            print(dim("  A held-out result is a record of one run, not a file that updates."))
            print(dim("  The first run is the measurement; delete it deliberately or"))
            print(dim("  write a fresh held-out set if you need a new number."))
            print()
            return 0
        saved = save(card, path)
        print(dim(f"  written to {saved}"))
        print()
    return 0


def _holdout_result_path(card):
    from bishop.eval.scorecard import RESULTS_DIR

    return RESULTS_DIR / f"holdout-{card.generated_at[:10]}.json"


def _wrap_text(text: str, width: int) -> list[str]:
    from bishop.eval.scorecard import _wrap

    return _wrap(text, width) if text else []


def cmd_triage(args: argparse.Namespace) -> int:
    """Triage an alert the user supplied, from a file or from stdin.

    The mapping report prints before the verdict on purpose. Bishop reads a
    subset of any real alert, and knowing which subset is the difference
    between a verdict you can act on and one you have to take on faith.
    """
    import sys

    from bishop.ingest import load_payload, normalise

    if args.path == "-":
        text = sys.stdin.read()
        origin = "stdin"
    else:
        source = Path(args.path)
        if not source.exists():
            print(red(f"  no file at {source}"))
            return 1
        text = source.read_text(encoding="utf-8")
        origin = str(source)

    try:
        payload = load_payload(text)
        alert, report = normalise(payload)
    except (TypeError, ValueError) as exc:
        print(red(f"  could not read an alert from {origin}: {exc}"))
        return 1

    if not args.quiet:
        _print_mapping(report, origin)

    if not report.usable and not args.force:
        print(red("  No detector can examine this alert."))
        print(dim("  Bishop would escalate it without measuring anything. Run with"))
        print(dim("  --force to do that anyway, or add a command line, connections"))
        print(dim("  or auth events so there is something to assess."))
        print()
        return 2

    incident, runtime, _ = _run_alerts(
        [alert],
        incident_id=f"INC-{alert.alert_id}",
        approve=args.approve,
        audit_path=Path(args.audit) if args.audit else None,
    )
    _print_incident(incident, verbose=args.verbose)
    _persist(incident, runtime)
    print(dim(f"  audit chain: {len(runtime.chain)} entries, verified {runtime.chain.is_intact()}"))
    print()
    return 0


def _print_mapping(report, origin: str) -> None:
    print()
    print(f"  {bold('WHAT BISHOP READ')}  {dim(origin)}")
    print(f"    format detected             {report.detected_format}")
    print(f"    fields understood           {len(report.mapped)}")
    print(f"    fields ignored              {len(report.ignored)}")
    if report.ignored:
        print(dim(f"      {', '.join(report.ignored[:12])}"))
        print(dim("      (kept in raw and injection-scanned, but not interpreted)"))

    if report.defaulted:
        print()
        print(f"    {yellow('defaulted')}")
        for name, value, why in report.defaulted:
            print(f"      {name} = {value}")
            for line in _wrap_text(why, 64):
                print(dim(f"        {line}"))

    print()
    detectors = report.detectors_with_jurisdiction
    if detectors:
        print(f"    {green(f'{len(detectors)} detectors can examine this')}")
        print(dim(f"      {', '.join(detectors)}"))
    else:
        print(f"    {red('no detector can examine this alert')}")

    for warning in report.warnings:
        print()
        lines = _wrap_text(warning, 66)
        for index, line in enumerate(lines):
            prefix = f"    {yellow('!')} " if index == 0 else "      "
            print(f"{prefix}{line}" if index == 0 else dim(f"{prefix}{line}"))
    print()


def cmd_keygen(args: argparse.Namespace) -> int:
    """Emit an API key. Printed once, never stored.

    Bishop will not generate a key at startup and log it, because a secret that
    appears in a deploy log is not a secret. So it is generated here, by a
    person, and pasted into the deployment's own secret store.
    """
    from bishop.config import generate_key

    keys = [generate_key() for _ in range(max(1, args.count))]
    if args.quiet:
        for key in keys:
            print(key)
        return 0

    print()
    print(f"  {bold('API KEY' if len(keys) == 1 else 'API KEYS')}")
    print()
    for key in keys:
        print(f"    {key}")
    print()
    print(f"  {dim('Set them on the API, comma-separated:')}")
    print(f"    BISHOP_API_KEYS={','.join(keys)}")
    print()
    print(dim("  This is the only time they are shown. Bishop stores a comparison"))
    print(dim("  against them, never a copy you can read back."))
    print()
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """Show the resolved deployment configuration, and whether it would serve."""
    from bishop.config import ConfigError, DeploymentSettings

    try:
        settings = DeploymentSettings()
    except ConfigError as exc:
        print()
        print(f"  {red('THIS CONFIGURATION WILL NOT START')}")
        print()
        for line in str(exc).splitlines():
            print(f"  {line}")
        print()
        return 1

    print()
    print(f"  {bold('DEPLOYMENT CONFIGURATION')}")
    print()
    for key, value in settings.redacted().items():
        rendered = ", ".join(str(v) for v in value) if isinstance(value, list) else value
        print(f"    {key:24} {rendered}")
    print()
    if not settings.is_production:
        print(dim("  Development defaults. Set BISHOP_ENVIRONMENT=production to have"))
        print(dim("  Bishop enforce authentication, a named CORS origin, a rate limit"))
        print(dim("  and a real database — refusing to start rather than warning."))
        print()
    return 0


def cmd_formats(args: argparse.Namespace) -> int:
    from bishop.ingest import supported_formats

    print()
    print(f"  {bold('ALERT FORMATS BISHOP ACCEPTS')}")
    print()
    for name, detail in supported_formats().items():
        print(f"    {name:10} {detail}")
    print()
    print(dim("  Detection is advisory — every payload is tried against every"))
    print(dim("  alias table, so a hybrid or partial shape still maps as far as"))
    print(dim("  it can. `bishop triage <file>` prints exactly what was read."))
    print()
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    from bishop.attck import build_matrix, render_markdown
    from bishop.eval import corpus_techniques

    matrix = build_matrix(corpus_techniques())
    markdown = render_markdown(matrix)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(markdown, encoding="utf-8")
    print(f"  {matrix.summary()}")
    print(dim(f"  written to {target}"))
    if matrix.invalid_hints:
        print(red(f"  {len(matrix.invalid_hints)} invalid technique hints — this is a bug"))
        return 1
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from bishop.audit import ChainBroken, load_chain

    path = Path(args.path)
    if not path.exists():
        print(red(f"  no audit chain at {path}"))
        return 1
    chain = load_chain(path)
    try:
        chain.verify(expected_head=args.expect_head, expected_length=args.expect_length)
    except ChainBroken as exc:
        print(f"  {red('CHAIN BROKEN')}: {exc}")
        return 1

    print(f"  {green('chain intact')} — {len(chain)} entries, head {chain.head[:32]}…")
    if not args.expect_head:
        print(
            dim(
                "  Verified from genesis forwards, which cannot detect that the end was cut "
                "off. Pass --expect-head with the incident's audit_head to check that too."
            )
        )
    return 0


def cmd_detectors(args: argparse.Namespace) -> int:
    import bishop.detectors as detectors
    from bishop.detectors.base import registry

    print()
    print(rule(f"{len(registry())} detectors"))
    for surface in detectors.SURFACES:
        specs = detectors.for_surface(surface)
        print()
        print(f"  {bold(surface)} ({len(specs)})")
        for spec in specs:
            techniques = ", ".join(spec.techniques) or dim("—")
            print(f"    {spec.name:28} {techniques}")
            for line in wrap(spec.summary, width=68, indent="      "):
                print(dim(line))
    print()
    return 0


# ── entry point ─────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bishop", description="An autonomous SOC analyst that proposes and never acts alone."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("alerts", help="list the labelled corpus").set_defaults(func=cmd_alerts)

    run = sub.add_parser("run", help="triage one alert")
    run.add_argument("alert_id", help="alert id or prefix, e.g. TP-01")
    run.add_argument(
        "--approve", choices=["all", "none", "reversible"], help="answer the gate without prompting"
    )
    run.add_argument("--audit", help="write the audit chain to this path")
    run.add_argument("-v", "--verbose", action="store_true")
    run.add_argument(
        "--correlate",
        action="store_true",
        help="triage the whole incident this alert belongs to, not just this alert",
    )
    run.set_defaults(func=cmd_run)

    demo = sub.add_parser("demo", help="the showcase run")
    demo.add_argument("alert_id", nargs="?", help="alert to run (default: the injection case)")
    demo.add_argument("--approve", choices=["all", "none", "reversible"])
    demo.add_argument("-v", "--verbose", action="store_true")
    demo.set_defaults(func=cmd_demo)

    ev = sub.add_parser("eval", help="run the scorecard")
    ev.add_argument("--save", action="store_true", help="write the scorecard to eval/results/")
    ev.add_argument("--gate", action="store_true", help="exit non-zero on a regression")
    ev.add_argument(
        "--holdout",
        action="store_true",
        help="run the held-out set instead — reported separately, never gated",
    )
    ev.set_defaults(func=cmd_eval)

    tr = sub.add_parser("triage", help="triage an alert of your own, from a file or stdin")
    tr.add_argument("path", help="path to a JSON alert, or - for stdin")
    tr.add_argument("--approve", help="comma-separated action ids to approve at the gate")
    tr.add_argument("--audit", help="write the audit chain to this path")
    tr.add_argument("-v", "--verbose", action="store_true", help="show every detector result")
    tr.add_argument("--quiet", action="store_true", help="skip the mapping report")
    tr.add_argument(
        "--force",
        action="store_true",
        help="run even when no detector can examine the alert",
    )
    tr.set_defaults(func=cmd_triage)

    fm = sub.add_parser("formats", help="the alert shapes Bishop accepts")
    fm.set_defaults(func=cmd_formats)

    kg = sub.add_parser("keygen", help="generate an API key for a deployment")
    kg.add_argument("-n", "--count", type=int, default=1, help="how many to generate")
    kg.add_argument("--quiet", action="store_true", help="print the keys and nothing else")
    kg.set_defaults(func=cmd_keygen)

    cfg = sub.add_parser("config", help="show the resolved deployment configuration")
    cfg.set_defaults(func=cmd_config)

    cov = sub.add_parser("coverage", help="regenerate the coverage matrix")
    cov.add_argument("--output", default="docs/COVERAGE.md")
    cov.set_defaults(func=cmd_coverage)

    ver = sub.add_parser("verify", help="verify a saved audit chain")
    ver.add_argument("path")
    ver.add_argument(
        "--expect-head",
        help="the audit_head recorded in the incident report; catches a truncated tail",
    )
    ver.add_argument("--expect-length", type=int, help="how many entries the chain should have")
    ver.set_defaults(func=cmd_verify)

    sub.add_parser("detectors", help="list the detector library").set_defaults(func=cmd_detectors)

    inc = sub.add_parser("incidents", help="show how the corpus correlates into incidents")
    inc.add_argument("--all", action="store_true", help="include single-alert incidents")
    inc.set_defaults(func=cmd_incidents)

    hist = sub.add_parser("history", help="stored incidents, with chain verification")
    hist.add_argument("--limit", type=int, default=25)
    hist.set_defaults(func=cmd_history)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Bishop's output is full of box-drawing characters and the occasional
    # attacker payload. Windows terminals default to a codepage that cannot
    # render either.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
