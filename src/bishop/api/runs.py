"""Run orchestration behind the API.

The graph is synchronous and one run can suspend for hours at the human gate,
so runs live in a manager rather than inside a request. Each run owns its own
runtime — its own audit chain, its own model provider — because two runs
sharing a chain would produce a log nobody could untangle afterwards.

Events are pushed onto a thread-safe queue by `Runtime.emit` and drained by the
SSE endpoint. Nodes run in a worker thread; the queue is the seam between that
and the event loop.
"""

from __future__ import annotations

import asyncio
import queue
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from bishop.eval import load_corpus
from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
from bishop.graph.nodes.report import build_incident
from bishop.schema import Alert

MAX_RUNS = 64

#: A run stops producing events once it reaches one of these.
_SETTLED = frozenset({"done", "failed", "awaiting_approval"})


@dataclass
class Run:
    run_id: str
    alert_id: str
    incident_id: str
    status: str = "queued"
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    events: list[dict[str, Any]] = field(default_factory=list)
    approval_request: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    submitted: bool = False

    #: One queue per connected stream, not one queue per run.
    #:
    #: There used to be a single shared queue, and `stream()` replayed
    #: `events` and then drained it. Both hold every event, so a console that
    #: connected after the run had started received the whole run **twice** —
    #: measured at 36 deliveries of 10 distinct events. And `Queue.get` is
    #: destructive, so two consoles watching the same run were taking live
    #: events from each other, each seeing a different subset.
    #:
    #: A queue per subscriber fixes both: the snapshot is taken under the same
    #: lock that registers the queue, so an event is either in the replay or in
    #: the feed and never in both, and one subscriber cannot consume another's.
    _subscribers: list[queue.Queue] = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _runtime: Any = field(default=None, repr=False)
    _graph: Any = field(default=None, repr=False)
    _config: Any = field(default=None, repr=False)
    _done: threading.Event = field(default_factory=threading.Event, repr=False)

    def push(self, event: dict[str, Any]) -> None:
        stamped = {**event, "at": datetime.now(UTC).isoformat()}
        with self._lock:
            self.events.append(stamped)
            for feed in self._subscribers:
                feed.put(stamped)

    def subscribe(self) -> tuple[list[dict[str, Any]], queue.Queue]:
        """Everything that has already happened, and a feed for what happens next.

        Both under one lock, so nothing can be pushed in the gap between the
        snapshot and the registration — which is the gap that would drop an
        event rather than duplicate one.
        """
        feed: queue.Queue = queue.Queue()
        with self._lock:
            self._subscribers.append(feed)
            return list(self.events), feed

    def unsubscribe(self, feed: queue.Queue) -> None:
        with self._lock:
            if feed in self._subscribers:
                self._subscribers.remove(feed)

    def incident(self):
        if self.result is None:
            return None
        head = self._runtime.chain.head if self._runtime else None
        return build_incident(self.result, audit_head=head)

    def audit(self) -> list[dict[str, Any]]:
        if self._runtime is None:
            return []
        return [entry.to_dict() for entry in self._runtime.chain]

    def audit_intact(self) -> bool:
        return bool(self._runtime and self._runtime.chain.is_intact())


class RunManager:
    def __init__(self) -> None:
        self._runs: dict[str, Run] = {}
        self._lock = threading.Lock()

    def get(self, run_id: str) -> Run | None:
        return self._runs.get(run_id)

    def list(self) -> list[Run]:
        return sorted(self._runs.values(), key=lambda r: r.created_at, reverse=True)

    def _evict(self) -> None:
        if len(self._runs) <= MAX_RUNS:
            return
        for run in sorted(self._runs.values(), key=lambda r: r.created_at)[
            : len(self._runs) - MAX_RUNS
        ]:
            self._runs.pop(run.run_id, None)

    def start(self, alert: Alert, *, alert_id: str, provider=None, submitted: bool = False) -> Run:
        run_id = f"run-{uuid.uuid4().hex[:12]}"
        run = Run(
            run_id=run_id,
            alert_id=alert_id,
            incident_id=f"INC-{alert_id}",
            submitted=submitted,
        )

        runtime = build_runtime(run_id=run_id, listener=run.push, provider=provider)
        run._runtime = runtime
        run._graph = build_graph()
        run._config = runtime_config(runtime)

        with self._lock:
            self._runs[run_id] = run
            self._evict()

        state = initial_state(run_id=run_id, alerts=[alert], incident_id=run.incident_id)
        threading.Thread(target=self._drive, args=(run, state), daemon=True).start()
        return run

    def resume(self, run: Run, decision: dict[str, Any]) -> None:
        from langgraph.types import Command

        with self._lock:
            if run.status != "awaiting_approval":
                raise ValueError(f"run {run.run_id} is {run.status}, not awaiting approval")
            run.status = "running"
        run.push({"kind": "resumed", "decision": decision.get("decision")})
        threading.Thread(
            target=self._drive, args=(run, Command(resume=decision)), daemon=True
        ).start()

    @staticmethod
    def _persist(run: Run) -> None:
        """Write the finished incident and its chain.

        Failure here must not fail the run: the triage happened, the analyst
        can see it, and losing the durable copy is a smaller problem than
        losing the answer. It is logged as a run error so it is not silent.
        """
        try:
            from bishop.config import get_settings
            from bishop.store import init_db, save_incident

            incident = run.incident()
            if incident is None:
                return

            if run.submitted and not get_settings().persist_submitted_alerts:
                run.push(
                    {
                        "kind": "not_persisted",
                        "reason": (
                            "this deployment is a public demo, so an alert you supplied is "
                            "triaged in memory and never written to the shared store"
                        ),
                    }
                )
                return

            init_db()
            save_incident(incident, chain=run._runtime.chain if run._runtime else None)
        except Exception as exc:
            run.push({"kind": "persist_failed", "error": f"{type(exc).__name__}: {exc}"})

    def _drive(self, run: Run, payload: Any) -> None:
        try:
            run.status = "running"
            run.push({"kind": "started" if run.result is None else "continued"})
            result = run._graph.invoke(payload, config=run._config)
            run.result = result

            interrupts = result.get("__interrupt__")
            if interrupts:
                run.status = "awaiting_approval"
                run.approval_request = interrupts[0].value
                run.push({"kind": "awaiting_approval", "request": run.approval_request})
            else:
                run.status = "done"
                self._persist(run)
                verdict = result.get("verdict")
                run.push(
                    {
                        "kind": "done",
                        "verdict": str(verdict.label) if verdict else None,
                        "confidence": verdict.confidence if verdict else None,
                    }
                )
                run._done.set()
        except Exception as exc:
            run.status = "failed"
            run.error = f"{type(exc).__name__}: {exc}"
            run.push({"kind": "failed", "error": run.error})
            run._done.set()

    async def stream(self, run: Run):
        """Yield events as they happen, then stop when the run settles.

        Replays what has already happened first, so a console that connects
        late still renders the whole run rather than only its tail. The replay
        and the live feed are taken together in `subscribe()`, so an event
        appears in exactly one of them.
        """
        history, feed = run.subscribe()
        try:
            for event in history:
                yield event
                if event.get("kind") in _SETTLED:
                    return

            while True:
                try:
                    event = await asyncio.to_thread(feed.get, True, 1.0)
                except queue.Empty:
                    if run.status in _SETTLED:
                        return
                    yield {"kind": "heartbeat", "at": datetime.now(UTC).isoformat()}
                    continue
                yield event
                if event.get("kind") in _SETTLED:
                    return
        finally:
            # A console that closes the tab mid-run would otherwise leave its
            # queue attached, and every later event would be copied into a
            # buffer nobody reads.
            run.unsubscribe(feed)


def corpus_index() -> dict[str, Any]:
    """The labelled corpus, for the console's alert list."""
    return {
        item.alert_id: {
            "alert_id": item.alert_id,
            "rule_name": item.alert.rule_name,
            "source": item.alert.source,
            "severity": str(item.alert.severity),
            "category": str(item.alert.category),
            "detected_at": item.alert.detected_at.isoformat(),
            "host": str(item.alert.device.hostname) if item.alert.device else None,
            "user": str(item.alert.principal.username) if item.alert.principal else None,
            "expected_verdict": item.expected_verdict,
            "why": item.why,
            "synthetic": item.synthetic,
        }
        for item in load_corpus()
    }
