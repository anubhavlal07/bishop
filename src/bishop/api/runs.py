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

#: Runs are held in memory. A restart loses in-flight runs, which is acceptable
#: for a demo and is called out in docs/ARCHITECTURE.md rather than papered over
#: with a database that would not survive contact with a real deployment either.
MAX_RUNS = 64


@dataclass
class Run:
    run_id: str
    alert_id: str
    incident_id: str
    status: str = "queued"  # queued | running | awaiting_approval | done | failed
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    events: list[dict[str, Any]] = field(default_factory=list)
    approval_request: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    error: str | None = None

    _queue: queue.Queue = field(default_factory=queue.Queue, repr=False)
    _runtime: Any = field(default=None, repr=False)
    _graph: Any = field(default=None, repr=False)
    _config: Any = field(default=None, repr=False)
    _done: threading.Event = field(default_factory=threading.Event, repr=False)

    def push(self, event: dict[str, Any]) -> None:
        stamped = {**event, "at": datetime.now(UTC).isoformat()}
        self.events.append(stamped)
        self._queue.put(stamped)

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

    def start(self, alert: Alert, *, alert_id: str) -> Run:
        run_id = f"run-{uuid.uuid4().hex[:12]}"
        run = Run(run_id=run_id, alert_id=alert_id, incident_id=f"INC-{alert_id}")

        # Mirror every node emit onto the run's queue so SSE sees it live.
        runtime = build_runtime(run_id=run_id, listener=run.push)
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

        # Under the lock: two simultaneous decisions could otherwise both pass
        # the check and both resume the graph, which on a gate means a
        # duplicated execution.
        with self._lock:
            if run.status != "awaiting_approval":
                raise ValueError(f"run {run.run_id} is {run.status}, not awaiting approval")
            run.status = "running"
        run.push({"kind": "resumed", "decision": decision.get("decision")})
        threading.Thread(
            target=self._drive, args=(run, Command(resume=decision)), daemon=True
        ).start()

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
        late still renders the whole run rather than only its tail.
        """
        for event in list(run.events):
            yield event

        while True:
            try:
                event = await asyncio.to_thread(run._queue.get, True, 1.0)
            except queue.Empty:
                if run.status in {"done", "failed", "awaiting_approval"}:
                    return
                # Keep the connection alive through a slow model call.
                yield {"kind": "heartbeat", "at": datetime.now(UTC).isoformat()}
                continue
            # The replay above already emitted everything up to now; skip
            # anything the queue hands back that we have already sent.
            yield event
            if event.get("kind") in {"done", "failed", "awaiting_approval"}:
                return


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
