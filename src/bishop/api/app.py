"""The FastAPI surface.

Read-only endpoints for the corpus, the detector library and the coverage
matrix; one endpoint that starts a run; one SSE stream; and one endpoint that
records a human decision.

The approval endpoint is the only one that changes anything consequential, and
it is deliberately shaped so that a client cannot approve an action the run did
not propose — `response_gate` discards unknown action ids, and
`response_execute` re-checks the decision per action. A console bug should not
be able to isolate a host.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from bishop import __version__
from bishop.api.runs import RunManager, corpus_index
from bishop.eval import load_corpus
from bishop.models import get_provider, is_offline

app = FastAPI(
    title="Bishop",
    version=__version__,
    description="An autonomous SOC analyst. Investigates and proposes; never contains alone.",
)

# The console is served from a different origin in development and from Netlify
# in production. Nothing here is authenticated, which is fine for a read-mostly
# demo over synthetic data and is stated as a limitation in the README and in
# docs/ARCHITECTURE.md rather than hidden.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

runs = RunManager()


class StartRun(BaseModel):
    """Start a run from the corpus, or from an alert the caller supplies.

    Exactly one of the two. Being able to submit your own alert is what makes
    this a tool rather than a replay of the committed fixtures.
    """

    alert_id: str | None = Field(None, description="An id from the labelled corpus.")
    alert: dict[str, Any] | None = Field(
        None,
        description=(
            "A raw alert in any recognised shape — Bishop's own schema, ECS, "
            "Sysmon/Windows event JSON, or flat JSON with common field names. "
            "Normalised on the way in; POST /ingest/preview to see the mapping "
            "without starting a run."
        ),
    )


class IngestPreview(BaseModel):
    """An alert to map without running anything."""

    alert: dict[str, Any] = Field(..., description="The raw alert payload.")


class Decision(BaseModel):
    decision: str = Field(..., description="approved | rejected | modified")
    #: Required for anything other than a rejection. An approval that names no
    #: action approves nothing — see `response_gate._parse_decision`.
    approved_action_ids: list[str] = Field(default_factory=list)
    decided_by: str = "console"
    note: str = ""


@app.get("/health")
def health() -> dict[str, Any]:
    from bishop.store import health as store_health

    provider = get_provider()
    return {
        "status": "ok",
        "version": __version__,
        "provider": provider.name,
        "model": provider.model_id,
        "offline": is_offline(provider),
        "store": store_health(),
    }


@app.get("/incidents")
def stored_incidents(limit: int = 50) -> dict[str, Any]:
    """Incidents that survived the process that produced them."""
    from bishop.store import init_db, list_incidents

    init_db()
    rows = list_incidents(limit=limit)
    return {"count": len(rows), "incidents": rows}


@app.get("/incidents/{incident_id}")
def stored_incident(incident_id: str) -> dict[str, Any]:
    from bishop.store import init_db, load_incident, verify_stored_chain

    init_db()
    incident = load_incident(incident_id)
    if incident is None:
        raise HTTPException(404, f"no stored incident {incident_id}")
    intact, detail = verify_stored_chain(incident_id)
    return {
        "incident": incident.model_dump(mode="json"),
        "audit_intact": intact,
        "audit_detail": detail,
    }


@app.get("/alerts")
def alerts() -> dict[str, Any]:
    index = corpus_index()
    return {"count": len(index), "alerts": list(index.values())}


@app.get("/alerts/{alert_id}")
def alert_detail(alert_id: str) -> dict[str, Any]:
    for item in load_corpus():
        if item.alert_id == alert_id:
            return {
                **item.alert.model_dump(mode="json"),
                "labels": {
                    "verdict": item.expected_verdict,
                    "techniques": list(item.expected_techniques),
                    "why": item.why,
                },
            }
    raise HTTPException(404, f"no alert {alert_id}")


@app.get("/detectors")
def detectors() -> dict[str, Any]:
    import bishop.detectors as detector_package
    from bishop.detectors.base import registry

    return {
        "count": len(registry()),
        "surfaces": list(detector_package.SURFACES),
        "detectors": [
            {
                "name": spec.name,
                "surface": spec.surface,
                "summary": spec.summary,
                "techniques": list(spec.techniques),
                "references": list(spec.references),
            }
            for spec in registry().values()
        ],
    }


@app.get("/coverage")
def coverage() -> dict[str, Any]:
    from bishop.attck import build_matrix
    from bishop.eval import corpus_techniques

    matrix = build_matrix(corpus_techniques())
    return {
        "attack_version": matrix.attack_version,
        "summary": matrix.summary(),
        "entries": [
            {
                "technique_id": entry.technique.id,
                "name": entry.technique.name,
                "tactics": list(entry.technique.tactic_names),
                "detectors": entry.detectors,
                "fixtures": entry.fixtures,
                "status": entry.status,
                "url": entry.technique.url,
            }
            for entry in matrix.entries
        ],
    }


@app.get("/scorecard")
def scorecard() -> dict[str, Any]:
    """The committed baseline, not a fresh run.

    Running the whole corpus on a web request would take as long as the corpus
    takes and give a different answer each deploy. `just eval` produces the
    number; this endpoint reports what was produced.
    """
    from bishop.eval import load_baseline

    baseline = load_baseline()
    if baseline is None:
        raise HTTPException(404, "no committed scorecard baseline; run `just eval --save`")
    return baseline


@app.get("/runs")
def list_runs() -> dict[str, Any]:
    return {
        "runs": [
            {
                "run_id": run.run_id,
                "alert_id": run.alert_id,
                "status": run.status,
                "created_at": run.created_at,
            }
            for run in runs.list()
        ]
    }


@app.post("/ingest/preview")
def ingest_preview(body: IngestPreview) -> dict[str, Any]:
    """Map an alert and report what Bishop understood, without running it.

    The useful half is `mapping.detectors_with_jurisdiction`. It is computed by
    running the detectors and asking which had data in their remit, so it says
    whether a run can produce anything before you wait for one. An empty list
    means Bishop will escalate whatever the alert says, because it has nothing
    it can measure.
    """
    from bishop.ingest import normalise

    try:
        alert, report = normalise(body.alert)
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return {
        "alert": alert.model_dump(mode="json"),
        "mapping": report.to_dict(),
        "usable": report.usable,
    }


@app.get("/ingest/formats")
def ingest_formats() -> dict[str, Any]:
    from bishop.ingest import supported_formats

    return {"formats": supported_formats()}


@app.post("/runs", status_code=202)
def start_run(body: StartRun) -> dict[str, Any]:
    if body.alert is not None:
        from bishop.ingest import normalise

        try:
            alert, report = normalise(body.alert)
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc
        run = runs.start(alert, alert_id=alert.alert_id)
        # The mapping travels with the run so the console can show what Bishop
        # read alongside what it concluded. A verdict without that is a verdict
        # you cannot audit.
        return {
            "run_id": run.run_id,
            "status": run.status,
            "alert_id": alert.alert_id,
            "mapping": report.to_dict(),
        }

    if body.alert_id is None:
        raise HTTPException(422, "supply either alert_id or alert")

    for item in load_corpus():
        if item.alert_id == body.alert_id:
            run = runs.start(item.alert, alert_id=item.alert_id)
            return {"run_id": run.run_id, "status": run.status}
    raise HTTPException(404, f"no alert {body.alert_id}")


def _run_or_404(run_id: str):
    run = runs.get(run_id)
    if run is None:
        raise HTTPException(404, f"no run {run_id}")
    return run


@app.get("/runs/{run_id}")
def run_state(run_id: str) -> dict[str, Any]:
    run = _run_or_404(run_id)
    incident = run.incident()
    return {
        "run_id": run.run_id,
        "alert_id": run.alert_id,
        "status": run.status,
        "error": run.error,
        "approval_request": run.approval_request,
        "incident": incident.model_dump(mode="json") if incident else None,
        "audit_entries": len(run.audit()),
        "audit_intact": run.audit_intact(),
    }


@app.get("/runs/{run_id}/events")
async def run_events(run_id: str) -> StreamingResponse:
    run = _run_or_404(run_id)

    async def generate():
        async for event in runs.stream(run):
            yield f"event: {event.get('kind', 'message')}\ndata: {json.dumps(event, default=str)}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Nginx and friends buffer SSE into uselessness without this.
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/runs/{run_id}/decision")
def submit_decision(run_id: str, body: Decision) -> dict[str, Any]:
    run = _run_or_404(run_id)
    try:
        runs.resume(run, body.model_dump())
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"run_id": run.run_id, "status": run.status}


@app.get("/runs/{run_id}/audit")
def run_audit(run_id: str) -> dict[str, Any]:
    run = _run_or_404(run_id)
    return {
        "run_id": run.run_id,
        "intact": run.audit_intact(),
        "entries": run.audit(),
    }
