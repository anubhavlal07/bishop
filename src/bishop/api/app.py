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
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from bishop import __version__
from bishop.api.runs import RunManager, corpus_index
from bishop.api.security import (
    AuthMiddleware,
    RateLimiter,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from bishop.config import get_settings
from bishop.eval import load_corpus
from bishop.logging_setup import configure_logging
from bishop.models import get_provider, is_offline

# Validated here, at import, so a misconfigured production deployment fails to
# start rather than serving. See `config.py` for what is enforced.
settings = get_settings()
configure_logging(json_logs=settings.json_logs, level=settings.log_level)
logger = logging.getLogger("bishop.api")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Announce the resolved configuration, and create tables if absent.

    The unauthenticated warning is emitted on every start rather than once,
    because the state it describes is dangerous and a single line at first
    deploy scrolls away.
    """
    logger.info("bishop starting", extra=settings.redacted())
    if not settings.auth_required:
        logger.warning(
            "the API is unauthenticated — set BISHOP_API_KEYS before exposing it",
            extra={"environment": settings.environment},
        )
    try:
        from bishop.store import init_db

        init_db()
    except Exception as exc:
        logger.error("could not prepare the store", extra={"error": str(exc)})
    yield


app = FastAPI(
    title="Bishop",
    version=__version__,
    description="An autonomous SOC analyst. Investigates and proposes; never contains alone.",
    # The interactive docs render the schema, which is fine, but they are an
    # unauthenticated surface in production and there is nothing in them a
    # deployed user needs.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    lifespan=lifespan,
)

# Ordering matters and reads backwards: the last middleware added is the
# outermost. So a request passes headers -> context (request id, body cap) ->
# auth -> rate limit, which means an unauthenticated request is rejected before
# it can consume a rate-limit slot belonging to a real key, and every rejection
# still carries a request id.
app.add_middleware(RateLimiter, settings=settings)
app.add_middleware(AuthMiddleware, settings=settings)
app.add_middleware(RequestContextMiddleware, settings=settings)
app.add_middleware(SecurityHeadersMiddleware)

# `allow_credentials` stays False: Bishop authenticates with a header, never a
# cookie, so the browser never needs to send credentials cross-origin — and
# with it False, a wildcard origin cannot be combined with credentials at all.
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining"],
)

runs = RunManager()


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    """Never return a stack trace.

    A traceback names file paths, package versions and sometimes the data that
    caused the failure. The request id is the thing a user should quote, and it
    is already in the logs beside the full exception.
    """
    request_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "an internal error occurred",
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id} if request_id else None,
    )


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


@app.get("/health/live")
def liveness() -> dict[str, str]:
    """Is the process up. Nothing else.

    Separate from readiness on purpose: a liveness probe that also checks the
    database will restart a healthy container every time the database blips,
    which turns a recoverable outage into a crash loop.
    """
    return {"status": "alive"}


@app.get("/health/ready")
def readiness() -> JSONResponse:
    """Can this instance serve traffic — i.e. can it reach its store."""
    from bishop.store import health as store_health

    store = store_health()
    ready = bool(store.get("connected"))
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ready" if ready else "not ready", "store": store},
    )


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
        "deployment": settings.redacted(),
        # What it would take to run live, reported rather than implied. A
        # console that says "mock model" without saying what is missing leaves
        # the reader to guess between "no key", "no dependency" and "by design".
        "live": _live_readiness(),
    }


def _live_readiness() -> dict[str, Any]:
    import importlib.util
    import os

    from bishop.models import PROVIDER_ENV

    package_present = importlib.util.find_spec("anthropic") is not None
    key_present = bool(os.environ.get("ANTHROPIC_API_KEY"))
    selected = (os.environ.get(PROVIDER_ENV) or "mock").strip().lower()

    missing: list[str] = []
    if not package_present:
        missing.append("uv sync --extra live")
    if not key_present:
        missing.append("set ANTHROPIC_API_KEY in .env")
    if selected not in {"anthropic"}:
        missing.append(f"set {PROVIDER_ENV}=anthropic")

    return {
        "selected": selected,
        "package_installed": package_present,
        "api_key_present": key_present,
        "ready": not missing,
        "missing": missing,
        # Said plainly because "mock" invites the assumption that nothing is
        # real. The detectors, ATT&CK validation, injection scanning,
        # correlation and the audit chain run identically either way; the model
        # only interprets and narrates what they produced.
        "what_mock_still_does": (
            "Detectors, ATT&CK validation, injection scanning, correlation and the "
            "audit chain are the same code in both modes. What the mock replaces is "
            "the model's judgement: the narrative is assembled from detector "
            "rationales and the weighing is arithmetic, so it will not spot the thing "
            "nobody wrote a detector for."
        ),
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


def _credentials_from(request: Request):
    """Build one user's model credentials from their request headers.

    Headers rather than the body, for two reasons. A body is the thing most
    likely to be logged by a proxy or echoed in an error, and putting the key
    outside the JSON means `POST /runs` can keep taking a bare alert. The key
    is used to construct a provider and is never stored, never logged and never
    written to the audit chain — the chain records the provider and model id,
    which is what makes a verdict reproducible.
    """
    from bishop.models.credentials import CredentialError, parse

    provider = request.headers.get("x-model-provider")
    if not provider:
        return None  # fall back to whatever the server is configured with
    try:
        return parse(
            provider,
            request.headers.get("x-model-key"),
            request.headers.get("x-model-id"),
            request.headers.get("x-model-endpoint"),
        )
    except CredentialError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.get("/providers")
def providers() -> dict[str, Any]:
    """What the console's setup modal renders. Carries no secrets."""
    from bishop.models.credentials import provider_catalogue

    return {
        "providers": provider_catalogue(),
        "note": (
            "Bishop stores no model key. Yours stays in your browser and travels with "
            "each request that needs it, so this deployment can never spend your money "
            "without you, and a compromise of it leaks no key."
        ),
    }


@app.post("/providers/verify")
def verify_provider(request: Request) -> dict[str, Any]:
    """One cheap call to confirm a key works, before the user relies on it.

    Worth doing at setup rather than three minutes into a run: the failure is
    identical either way, but here it is attached to the field just typed.
    """
    from bishop.models.byok import verify_credentials

    credentials = _credentials_from(request)
    if credentials is None:
        raise HTTPException(422, "supply X-Model-Provider and X-Model-Key")
    return verify_credentials(credentials)


@app.get("/ingest/formats")
def ingest_formats() -> dict[str, Any]:
    from bishop.ingest import supported_formats

    return {"formats": supported_formats()}


@app.post("/runs", status_code=202)
def start_run(body: StartRun, request: Request) -> dict[str, Any]:
    credentials = _credentials_from(request)
    provider = None
    if credentials is not None and not credentials.is_mock:
        from bishop.models.byok import build_provider

        provider = build_provider(credentials)

    if body.alert is not None:
        from bishop.ingest import normalise

        try:
            alert, report = normalise(body.alert)
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc
        run = runs.start(alert, alert_id=alert.alert_id, provider=provider)
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
            run = runs.start(item.alert, alert_id=item.alert_id, provider=provider)
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
