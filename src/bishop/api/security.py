"""Authentication, rate limiting and request hygiene for the API.

Bishop serves security incidents: hostnames, account names, command lines, and
its own assessment of which of them are compromised. That is exactly the
inventory an intruder would like, so the API in front of it needs the controls
any other internal security tool would get.

Three of them live here.

**Authentication** is an API key in `Authorization: Bearer …` or `X-API-Key`.
Keys are compared in constant time (`config.key_matches`). When no keys are
configured the API is open — that is the laptop default, and `config.py`
refuses to start in production without them, so "open" can never be the
deployed state by accident.

**Rate limiting** is per key, fixed-window, in process memory. Stated plainly
because the limitation matters: with more than one instance the effective limit
is the configured number times the instance count, and a restart clears the
window. It is a guard against an accidental loop and a cost blowout, not a
defence against a determined attacker, and it is not a substitute for a limiter
at the edge.

**Request limits** cap the body size, because an alert is kilobytes and the
triage path holds the payload in memory.

**What is deliberately not here.** No user accounts, no roles, no per-tenant
isolation. Every valid key today has the same authority, including approving
containment. That is a real gap for a multi-team deployment and it is written
down in the README rather than implied away.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from bishop.config import DeploymentSettings, key_matches

logger = logging.getLogger("bishop.api")

__all__ = [
    "AuthMiddleware",
    "RateLimiter",
    "RequestContextMiddleware",
    "SecurityHeadersMiddleware",
]

PUBLIC_PATHS = frozenset(
    {"/health", "/health/live", "/health/ready", "/docs", "/openapi.json", "/redoc"}
)


_QUERY_KEY_PATH_SUFFIX = "/events"


def _presented_key(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    from_header = request.headers.get("x-api-key", "").strip()
    if from_header:
        return from_header
    if request.url.path.endswith(_QUERY_KEY_PATH_SUFFIX):
        return request.query_params.get("api_key", "").strip()
    return ""


class AuthMiddleware(BaseHTTPMiddleware):
    """Reject unauthenticated requests when keys are configured."""

    def __init__(self, app, settings: DeploymentSettings) -> None:
        super().__init__(app)
        self._settings = settings

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        if not self._settings.auth_required:
            return await call_next(request)

        presented = _presented_key(request)
        if not key_matches(presented, self._settings.keys):
            logger.warning(
                "rejected an unauthenticated request",
                extra={
                    "path": request.url.path,
                    "request_id": getattr(request.state, "request_id", None),
                    "key_presented": bool(presented),
                },
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "a valid API key is required"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        request.state.api_key_id = _fingerprint(presented)
        return await call_next(request)


def _fingerprint(key: str) -> str:
    """Eight hex characters, enough to group requests, useless as a credential."""
    import hashlib

    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


class RateLimiter(BaseHTTPMiddleware):
    """Fixed-window per-key limiting, in process memory.

    In-process on purpose rather than by omission: adding Redis to a tool that
    otherwise has no runtime dependency would be a large cost for a guard whose
    job is to stop a runaway loop. The multi-instance caveat is documented
    rather than hidden — see the module docstring.
    """

    def __init__(self, app, settings: DeploymentSettings) -> None:
        super().__init__(app)
        self._limit = settings.rate_limit_per_minute
        self._hits: dict[tuple[str, int], int] = defaultdict(int)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if self._limit <= 0 or request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        identity = getattr(request.state, "api_key_id", None) or (
            request.client.host if request.client else "anonymous"
        )
        window = int(time.time() // 60)
        bucket = (identity, window)
        self._hits[bucket] += 1
        used = self._hits[bucket]

        if len(self._hits) > 4096:
            self._hits = defaultdict(
                int, {k: v for k, v in self._hits.items() if k[1] >= window - 1}
            )

        if used > self._limit:
            logger.warning("rate limited", extra={"identity": identity, "limit": self._limit})
            return JSONResponse(
                status_code=429,
                content={"detail": f"rate limit of {self._limit} requests per minute exceeded"},
                headers={"Retry-After": str(60 - int(time.time() % 60))},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self._limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self._limit - used))
        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """A request id on every request, a body cap, and one structured access log.

    The request id is echoed back in `X-Request-ID` and appears in every log
    line for the request, so a user reporting "it failed at 14:32" can be
    matched to the exact trace without guessing.
    """

    def __init__(self, app, settings: DeploymentSettings) -> None:
        super().__init__(app)
        self._max_bytes = settings.max_request_bytes

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id

        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self._max_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": f"request body exceeds {self._max_bytes} bytes"},
                headers={"X-Request-ID": request_id},
            )

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "unhandled error", extra={"request_id": request_id, "path": request.url.path}
            )
            raise

        duration_ms = int((time.perf_counter() - started) * 1000)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "identity": getattr(request.state, "api_key_id", None),
            },
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Headers that cost nothing and close whole classes of browser attack."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
        return response
