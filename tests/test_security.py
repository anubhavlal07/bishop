"""Tests for the API's authentication, limits and configuration guards.

These are the controls that decide whether Bishop can be exposed to real users
at all, so they are tested the way a control should be: by asserting the
failure is closed, not that the happy path works.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from bishop.api.security import (
    AuthMiddleware,
    RateLimiter,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from bishop.config import ConfigError, DeploymentSettings, generate_key, key_matches

KEY = "k" * 40
OTHER = "z" * 40


def build_app(**overrides) -> TestClient:
    settings = DeploymentSettings(**overrides)
    app = FastAPI()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/incidents")
    def incidents():
        return {"incidents": []}

    app.add_middleware(RateLimiter, settings=settings)
    app.add_middleware(AuthMiddleware, settings=settings)
    app.add_middleware(RequestContextMiddleware, settings=settings)
    app.add_middleware(SecurityHeadersMiddleware)
    return TestClient(app)


class TestAuthentication:
    def test_without_keys_configured_the_api_is_open(self):
        """The laptop default. `config.py` is what stops this reaching production."""
        client = build_app(api_keys="")
        assert client.get("/incidents").status_code == 200

    def test_a_configured_key_is_required(self):
        client = build_app(api_keys=KEY)
        assert client.get("/incidents").status_code == 401

    def test_a_valid_bearer_token_is_accepted(self):
        client = build_app(api_keys=KEY)
        response = client.get("/incidents", headers={"Authorization": f"Bearer {KEY}"})
        assert response.status_code == 200

    def test_the_x_api_key_header_also_works(self):
        client = build_app(api_keys=KEY)
        assert client.get("/incidents", headers={"X-API-Key": KEY}).status_code == 200

    def test_a_wrong_key_is_rejected(self):
        client = build_app(api_keys=KEY)
        assert client.get("/incidents", headers={"X-API-Key": OTHER}).status_code == 401

    def test_one_of_several_configured_keys_works(self):
        """Several keys so a key can be rotated without an outage."""
        client = build_app(api_keys=f"{KEY},{OTHER}")
        assert client.get("/incidents", headers={"X-API-Key": OTHER}).status_code == 200

    def test_health_stays_reachable_without_a_key(self):
        """An orchestrator's probe should not need a credential."""
        client = build_app(api_keys=KEY)
        assert client.get("/health").status_code == 200

    def test_a_missing_and_a_wrong_key_are_indistinguishable(self):
        """Distinguishing them tells a prober which half they got right."""
        client = build_app(api_keys=KEY)
        absent = client.get("/incidents")
        wrong = client.get("/incidents", headers={"X-API-Key": OTHER})
        assert absent.status_code == wrong.status_code == 401
        assert absent.json() == wrong.json()


class TestKeyComparison:
    def test_a_generated_key_is_long_enough_for_production(self):
        assert len(generate_key()) >= 32

    def test_generated_keys_are_unique(self):
        assert len({generate_key() for _ in range(50)}) == 50

    def test_an_empty_presented_key_never_matches(self):
        assert not key_matches("", (KEY,))

    def test_no_configured_keys_never_matches(self):
        assert not key_matches(KEY, ())

    def test_a_prefix_of_a_valid_key_does_not_match(self):
        assert not key_matches(KEY[:20], (KEY,))


class TestRateLimiting:
    def test_requests_beyond_the_limit_are_refused(self):
        client = build_app(api_keys="", rate_limit_per_minute=3)
        codes = [client.get("/incidents").status_code for _ in range(5)]
        assert codes[:3] == [200, 200, 200]
        assert codes[3:] == [429, 429]

    def test_the_response_says_when_to_retry(self):
        client = build_app(api_keys="", rate_limit_per_minute=1)
        client.get("/incidents")
        limited = client.get("/incidents")
        assert limited.status_code == 429
        assert "Retry-After" in limited.headers

    def test_remaining_budget_is_reported(self):
        client = build_app(api_keys="", rate_limit_per_minute=10)
        response = client.get("/incidents")
        assert response.headers["X-RateLimit-Remaining"] == "9"

    def test_health_is_not_rate_limited(self):
        """A probe hammering /health must not lock out real traffic."""
        client = build_app(api_keys="", rate_limit_per_minute=2)
        for _ in range(10):
            assert client.get("/health").status_code == 200

    def test_a_zero_limit_disables_the_limiter(self):
        client = build_app(api_keys="", rate_limit_per_minute=0)
        assert all(client.get("/incidents").status_code == 200 for _ in range(20))


class TestRequestHygiene:
    def test_every_response_carries_a_request_id(self):
        client = build_app()
        assert client.get("/incidents").headers["X-Request-ID"]

    def test_a_supplied_request_id_is_preserved(self):
        """So a caller can correlate its own trace with Bishop's logs."""
        client = build_app()
        response = client.get("/incidents", headers={"X-Request-ID": "abc123"})
        assert response.headers["X-Request-ID"] == "abc123"

    def test_an_oversized_body_is_refused(self):
        client = build_app(max_request_bytes=100)
        response = client.get(
            "/incidents", headers={"Content-Length": "5000", "Content-Type": "application/json"}
        )
        assert response.status_code == 413

    def test_security_headers_are_present(self):
        headers = build_app().get("/incidents").headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


class TestProductionGuards:
    """The point of these is that production cannot be misconfigured quietly."""

    def base(self, **overrides):
        defaults = {
            "environment": "production",
            "api_keys": KEY,
            "cors_origins": "https://console.example",
            "rate_limit_per_minute": 60,
            "database_url": "postgresql+psycopg://u:p@host/bishop",
        }
        return {**defaults, **overrides}

    def test_a_complete_production_config_is_accepted(self):
        settings = DeploymentSettings(**self.base())
        assert settings.is_production
        assert settings.auth_required

    def test_production_without_keys_refuses_to_start(self):
        with pytest.raises(ConfigError, match="BISHOP_API_KEYS"):
            DeploymentSettings(**self.base(api_keys=""))

    def test_production_with_a_short_key_refuses_to_start(self):
        with pytest.raises(ConfigError, match="32 characters"):
            DeploymentSettings(**self.base(api_keys="short"))

    def test_production_with_wildcard_cors_refuses_to_start(self):
        with pytest.raises(ConfigError, match="CORS"):
            DeploymentSettings(**self.base(cors_origins="*"))

    def test_production_without_a_rate_limit_refuses_to_start(self):
        with pytest.raises(ConfigError, match=r"rate limit|RATE_LIMIT"):
            DeploymentSettings(**self.base(rate_limit_per_minute=0))

    def test_production_on_sqlite_refuses_to_start(self):
        """An audit chain that does not survive a restart is not an audit chain."""
        with pytest.raises(ConfigError, match="SQLite"):
            DeploymentSettings(**self.base(database_url="sqlite:///storage/bishop.db"))

    def test_development_enforces_none_of_it(self):
        settings = DeploymentSettings(environment="development", api_keys="", cors_origins="*")
        assert not settings.is_production
        assert not settings.auth_required

    def test_the_redacted_view_carries_no_secret(self):
        rendered = str(DeploymentSettings(**self.base()).redacted())
        assert KEY not in rendered
        assert "u:p@host" not in rendered


class TestEventStreamAuth:
    """`EventSource` cannot set headers, so the SSE path takes a query key.

    Narrowly: the concession is one path suffix, because a key in a URL reaches
    proxy logs and browser history.
    """

    def build(self):
        settings = DeploymentSettings(api_keys=KEY)
        app = FastAPI()

        @app.get("/runs/{run_id}/events")
        def events(run_id: str):
            return {"run_id": run_id}

        @app.get("/incidents")
        def incidents():
            return {"incidents": []}

        app.add_middleware(AuthMiddleware, settings=settings)
        app.add_middleware(RequestContextMiddleware, settings=settings)
        return TestClient(app)

    def test_a_query_key_authenticates_the_stream(self):
        assert self.build().get(f"/runs/r1/events?api_key={KEY}").status_code == 200

    def test_a_wrong_query_key_is_still_refused(self):
        assert self.build().get(f"/runs/r1/events?api_key={OTHER}").status_code == 401

    def test_other_endpoints_do_not_accept_a_query_key(self):
        """The concession must not become a general bypass."""
        assert self.build().get(f"/incidents?api_key={KEY}").status_code == 401


class TestPublicDemoMode:
    """An open deployment where visitors bring their own model key.

    The mode exists so that "no authentication" is an explicit choice with its
    own constraints, rather than a missing setting that happens to boot.
    """

    def base(self, **overrides):
        defaults = {
            "environment": "production",
            "api_keys": "",
            "public_demo": True,
            "cors_origins": "https://bishop.anubhavlal.dev",
            "rate_limit_per_minute": 30,
            "database_url": "postgresql+psycopg://u:p@host/bishop",
        }
        return {**defaults, **overrides}

    def test_production_without_keys_is_allowed_when_declared(self):
        settings = DeploymentSettings(**self.base())
        assert settings.is_production
        assert not settings.auth_required

    def test_the_plain_missing_key_case_still_refuses(self):
        """Without the flag, an empty key list is still a refusal. The mode has
        to be chosen, not fallen into."""
        with pytest.raises(ConfigError, match="BISHOP_API_KEYS"):
            DeploymentSettings(**self.base(public_demo=False))

    def test_the_refusal_names_the_demo_flag(self):
        with pytest.raises(ConfigError, match="BISHOP_PUBLIC_DEMO"):
            DeploymentSettings(**self.base(public_demo=False))

    def test_a_loose_rate_limit_is_refused(self):
        """An unauthenticated endpoint needs a tighter limit, not the same one."""
        with pytest.raises(ConfigError, match="tighter"):
            DeploymentSettings(**self.base(rate_limit_per_minute=120))

    def test_demo_mode_with_keys_is_refused_as_contradictory(self):
        with pytest.raises(ConfigError, match="Pick one"):
            DeploymentSettings(**self.base(api_keys=KEY))

    def test_submitted_alerts_are_not_persisted(self):
        """The reason the mode exists.

        The store is shared and /incidents lists it, so persisting an alert a
        stranger pasted publishes it to every other visitor.
        """
        assert not DeploymentSettings(**self.base()).persist_submitted_alerts

    def test_a_keyed_deployment_does_persist_them(self):
        keyed = DeploymentSettings(
            environment="production",
            api_keys=KEY,
            cors_origins="https://console.example",
            rate_limit_per_minute=60,
            database_url="postgresql+psycopg://u:p@host/bishop",
        )
        assert keyed.persist_submitted_alerts

    def test_health_reports_the_mode_rather_than_implying_it(self):
        reported = DeploymentSettings(**self.base()).redacted()
        assert reported["public_demo"] is True
        assert reported["persists_submitted_alerts"] is False
        assert reported["auth_required"] is False

    def test_demo_mode_does_not_require_postgres(self):
        """Reasoned, not convenient: in demo mode there is no chain to lose.

        Submitted alerts are never written, and corpus runs are reproducible
        from a committed synthetic set.
        """
        settings = DeploymentSettings(**self.base(database_url=""))
        assert settings.is_production
        assert not settings.durable_store_required

    def test_a_keyed_production_still_requires_postgres(self):
        with pytest.raises(ConfigError, match="DATABASE_URL"):
            DeploymentSettings(
                environment="production",
                api_keys=KEY,
                cors_origins="https://console.example",
                rate_limit_per_minute=60,
                database_url="",
            )
