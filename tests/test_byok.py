"""Bring-your-own-key: validation, provider construction, and key hygiene.

The hygiene tests are the ones that matter. Bishop now handles a secret that
belongs to somebody else, and the failure mode is not a crash — it is a key
sitting in a log aggregator or an audit chain that somebody exports. So these
assert the negative: that the key is *not* in places it could plausibly end up.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from bishop.models.byok import _sanitise, build_provider
from bishop.models.credentials import (
    PROVIDERS,
    CredentialError,
    Credentials,
    parse,
    provider_catalogue,
)

ANTHROPIC = "sk-ant-" + "a" * 40
OPENAI = "sk-" + "b" * 40
GEMINI = "AIza" + "c" * 36
AZURE = "d" * 40


class TestValidation:
    def test_each_advertised_provider_parses(self):
        assert parse("anthropic", ANTHROPIC).provider == "anthropic"
        assert parse("openai", OPENAI).provider == "openai"
        assert parse("gemini", GEMINI).provider == "gemini"
        assert (
            parse("azure-openai", AZURE, endpoint="https://x.openai.azure.com").provider
            == "azure-openai"
        )

    def test_mock_needs_no_key(self):
        assert parse("mock", None).is_mock

    def test_an_unknown_provider_is_refused(self):
        with pytest.raises(CredentialError, match="unknown provider"):
            parse("hal9000", "k")

    def test_a_missing_key_is_refused(self):
        with pytest.raises(CredentialError, match="needs an API key"):
            parse("openai", "")

    def test_a_malformed_key_is_refused_before_any_network_call(self):
        """The message says nothing was sent, and that must be true."""
        with pytest.raises(CredentialError, match="Nothing was sent"):
            parse("anthropic", "not-a-key")

    def test_the_default_model_is_applied(self):
        assert parse("anthropic", ANTHROPIC).model_id == PROVIDERS["anthropic"].default_model

    def test_an_explicit_model_wins(self):
        assert parse("openai", OPENAI, "gpt-4.1-mini").model_id == "gpt-4.1-mini"


class TestAzureEndpointIsNotAnSsrfPrimitive:
    """ "Bring your own endpoint" plus a secret is server-side request forgery.

    The allowlist is the whole defence, so it gets its own class.
    """

    def test_azure_requires_an_endpoint(self):
        with pytest.raises(CredentialError, match="resource endpoint"):
            parse("azure-openai", AZURE)

    def test_an_azure_hostname_is_accepted(self):
        creds = parse("azure-openai", AZURE, endpoint="https://mine.openai.azure.com")
        assert creds.endpoint == "https://mine.openai.azure.com"

    @pytest.mark.parametrize(
        "hostile",
        [
            "https://evil.example.com",
            "https://169.254.169.254",
            "https://openai.azure.com.evil.example",
            "http://mine.openai.azure.com",
        ],
    )
    def test_a_non_azure_or_plaintext_endpoint_is_refused(self, hostile):
        with pytest.raises(CredentialError):
            parse("azure-openai", AZURE, endpoint=hostile)


class TestTheKeyDoesNotLeak:
    def test_repr_redacts(self):
        assert ANTHROPIC not in repr(parse("anthropic", ANTHROPIC))

    def test_str_redacts(self):
        assert ANTHROPIC not in str(parse("anthropic", ANTHROPIC))

    def test_describe_carries_no_key(self):
        described = parse("openai", OPENAI).describe()
        assert OPENAI not in str(described)
        assert described["provider"] == "openai"

    def test_an_interpolated_credential_cannot_leak_via_a_log_line(self, caplog):
        """The realistic accident: someone writes `logger.info(f"{creds}")`."""
        creds = parse("gemini", GEMINI)
        with caplog.at_level(logging.INFO):
            logging.getLogger("test").info("using %s", creds)
        assert GEMINI not in caplog.text
        assert "redacted" in caplog.text

    def test_a_vendor_error_quoting_the_key_is_sanitised(self):
        """Vendors echo request context back. This is the last place to catch it."""
        leaked = f"401 unauthorized for key {ANTHROPIC} on model x"
        assert ANTHROPIC not in _sanitise(leaked)
        assert "<redacted>" in _sanitise(leaked)

    def test_the_catalogue_carries_no_secret_fields(self):
        rendered = str(provider_catalogue())
        assert "key_pattern" not in rendered
        for secret in (ANTHROPIC, OPENAI, GEMINI):
            assert secret not in rendered


class TestProviderConstruction:
    def test_mock_credentials_build_the_deterministic_model(self):
        assert build_provider(Credentials(provider="mock")).name == "mock"

    @pytest.mark.parametrize(
        ("provider", "key", "extra"),
        [
            ("anthropic", ANTHROPIC, {}),
            ("openai", OPENAI, {}),
            ("gemini", GEMINI, {}),
            ("azure-openai", AZURE, {"endpoint": "https://x.openai.azure.com"}),
        ],
    )
    def test_every_provider_builds_without_a_network_call(self, provider, key, extra):
        """Construction must not touch the network — only `complete` may."""
        built = build_provider(parse(provider, key, **extra))
        assert built.name == provider
        assert built.model_id
        assert hasattr(built, "complete")

    def test_azure_puts_the_deployment_in_the_path(self):
        """On Azure the deployment name replaces the model in the URL."""
        built = build_provider(
            parse("azure-openai", AZURE, "my-deployment", "https://mine.openai.azure.com")
        )
        url = built._url()
        assert url.startswith("https://mine.openai.azure.com/openai/deployments/my-deployment")
        assert "api-version=" in url

    def test_openai_strict_schema_marks_every_property_required(self):
        from bishop.models.byok import _strict

        tightened = _strict(
            {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "integer"}}}
        )
        assert set(tightened["required"]) == {"a", "b"}
        assert tightened["additionalProperties"] is False

    def test_gemini_schema_drops_keywords_it_rejects(self):
        from bishop.models.byok import _gemini_schema

        cleaned = _gemini_schema(
            {"type": "object", "additionalProperties": False, "$schema": "x", "properties": {}}
        )
        assert "additionalProperties" not in cleaned
        assert "$schema" not in cleaned


class TestTheApiSurface:
    @pytest.fixture
    def client(self):
        from bishop.api.app import app

        with TestClient(app) as c:
            yield c

    def test_the_catalogue_is_served(self, client):
        body = client.get("/providers").json()
        keys = {p["key"] for p in body["providers"]}
        assert {"anthropic", "openai", "gemini", "azure-openai", "mock"} <= keys

    def test_a_bad_key_shape_is_rejected_with_a_useful_message(self, client):
        response = client.post(
            "/providers/verify",
            headers={"X-Model-Provider": "anthropic", "X-Model-Key": "nope"},
        )
        assert response.status_code == 422
        assert "sk-ant-" in response.json()["detail"]

    def test_verify_without_headers_explains_what_is_needed(self, client):
        assert client.post("/providers/verify").status_code == 422

    def test_a_run_without_credentials_still_uses_the_server_default(self, client):
        """BYOK is additive. A deployment with a server key must keep working."""
        response = client.post("/runs", json={"alert_id": "FP-07-cdn-dns"})
        assert response.status_code == 202

    def test_a_malformed_credential_header_fails_the_run_cleanly(self, client):
        response = client.post(
            "/runs",
            json={"alert_id": "FP-07-cdn-dns"},
            headers={"X-Model-Provider": "openai", "X-Model-Key": "bad"},
        )
        assert response.status_code == 422

    def test_the_key_is_never_echoed_in_a_response(self, client):
        response = client.post(
            "/runs",
            json={"alert_id": "FP-07-cdn-dns"},
            headers={"X-Model-Provider": "anthropic", "X-Model-Key": ANTHROPIC},
        )
        assert ANTHROPIC not in response.text


class TestTheAuditChainRecordsTheModelNotTheKey:
    def test_a_run_records_provider_and_model_but_no_key(self):
        """The chain must stay reproducible without becoming a secret store."""
        from bishop.graph import build_graph, build_runtime, initial_state, runtime_config
        from tests.graph.conftest import quiet_alert

        runtime = build_runtime(run_id="byok-audit")
        build_graph().invoke(
            initial_state(run_id="byok-audit", alerts=[quiet_alert()], incident_id="INC-B"),
            config=runtime_config(runtime),
        )
        serialised = str([e.to_dict() for e in runtime.chain])
        for secret in (ANTHROPIC, OPENAI, GEMINI, AZURE):
            assert secret not in serialised


class TestSubmittedAlertsStayPrivateInDemoMode:
    """The leak public-demo mode exists to prevent.

    A visitor pastes an alert from their own SIEM into an open deployment.
    Without this, it lands in the shared store and `/incidents` serves it to
    every other visitor.
    """

    def test_a_submitted_run_is_flagged_as_submitted(self):
        from bishop.api.runs import RunManager
        from tests.graph.conftest import quiet_alert

        manager = RunManager()
        run = manager.start(quiet_alert(), alert_id="A-1", submitted=True)
        assert run.submitted
        run._done.wait(timeout=30)

    def test_a_corpus_run_is_not_flagged(self):
        from bishop.api.runs import RunManager
        from tests.graph.conftest import quiet_alert

        manager = RunManager()
        run = manager.start(quiet_alert(), alert_id="A-2")
        assert not run.submitted
        # Waited on deliberately. A run left in flight finishes during the next
        # test and lands in whatever that test patched, which is a false
        # failure that looks exactly like a real leak.
        run._done.wait(timeout=30)

    def test_a_submitted_run_never_reaches_the_store_in_demo_mode(self, monkeypatch):
        """Driven through a real run, because the guard sits after the incident
        is built and a stubbed run would skip past it."""
        from bishop.api.runs import RunManager
        from bishop.config import reset_settings
        from tests.graph.conftest import quiet_alert

        monkeypatch.setenv("BISHOP_PUBLIC_DEMO", "true")
        reset_settings()
        try:
            written: list[object] = []
            monkeypatch.setattr("bishop.store.save_incident", lambda *a, **k: written.append(a))

            manager = RunManager()
            run = manager.start(quiet_alert(), alert_id="LEAK-1", submitted=True)
            run._done.wait(timeout=30)

            mine = [a for a in written if a and getattr(a[0], "incident_id", "") == "INC-LEAK-1"]
            assert mine == [], "a visitor's alert was written to the shared store"
            assert any(e.get("kind") == "not_persisted" for e in run.events)
        finally:
            reset_settings()

    def test_a_corpus_run_is_still_persisted_in_demo_mode(self, monkeypatch):
        """The corpus is synthetic and already public, so it still stores."""
        from bishop.api.runs import RunManager
        from bishop.config import reset_settings
        from tests.graph.conftest import quiet_alert

        monkeypatch.setenv("BISHOP_PUBLIC_DEMO", "true")
        reset_settings()
        try:
            written: list[object] = []
            monkeypatch.setattr("bishop.store.save_incident", lambda *a, **k: written.append(a))
            monkeypatch.setattr("bishop.store.init_db", lambda *a, **k: None)

            manager = RunManager()
            run = manager.start(quiet_alert(), alert_id="CORPUS-1")
            run._done.wait(timeout=30)

            mine = [a for a in written if a and getattr(a[0], "incident_id", "") == "INC-CORPUS-1"]
            assert mine, "a corpus run should still be stored"
        finally:
            reset_settings()


class TestTheHarnessCanReachEveryProvider:
    """`get_provider` is how the eval harness gets a model.

    It used to build only `anthropic`, while the console reached all four
    through BYOK. So `just eval-live` could score one of the four providers the
    README advertises and the other three could not be measured at all — the
    live path for Gemini, OpenAI and Azure had no way to produce a number.

    Resolution is offline: building a provider constructs an HTTP client and
    sends nothing, so these make no network calls.
    """

    @pytest.mark.parametrize(
        ("provider", "variable", "key"),
        [
            ("openai", "OPENAI_API_KEY", "sk-" + "x" * 40),
            ("gemini", "GEMINI_API_KEY", "AQ." + "x" * 30),
            ("azure-openai", "AZURE_OPENAI_API_KEY", "x" * 32),
        ],
    )
    def test_a_provider_is_built_from_its_environment_key(
        self, provider, variable, key, monkeypatch
    ):
        from bishop.models import get_provider

        monkeypatch.setenv("BISHOP_MODEL_PROVIDER", provider)
        monkeypatch.setenv(variable, key)
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")

        assert get_provider().name == provider

    def test_a_badly_shaped_key_raises_the_documented_type(self, monkeypatch):
        """`parse` raises a `ValueError` because it is written for a request
        handler. `get_provider` promises a `ModelError`, and a caller catching
        the documented type would have missed this entirely."""
        from bishop.models import ModelError, get_provider

        monkeypatch.setenv("BISHOP_MODEL_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "sk-this-is-not-a-gemini-key")

        with pytest.raises(ModelError, match="unusable"):
            get_provider()

    def test_the_default_is_still_the_mock(self, monkeypatch):
        from bishop.models import get_provider, is_offline

        monkeypatch.delenv("BISHOP_MODEL_PROVIDER", raising=False)
        assert is_offline(get_provider())

    def test_selecting_a_provider_without_its_key_fails_loudly(self, monkeypatch):
        """Never a silent fall back to the mock: that produces numbers nobody
        can reproduce, attributed to a model that was never called."""
        from bishop.models import ModelError, get_provider

        monkeypatch.setenv("BISHOP_MODEL_PROVIDER", "gemini")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)

        with pytest.raises(ModelError, match="GEMINI_API_KEY is not set"):
            get_provider()

    def test_an_unknown_provider_lists_the_real_ones(self, monkeypatch):
        from bishop.models import ModelError, get_provider

        monkeypatch.setenv("BISHOP_MODEL_PROVIDER", "llama-on-a-toaster")
        with pytest.raises(ModelError) as caught:
            get_provider()
        for name in ("mock", "anthropic", "gemini", "openai", "azure-openai"):
            assert name in str(caught.value)

    def test_the_model_id_can_be_overridden(self, monkeypatch):
        from bishop.models import get_provider

        monkeypatch.setenv("BISHOP_MODEL_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "AQ." + "x" * 30)
        monkeypatch.setenv("BISHOP_MODEL_ID", "gemini-flash-latest")

        assert get_provider().model_id == "gemini-flash-latest"
