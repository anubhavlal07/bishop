"""Bring-your-own-key credentials, carried per request and never stored.

Bishop's deployment holds no model key. Each analyst supplies their own, it
lives in their browser, and it travels with the request that needs it. That is
a deliberate trade and it is worth being precise about what it buys and what it
costs.

**What it buys.** The server has no model secret to leak, rotate or bill. A
compromise of the API does not hand an attacker a key that can spend money.
Every user's spend is their own, and the deployment needs no payment
relationship with a model vendor at all.

**What it costs.** The key travels over the wire on every run, and it sits in
the browser's `localStorage`, which any script running on that origin can read.
So an XSS bug in the console is a key-theft bug. That is stated in the setup
modal rather than hidden, and it is the reason the console ships a strict CSP
and why the key is never put in a URL.

**The rules this module exists to enforce.**

1. A key is never logged. `Credentials.__repr__` redacts, so it cannot reach a
   log line by being interpolated into a message by accident.
2. A key is never written to the audit chain, an incident, or the store. The
   chain records the provider and model id, which is what makes a verdict
   reproducible; the key is not part of that.
3. A key is never echoed back from an endpoint.
4. The endpoint a key is sent to is not attacker-chosen. Azure needs a
   customer-specific hostname, so that one field is validated against an
   allowlist of suffixes — otherwise "bring your own endpoint" is a
   server-side request forgery primitive with a friendly name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "PROVIDERS",
    "CredentialError",
    "Credentials",
    "provider_catalogue",
]


class CredentialError(ValueError):
    """Supplied credentials are unusable. The message is shown to the user."""


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """One model vendor Bishop can talk to."""

    key: str
    label: str
    default_model: str
    #: Models offered in the console's picker. Not a restriction — any id the
    #: vendor accepts works — just the ones worth suggesting.
    models: tuple[str, ...]
    #: Roughly what a key looks like, so an obvious paste error is caught in the
    #: browser rather than after a failed run. Deliberately loose: vendors
    #: change their formats and a strict check would reject valid keys.
    key_hint: str
    key_pattern: str
    #: Azure needs a customer-specific endpoint; nothing else does.
    needs_endpoint: bool = False
    help_url: str = ""


PROVIDERS: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        key="anthropic",
        label="Anthropic",
        default_model="claude-opus-5",
        models=("claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5-20251001"),
        key_hint="starts with sk-ant-",
        key_pattern=r"^sk-ant-[A-Za-z0-9_\-]{20,}$",
        help_url="https://console.anthropic.com/settings/keys",
    ),
    "openai": ProviderSpec(
        key="openai",
        label="OpenAI",
        default_model="gpt-4.1",
        models=("gpt-4.1", "gpt-4.1-mini", "o4-mini"),
        key_hint="starts with sk-",
        key_pattern=r"^sk-[A-Za-z0-9_\-]{20,}$",
        help_url="https://platform.openai.com/api-keys",
    ),
    "gemini": ProviderSpec(
        key="gemini",
        label="Google Gemini",
        default_model="gemini-2.5-pro",
        models=("gemini-2.5-pro", "gemini-2.5-flash"),
        key_hint="starts with AIza",
        key_pattern=r"^AIza[A-Za-z0-9_\-]{30,}$",
        help_url="https://aistudio.google.com/apikey",
    ),
    "azure-openai": ProviderSpec(
        key="azure-openai",
        label="Azure OpenAI",
        default_model="gpt-4.1",
        models=("gpt-4.1", "gpt-4.1-mini"),
        key_hint="32 hex characters, or an Entra token",
        key_pattern=r"^[A-Za-z0-9_\-\.]{20,}$",
        needs_endpoint=True,
        help_url="https://learn.microsoft.com/azure/ai-services/openai/",
    ),
    "mock": ProviderSpec(
        key="mock",
        label="Deterministic (no key)",
        default_model="mock",
        models=("mock",),
        key_hint="no key needed",
        key_pattern=r"^$",
    ),
}

#: Hostnames an Azure endpoint may end with. Without this, the endpoint field is
#: an arbitrary URL that the server will send a request to with a secret
#: attached — which is server-side request forgery, and the fact that the user
#: typed the URL themselves does not make it safe, because the user is not
#: necessarily the person who chose it.
_ALLOWED_ENDPOINT_SUFFIXES = (
    ".openai.azure.com",
    ".cognitiveservices.azure.com",
    ".services.ai.azure.com",
)


@dataclass(frozen=True, slots=True)
class Credentials:
    """One user's model access, for the lifetime of one request.

    Frozen and never persisted. It is built from request headers, handed to a
    provider, and dropped when the run ends.
    """

    provider: str
    api_key: str = field(repr=False, default="")
    model_id: str = ""
    endpoint: str = ""

    def __repr__(self) -> str:
        # Explicit rather than relying on `field(repr=False)` alone, so that a
        # future field cannot silently become loggable.
        return (
            f"Credentials(provider={self.provider!r}, model_id={self.model_id!r}, key=<redacted>)"
        )

    __str__ = __repr__

    @property
    def spec(self) -> ProviderSpec:
        return PROVIDERS[self.provider]

    @property
    def is_mock(self) -> bool:
        return self.provider == "mock"

    def describe(self) -> dict[str, Any]:
        """Safe to log, to return, and to write to the audit chain."""
        return {
            "provider": self.provider,
            "model_id": self.model_id
            or (self.spec.default_model if self.provider in PROVIDERS else ""),
        }


def parse(
    provider: str | None,
    api_key: str | None,
    model_id: str | None = None,
    endpoint: str | None = None,
) -> Credentials:
    """Validate what a client sent, or raise with a message worth showing.

    Validation is shape-only. Whether the key actually works is a question for
    the vendor, answered by `verify()` — guessing here would mean rejecting
    valid keys whenever a vendor changes its format.
    """
    name = (provider or "mock").strip().lower()
    if name not in PROVIDERS:
        known = ", ".join(sorted(PROVIDERS))
        raise CredentialError(f"unknown provider {name!r}. Bishop supports: {known}")

    spec = PROVIDERS[name]
    key = (api_key or "").strip()
    model = (model_id or "").strip() or spec.default_model

    if name == "mock":
        return Credentials(provider="mock", model_id="mock")

    if not key:
        raise CredentialError(f"{spec.label} needs an API key ({spec.key_hint}).")
    if not re.match(spec.key_pattern, key):
        raise CredentialError(
            f"That does not look like a {spec.label} key — it {spec.key_hint}. "
            f"Nothing was sent to {spec.label}."
        )

    resolved_endpoint = (endpoint or "").strip().rstrip("/")
    if spec.needs_endpoint:
        if not resolved_endpoint:
            raise CredentialError(
                f"{spec.label} needs your resource endpoint, e.g. "
                f"https://my-resource.openai.azure.com"
            )
        _check_endpoint(resolved_endpoint, spec.label)

    return Credentials(provider=name, api_key=key, model_id=model, endpoint=resolved_endpoint)


def _check_endpoint(endpoint: str, label: str) -> None:
    from urllib.parse import urlparse

    parsed = urlparse(endpoint)
    if parsed.scheme != "https":
        raise CredentialError(f"the {label} endpoint must be https.")
    host = (parsed.hostname or "").lower()
    if not host.endswith(_ALLOWED_ENDPOINT_SUFFIXES):
        allowed = ", ".join(_ALLOWED_ENDPOINT_SUFFIXES)
        raise CredentialError(
            f"that endpoint is not an Azure OpenAI hostname. Bishop only sends keys to "
            f"{allowed} — an unrestricted endpoint field would let this server be pointed "
            f"at anything with a secret attached."
        )


def provider_catalogue() -> list[dict[str, Any]]:
    """What the console's setup modal renders. Carries no secrets."""
    return [
        {
            "key": spec.key,
            "label": spec.label,
            "default_model": spec.default_model,
            "models": list(spec.models),
            "key_hint": spec.key_hint,
            "needs_endpoint": spec.needs_endpoint,
            "help_url": spec.help_url,
        }
        for spec in PROVIDERS.values()
    ]
