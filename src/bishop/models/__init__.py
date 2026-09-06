"""Model providers.

`get_provider()` returns the mock unless a live provider is explicitly selected
*and* its credentials are present. Both conditions, deliberately: an exported
`ANTHROPIC_API_KEY` left over from another project should not silently turn a
`just demo` into a billed run, and selecting a provider without a key should
fail loudly rather than quietly fall back to the mock and produce numbers
nobody can reproduce.
"""

from __future__ import annotations

import os

from bishop.models.base import (
    PRICING,
    ModelError,
    ModelProvider,
    ModelResponse,
    SchemaViolation,
    Usage,
    cost_usd,
    extract_json,
    require_fields,
)
from bishop.models.mock import MockModel

PROVIDER_ENV = "BISHOP_MODEL_PROVIDER"


def get_provider(name: str | None = None) -> ModelProvider:
    """Resolve the configured provider.

    Raises rather than degrading when a live provider is asked for and cannot be
    built — see the module docstring.
    """
    selected = (name or os.environ.get(PROVIDER_ENV) or "mock").strip().lower()

    if selected in {"mock", "", "offline"}:
        return MockModel()

    if selected == "anthropic" and os.environ.get("ANTHROPIC_API_KEY"):
        from bishop.models.anthropic_provider import AnthropicProvider

        return AnthropicProvider()

    return _from_environment(selected)


#: Where each provider's key lives when Bishop is driving rather than a browser.
#:
#: The console reaches every provider through BYOK, one key per request. The
#: eval harness reaches only what `get_provider` builds, and for a long time
#: that was `anthropic` alone — so `just eval-live` could measure one of the
#: four providers the README advertises, and the other three had no way to be
#: scored at all. Same provider classes, credentials from the environment
#: instead of a header.
_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "azure-openai": "AZURE_OPENAI_API_KEY",
}


def _from_environment(selected: str) -> ModelProvider:
    from bishop.models.byok import build_provider
    from bishop.models.credentials import PROVIDERS, parse

    if selected not in PROVIDERS:
        known = ", ".join(["mock", *sorted(PROVIDERS)])
        raise ModelError(f"unknown model provider {selected!r}. Bishop ships: {known}.")

    variable = _KEY_ENV[selected]
    key = os.environ.get(variable)
    if not key:
        raise ModelError(
            f"{PROVIDER_ENV}={selected} but {variable} is not set. "
            f"Unset {PROVIDER_ENV} to run offline against the mock."
        )

    from bishop.models.credentials import CredentialError

    try:
        credentials = parse(
            selected,
            key,
            os.environ.get("BISHOP_MODEL_ID"),
            os.environ.get("AZURE_OPENAI_ENDPOINT"),
        )
    except CredentialError as exc:
        # `parse` raises a `ValueError` because it is written for a request
        # handler that turns one into a 422. `get_provider` promises callers a
        # `ModelError`, and a caller catching the documented type would have
        # missed this one entirely.
        raise ModelError(f"{variable} is set but unusable: {exc}") from exc

    return build_provider(credentials)


def is_offline(provider: ModelProvider) -> bool:
    return getattr(provider, "name", "") == "mock"


__all__ = [
    "PRICING",
    "PROVIDER_ENV",
    "MockModel",
    "ModelError",
    "ModelProvider",
    "ModelResponse",
    "SchemaViolation",
    "Usage",
    "cost_usd",
    "extract_json",
    "get_provider",
    "is_offline",
    "require_fields",
]
