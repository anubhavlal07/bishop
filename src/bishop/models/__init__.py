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

#: Set to `anthropic` for a live run. Anything else, including unset, is the mock.
PROVIDER_ENV = "BISHOP_MODEL_PROVIDER"


def get_provider(name: str | None = None) -> ModelProvider:
    """Resolve the configured provider.

    Raises rather than degrading when a live provider is asked for and cannot be
    built — see the module docstring.
    """
    selected = (name or os.environ.get(PROVIDER_ENV) or "mock").strip().lower()

    if selected in {"mock", "", "offline"}:
        return MockModel()

    if selected == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise ModelError(
                f"{PROVIDER_ENV}=anthropic but ANTHROPIC_API_KEY is not set. "
                f"Unset {PROVIDER_ENV} to run offline against the mock."
            )
        from bishop.models.anthropic_provider import AnthropicProvider

        return AnthropicProvider()

    raise ModelError(
        f"unknown model provider {selected!r}. Bishop ships 'mock' (the default) and 'anthropic'."
    )


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
