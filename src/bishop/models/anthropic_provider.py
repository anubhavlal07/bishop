"""The live Claude provider.

Imported lazily and only when `BISHOP_MODEL_PROVIDER=anthropic` and a key is
present. The `anthropic` package is an optional extra (`uv sync --extra live`),
so a default install has no provider dependency at all and cannot accidentally
make a network call.

Structured output is requested through `output_config.format` rather than by
asking for JSON in the prompt and hoping. A verdict parsed out of prose is a
verdict with a parser between it and the truth.
"""

from __future__ import annotations

import os
from typing import Any

from bishop.models.base import (
    ModelError,
    ModelResponse,
    Usage,
    extract_json,
)

DEFAULT_MODEL = "claude-opus-5"


class AnthropicProvider:
    """Claude behind Bishop's model interface."""

    name = "anthropic"

    def __init__(
        self,
        *,
        model_id: str | None = None,
        api_key: str | None = None,
        timeout: float = 120.0,
        max_retries: int = 2,
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on the extra
            raise ModelError(
                "the anthropic package is not installed. Bishop's default provider is the "
                "offline mock; for a live run install the extra with `uv sync --extra live`."
            ) from exc

        self.model_id = model_id or os.environ.get("BISHOP_MODEL_ID", DEFAULT_MODEL)
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"),
            timeout=timeout,
            max_retries=max_retries,
        )

    def complete(
        self,
        *,
        system: str,
        prompt: str,
        task: str,
        schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
    ) -> ModelResponse:
        import anthropic

        request: dict[str, Any] = {
            "model": self.model_id,
            "max_tokens": max_tokens,
            "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": prompt}],
            "thinking": {"type": "adaptive"},
        }
        if schema is not None:
            request["output_config"] = {
                "format": {"type": "json_schema", "schema": schema},
                "effort": os.environ.get("BISHOP_MODEL_EFFORT", "high"),
            }

        try:
            response = self._client.messages.create(**request)
        except anthropic.RateLimitError as exc:
            raise ModelError(f"{task}: rate limited by the provider") from exc
        except anthropic.APIStatusError as exc:
            raise ModelError(f"{task}: provider returned {exc.status_code}") from exc
        except anthropic.APIConnectionError as exc:
            raise ModelError(f"{task}: could not reach the provider") from exc

        if response.stop_reason == "refusal":
            detail = getattr(response.stop_details, "category", None)
            raise ModelError(f"{task}: the model declined to answer (category: {detail})")

        text = "".join(block.text for block in response.content if block.type == "text")
        usage = Usage(
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0) or 0,
        )
        data = extract_json(text) if schema is not None else None
        return ModelResponse(
            text=text,
            data=data,
            usage=usage,
            model=self.model_id,
            stop_reason=response.stop_reason or "end_turn",
        )
