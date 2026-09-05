"""The model interface every Bishop node talks to.

One wrapper, three properties that matter:

**Structured by default.** Nodes ask for JSON against a schema, not prose.
Free text from a model is not something a downstream node can act on, and
parsing it back out is where hallucinations get laundered into fields.

**Metered.** Every call returns token counts, and the pricing table turns those
into a number the scorecard can publish. Cost per alert is a headline metric in
`PLAN.md` §8, so it is measured rather than estimated.

**Swappable, with the mock as the default.** `MockModel` is not a test double
bolted on afterwards — it is the provider `just demo` uses. A live provider
switches on only when its API key is present.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


class ModelError(RuntimeError):
    """A model call failed in a way the node cannot proceed through."""


class SchemaViolation(ModelError):
    """The model returned JSON that does not satisfy the requested schema."""


@dataclass(slots=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
        )


PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-haiku-4-5": (1.00, 5.00),
    "mock": (0.0, 0.0),
}


def cost_usd(model: str, usage: Usage) -> float:
    """Dollars for one call. Unknown models cost 0 and say so in the scorecard."""
    rates = PRICING.get(model)
    if rates is None:
        return 0.0
    input_rate, output_rate = rates
    return (usage.input_tokens * input_rate + usage.output_tokens * output_rate) / 1_000_000


@dataclass(slots=True)
class ModelResponse:
    text: str
    data: dict[str, Any] | None = None
    usage: Usage = field(default_factory=Usage)
    model: str = "mock"
    stop_reason: str = "end_turn"

    @property
    def cost_usd(self) -> float:
        return cost_usd(self.model, self.usage)


@runtime_checkable
class ModelProvider(Protocol):
    """What a Bishop node is allowed to ask a model for."""

    name: str
    model_id: str

    def complete(
        self,
        *,
        system: str,
        prompt: str,
        task: str,
        schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
    ) -> ModelResponse:
        """One structured completion.

        `task` names the calling node. It is written to the audit chain, and the
        mock provider uses it to decide which shape to return.
        """
        ...


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> dict[str, Any]:
    """Pull a JSON object out of a model response.

    Needed even with structured output enabled, because a provider that falls
    back to prose on an error should fail loudly here rather than silently
    return an empty verdict.
    """
    candidate = text.strip()
    if fenced := _FENCE.search(candidate):
        candidate = fenced.group(1).strip()
    if not candidate.startswith("{"):
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end <= start:
            raise SchemaViolation(f"no JSON object in model output: {text[:200]!r}")
        candidate = candidate[start : end + 1]
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise SchemaViolation(f"model output was not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SchemaViolation(f"expected a JSON object, got {type(parsed).__name__}")
    return parsed


def require_fields(data: dict[str, Any], required: tuple[str, ...], *, task: str) -> None:
    """Fail loudly when a required field is missing.

    Bishop never fills in a missing field with a default — a verdict with a
    silently-defaulted confidence is worse than a failed run, because it looks
    like an answer.
    """
    missing = [key for key in required if key not in data]
    if missing:
        raise SchemaViolation(f"{task}: model omitted required fields {missing}")
