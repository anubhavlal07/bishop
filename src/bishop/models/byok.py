"""Providers built from a user's own key, over plain HTTP.

Bishop already had an Anthropic provider that used the vendor SDK. Adding three
more vendors that way would mean three more dependencies in the runtime image,
each with its own release cadence, for four HTTP calls that are all the same
shape: post JSON, read JSON. So these speak the REST APIs directly through
`httpx`, which Bishop already depends on.

The Anthropic SDK path stays for the server-configured case — it handles
retries, streaming and prompt caching properly. This module is for the
bring-your-own-key path, where the request is one short structured completion
and the key belongs to whoever is sitting in front of the console.

**Every provider here must behave identically in three ways**, because the
graph cannot tell them apart:

1. Return valid JSON matching the requested schema, or raise `ModelError`. A
   node that receives prose where it expected an object produces an empty
   verdict, and an empty verdict looks like a clean alert.
2. Report token usage, so cost is measured rather than modelled.
3. Never let a vendor error message reach the user with the key in it. Vendors
   echo request context in errors, and the sanitiser below is the last place
   that can be caught.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from bishop.models.base import ModelError, ModelResponse, Usage, extract_json
from bishop.models.credentials import Credentials

__all__ = ["build_provider", "verify_credentials"]

TIMEOUT = httpx.Timeout(90.0, connect=10.0)

_SECRET_SHAPED = re.compile(r"(sk-ant-[\w\-]+|sk-[\w\-]{20,}|AIza[\w\-]{30,}|Bearer\s+\S+)")


def _sanitise(message: str) -> str:
    return _SECRET_SHAPED.sub("<redacted>", message)[:400]


#: Finish reasons that mean the model ran out of room mid-answer. Worth naming
#: separately: a truncated response fails downstream as "not valid JSON", which
#: sends whoever debugs it looking at the schema rather than at the budget.
_TRUNCATED = {"MAX_TOKENS", "max_tokens", "length"}


def _check_not_truncated(finish_reason: str | None, provider: str, max_tokens: int) -> None:
    """Fail on a half-finished answer, naming the real cause.

    Measured against the live Gemini API: a 200-token budget was spent 189 on
    thinking and 7 on content, and the reply came back as the prose "Here is
    the JSON requested:" with a 200 status. Without this the next thing to fail
    is the JSON parser, and the message points at the schema rather than at the
    budget that actually ran out.
    """
    if finish_reason and finish_reason in _TRUNCATED:
        raise ModelError(
            f"{provider}: the model hit the {max_tokens}-token output limit before "
            f"finishing its answer, so the result is incomplete. On Gemini this is "
            f"usually thinking tokens consuming the budget."
        )


class _HttpProvider:
    """Shared plumbing: one POST, JSON in, JSON out, errors sanitised."""

    name = "byok"

    def __init__(self, credentials: Credentials) -> None:
        self._credentials = credentials
        self.model_id = credentials.model_id or credentials.spec.default_model

    def _post(self, url: str, *, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = httpx.post(url, headers=headers, json=body, timeout=TIMEOUT)
        except httpx.TimeoutException as exc:
            raise ModelError(f"{self.name}: the model did not respond in time") from exc
        except httpx.HTTPError as exc:
            raise ModelError(f"{self.name}: could not reach the provider") from exc

        if response.status_code == 401 or response.status_code == 403:
            raise ModelError(f"{self.name}: the API key was rejected. Check it in Settings.")
        if response.status_code == 429:
            raise ModelError(f"{self.name}: rate limited by the provider. Try again shortly.")
        if response.status_code >= 400:
            raise ModelError(
                f"{self.name}: provider returned {response.status_code} — {_sanitise(response.text)}"
            )

        try:
            return response.json()
        except ValueError as exc:
            raise ModelError(f"{self.name}: the provider returned a non-JSON body") from exc


class AnthropicHttp(_HttpProvider):
    name = "anthropic"

    def complete(
        self,
        *,
        system: str,
        prompt: str,
        task: str,
        schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
    ) -> ModelResponse:
        body: dict[str, Any] = {
            "model": self.model_id,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        if schema is not None:
            body["output_config"] = {"format": {"type": "json_schema", "schema": schema}}

        payload = self._post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self._credentials.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            body=body,
        )
        text = "".join(
            block.get("text", "")
            for block in payload.get("content", [])
            if block.get("type") == "text"
        )
        _check_not_truncated(payload.get("stop_reason"), self.name, max_tokens)
        usage = payload.get("usage", {})
        return ModelResponse(
            text=text,
            data=extract_json(text) if schema is not None else None,
            usage=Usage(
                input_tokens=usage.get("input_tokens", 0),
                output_tokens=usage.get("output_tokens", 0),
            ),
            model=self.model_id,
            stop_reason=payload.get("stop_reason") or "end_turn",
        )


class OpenAIHttp(_HttpProvider):
    name = "openai"
    _base = "https://api.openai.com/v1"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._credentials.api_key}",
            "Content-Type": "application/json",
        }

    def _url(self) -> str:
        return f"{self._base}/chat/completions"

    def _body(
        self, system: str, prompt: str, schema: dict[str, Any] | None, max_tokens: int
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_completion_tokens": max_tokens,
        }
        if schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "bishop", "schema": _strict(schema), "strict": True},
            }
        return body

    def complete(
        self,
        *,
        system: str,
        prompt: str,
        task: str,
        schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
    ) -> ModelResponse:
        payload = self._post(
            self._url(),
            headers=self._headers(),
            body=self._body(system, prompt, schema, max_tokens),
        )
        choices = payload.get("choices") or []
        if not choices:
            raise ModelError(f"{self.name}: the provider returned no choices")
        text = choices[0].get("message", {}).get("content") or ""
        _check_not_truncated(choices[0].get("finish_reason"), self.name, max_tokens)
        usage = payload.get("usage", {})
        return ModelResponse(
            text=text,
            data=extract_json(text) if schema is not None else None,
            usage=Usage(
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
            ),
            model=self.model_id,
            stop_reason=choices[0].get("finish_reason") or "stop",
        )


class AzureOpenAIHttp(OpenAIHttp):
    """Azure speaks the OpenAI wire format at a customer-specific host.

    The endpoint was validated against an allowlist in `credentials.py` before
    reaching here — an unrestricted endpoint plus a secret is server-side
    request forgery with a friendly name.
    """

    name = "azure-openai"
    api_version = "2024-10-21"

    def _headers(self) -> dict[str, str]:
        return {"api-key": self._credentials.api_key, "Content-Type": "application/json"}

    def _url(self) -> str:
        return (
            f"{self._credentials.endpoint}/openai/deployments/{self.model_id}"
            f"/chat/completions?api-version={self.api_version}"
        )


class GeminiHttp(_HttpProvider):
    name = "gemini"

    def complete(
        self,
        *,
        system: str,
        prompt: str,
        task: str,
        schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
    ) -> ModelResponse:
        body: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                # Set on every call, not only the schema'd ones. Thinking is on
                # by default on Gemini 3.x and `maxOutputTokens` covers thinking
                # *and* output, so a small budget is spent entirely on thoughts.
                # Measured against the live API: a 200-token budget went 189 on
                # thoughts and 7 on content, and the reply arrived as the prose
                # "Here is the JSON requested:" with a 200 status — a node handed
                # prose where it expected an object yields an empty verdict, and
                # an empty verdict reads as a clean alert. The 16-token
                # connectivity ping in `verify_credentials` truncated the same
                # way and told users their valid key had been rejected.
                #
                # Turned down rather than up: Bishop asks this path for one
                # structured extraction, where the reasoning adds little, and
                # raising budgets instead burns ~200 discarded tokens per call.
                "thinkingConfig": {"thinkingLevel": "low"},
            },
        }
        if schema is not None:
            body["generationConfig"]["responseMimeType"] = "application/json"
            body["generationConfig"]["responseSchema"] = _gemini_schema(schema)

        payload = self._post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_id}:generateContent",
            headers={
                "x-goog-api-key": self._credentials.api_key,
                "Content-Type": "application/json",
            },
            body=body,
        )
        candidates = payload.get("candidates") or []
        if not candidates:
            reason = (payload.get("promptFeedback") or {}).get("blockReason")
            raise ModelError(
                f"{self.name}: no candidates returned" + (f" (blocked: {reason})" if reason else "")
            )
        text = "".join(
            part.get("text", "") for part in candidates[0].get("content", {}).get("parts", [])
        )
        _check_not_truncated(candidates[0].get("finishReason"), self.name, max_tokens)
        usage = payload.get("usageMetadata", {})
        return ModelResponse(
            text=text,
            data=extract_json(text) if schema is not None else None,
            usage=Usage(
                input_tokens=usage.get("promptTokenCount", 0),
                output_tokens=usage.get("candidatesTokenCount", 0),
            ),
            model=self.model_id,
            stop_reason=candidates[0].get("finishReason") or "STOP",
        )


def _strict(schema: dict[str, Any]) -> dict[str, Any]:
    """OpenAI's strict mode requires every property to be required.

    Rather than hand-maintaining a second copy of each schema, the constraint
    is applied here: `additionalProperties: false` everywhere, and `required`
    listing every key. Optional fields come back as null instead of absent,
    which the nodes already tolerate.
    """
    if not isinstance(schema, dict):
        return schema
    out = dict(schema)
    if out.get("type") == "object":
        properties = out.get("properties") or {}
        out["properties"] = {k: _strict(v) for k, v in properties.items()}
        out["required"] = list(properties)
        out["additionalProperties"] = False
    elif out.get("type") == "array" and "items" in out:
        out["items"] = _strict(out["items"])
    return out


def _gemini_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Translate a JSON Schema into Gemini's dialect.

    Gemini validates against a protobuf definition rather than JSON Schema, and
    the differences are not cosmetic — they are 400s. Two matter here.

    **A union type is a list, and proto has no list-typed field.** JSON Schema
    writes an optional string as `{"type": ["string", "null"]}`; Gemini rejects
    it with `Proto field is not repeating, cannot start list`. The equivalent is
    a single type plus `nullable`. This is not hypothetical: `SYNTHESIS_SCHEMA`
    has exactly one such property (`escalation_reason`), and it failed every
    live synthesis call until this collapsed it.

    **`anyOf` around a null is the same construct spelled differently**, and is
    normalised the same way.

    Unknown keywords are dropped rather than passed through, because Gemini
    rejects the whole request on the first one it does not recognise.
    """
    if not isinstance(schema, dict):
        return schema

    dropped = {
        "additionalProperties",
        "$schema",
        "definitions",
        "$defs",
        "default",
        "title",
        "examples",
        "const",
        "exclusiveMinimum",
        "exclusiveMaximum",
    }
    out = {k: v for k, v in schema.items() if k not in dropped}

    # `anyOf: [{...}, {"type": "null"}]` -> the non-null branch, marked nullable.
    if "anyOf" in out:
        branches = [b for b in out.pop("anyOf") if isinstance(b, dict)]
        concrete = [b for b in branches if b.get("type") != "null"]
        if len(branches) != len(concrete):
            out["nullable"] = True
        if concrete:
            merged = dict(concrete[0])
            merged.update({k: v for k, v in out.items() if k != "nullable"})
            out = {**merged, **({"nullable": True} if out.get("nullable") else {})}

    # `type: ["string", "null"]` -> `type: "string"` + `nullable: true`.
    declared = out.get("type")
    if isinstance(declared, list):
        concrete_types = [t for t in declared if t != "null"]
        if len(concrete_types) != len(declared):
            out["nullable"] = True
        # More than one concrete type has no proto equivalent; the first is the
        # one the caller actually means, and guessing beyond that would be worse
        # than a predictable narrowing.
        out["type"] = concrete_types[0] if concrete_types else "string"

    if "properties" in out:
        out["properties"] = {k: _gemini_schema(v) for k, v in out["properties"].items()}
    if "items" in out:
        out["items"] = _gemini_schema(out["items"])
    return out


_BUILDERS = {
    "anthropic": AnthropicHttp,
    "openai": OpenAIHttp,
    "azure-openai": AzureOpenAIHttp,
    "gemini": GeminiHttp,
}


def build_provider(credentials: Credentials):
    """A provider for one run, from one user's credentials."""
    if credentials.is_mock:
        from bishop.models.mock import MockModel

        return MockModel()
    builder = _BUILDERS.get(credentials.provider)
    if builder is None:
        raise ModelError(f"no provider implementation for {credentials.provider!r}")
    return builder(credentials)


def verify_credentials(credentials: Credentials) -> dict[str, Any]:
    """One cheap call, to tell the user their key works before they rely on it.

    Worth doing at setup rather than discovering it three minutes into a run:
    the failure is the same either way, but here it costs one token and is
    attached to the field the user just typed.
    """
    if credentials.is_mock:
        return {"ok": True, "provider": "mock", "model": "mock", "detail": "no key needed"}

    provider = build_provider(credentials)
    try:
        response = provider.complete(
            system="You are a connectivity check. Reply with the single word OK.",
            prompt="Reply with OK.",
            task="verify",
            # Not 16. A thinking model spends its budget on thoughts before it
            # writes anything, so a tiny ping truncates and reads as a bad key.
            max_tokens=256,
        )
    except ModelError as exc:
        return {"ok": False, "provider": credentials.provider, "detail": _sanitise(str(exc))}

    return {
        "ok": True,
        "provider": credentials.provider,
        "model": provider.model_id,
        "detail": f"responded in {response.usage.input_tokens + response.usage.output_tokens} tokens",
    }
