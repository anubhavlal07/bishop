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
            "generationConfig": {"maxOutputTokens": max_tokens},
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
    """Gemini's schema dialect is OpenAPI-flavoured and rejects some keywords."""
    if not isinstance(schema, dict):
        return schema
    dropped = {"additionalProperties", "$schema", "definitions", "$defs", "default"}
    out = {k: v for k, v in schema.items() if k not in dropped}
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
            max_tokens=16,
        )
    except ModelError as exc:
        return {"ok": False, "provider": credentials.provider, "detail": _sanitise(str(exc))}

    return {
        "ok": True,
        "provider": credentials.provider,
        "model": provider.model_id,
        "detail": f"responded in {response.usage.input_tokens + response.usage.output_tokens} tokens",
    }
