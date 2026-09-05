"""Deployment configuration, validated once at startup.

Bishop's defaults are tuned for a laptop: SQLite, no authentication, CORS open
to everything, the deterministic model. Every one of those is wrong for a
deployment that real users reach over the internet, and the failure mode of
getting it wrong is silent — an unauthenticated API serving security incidents
looks exactly like an authenticated one until somebody finds it.

So this module does two things. It reads configuration from the environment
into one validated object, and in `production` mode it **refuses to start**
when a setting is unsafe rather than warning about it. A warning in a log
nobody reads is not a control.

The environment name is the switch:

- `development` (default) — the laptop defaults. Auth optional, CORS open,
  SQLite allowed. Nothing here is enforced, and `/health` says so plainly.
- `production` — every check below is enforced at import time. The process
  exits rather than serving.

**What this deliberately does not do.** It does not invent secrets. If
`BISHOP_API_KEYS` is unset in production, Bishop stops; it does not generate a
key and print it, because a key that appears in a deploy log is not a secret.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from functools import lru_cache
from typing import Any, Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = [
    "ConfigError",
    "DeploymentSettings",
    "get_settings",
    "reset_settings",
]


class ConfigError(RuntimeError):
    """A deployment is configured in a way that is not safe to serve.

    Raised at startup, never at request time. A misconfiguration that only
    surfaces on the first request has already been serving for a while.
    """


Environment = Literal["development", "production"]


class DeploymentSettings(BaseSettings):
    """Everything that changes between a laptop and a deployment."""

    model_config = SettingsConfigDict(
        env_prefix="BISHOP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    environment: Environment = "development"

    api_keys: str = ""

    cors_origins: str = "*"

    rate_limit_per_minute: int = 120

    max_request_bytes: int = 1_048_576

    database_url: str = ""

    public_demo: bool = False

    #: Turn on in-house accounts: sign-in, roles, and an approver check on the
    #: containment gate. Off by default so a laptop run needs no user table.
    #: When on, `decided_by` in the audit chain comes from the session rather
    #: than from whatever the client sent.
    require_accounts: bool = False

    json_logs: bool = False
    log_level: str = "INFO"

    public_url: str = ""

    @field_validator("log_level")
    @classmethod
    def _upper(cls, value: str) -> str:
        return value.upper()

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(k.strip() for k in self.api_keys.split(",") if k.strip())

    @property
    def origins(self) -> tuple[str, ...]:
        return tuple(o.strip() for o in self.cors_origins.split(",") if o.strip())

    @property
    def auth_required(self) -> bool:
        """Auth is on whenever keys exist, and mandatory in production.

        Deliberately not a separate switch. A boolean that can disagree with
        whether any keys are configured is a boolean that will eventually be
        set wrong.
        """
        return bool(self.keys)

    @model_validator(mode="after")
    def _enforce_production(self) -> DeploymentSettings:
        if not self.is_production:
            return self

        problems: list[str] = []

        if not self.keys and not self.public_demo:
            problems.append(
                "BISHOP_API_KEYS is empty. A production API serving security incidents "
                "must authenticate. Generate one with `bishop keygen` and set it; Bishop "
                "will not invent a key for you, because a key printed into a deploy log "
                "is not a secret. If this deployment is a public demo over the synthetic "
                "corpus, set BISHOP_PUBLIC_DEMO=true instead — it makes that an explicit "
                "choice rather than a missing setting."
            )
        else:
            weak = [k for k in self.keys if len(k) < 32]
            if weak:
                problems.append(
                    f"{len(weak)} API key(s) are shorter than 32 characters. Use "
                    f"`bishop keygen`, which emits 43 characters of URL-safe randomness."
                )

        if "*" in self.origins:
            problems.append(
                "BISHOP_CORS_ORIGINS is '*'. Name the console's origin explicitly — "
                "with a wildcard, any page on the internet can read incident data from "
                "a browser that holds a key."
            )
        if not self.origins:
            problems.append("BISHOP_CORS_ORIGINS is empty. Name the console's origin.")

        if self.rate_limit_per_minute <= 0:
            problems.append(
                "BISHOP_RATE_LIMIT_PER_MINUTE is disabled. Every run costs model tokens, "
                "so an unlimited API is an unlimited bill."
            )

        url = self.database_url or os.environ.get("DATABASE_URL", "")
        if not self.public_demo:
            if not url:
                problems.append(
                    "No DATABASE_URL. Production defaults to SQLite under storage/, which "
                    "does not survive a container restart on most platforms — and an audit "
                    "chain that does not survive is not an audit chain."
                )
            elif url.startswith("sqlite"):
                problems.append(
                    "DATABASE_URL is SQLite. Use Postgres in production, for the same reason."
                )

        if self.public_demo:
            if self.rate_limit_per_minute > 60:
                problems.append(
                    f"BISHOP_PUBLIC_DEMO is on with a limit of {self.rate_limit_per_minute}/min. "
                    f"An unauthenticated endpoint needs a tighter one than a keyed deployment: "
                    f"set BISHOP_RATE_LIMIT_PER_MINUTE to 60 or less."
                )
            if self.keys:
                problems.append(
                    "BISHOP_PUBLIC_DEMO is on and BISHOP_API_KEYS is set. Pick one. A public "
                    "demo that also demands a key locks out the visitors it is for, and a "
                    "key baked into a public console's JavaScript protects nothing."
                )

        if problems:
            raise ConfigError(
                "Bishop refuses to start in production with this configuration:\n\n"
                + "\n\n".join(f"  - {p}" for p in problems)
                + "\n\nSet BISHOP_ENVIRONMENT=development to run with laptop defaults."
            )
        return self

    @property
    def durable_store_required(self) -> bool:
        """Whether production must be pointed at Postgres.

        True everywhere except a public demo, and the exception is reasoned
        rather than convenient. The requirement exists because an audit chain
        that does not survive a restart is not an audit chain. In demo mode
        there is no such chain to lose: alerts a visitor supplies are never
        written at all, and the only things stored are runs over the synthetic
        corpus committed to this repository, which can be reproduced by running
        them again.

        A DATABASE_URL is still used when one is set. This only stops Bishop
        refusing to start without one.
        """
        return not self.public_demo

    @property
    def persist_submitted_alerts(self) -> bool:
        """Whether an alert a visitor supplied may be written to the store.

        False in public-demo mode, and this is the load-bearing part of that
        mode rather than a detail. The store is shared and `/incidents` lists
        it, so persisting a submitted alert on an open deployment publishes one
        stranger's alert to every other visitor. Somebody pasting a real alert
        from their own SIEM into a demo box has not consented to that.

        Corpus runs are still persisted: those alerts are synthetic, committed
        to this repository, and already public.
        """
        return not self.public_demo

    def redacted(self) -> dict[str, Any]:
        """Safe to log and to serve from `/health`."""
        return {
            "environment": self.environment,
            "auth_required": self.auth_required,
            "api_keys_configured": len(self.keys),
            "cors_origins": list(self.origins),
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "max_request_bytes": self.max_request_bytes,
            "database": _describe_database(self.database_url or os.environ.get("DATABASE_URL", "")),
            "json_logs": self.json_logs,
            "public_demo": self.public_demo,
            "require_accounts": self.require_accounts,
            "persists_submitted_alerts": self.persist_submitted_alerts,
        }


def _describe_database(url: str) -> str:
    """The engine, never the credentials."""
    if not url:
        return "sqlite (default)"
    scheme = url.split("://", 1)[0]
    return f"{scheme} (configured)"


def generate_key() -> str:
    """A new API key. 32 bytes of randomness, URL-safe."""
    return secrets.token_urlsafe(32)


def key_matches(presented: str, accepted: tuple[str, ...]) -> bool:
    """Constant-time membership test.

    Hashed before comparison so every comparison is over a fixed 32 bytes: a
    plain `hmac.compare_digest` on the raw strings still leaks length, and
    length is a meaningful hint when keys are generated to a fixed size.
    """
    if not presented or not accepted:
        return False
    candidate = hashlib.sha256(presented.encode("utf-8")).digest()
    matched = False
    for key in accepted:
        if hmac.compare_digest(candidate, hashlib.sha256(key.encode("utf-8")).digest()):
            matched = True
    return matched


@lru_cache(maxsize=1)
def get_settings() -> DeploymentSettings:
    """The process-wide settings, validated once.

    Cached because validation is the expensive part and because settings that
    can change mid-process are settings that will differ between two requests.
    """
    return DeploymentSettings()


def reset_settings() -> None:
    """Drop the cache. For tests that change the environment."""
    get_settings.cache_clear()
