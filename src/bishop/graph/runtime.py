"""Per-run services the nodes reach for: the model, the audit chain, settings.

Passed through LangGraph's `configurable` rather than held in module state, so
two runs in one process — which is what the API server does — cannot write into
each other's audit chain.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from langchain_core.runnables import RunnableConfig

from bishop.audit import AuditChain
from bishop.models import ModelProvider, get_provider

RUNTIME_KEY = "bishop_runtime"


@dataclass(slots=True)
class Settings:
    max_critic_rounds: int = 1
    escalation_threshold: float = 0.45
    surfaces: tuple[str, ...] = ("identity", "endpoint", "network", "threatintel", "context")
    max_tokens: int = 4096


@dataclass(slots=True)
class Runtime:
    run_id: str
    provider: ModelProvider
    chain: AuditChain
    settings: Settings = field(default_factory=Settings)
    events: list[dict[str, Any]] = field(default_factory=list)
    listener: Callable[[dict[str, Any]], None] | None = None

    def emit(self, kind: str, **payload: Any) -> None:
        event = {"kind": kind, **payload}
        self.events.append(event)
        if self.listener is not None:
            with suppress(Exception):
                self.listener(event)


def build_runtime(
    *,
    run_id: str,
    provider: ModelProvider | None = None,
    audit_path: Path | None = None,
    settings: Settings | None = None,
    listener: Callable[[dict[str, Any]], None] | None = None,
) -> Runtime:
    return Runtime(
        run_id=run_id,
        provider=provider or get_provider(),
        chain=AuditChain(run_id=run_id, path=audit_path),
        settings=settings or Settings(),
        listener=listener,
    )


def runtime_config(runtime: Runtime, *, thread_id: str | None = None) -> dict[str, Any]:
    """The `config` to hand LangGraph's `invoke`/`stream`."""
    return {
        "configurable": {
            RUNTIME_KEY: runtime,
            "thread_id": thread_id or runtime.run_id,
        }
    }


def get_runtime(config: RunnableConfig | None) -> Runtime:
    """Pull the runtime out of a node's config, failing loudly if absent.

    A node that silently built its own runtime would write to a different audit
    chain than the rest of the run, which is the sort of bug that only shows up
    when someone tries to verify the chain months later.
    """
    configurable = (config or {}).get("configurable") or {}
    runtime = configurable.get(RUNTIME_KEY)
    if runtime is None:
        raise RuntimeError(
            "no Bishop runtime in the graph config. Build one with `build_runtime` and "
            "pass `runtime_config(runtime)` to invoke()."
        )
    return runtime
