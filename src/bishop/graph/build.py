"""The graph topology.

    ingest → triage_supervisor ──Send──▶ investigate xN ──▶ synthesis
                                                                 │
                                                     ┌───────────┴───────────┐
                                                     ▼                       │
                                            adversarial_critic ──────────────┘
                                                     │  (bounded)
                                                     ▼
                                             response_planner
                                                     ▼
                                        ╔════════════════════════╗
                                        ║  response_gate         ║  interrupt()
                                        ╚════════════════════════╝
                                                     ▼
                                             response_execute (mocked)
                                                     ▼
                                                  report

`Send` is what makes the fan-out real rather than a loop wearing a costume: the
supervisor returns one `Send` per dispatched surface and LangGraph runs them
concurrently, merging their writes through the `reports` reducer.

The checkpointer is not optional. `interrupt()` suspends the run mid-graph and
the state has to live somewhere until a human answers, which may be hours.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Literal, Optional

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from bishop.graph.nodes.adversarial_critic import adversarial_critic
from bishop.graph.nodes.ingest import ingest
from bishop.graph.nodes.investigators import investigate
from bishop.graph.nodes.report import report
from bishop.graph.nodes.response_execute import response_execute
from bishop.graph.nodes.response_gate import response_gate
from bishop.graph.nodes.response_planner import response_planner
from bishop.graph.nodes.synthesis import synthesis
from bishop.graph.nodes.triage_supervisor import triage_supervisor
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.schema import (
    ActionType,
    Alert,
    AlertCategory,
    AttackStage,
    BlastRadius,
    Decision,
    DetectorResult,
    Device,
    Evidence,
    EvidenceKind,
    HumanDecision,
    InvestigatorReport,
    Principal,
    Process,
    ResponseAction,
    ResponsePlan,
    RunCost,
    Severity,
    Verdict,
    VerdictLabel,
)


def dispatch_investigators(state: BishopState) -> list[Send]:
    """Fan out to one investigator per dispatched surface.

    Each `Send` carries only what that investigator needs — its surface, the
    alerts, and the already-fenced quarantine block. It never receives the raw
    alert text by a second route.
    """
    return [
        Send(
            "investigate",
            {
                "run_id": state["run_id"],
                "surface": surface,
                "alerts": state.get("alerts") or [],
                "quarantine_block": state.get("quarantine_block", ""),
                "incident_id": state.get("incident_id", ""),
            },
        )
        for surface in (state.get("dispatch") or [])
    ]


def after_critic(
    state: BishopState,
    config: Optional[RunnableConfig] = None,
) -> Literal["synthesis", "response_planner"]:
    """Send the verdict back for one more pass, or move on.

    Bounded by `Settings.max_critic_rounds`. The loop re-enters synthesis only
    when the critic actually moved the verdict — a critic that agreed has
    nothing for synthesis to reconsider, and re-running it would spend a model
    call to produce the same answer.
    """
    runtime = get_runtime(config)
    rounds = state.get("critic_rounds", 0)
    if rounds >= runtime.settings.max_critic_rounds:
        return "response_planner"
    if not state.get("critique"):
        return "response_planner"
    return "synthesis"


#: Bishop's own types that travel through a checkpoint. Declared explicitly so
#: the checkpointer can run under `LANGGRAPH_STRICT_MSGPACK`, which restricts
#: deserialisation to an allowlist. That matters here: the checkpoint holds a
#: suspended run, and anyone who can write to the checkpoint store of a security
#: tool should not also get arbitrary type construction on resume.
CHECKPOINT_TYPES: tuple[type, ...] = (
    Alert,
    AlertCategory,
    AttackStage,
    Device,
    DetectorResult,
    Evidence,
    EvidenceKind,
    HumanDecision,
    InvestigatorReport,
    Principal,
    Process,
    ResponseAction,
    ResponsePlan,
    ActionType,
    BlastRadius,
    Decision,
    RunCost,
    Severity,
    Verdict,
    VerdictLabel,
)


def build_serialiser() -> JsonPlusSerializer:
    """A checkpoint serialiser restricted to Bishop's own types.

    The allowlist has to go to the constructor. `with_msgpack_allowlist` merges
    into an existing list and short-circuits when that list is `True` — which is
    the permissive default — so building it that way returned an unrestricted
    serialiser while looking like it had been locked down. The eleven
    "Deserializing unregistered type" warnings on every run were the runtime
    saying so.
    """
    return JsonPlusSerializer(allowed_msgpack_modules=CHECKPOINT_TYPES)


def default_checkpointer() -> Any:
    """A checkpointer that survives a restart when one is configured.

    `interrupt()` suspends a run mid-graph and the state has to live somewhere
    until a human answers, which may be hours. In memory that means a restart
    silently drops every run waiting at the gate — the analyst comes back to a
    console that has forgotten it asked them something.

    `BISHOP_CHECKPOINT_DB` points at a SQLite file to make that durable. The
    default stays in-memory because the test suite and `just demo` should not
    leave state behind, and because a checkpoint store holds suspended runs
    including their alert text.
    """
    path = os.environ.get("BISHOP_CHECKPOINT_DB", "").strip()
    if not path:
        return InMemorySaver(serde=build_serialiser())

    from langgraph.checkpoint.sqlite import SqliteSaver

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, check_same_thread=False)
    saver = SqliteSaver(connection)
    saver.setup()
    return saver


def build_graph(*, checkpointer: Any | None = None):
    """Compile the graph. Pass a checkpointer or get the configured default."""
    builder = StateGraph(BishopState)

    builder.add_node("ingest", ingest)
    builder.add_node("triage_supervisor", triage_supervisor)
    builder.add_node("investigate", investigate)
    builder.add_node("synthesis", synthesis)
    builder.add_node("adversarial_critic", adversarial_critic)
    builder.add_node("response_planner", response_planner)
    builder.add_node("response_gate", response_gate)
    builder.add_node("response_execute", response_execute)
    builder.add_node("report", report)

    builder.add_edge(START, "ingest")
    builder.add_edge("ingest", "triage_supervisor")
    builder.add_conditional_edges("triage_supervisor", dispatch_investigators, ["investigate"])
    builder.add_edge("investigate", "synthesis")
    builder.add_edge("synthesis", "adversarial_critic")
    builder.add_conditional_edges(
        "adversarial_critic", after_critic, ["synthesis", "response_planner"]
    )
    builder.add_edge("response_planner", "response_gate")
    # There is exactly one edge into `response_execute`, and it comes from the
    # gate. `tests/graph/test_gate.py` asserts that stays true.
    builder.add_edge("response_gate", "response_execute")
    builder.add_edge("response_execute", "report")
    builder.add_edge("report", END)

    return builder.compile(checkpointer=checkpointer or default_checkpointer())


#: The node that must be the only predecessor of the executor.
EXECUTOR_NODE = "response_execute"
GATE_NODE = "response_gate"
