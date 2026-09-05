"""Bishop's runtime agents — the LangGraph nodes that are the product.

Not to be confused with the build-time subagents in `.claude/agents/`; see
`CLAUDE.md` §2. Nodes are `snake_case` and ship to users.
"""

from bishop.graph.nodes.adversarial_critic import adversarial_critic
from bishop.graph.nodes.ingest import ingest
from bishop.graph.nodes.investigators import investigate
from bishop.graph.nodes.report import build_incident, report
from bishop.graph.nodes.response_execute import (
    ExecutionRefused,
    Executor,
    MockExecutor,
    response_execute,
)
from bishop.graph.nodes.response_gate import response_gate
from bishop.graph.nodes.response_planner import response_planner
from bishop.graph.nodes.synthesis import synthesis
from bishop.graph.nodes.triage_supervisor import triage_supervisor

__all__ = [
    "ExecutionRefused",
    "Executor",
    "MockExecutor",
    "adversarial_critic",
    "build_incident",
    "ingest",
    "investigate",
    "report",
    "response_execute",
    "response_gate",
    "response_planner",
    "synthesis",
    "triage_supervisor",
]
