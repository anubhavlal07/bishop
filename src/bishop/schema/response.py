"""Proposed response actions and their blast radius.

Bishop proposes. It does not act. Every action in this module — including the
ones that look harmless — passes the human gate in
`bishop.graph.nodes.response_gate` and executes against a mocked interface.
There is deliberately no `auto_execute` flag and no severity threshold above
which the gate is skipped, because the first thing anyone would do with such a
flag is turn it on.

`blast_radius` exists because "isolate the host" is a different decision when
the host is a developer laptop than when it is the domain controller. An
approval prompt that does not tell the analyst what breaks is not informed
consent, it is a rubber stamp.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from bishop.schema.alert import BishopModel


class ActionType(StrEnum):
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    REVOKE_SESSIONS = "revoke_sessions"
    FORCE_PASSWORD_RESET = "force_password_reset"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    COLLECT_FORENSICS = "collect_forensics"
    OPEN_TICKET = "open_ticket"
    NOTIFY_OWNER = "notify_owner"
    MONITOR = "monitor"


IRREVERSIBLE_ACTIONS: frozenset[ActionType] = frozenset(
    {
        ActionType.ISOLATE_HOST,
        ActionType.DISABLE_ACCOUNT,
        ActionType.FORCE_PASSWORD_RESET,
        ActionType.QUARANTINE_FILE,
        ActionType.KILL_PROCESS,
    }
)


class BlastRadius(BishopModel):
    """What breaks if this action is approved."""

    users_affected: int = 0
    hosts_affected: int = 0
    services_affected: list[str] = Field(default_factory=list)
    summary: str = ""
    timing_context: str = "unknown"


class ResponseAction(BishopModel):
    action_id: str
    action_type: ActionType
    target: str
    rationale: str
    blast_radius: BlastRadius = Field(default_factory=BlastRadius)
    evidence_ids: list[str] = Field(default_factory=list)
    rollback: str | None = None
    priority: int = 50

    @property
    def is_irreversible(self) -> bool:
        return self.action_type in IRREVERSIBLE_ACTIONS


class ResponsePlan(BishopModel):
    actions: list[ResponseAction] = Field(default_factory=list)
    strategy: str = ""
    no_action_rationale: str | None = None

    @property
    def requires_approval(self) -> bool:
        """Always true when there is anything to do.

        Every action is gated, not just the irreversible ones. See the module
        docstring for why there is no threshold here.
        """
        return bool(self.actions)


class Decision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"


class HumanDecision(BishopModel):
    """The record of a human standing behind an action.

    Written to the audit chain before anything executes. If this record does not
    exist, the executor refuses.
    """

    decided_by: str
    decision: Decision
    approved_action_ids: list[str] = Field(default_factory=list)
    note: str = ""
    decided_at: str = ""
