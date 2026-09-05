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

from pydantic import ConfigDict, Field, model_validator

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


#: Refused as policy, whatever they name.
#:
#: A process-scoped or file-scoped action identifies its target by a process
#: name or a file path, and both of those come out of the alert payload — a
#: string the attacker wrote. Checking one against the incident would mean
#: checking it against itself, so the relationship test below has nothing to
#: test and the guard silently degrades from "an entity this incident is about"
#: to "a string that appeared in the alert".
#:
#: Widening `_known_entities` to include process names and paths is the obvious
#: repair and it is the wrong one, which is why this is stated here rather than
#: left to be inferred. Before it was explicit, these were *mostly* refused —
#: only because a process name is rarely also a hostname. A plan naming
#: `quarantine_file` on `10.20.30.40` passed the check and executed, which is
#: worse than either refusing or supporting them.
#:
#: They stay in `ActionType`. Removing them would let a model invent a spelling
#: of its own — the `terminate_process` defect — and get a vaguer refusal.
UNSUPPORTED_ACTIONS: dict[str, str] = {
    "kill_process": (
        "Bishop does not propose process-scoped containment. A process name comes "
        "from the alert payload, so checking it against the incident would be "
        "checking it against itself. Kill the process by hand if the evidence "
        "warrants it."
    ),
    "quarantine_file": (
        "Bishop does not propose file-scoped containment. A file path comes from "
        "the alert payload, so checking it against the incident would be checking "
        "it against itself. Quarantine the file by hand if the evidence warrants it."
    ),
}


#: Actions whose effect is not confined to the incident's own hosts and
#: accounts. Blocking egress applies at the proxy, to everyone.
ESTATE_WIDE_ACTIONS: frozenset[ActionType] = frozenset(
    {ActionType.BLOCK_IP, ActionType.BLOCK_DOMAIN}
)

#: Actions that record rather than contain. Everything else in `ActionType`
#: changes the state of a host, an account or the network — so a type added
#: later counts as containment until someone decides otherwise, which is the
#: safe direction for the default to point.
RECORD_ONLY: frozenset[ActionType] = frozenset(
    {
        ActionType.OPEN_TICKET,
        ActionType.NOTIFY_OWNER,
        ActionType.MONITOR,
        ActionType.COLLECT_FORENSICS,
    }
)


def _describe(actions: list[ResponseAction]) -> str:
    """Name the actions, with counts.

    Counts, because collapsing them loses the only thing the sentence is for.
    Thirty-nine isolations across thirty-nine hosts and one isolation of one
    host both read "isolate host" without them, and this module's own docstring
    says an approval prompt that does not say *which* host is a rubber stamp.
    """
    counted: dict[str, int] = {}
    for action in actions:
        name = str(action.action_type).replace("_", " ")
        counted[name] = counted.get(name, 0) + 1
    if not counted:
        return "nothing"
    # Insertion order, so the sentence reads in the order the actions are
    # listed underneath it. Sorting alphabetically made the summary and the
    # list disagree about which action comes first.
    names = [f"{count} x {name}" if count > 1 else name for name, count in counted.items()]
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + " and " + names[-1]


def summarise(actions: list[ResponseAction]) -> str:
    """One sentence saying what a plan does, computed from the plan.

    See `ResponsePlan.proposes` for why this exists rather than trusting the
    strategy, and `docs/THREAT-MODEL.md` §6 for why it computes rather than
    reads.
    """
    if not actions:
        return "This plan proposes no actions."

    sentence = f"This plan proposes: {_describe(actions)}."

    irreversible = sum(1 for action in actions if action.is_irreversible)
    if irreversible:
        sentence += (
            f" {irreversible} of {len(actions)} "
            f"{'is' if irreversible == 1 else 'are'} irreversible."
        )

    # Irreversibility is not the only kind of cost, and it was briefly the only
    # one this sentence mentioned. An egress block is reversible in one line of
    # firewall config and applies to every machine in the estate, so the two
    # corpus plans whose sole containment action was a `block_domain` produced
    # the blandest sentence in the set while proposing the widest change in it.
    estate_wide = sum(1 for action in actions if action.action_type in ESTATE_WIDE_ACTIONS)
    if estate_wide:
        sentence += (
            f" {estate_wide} {'affects' if estate_wide == 1 else 'affect'} the whole estate."
        )
    if not [action for action in actions if action.action_type not in RECORD_ONLY]:
        sentence += " No containment action is included."
    return sentence


class ResponsePlan(BishopModel):
    # Frozen, and the actions are a tuple. `proposes` is derived from `actions`
    # at construction, so anything that could mutate either afterwards would
    # leave the two disagreeing — which is the exact failure the field exists to
    # prevent. Nothing did, but "nothing does" is a convention and this is an
    # invariant.
    model_config = ConfigDict(extra="forbid", frozen=True)

    actions: tuple[ResponseAction, ...] = ()

    #: The model's own words about what it intends. Never edited, because the
    #: analyst's screen is the wrong place to silently delete a sentence — one
    #: reading "do not isolate the file server" is exactly the sort that gets
    #: written and exactly the sort a rule looking for containment words would
    #: throw away.
    strategy: str = ""

    #: Bishop's own sentence, derived from `actions` rather than written by
    #: anything. It exists because `strategy` can be wrong about the plan it
    #: sits above: a confirmed token replay once came back with "contain the
    #: account and the host together" over a single action, open a ticket.
    #:
    #: It is recomputed on every construction rather than merely defaulted, so
    #: it cannot be absent and cannot be stale. A plan rehydrated from the store
    #: or from a checkpoint written before this field existed gets the right
    #: sentence, and a payload that arrives carrying a different one has it
    #: overwritten. A claim that cannot disagree with the buttons is worth
    #: nothing if some path can hand the gate a blank line instead.
    proposes: str = ""

    no_action_rationale: str | None = None

    @model_validator(mode="after")
    def _derive_proposes(self) -> ResponsePlan:
        computed = summarise(list(self.actions))
        if self.proposes != computed:
            object.__setattr__(self, "proposes", computed)
        return self

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
