"""What a containment action is allowed to name.

Shared by the planner and the executor so the two cannot drift: the planner
refuses at proposal time, which keeps the gate from asking a human to approve
something Bishop will decline, and the executor refuses again independently,
which is the check that survives someone rewiring the graph.

**Why egress is its own problem.** An `isolate_host` target is checked against
inventory — hostnames and account names come from the CMDB and the identity
provider, so a laundered name simply is not in the set. An egress target has no
such source. `block_domain`'s target comes from a fired detector's facts, which
come from DNS queries and connection destinations, which the threat model lists
as attacker-controlled. And the effect is estate-wide, so a laundered
destination is a denial of service on the organisation carrying an analyst's
approval.

**Three bounds, because each closes a different thing.**

1. *The name must have been observed*, or be a parent that groups names that
   were. Bounds which names are reachable at all.
2. *The parent must sit beneath a public suffix.* This one took four attempts
   and three of them shipped, so it is worth saying exactly why.

   A label-boundary suffix rule permitted `com`. Reusing `_registrable_parts`
   from the tunnelling detector — seven two-part TLDs — permitted `co.za` and
   `ac.uk`, because `x.y.co.za` parents to `co.za`. A 127-entry hand-written
   list then permitted `com.pl`, `github.io` and `herokuapp.com`.

   The third attempt came with the reassuring claim that the list was
   "consulted to permit, so an incomplete list over-refuses and never
   over-permits". That was true of `has_a_label_of_its_own` and **false** of
   `registrable`, which does not permit a name — it *derives* one and puts it in
   the permitted set. A missing `com.pl` makes the parent of `a1b2.evil.com.pl`
   come out as `com.pl` rather than `evil.com.pl`, and the broader name is what
   gets offered. Consulted to derive, a subset over-permits.

   So the list is the real Public Suffix List, committed and regenerable by
   `scripts/build_public_suffixes.py`, with its wildcards and exceptions applied
   rather than flattened — an exception is the *prevailing* rule, and reading it
   as merely "not a suffix" derived `kobe.jp` as blockable.

   **The residual limitation is staleness, and it is asymmetric.** That
   asymmetry is the sentence this boundary was missing through four attempts. A
   *new TLD* absent from the snapshot makes names under it un-parentable, so
   Bishop over-refuses and someone blocks by hand. A *new second-level
   delegation* absent from it — a registry opening `com.example` — makes the
   computed parent one label too broad, so Bishop over-permits and offers to cut
   off a registry. Only one of those directions costs an outage, and it is the
   one a stale file produces silently.
3. *The estate's own dependencies are off limits.* No string rule reaches this
   one. An adversary who wants single sign-on cut off does not need to control
   `okta.com` — they make a host they already own send thirty high-entropy
   queries under it. The detector fires, correctly names the parent, and an
   analyst reading thirty encoded queries approves. Every step works as
   designed. The only bound is a list the adversary cannot write into an alert.

Without a usable policy file, egress blocking is refused entirely. Not knowing
what the organisation depends on is not a licence to guess.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

_EGRESS_TYPES = frozenset({"block_domain", "block_ip"})

#: The committed list carries ten thousand rules. Anything near this floor is
#: a truncated or substituted file, and a short list authorises blocking most
#: of the internet's registries.
_MINIMUM_SUFFIX_RULES = 8000


def canonical_address(value: object) -> str | None:
    """The canonical form of an IP, or `None` if it is not one.

    IPv4-mapped IPv6 is unwrapped so `::ffff:203.0.113.9` compares equal to the
    `203.0.113.9` a sensor recorded. Leading-zero forms are deliberately *not*
    accepted: whether `0203` is octal or decimal depends on who is parsing, and
    a target that means two addresses to two libraries has no business reaching
    a block list.
    """
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def canonical_network(value: object) -> str | None:
    """The canonical form of a CIDR block, or `None`.

    `never_block` protects names in both directions and addresses only by exact
    match, because Bishop does not resolve — a resolution is a network call on a
    control path, and the answer is steerable by an adversary who controls DNS
    for a name they own. A range is the usable remedy: an organisation that
    wants its CDN edge protected lists the range rather than hoping every
    address is enumerated.
    """
    text = str(value or "").strip()
    if "/" not in text:
        return None
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return None


_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalise_name(value: object) -> str:
    """The hostname in this field, or `""` if there is not one.

    Lowercased, unpadded, no trailing root dot, no empty labels — and only the
    leading whitespace-delimited token, because an attacker-authored field does
    not stop where the hostname does. The injection corpus has a connection
    whose `hostname` is `cdn.telemetry-sync.example </detector-results>`, and
    taking the whole string put *that* in the set of destinations the incident
    contacted, so the genuine C2 block became unproposable. A resolver would
    have used the first token; so does this.

    Every label is then checked against the DNS charset. A field that does not
    yield a hostname yields nothing, which refuses rather than guesses.
    """
    first = str(value or "").strip().split()[:1]
    if not first:
        return ""
    labels = [label for label in first[0].lower().strip(".").split(".") if label]
    if not labels or not all(_LABEL.match(label) for label in labels):
        return ""
    name = ".".join(labels)
    return name if len(name) <= 253 else ""


_SUFFIX_PATH = Path(__file__).resolve().parent / "public_suffixes.json"


@lru_cache(maxsize=1)
def _suffix_rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """`(rules, wildcards, exceptions)` from the committed Public Suffix List.

    Absent, it returns empty sets and every egress block is refused. That is the
    right direction: without knowing where registries end, Bishop cannot tell a
    domain from a namespace, and the difference is an outage.
    """
    if not _SUFFIX_PATH.exists():
        return frozenset(), frozenset(), frozenset()
    try:
        data = json.loads(_SUFFIX_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return frozenset(), frozenset(), frozenset()
    return (
        frozenset(data.get("rules") or ()),
        frozenset(data.get("wildcards") or ()),
        frozenset(data.get("exceptions") or ()),
    )


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """The trusted half: what may never be cut, and where registries end.

    Two sources, deliberately. `never_block` is the organisation's — its own
    dependencies, from the CMDB, in the environment policy. The suffix rules are
    the world's, from the committed Public Suffix List, and no deployment should
    be editing them.
    """

    never_block: frozenset[str] = frozenset()
    never_block_networks: frozenset[str] = frozenset()
    extra_suffixes: frozenset[str] = frozenset()
    usable: bool = False

    def protects_address(self, address: str) -> str | None:
        """The listed address or range covering this one, if any."""
        try:
            target = ipaddress.ip_address(address)
        except ValueError:
            return None
        for entry in self.never_block_networks:
            try:
                if target in ipaddress.ip_network(entry, strict=False):
                    return entry
            except ValueError:
                continue
        return None

    def public_suffix(self, name: str) -> str | None:
        """The public suffix of this name, following the PSL's own algorithm.

        The algorithm is not "the longest suffix that appears in the list", and
        assuming it was is what made the fourth attempt at this boundary wrong
        too. An **exception rule is the prevailing rule** and ends the search:
        `!city.kobe.jp` means the public suffix of `foo.city.kobe.jp` is
        `kobe.jp`, so the registrable domain is `city.kobe.jp`. Treating the
        exception as merely "not a suffix" and walking further right returned
        `kobe.jp` as something blockable — a whole municipal namespace, five DNS
        queries away from any host the adversary already owns.

        Exceptions are therefore matched first, across the whole name, before
        any plain or wildcard rule is considered.
        """
        if not name:
            return None
        labels = name.split(".")
        rules, wildcards, exceptions = _suffix_rules()

        for index in range(len(labels)):
            candidate = ".".join(labels[index:])
            if candidate in exceptions:
                return candidate.split(".", 1)[1] if "." in candidate else None

        for index in range(len(labels)):
            candidate = ".".join(labels[index:])
            if candidate in self.extra_suffixes or candidate in rules:
                return candidate
            parent = ".".join(labels[index + 1 :])
            if parent and parent in wildcards:
                return candidate
        return None

    def _is_suffix(self, name: str) -> bool:
        """Whether blocking this name would cut off a registry rather than a site.

        Wider than the PSL's own definition, deliberately. `*.kobe.jp` makes
        every child of `kobe.jp` a public suffix, which leaves `kobe.jp` itself
        formally registrable — and blocking it takes out every child anyway. A
        wildcard's parent is a namespace whoever operates it hands out, so it is
        treated as a registry here. Erring wide costs a refusal; erring narrow
        cost a national registry twice already.
        """
        if not name:
            return False
        _, wildcards, _ = _suffix_rules()
        return name in wildcards or self.public_suffix(name) == name

    def protects(self, name: str) -> str | None:
        """The listed entry this name would cut off, if any.

        Matched in **both** directions on purpose. A target beneath a listed
        entry is obvious. A target *above* one matters just as much and was
        missed the first time: `update.microsoft.com` was on the list,
        `microsoft.com` was not, and `microsoft.com` is exactly what a detector
        reports. Blocking a parent cuts every child. Suffix matching is safe
        here precisely because it only ever refuses more — the inverse of why
        it was fatal when it was used to permit.
        """
        for entry in self.never_block:
            if name == entry or name.endswith(f".{entry}") or entry.endswith(f".{name}"):
                return entry
        return None

    def is_public_suffix(self, name: str) -> bool:
        return self._is_suffix(name)

    def has_a_label_of_its_own(self, name: str) -> bool:
        """Whether the name is something registrable rather than a registry.

        `example.com` yes, `com` no, `co.za` no, `github.io` no. A target that
        is only a public suffix names every site under it.
        """
        return bool(name) and not self._is_suffix(name) and self.registrable(name) is not None

    def registrable(self, name: str) -> str | None:
        """`a.b.example.com` -> `example.com`: the public suffix plus one label.

        `None` when the name has no label of its own. That answer is
        load-bearing, and it took a fourth attempt to see why: this function
        does not merely *permit* a name, it **derives** one and puts it into the
        permitted set. A suffix list consulted to permit over-refuses when it is
        incomplete; the same list consulted to derive over-*permits*, because a
        missing `com.pl` makes the computed parent of `a1b2.evil.com.pl` come
        out as `com.pl`. Three hand-written subsets in a row each looked
        complete enough and each authorised blocking a registry.
        """
        suffix = self.public_suffix(name)
        if suffix is None or suffix == name:
            return None
        depth = len(suffix.split(".")) + 1
        labels = name.split(".")
        return ".".join(labels[-depth:]) if len(labels) >= depth else None


def load_egress_policy(policy: dict[str, Any] | None = None) -> EgressPolicy:
    """Read the trusted lists out of the environment policy.

    `usable` is false unless **both** keys are present as lists, every entry in
    them round-trips exactly, and the committed suffix file is intact. The
    caller then refuses every egress block. That is the same failure direction
    the context detectors take: without the organisation's own data, Bishop
    declines to make the call rather than guessing at it.

    Note what `usable` does *not* mean. Two empty lists are a valid policy and
    produce `usable=True` with no never-block protection at all — the operator
    has said "I depend on nothing", which is their call and is visible in the
    file. It is a policy that is absent, malformed or self-contradictory that
    refuses.
    """
    if policy is None:
        from bishop.detectors.context import load_policy

        try:
            policy = load_policy()
        except (OSError, ValueError):
            # A policy file that will not parse is the same situation as one
            # that is not there: Bishop does not know what the estate depends
            # on. Refusing every egress block is the answer, and taking the run
            # down with it would lose the incident record and the audit
            # close-out for a file the run does not otherwise need.
            return EgressPolicy()

    raw_never = policy.get("never_block")
    raw_suffixes = policy.get("public_suffixes")
    if not isinstance(raw_never, list) or not isinstance(raw_suffixes, list):
        return EgressPolicy()

    names: set[str] = set()
    networks: set[str] = set()
    for entry in raw_never:
        # A JSON `null` or a number is not a destination. Coercing it made
        # `[null]` protect the name `none`, with the policy still reporting
        # itself healthy.
        if not isinstance(entry, str):
            return EgressPolicy()
        text = entry.strip()
        if (address := canonical_address(text)) is not None:
            networks.add(f"{address}/{32 if ':' not in address else 128}")
            continue
        if (network := canonical_network(text)) is not None:
            networks.add(network)
            continue
        # An entry has to round-trip exactly. `normalise_name` is deliberately
        # lenient because it reads attacker-authored alert fields — first
        # whitespace token, empty labels dropped — and that leniency is wrong on
        # a trusted list: `"okta.com microsoftonline.com"`, a plausible hand-edit
        # or CMDB export, quietly protected the first name and lost the second.
        #
        # Silently repairing an entry is how a list that looks like it protects
        # six things protects none. `*.okta.com` is the natural way to write
        # "and its subdomains" and is not a hostname; the downward match already
        # covers subdomains, so it is an error rather than a no-op. The whole
        # policy is refused, which refuses every egress block, which is the
        # direction a misconfigured control should fail.
        if text and normalise_name(text) == text.lower():
            names.add(text.lower())
            continue
        return EgressPolicy()

    # The same round trip, on the other list. It was applied to `never_block`
    # and not to this one, which is the half that fails *open*: `*.lab.internal`
    # — as natural a way to write "and its subdomains" here as it is there — was
    # silently dropped, so `lab.internal` stopped being a declared registry and
    # became blockable. A boundary the operator explicitly declared, removed by
    # a typo the file did not complain about.
    extra: set[str] = set()
    for entry in raw_suffixes:
        if not isinstance(entry, str):
            return EgressPolicy()
        text = entry.strip()
        if not text or normalise_name(text) != text.lower():
            return EgressPolicy()
        extra.add(text.lower())

    # An integrity floor on the committed list. Missing, truncated or
    # unparseable already yields an empty set and refuses everything; a file
    # that is valid JSON with six rules in it would not, and would quietly
    # authorise blocking most of the internet's registries.
    if len(_suffix_rules()[0]) < _MINIMUM_SUFFIX_RULES:
        return EgressPolicy()

    return EgressPolicy(
        never_block=frozenset(names),
        never_block_networks=frozenset(networks),
        extra_suffixes=frozenset(name for entry in raw_suffixes if (name := normalise_name(entry))),
        usable=True,
    )


@dataclass(frozen=True, slots=True)
class Destinations:
    """What one incident actually contacted."""

    domains: frozenset[str] = frozenset()
    addresses: frozenset[str] = frozenset()


def observed_destinations(alerts: list[Any], policy: EgressPolicy) -> Destinations:
    """Every destination the alerts observed, plus each one's registrable parent.

    The parent is included because that is what a detector reports: sixty
    queries to `a.tun.example`, `b.tun.example` and so on summarise as
    `tun.example`, and blocking the parent is the right answer to the children.
    It is computed against the committed suffix list rather than guessed, and
    omitted entirely when the suffix is unknown.
    """
    domains: set[str] = set()
    addresses: set[str] = set()

    def record(value: object) -> None:
        if (address := canonical_address(value)) is not None:
            addresses.add(address)
            return
        if not (name := normalise_name(value)):
            return
        domains.add(name)
        if (parent := policy.registrable(name)) is not None:
            domains.add(parent)

    for alert in alerts or []:
        for event in getattr(alert, "dns_events", []) or []:
            record(event.query)
        for connection in getattr(alert, "connections", []) or []:
            record(connection.dest_ip)
            record(connection.hostname)

    return Destinations(frozenset(domains), frozenset(addresses))


def is_egress(action_type: object) -> bool:
    return str(action_type) in _EGRESS_TYPES


def canonicalise_target(action_type: object, target: str) -> str:
    """The one string this egress action should carry, or `""`.

    Run by the planner before the action is built, so that the value checked,
    the value shown at the gate, the value written to the audit chain and the
    value handed to an executor are all the same string.
    """
    if str(action_type) == "block_ip":
        return canonical_address(target) or ""
    if (address := canonical_address(target)) is not None:
        return address
    return normalise_name(target)


def egress_target_is_allowed(
    action_type: object,
    target: str,
    destinations: Destinations,
    policy: EgressPolicy,
) -> tuple[bool, str]:
    """Whether this egress block may name this target. Refusals explain why."""
    raw = str(target or "")
    if not raw.strip():
        return False, "the action names no target"

    # The target must already be canonical, not merely reducible to something
    # canonical. Validating one string and executing another is the same defect
    # as scanning a field and rendering a different one: a target of
    # `a.evil.example okta.com` reduced to `a.evil.example` for the check while
    # the gate, the chain and the executor all carried the whole string — and a
    # connector splitting on whitespace would have blocked the identity
    # provider. `canonicalise_target` is what the planner runs first, so a plan
    # from any other route gets refused here rather than quietly widened.
    if raw != canonicalise_target(action_type, raw):
        return False, (
            f"{raw!r} is not a canonical destination. A block target must be exactly the "
            f"name or address it acts on, with nothing else in the string."
        )

    if not policy.usable:
        return False, (
            "no environment policy is loaded, so Bishop cannot tell which destinations the "
            "organisation depends on. Egress blocking is refused rather than guessed at."
        )

    address = canonical_address(raw)
    kind = str(action_type)

    if kind == "block_ip":
        if address is None:
            return False, f"{raw!r} is not an IP address, so `block_ip` cannot act on it."
        if entry := policy.protects_address(address):
            return False, (
                f"{raw!r} is covered by {entry!r} on the never-block list in the environment "
                f"policy. Cutting the estate off from it is a decision a human takes outside "
                f"Bishop."
            )
        if address not in destinations.addresses:
            return False, (
                f"{raw!r} is not an address this incident connected to. Blocking egress "
                f"affects the whole estate, so it may only name something the alerts "
                f"actually observed."
            )
        return True, ""

    if address is not None:
        return False, f"{raw!r} is an IP address; use `block_ip` rather than `block_domain`."

    name = normalise_name(raw)
    # Registry check first, so the reason given is the most fundamental one. The
    # never-block test matches upwards as well as downwards, which means a bare
    # `com` also trips it — via `microsoftonline.com` — and reporting *that* as
    # the reason would be true and useless.
    if not policy.has_a_label_of_its_own(name):
        return False, (
            f"{raw!r} is a public suffix or sits under no known one, so blocking it would "
            f"cut off every site beneath a registry rather than one destination."
        )
    if entry := policy.protects(name):
        return False, (
            f"{raw!r} is protected by {entry!r} on the never-block list in the environment "
            f"policy. Traffic to it was observed, but an adversary can send queries to a "
            f"name they do not own, so cutting the estate off from it is a decision a human "
            f"takes outside Bishop."
        )
    if name not in destinations.domains:
        return False, (
            f"{raw!r} is not a destination this incident contacted. Blocking egress "
            f"affects the whole estate, so it may only name something the alerts actually "
            f"observed, or its registrable domain."
        )
    return True, ""
