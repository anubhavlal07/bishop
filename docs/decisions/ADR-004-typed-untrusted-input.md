# ADR-004 — Typed untrusted input, and escalate rather than strip

**Status:** accepted

## Context

Bishop's inputs are attacker-controlled by definition — file names, command lines, user-agent
strings, DNS queries, email subjects. An intruder who suspects an LLM is triaging can write
instructions into any of them. See [`docs/THREAT-MODEL.md`](../THREAT-MODEL.md) for the full
argument.

Two questions had to be answered: **how does the boundary stay intact as the codebase grows**,
and **what happens when a payload is found**.

## Decision 1 — the marker lives in the type system

`UntrustedStr` is a `str` subclass. It behaves as a string everywhere Python expects one, so
nothing downstream breaks, but it is findable by instance check anywhere in an argument tree.

- `walk_untrusted()` traverses dicts, lists, sets and object `__dict__`s to a bounded depth and
  returns **dotted paths** — `auth_events[2].user_agent`. Which field carried the payload is
  itself evidence, so "something was untrusted" is not a useful answer.
- `assert_no_untrusted()` runs at every prompt-assembly site and raises `UntrustedLeakError`
  rather than sending an unwrapped value to a model. It is deliberately redundant with the
  quarantine call: one is the control, the other asserts the control was applied.
- The fence marker derives from the run id, so it differs per run. Delimiter-escape attacks need
  a delimiter the attacker can predict, and there isn't one.
- Values flatten to a single line and truncate at 2000 characters. Newlines are the cheapest way
  to fake a turn boundary; truncation bounds the denial-of-analysis goal.

The rejected alternative was a naming convention (`untrusted_command_line`) plus code review.
Both fail identically: a field added months later by someone who never read the threat model.
Making the boundary mechanical means it does not depend on anyone remembering.

## Decision 2 — a detected attempt is escalated, not stripped

`scan_text()` scores twelve techniques and returns a `FieldRisk`. Above `INJECTION_THRESHOLD`
(0.5), `injection_evidence()` converts the finding into an `Evidence` object that enters the
incident and **raises severity**.

The reasoning: **a payload aimed at the triage system is not a false positive — it is one of the
strongest signals in the alert.**

Commodity malware does not talk to the analyst. An attacker who writes an instruction into a
file name knows an LLM is reading it, has reasoned about the defensive stack, and is targeting
this organisation specifically. Sanitising that quietly and moving on discards the highest-value
indicator present.

So neutralising the instruction is only half a pass. The defence succeeds when **both** hold:

1. the instruction is not followed — the verdict is what it would have been without the payload
2. the attempt is escalated as an IOC

`tests/injection/` enforces both. A payload that is neutralised but not escalated is recorded as
a HIGH finding, not a pass.

## Consequences

**Good.** The boundary is enforced by the type checker and a runtime assertion rather than by
discipline. Escalation turns the primary threat into a detection capability, which is the most
interesting claim this project makes and the one worth writing up. It is directly testable, so
the claim is falsifiable rather than rhetorical.

**Bad.** `UntrustedStr` must be applied correctly at normalisation — if a field is not marked
there, nothing downstream can tell. That makes the ingest layer the weak point, and it is not
protected by the same mechanism it enables. The scanner is pattern- and heuristic-based, so
twelve techniques is not all techniques, and a false-positive scan raises severity on a benign
alert — noise, which is the acceptable direction to fail.

**Unresolved.** Semantic steering with no imperative — a payload supplying a fabricated
change-ticket reference or maintenance window — contains nothing for the scanner to match. The
mitigation is ADR-002's deterministic detectors plus low-confidence escalation, and it is
partial. This is stated as residual risk rather than solved.
