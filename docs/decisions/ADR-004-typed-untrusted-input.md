# ADR-004 — Untrusted input: a typed marker, and why it was not enough

**Status:** accepted, amended after red-teaming

> This ADR was originally written with only the first two decisions below. Red-teaming defeated
> both. Decision 3 is the amendment, and it is the one that closed the attacks. The original
> reasoning is kept rather than rewritten, because the way it failed is more instructive than a
> clean document would be.

## Context

Bishop's inputs are attacker-controlled by definition — file names, command lines, user-agent
strings, DNS queries, email subjects. An intruder who suspects an LLM is triaging can write
instructions into any of them. See [`../THREAT-MODEL.md`](../THREAT-MODEL.md) for the full
argument.

Two questions had to be answered: **how does the boundary stay intact as the codebase grows**,
and **what happens when a payload is found**. A third turned out to matter more than either.

## Decision 1 — the marker lives in the type system

`UntrustedStr` is a `str` subclass, findable by instance check anywhere in an argument tree.
`walk_untrusted()` returns dotted paths (`auth_events[2].user_agent`) because which field carried
the payload is itself evidence. `assert_no_untrusted()` runs at every prompt-assembly site and
raises rather than sending an unwrapped value to a model. The fence marker derives from the run
id, so delimiter-escape has no predictable delimiter to close.

The rejected alternative was a naming convention plus code review, which fails to a field added
months later by someone who never read the threat model. Making the boundary mechanical means it
does not depend on anyone remembering.

**This reasoning is still correct and the mechanism still ships. It is also insufficient, and
the gap is not a bug in the implementation — it is a property of the language.**

## Decision 2 — a detected attempt is escalated, not stripped

`scan_text()` scores thirteen techniques. Above `INJECTION_THRESHOLD` (0.5),
`injection_evidence()` converts the finding into `Evidence` that enters the incident and raises
severity.

A payload aimed at the triage system is not a false positive — it is one of the strongest
signals available. Commodity malware does not talk to the analyst. Someone who writes an
instruction into a file name has reasoned about the defensive stack and is targeting this
organisation specifically. Sanitising that quietly discards the highest-value indicator present.

**Still correct. Also insufficient, and in a way worth stating precisely:** red-teaming produced
a case (BLK-03) where Bishop detected the injection, scored it, raised it as an IOC, wrote it to
the audit chain, printed it in the incident report — and returned `false_positive` anyway,
because a second field forged an empty `<injection-findings>` block. Every part of Decision 2
worked. The verdict was still wrong.

Detection and escalation are a detection capability. They are not a defence. The original
version of this ADR did not distinguish those, and read as though escalation settled the matter.

## Decision 3 — the invariant moves to the render boundary

**Nothing serialised into a block the prompt describes as trusted may contain a block
delimiter.** Enforced unconditionally by `safe_block()`.

### Why the type could not carry it

`assert_no_untrusted()` is an instance check. Every string operation in Python returns a plain
`str` — `str(x)`, `x.lower()`, an f-string, a `%` format, a `json.dumps` round-trip. **The marker
does not survive any of them.**

That is not fixable at the type. You cannot subclass your way into propagating through `str()`,
and auditing every site that might stringify is precisely the discipline-based approach Decision
1 existed to avoid. The marker tells you a value *is* untrusted; it cannot tell you a value
*was*.

Four live laundering paths existed: `Alert.entity_key()`, detector facts, the response planner's
context, and `Alert.raw` — typed `dict[str, Any]`, so it never carried markers and was never
scanned at all.

The impact was not a leak, it was forgery. Laundered text reached `<detector-results>` — the
block the system prompt calls Bishop's own output — carrying a literal `</detector-results>`.
`json.dumps` escapes quotes and not angle brackets. A nineteen-character suffix on a genuine
credential-dumping command line flipped `true_positive 0.95` to `false_positive 0.95` and
dropped all five containment actions.

### What was built

- **`safe_block()`** escapes delimiters in anything entering a trusted block. Not scanned for,
  not detected — escaped, always.
- **`_mark_quoted()`** renders string leaves in detector facts in guillemets, length-capped, so
  they read structurally as excerpts rather than as Bishop's prose. This also closed a decoding
  oracle: `encoded_command` base64-decodes a payload into its own facts, so the attacker writes
  base64 and Bishop decodes it into the trusted region for them.

  Sixteen keys are exempt via `BISHOP_VOCABULARY` (detector names, technique ids, enum labels,
  computed field paths). The exemption is load-bearing: marking every leaf broke
  `routine_software`'s `facts["explains"]` contract, which synthesis compares against the fired
  detector set, and verdict accuracy fell 100% → 85% with no error raised. **Escaping is safe to
  apply unconditionally; marking is not** — escaping removes structural meaning a value should
  never have had, while marking changes values other code compares. See THREAT-MODEL §4.5.
- **`Alert.raw` is walked and scanned** like every typed field.
- **Fields past the render cap are scanned before being dropped**, so a payload cannot hide
  behind a hundred harmless ones.

### Why this one generalises

Decisions 1 and 2 both work by **recognising** hostile input — the right type, the right
pattern. Both were defeated by input they did not recognise, which is the standing failure mode
of every recognition-based control.

Decision 3 works by maintaining a **structural invariant**. "No delimiter inside a trusted block"
holds whatever the payload says, in any language, in any encoding, including techniques nobody
has thought of. Five of the six live breaks were closed by `safe_block()`; the sixth by scanning
before dropping.

That is the transferable result, and it is worth more than the specific fix: **against untrusted
input reaching an LLM, prefer invariants you can enforce over attacks you can enumerate.**

**Prefer, not replace.** The scanner has since learned these forgeries — its closing-tag pattern
had required `>` immediately after the tag name, so it missed `</untrusted-alert-data
nonce="...">` and knew nothing of the trusted block names. Decision 3 makes a forgery
*ineffective*; Decision 2 makes it *visible*. Alone, Decision 3 absorbs an attack silently and
raises no indicator, and Decision 2 flags an attack it cannot stop. Keeping both is not
belt-and-braces — it is containment and detection being genuinely different properties, as
BLK-03 demonstrated in the other direction.

## Consequences

**Good.** The boundary no longer depends on a marker surviving arbitrary string handling. The
generalising layer is one small function with a property that can be stated in a sentence and
tested exhaustively. Escalation still turns the primary threat into a detection capability —
Decision 2's value is intact, it is just correctly scoped now.

**Bad.** `safe_block()` is a discipline dependency of a different shape: a new prompt-assembly
site that does not route through it is not protected. That is narrower and far more reviewable
than "every site that might stringify", but it is not zero. `UntrustedStr` must still be applied
correctly at normalisation, and the ingest layer is not protected by the mechanism it enables.

**Measured.** 120 of 132 corpus payloads caught, 0 false positives on 38 benign samples. The 12
that evade are strict-xfail, so the suite fails when one is fixed. They are semantic steering —
plausible context with no imperative — for which the mitigation is symmetric detector grounding
and the human gate, not the scanner.

This ADR first recorded 58/132. That was accurate when it was written and went stale when the
scanner improved; the number above is what `tests/injection/test_corpus_recall.py` reports now.

**Unresolved.** Semantic steering remains the open class. See THREAT-MODEL §7.
