# Architecture

How Bishop is put together, and why each piece is where it is. The decisions
that needed an argument have their own ADRs in [`decisions/`](decisions/); this
document is the map.

---

## The shape of a run

```
alert (JSON)
   │
   ▼
ingest ──────────────── quarantine: every attacker-influenced field is found by
   │                    type, scored for injection intent, and fenced. Injection
   │                    findings are raised here, before any investigator runs.
   ▼
triage_supervisor ───── deterministic routing. Which surfaces have data?
   │
   ├──Send──▶ identity_investigator      4 detectors   auth events
   ├──Send──▶ endpoint_investigator      9 detectors   process tree, registry, files
   ├──Send──▶ network_investigator       3 detectors   connections, DNS
   ├──Send──▶ threatintel_investigator   1 detector    cached indicator reputation
   └──Send──▶ context_investigator       2 detectors   asset inventory, change management
   │
   │          (these run concurrently; their writes merge through a reducer)
   ▼
synthesis ───────────── fuse the reports. Propose technique IDs, validate them
   │                    against the ATT&CK bundle, re-prompt once on rejection.
   │                    Apply the grounding rule and the abstention threshold.
   ▼
adversarial_critic ──── one bounded pass at proving the verdict wrong. May only
   │                    lower confidence, never raise it.
   ▼
response_planner ────── propose containment, with a blast radius per action.
   ▼
╔══════════════════════════════════════════════════════════════════╗
║ response_gate — interrupt(). The run suspends here and is        ║
║ checkpointed. It resumes only when a human supplies a decision.  ║
╚══════════════════════════════════════════════════════════════════╝
   ▼
response_execute ────── mocked. Re-checks the human decision per action and
   │                    refuses anything not named in it.
   ▼
report ──────────────── assemble the incident, close the audit chain.
```

Every node writes to the audit chain as it goes, so a run that fails halfway
still leaves a readable, verifiable record of how far it got.

---

## Why multi-agent, and where it would be decoration

The honest test for "should this be several agents" is whether the agents have
genuinely disjoint inputs. Bishop's do:

| Investigator | Reads | Cannot see |
|---|---|---|
| `identity` | `auth_events`, `principal` | the process tree |
| `endpoint` | processes, registry, files, scheduled tasks | logins |
| `network` | `connections`, `dns_events` | anything on disk |
| `threatintel` | indicators, against a cached corpus | behaviour |
| `context` | asset inventory and change management | the alert's own claims |

That buys three things. They run inside one latency budget instead of five.
They fail independently — a broken endpoint investigator does not take the
identity verdict with it. And each is separately evaluable, which is what makes
the scorecard able to attribute a miss.

Where it would have been decoration: the supervisor is **not** a model call.
Routing an alert to the wrong specialist is a failure the model cannot detect
afterwards — an investigator asked about the wrong surface honestly reports
nothing, which reads identically to "nothing happened". So dispatch is a
deterministic function of which fields the alert carries, and it is deliberately
generous: a surface runs whenever it has *any* data to read, because an
investigator that runs and finds nothing costs one cheap model call and one that
never ran costs an intrusion.

---

## The trust boundary

This is the part of the design everything else is arranged around.

**Untrusted by type, not by convention.** `UntrustedStr` is a `str` subclass.
Fields in `bishop.schema` that an attacker can write are annotated with it —
command lines, file names, DNS queries, user agents, hostnames, usernames from
external sources. `walk_untrusted()` finds every one of them in a value tree by
instance check, returning dotted paths like `auth_events[2].user_agent`. Adding
a field to the schema cannot accidentally omit it from the boundary, because
discovery is by type rather than by a hand-maintained list.

**One way through — and why that was not enough.** `render_block()` is the
only thing that puts alert text in front of a model *as alert text*, and every
prompt builder ends with `assert_no_untrusted(...)` over its own inputs.

That check is an instance check on `UntrustedStr`, and every string operation in
Python returns a plain `str`. `str(x)`, `x.lower()`, an f-string — the marker
does not survive any of them. Red-teaming found four live paths where it did
not: `Alert.entity_key()`, detector facts, the response planner's context, and
`Alert.raw`, which is `dict[str, Any]` and carried no markers to begin with.
Attacker text was arriving inside `<detector-results>`, the block the system
prompt calls Bishop's own output, carrying a literal `</detector-results>` that
closed it early.

Tracking provenance through `str()` is not something Python permits. So the
defence moved to the render boundary, where it does not need provenance:

- `safe_block()` escapes `<` and `>` in **everything** it serialises into a
  trusted block. `json.dumps` escapes quotes and backslashes but not angle
  brackets, and angle brackets are what carries structural meaning here.
- `_mark_quoted()` wraps string leaves in detector facts in guillemets and caps
  their length, because they are excerpts rather than Bishop's prose — and
  `encoded_command` is a decoding oracle, base64-decoding an attacker's payload
  into the trusted region on their behalf.
- `Alert.raw` is walked explicitly and scanned like every typed field.

`assert_no_untrusted` stays. It catches the direct mistake, which is worth
catching; it just cannot be the only thing standing there.

**The fence.** Untrusted values render inside
`<untrusted-alert-data nonce="…">`, where the nonce derives from the run id via
SHA-256. An attacker writing into a log field cannot predict it, so there is no
known delimiter to close. Values flatten to a single escaped line, because a
newline is the cheapest way to fake a turn boundary, and they truncate at 2000
characters so one field cannot flood the context.

**Ordering.** Trusted content always precedes untrusted content: system prompt,
then `<detector-results>` (Bishop's own output, parsed rather than fenced), then
the fenced block, then a trailer restating that the block is data. A model that
has already read its instructions and the detector findings is in a much better
position to recognise a fake instruction than one that meets the payload first.

**Escalate, don't strip.** A detected payload is preserved verbatim, still
rendered to the model, *and* raised as evidence. See
[ADR-004](decisions/ADR-004-typed-untrusted-input.md).

---

## Where the LLM is, and is not

The rule is that the LLM reasons and unit-tested Python decides. Concretely:

**Python decides** what fired. Every detector in `bishop.detectors` is a pure
function — no model, no network, no database, no clock read, no randomness. The
same alert produces the same result on any machine in any year, which is what
makes `pytest tests/detectors` a meaningful gate.

**Python decides** whether a technique ID is real, whether a verdict clears the
abstention threshold, whether an action was approved, and whether a finding is
grounded.

**The model interprets.** It phrases findings, chooses which to lead with,
correlates across surfaces, writes the narrative, and proposes technique IDs and
containment actions.

**The model cannot invent a signal.** `_ground()` in
`graph/nodes/investigators.py` drops any finding citing a detector that did not
fire, and caps a finding's confidence at the detector's own score. A model that
hallucinates a beacon produces nothing, and the drop is written to the audit
chain.

That boundary also caps the blast radius of a successful injection. A payload
that fully steered the model could bias a narrative; it could not manufacture a
haversine distance or erase a jitter coefficient.

---

## The mock model is the default

`bishop.models.mock.MockModel` is what `just demo`, the test suite and the
scorecard run against. It takes no key and makes no network call.

It can produce a real verdict without a model because the prompt already
contains every signal the verdict rests on — that is what the hard rule above
buys. It parses the `<detector-results>` block and composes the same structured
output a real model would be asked for, weighing detector scores with a
probabilistic OR and assembling prose from the detectors' own rationales.

So the offline demo is not a puppet show: the verdict, the evidence and the
numbers are real and checkable. What is missing is judgement. The narrative
reads like a report generator, correlation across signals is crude, and it will
not notice the thing nobody wrote a detector for. That gap is what the live
provider is for, and it is why the scorecard labels which provider produced it.

---

## State and concurrency

`BishopState` is a `TypedDict`. Two things about its shape are load-bearing:

`reports` and `cost` are **reducer fields** — investigators run in parallel via
`Send`, so their writes merge rather than overwrite. Everything else is written
by exactly one node, which is what keeps the concurrency comprehensible.

Confidence means different things by provider. Under the mock it is arithmetic
over detector scores; under a live provider it is the model's own assertion,
clamped only by the abstention threshold. The scorecard names the provider for
exactly this reason.

`quarantine_evidence` is **its own field**, not a slot inside `reports`. An
alert whose only notable feature is an injected instruction produces no detector
hits at all. If injection findings travelled with the investigator reports they
would arrive empty and the most interesting alert in the corpus would come back
clean. `tests/graph/test_pipeline.py::TestInjectionOnlyAlert` pins that path.

---

## The human gate

`interrupt()` suspends the run mid-graph and checkpoints it; the graph resumes
only when a human supplies a decision, which may be hours later. The checkpointer
is therefore not optional.

The gate is defended twice, on purpose:

1. `response_gate` is the only edge into `response_execute`, and
   `tests/graph/test_gate.py` asserts that stays true.
2. `response_execute` re-checks the decision **per action** and refuses anything
   not named in it — including when the graph is invoked directly, a state is
   restored from a checkpoint, or someone wires a new edge.

The second check is the one that survives refactoring. A control that lives only
in the graph topology is one edge away from being gone, and nobody would notice
until an account got disabled.

Everything downstream is mocked. `MockExecutor` records what it would have done
and performs no side effect. There is no `auto_execute` flag and no severity
above which the gate is skipped, because the first thing anyone would do with
such a flag is turn it on at 2am during an incident. See
[ADR-003](decisions/ADR-003-human-gated-response.md).

Unrecognised input at the gate is treated as a rejection. Defaulting the other
way would mean a malformed resume payload could isolate a host.

---

## The audit chain

Append-only, hash-chained. Each entry commits to the one before it, so changing
any earlier entry breaks every hash after it.

There is no `update` and no `delete`. A correction is a new entry referencing the
old one — an audit log you can quietly fix is not an audit log, it is a note.

**What this gives you and what it does not.** It detects tampering by anyone who
cannot recompute the whole chain: accidental corruption, a partial overwrite, an
attacker editing one row. It does **not** defend against someone who can rewrite
the entire file and recompute every hash forward. That needs the head published
somewhere Bishop does not control — a transparency log, or simply mailing the
head hash somewhere append-only. Not implemented, and worth saying rather than
implying.

One quirk worth knowing: LangGraph re-runs a node from the top when a run
resumes, so `approval_requested` is written twice for every approval. Both are
recorded — the chain is append-only and deleting the first would be a lie about
what happened — and the second carries `replayed_after_resume: true`.

---

## Storage

In memory. Incidents and audit chains live for the process, and a restart loses
in-flight runs.

`PLAN.md` specifies Postgres with pgvector, and the seams are there —
`AuditChain` takes a path and persists as JSON Lines, `DATABASE_URL` is in
`.env.example`. What is not built is the persistence layer behind them. For a
demo over a 20-alert corpus this is the right trade; for anything real it is the
first thing to fix, and it is listed as a limitation rather than dressed up.

---

## The API surface

FastAPI. Read-only endpoints for the corpus, detectors, coverage matrix and
scorecard; one endpoint that starts a run; one SSE stream; one that records a
decision.

The stream closes when a run settles — including at `awaiting_approval`, which
is a pause rather than an end — so a client re-subscribes after submitting a
decision. It replays everything that already happened before going live, so a
console opened halfway through renders the whole run.

Nothing is authenticated. That is fine for a read-mostly demo over synthetic
data and would not be fine for anything else.

---

## What I would change first

1. **A held-out evaluation set.** The current corpus was written before the
   thresholds were tuned against it. That measures consistency, not
   generalisation, and the scorecard says so — but saying so is not fixing it.
2. **Multi-alert correlation.** Bishop triages one alert at a time.
   `Alert.entity_key()` exists and nothing uses it to stitch alerts into an
   incident, which is exactly the reasoning a tier-2 analyst is paid for.
3. **Persistence.** See above.
4. **A real detection surface for the techniques at 76% recall.**
   [`COVERAGE.md`](COVERAGE.md) names them.
