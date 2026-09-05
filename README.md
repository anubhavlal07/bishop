# Bishop

[![CI](https://github.com/anubhavlal07/bishop/actions/workflows/ci.yml/badge.svg)](https://github.com/anubhavlal07/bishop/actions/workflows/ci.yml)
![Python 3.12](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-16-000000?logo=next.js&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-supervisor%20%2B%20HITL-1C3C3C)
![ATT&CK v17.1](https://img.shields.io/badge/ATT%26CK-v17.1-B02A37)
![tests](https://img.shields.io/badge/tests-1050%20passing-16a34a)
![bring your own key](https://img.shields.io/badge/model-bring%20your%20own%20key-8b5cf6)

An **autonomous SOC analyst** built on **LangGraph** — and a study in what it takes to let a
language model near a security decision without letting it *make* one. Give Bishop an alert; it
quarantines every attacker-controlled field, dispatches a team of specialist investigators in
parallel, fuses their findings into a **MITRE ATT&CK-mapped verdict**, argues against itself,
proposes containment, and **stops dead at a human gate** before anything irreversible happens.
Every step is written to an append-only, hash-chained audit log.

<p align="center">
  <img src="docs/demo/gate.svg" alt="Bishop stopping at the human approval gate, with blast radius per action" width="820">
</p>

<p align="center"><em>Bishop will not contain a host on its own. It proposes, states the blast
radius of each action, and waits.</em></p>

It is built around four claims that are each **individually checkable**:

1. **The LLM reasons; unit-tested Python decides.** Every signal behind a verdict comes from a
   pure, deterministic detector. A model that invents a finding has it dropped and the refusal
   audited.
2. **The agent is an attack surface.** Alert fields are written by attackers. Bishop treats
   them as hostile input, and a payload that tries to steer it is escalated as an **IOC**, not
   stripped.
3. **Abstention is a feature.** Below its confidence threshold — or with nothing it can
   actually measure — Bishop hands the alert to a human and says why.
4. **No autonomous containment, ever.** Every action goes through `interrupt()` and a mocked
   executor. There is no code path that isolates a host without a recorded human decision.

**Live:** [bishop.anubhavlal.dev](https://bishop.anubhavlal.dev) · API at
[api.bishop.anubhavlal.dev](https://api.bishop.anubhavlal.dev/health)

The console is a **static export on Netlify** — every page is a client
component that talks to the API directly, so there is no server rendering to do
and the build is 1.1 MB of files. The API is a **Docker container on Render**,
with **Postgres in a Supabase schema**.

Both custom domains are served by small **Cloudflare Workers** that rewrite the
Host header, because Netlify and Render each only answer for hostnames
registered against them. The API proxy passes the SSE body through as a stream
rather than awaiting it — buffer that and the live topology view shows nothing
for twenty seconds and then everything at once.

> **Bring your own key.** The deployment stores no model credential. Pick Anthropic, OpenAI,
> Gemini or Azure OpenAI in the console, paste your key, and it stays in your browser. Or pick
> the **deterministic model** and run the whole thing with no key at all — the detectors, the
> ATT&CK validation, the injection scanner, the correlation and the audit chain are the same
> code either way.

---

## Capabilities

- **Parallel investigation graph** — the `StateGraph` is the single source of truth:
  `ingest → triage_supervisor →` `Send` fan-out to `identity / endpoint / network / threatintel
  / context` investigators `→ synthesis → adversarial_critic → response_planner → response_gate
  (HITL) → response_execute → report`. The supervisor dispatches only surfaces that have data.
- **19 deterministic detectors** — impossible travel, MFA fatigue, password spray, credential
  dumping, LOLBin abuse, encoded commands, masquerading, persistence, beaconing, DNS
  tunnelling, outbound volume, data staging, IOC reputation, and two *mitigating* detectors
  that can argue **against** malice. No model, no network, no clock read, no randomness —
  enforced by AST checks and double-run tests.
- **Indirect prompt-injection defence** — 13 techniques scored across a
  **132-payload red-team corpus**, currently **124 caught with 0 false positives** on 38 benign
  samples. Defence sits at the *render boundary*, because provenance cannot survive `str()`.
- **Validated ATT&CK mapping** — a technique ID reaches a report only after it is confirmed in
  the committed STIX bundle (823 techniques, v17.1). A model-proposed ID that fails validation
  is rejected and re-prompted, never passed through with a caveat.
- **Bring your own alert** — Sysmon, Elastic Common Schema, or any JSON with recognisable field
  names. The normaliser reports what it read, what it ignored, and **which detectors have
  jurisdiction** over what survived.
- **Hash-chained audit** — every dispatch, finding, refusal, verdict and decision is a link.
  The chain head is stored beside the incident, so a **truncated tail is detectable** —
  verifying a chain against itself cannot see that its end was removed.
- **Multi-alert correlation** — connected components over shared host or account within an
  hour. Three low-severity alerts become one intrusion.
- **Honest evaluation** — a tuned development set *and* a **held-out set run once**, reported
  side by side. The held-out number is 33%, and it is in this README because that is the number
  that means something.

---

## Architecture

```
Backend (Python 3.12, FastAPI, LangGraph, SSE)        Frontend (Next.js App Router, React Flow)
──────────────────────────────────────────────        ──────────────────────────────────────────
quarantine/   the security boundary                    app/
detectors/    pure functions · no LLM · no network       /            alert queue
attck/        STIX validation + coverage matrix          /triage      bring your own alert
graph/        the StateGraph                             /runs/[id]   live topology + evidence
  ingest ─▶ triage_supervisor ─Send▶ investigators       /coverage    ATT&CK matrix
  ─▶ synthesis ─▶ adversarial_critic                     /scorecard   metrics + caveats
  ─▶ response_planner ─▶ response_gate (HITL)          components/
  ─▶ response_execute ─▶ report                          Topology     React Flow graph
audit/        append-only hash chain                     ApprovalModal per-action approval
models/       mock · anthropic · openai · gemini · azure  ProviderSetup BYOK dialog
store/        incidents + chains (SQLite / Postgres)   lib/           typed client · SSE
```

**The graph** — what actually runs, and where it stops:

```mermaid
flowchart TD
  A["alert in"] --> Q["quarantine<br/>every attacker-controlled field"]
  Q --> S["triage_supervisor<br/>dispatch only surfaces with data"]

  S -->|Send| I1["identity"]
  S -->|Send| I2["endpoint"]
  S -->|Send| I3["network"]
  S -->|Send| I4["threatintel"]
  S -->|Send| I5["context<br/>argues against malice"]

  I1 & I2 & I3 & I4 & I5 --> F["synthesis<br/>grounding in three directions"]
  F --> C["adversarial_critic<br/>what would make this wrong"]
  C -->|bounded loop| F
  C --> P["response_planner<br/>blast radius per action"]
  P --> G{"response_gate<br/>interrupt()"}

  G -->|approved subset| X["response_execute<br/>mocked · per-action recheck"]
  G -->|rejected| R["report"]
  X --> R

  style G fill:#e3b341,color:#0b0d10
  style Q fill:#b02a37,color:#fff
  style F fill:#1c3c3c,color:#fff
```

**Grounding — the rule that makes a verdict mean something.** A label is only allowed if
something deterministic backs it, in *all three* directions:

```mermaid
flowchart LR
  V["model proposes<br/>a label"] --> T{"true_positive?"}
  T -->|"no detector fired"| E["escalate"]
  T -->|"grounded"| OK1["stands"]

  V --> B{"benign_true_positive?"}
  B -->|"no mitigating detector"| E
  B -->|"grounded"| OK2["stands"]

  V --> FP{"false_positive?"}
  FP -->|"nothing examined it"| E
  FP -->|"a detector looked"| OK3["stands"]

  style E fill:#e3b341,color:#0b0d10
```

The third arm is the one a held-out set found: closing a ticket is a claim that *someone
looked*. When every detector returned "nothing to work with", Bishop was reading **nobody
checked** as **nothing to find**.

**Untrusted data flow** — where attacker text is allowed to go:

```mermaid
flowchart LR
  subgraph Hostile["attacker-controlled by definition"]
    CL["command lines"]
    FN["file names"]
    DNS["DNS queries"]
    EM["email subject / body"]
    RAW["raw{} — every leaf"]
  end

  Hostile --> SC["scan<br/>13 injection techniques"]
  SC -->|"score ≥ 0.5"| IOC["escalate as an IOC<br/>never stripped"]
  SC --> SB["safe_block()<br/>escapes &lt; and &gt; unconditionally"]
  SB --> NF["nonce-fenced quarantine block"]
  NF --> PR["prompt"]

  DET["detector results<br/>Bishop's own output"] --> PR

  style IOC fill:#b02a37,color:#fff
  style SB fill:#1c3c3c,color:#fff
```

---

## Tech stack

| Layer | Choice |
|---|---|
| Language | Python 3.12, `uv` for deps, `just` for tasks |
| Orchestration | LangGraph — supervisor, `Send` fan-out, `interrupt()`, checkpointing |
| API | FastAPI + SSE |
| Model | Deterministic mock (default) · Anthropic · OpenAI · Gemini · Azure OpenAI |
| Store | SQLite by default, Postgres in production — same schema either way |
| Console | Next.js App Router, React Flow, Tailwind v4 |
| Deploy | Docker · Render (API + Postgres) · Netlify (console) |

---

## Quick start

Requires Python 3.12 and [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev
just demo                  # triage an alert end to end, including the human gate
just eval                  # the scorecard, on the tuned development set
just eval-holdout          # the held-out set — the number that means something
just test                  # 1050 tests, 12 xfail (open injection gaps)
```

Then the console:

```bash
just api                   # FastAPI on :8000
just console               # Next.js on :3000
```

Everything above runs **offline with no key**. A model activates when you pick one in the
console, or with `BISHOP_MODEL_PROVIDER` and a key in `.env`.

### Triage an alert of your own

```bash
just triage my-alert.json        # or: cat alert.json | uv run bishop triage -
just formats                     # the shapes it recognises
```

It prints **what it read before what it concluded**, and that order is the point — a verdict is
only worth as much as the fields behind it:

<p align="center">
  <img src="docs/demo/triage.svg" alt="The mapping report: what Bishop understood, ignored, defaulted, and which detectors have jurisdiction" width="820">
</p>

That detector list is computed by *running* them — a fact about your alert, not a claim about
the tool. When it comes back empty, `triage` says so and exits rather than producing a verdict
with nothing behind it.

---

## Using it

`just demo` triages a credential-dumping alert and stops at the gate shown at the top of this
page. Approve a subset and the rest come back `refused`, by name, in the execution log — a
console bug cannot isolate a host. The verdict it reaches:

<p align="center">
  <img src="docs/demo/verdict.svg" alt="The verdict: true positive at 0.95, three detectors, validated ATT&CK techniques" width="820">
</p>

### Other things worth typing

```bash
just alerts                # the labelled corpus
just detectors             # every detector and what it measures
just incidents             # how the corpus correlates into incidents
just coverage              # regenerate docs/COVERAGE.md from the code
just keygen                # an API key for a deployment
just check-production      # would this config be allowed to serve?
```

---

## Evaluation

Two numbers, and the second is the honest one.

| | Development set | Held-out set |
|---|---|---|
| Alerts | 30 | 15 |
| False-negative rate on true positives | **0%** | **50%** |
| Verdict accuracy | 100% | **33%** |
| False-positive rate | 0% | 20% |
| Escalation precision / recall | 100% / 100% | 50% / 17% |
| ATT&CK technique recall | 100% | 36% |
| Invalid technique IDs emitted | 0 | 0 |
| Median time to triage | 0.03 s | 0.03 s |

The development set was written first and the thresholds were tuned against it, so 100% there
measures **internal consistency** — detectors, mitigating rules and label definitions agreeing
with each other. It is a smoke test, not a benchmark.

The held-out set is fifteen alerts written **after** the thresholds were frozen, run **once**,
and reported whatever it said. `just eval-holdout` deliberately has **no baseline and no
regression gate**, because a gate on a held-out set is precisely what turns it back into a
training set. The result is committed at `eval/results/holdout-2026-09-05.json`.

**What the 33% was made of.** Ten of fifteen wrong, in three different ways: one real logic
defect (the third grounding arm, now fixed — it moved the score to 40%), a set of coverage gaps
where Bishop simply has no detector, and two cases where my own label is arguable. I have not
fixed the rest and will not: debugging against a held-out case converts it into a development
case, and anything I fixed would make the number look better and mean less.

### Measured against a live model

The deterministic model is the default, so the live path was code-reviewed but
unrun for a long time. It has now been exercised against **Gemini 3.8 Flash**
over six alerts: **5 of 6 correct**, ~21 s and ~19k tokens per triage, 5 model
calls each. The one miss is a label disagreement rather than a failure — the
model called an admin PowerShell session `benign_true_positive` where the corpus
says `false_positive`, and it grounded that on a mitigating detector.

Running it live found four bugs the deterministic model could never surface, all
now fixed and covered by tests:

- **A valid key was rejected before any request.** The Gemini key pattern
  matched only the historical `AIza…` form, not the `AQ.` keys AI Studio now
  issues.
- **Thinking tokens ate the output budget.** `maxOutputTokens` covers thinking
  *and* output on Gemini 3.x, so a 16-token connectivity ping spent it all on
  thoughts and returned prose with a 200 status — telling users with a working
  key that it had been rejected.
- **A nullable field broke every synthesis call.** JSON Schema writes an optional
  string as `{"type": ["string", "null"]}`; Gemini's proto validator rejects a
  list-typed field outright.
- **The critic escalated everything.** It asked to escalate while writing "the
  verdict easily survives adversarial critique" and leaving confidence at 0.98.
  A competent critic can always name *some* alternative, so honouring an
  unsupported flag escalates every true positive — and a tool that escalates
  everything has perfect recall and is useless. The flag is now honoured only
  when the critic's own confidence adjustment supports it, and the refusal is
  written to the audit chain.

A fifth, smaller one: `action_type` was a free string, so the model proposed
`terminate_process` for what Bishop calls `kill_process`. The executor correctly
refused it, which left a containment plan quietly missing the actions the model
intended. The schema now enumerates the twelve real actions.

Each is the same shape of defect: a model asserting something its own
measurements do not support — the failure the grounding rules exist for.

Both corpora are synthetic. Real SOC data is either licence-encumbered or full of somebody's
real hostnames, and a golden set has to be labelled. That buys honest labels and costs any
claim about real-world noise.

---

## Red-teaming the prompt surface

`tests/injection/` is a corpus of **132 payloads and 38 benign samples** written to defeat
Bishop's own defences. It found six ways in, and every one worked the same way: **not by
attacking the fence, but by going around it.**

`assert_no_untrusted()` was an instance check on a marker type — and every Python string
operation returns a plain `str`, so the marker did not survive `str(x)`, `x.lower()`, or an
f-string. Four live paths laundered attacker text into the block the system prompt describes as
*Bishop's own output*. A nineteen-character suffix on a real credential-dumping command line
flipped the verdict to `false_positive` and dropped all five containment actions.

The worst one was subtler: Bishop **detected** the injection, raised it as an IOC, wrote it to
the audit chain — and still returned `false_positive`, because a second field forged an empty
`<injection-findings>` block. **Detection and escalation are not the same thing as defence.**

The fix moved the boundary. Provenance cannot be tracked through `str()` in Python; refusing to
*emit* a delimiter can be. `safe_block()` escapes `<` and `>` unconditionally.

Current score: **124/132 caught, 38/38 benign clean**. The 8 that evade are strict-xfail tests,
so the suite fails the moment one is fixed and the ledger cannot go stale.

---

## Deployment

Full guide in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

Bishop's defaults are laptop defaults. `BISHOP_ENVIRONMENT=production` turns them into
**startup checks** — it refuses to serve rather than warning, because a warning in a log nobody
reads is not a control:

| Setting | Required in production | Why |
|---|---|---|
| `BISHOP_API_KEYS` | ≥1 key, ≥32 chars | the API serves hostnames, accounts, and Bishop's view of which are compromised |
| `BISHOP_CORS_ORIGINS` | a named origin, never `*` | a wildcard lets any page read incident data from a browser holding a key |
| `BISHOP_RATE_LIMIT_PER_MINUTE` | above zero | every run costs tokens; an unlimited API is an unlimited bill |
| `DATABASE_URL` | Postgres, never SQLite | an audit chain that does not survive a restart is not an audit chain |

```bash
uv run bishop keygen              # Bishop will not invent a key for you
docker build -t bishop .          # non-root, no toolchain, frozen lockfile
uv run bishop config              # would this configuration be allowed to serve?
```

### The public demo is a declared mode, not a missing setting

The deployment above runs with `BISHOP_PUBLIC_DEMO=true`, and that flag is an
explicit choice with its own constraints rather than an absence of one. With it
on, Bishop **refuses** a rate limit looser than 60/min, **refuses** to also
demand an API key (a key baked into a public console's JavaScript protects
nothing), and **never writes an alert a visitor supplied to the shared store**.

That last one is the reason the mode exists. The store is shared and
`/incidents` lists it, so persisting a submitted alert on an open deployment
would publish one stranger's alert to every other visitor — and somebody
pasting a real alert from their own SIEM into a demo box has not agreed to
that. Corpus runs are still stored: those are synthetic and already in this
repository.

Demo mode also drops the Postgres requirement, for a stated reason rather than
convenience: the requirement exists because an audit chain that does not
survive a restart is not an audit chain, and in demo mode there is no such
chain — submitted alerts are never written, and corpus runs can simply be run
again.

---

## What this doesn't do

The honest list. If any of these matters to you, it needs building before Bishop is the right
tool for the job.

- **No per-user accounts or roles.** Every valid API key has identical authority, including
  approving containment. The chain records `decided_by` as whatever the client sent — it
  *attributes* a decision without *authenticating* who made it.
- **Bishop covers 31 ATT&CK techniques of 823.** Outside those it escalates rather than
  guessing. That is correct behaviour and still means a human does the work.
- **It triages what the SIEM gives it.** It inherits every gap in the detection layer above it
  and adds no coverage of its own.
- **The injection scanner is pattern- and heuristic-based.** Thirteen techniques is not all
  techniques; a regression corpus demonstrates the classes I thought of, which is not a proof.
- **Semantic steering** — a payload supplying plausible benign context with no imperative to
  detect — is the hardest class and only partially mitigated.
- **Rate limiting is per-instance and in memory.** Two instances means double the effective
  limit. Put a real limiter at the edge.
- **No SIEM connector.** Alerts arrive by API call, file, or paste.
- **No live containment integrations.** Every executor is a mock, on purpose.
- **A poisoned threat-intel feed degrades verdicts** without tripping the scanner.
- **The mitigating detectors read `fixtures/environment/policy.json`.** Anyone who can write to
  that file can exonerate themselves.

---

## Documentation

| | |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | graph topology, state shape, storage, the API surface |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | including "the agent is an attack surface", and what is *not* defended |
| [`docs/DETECTORS.md`](docs/DETECTORS.md) | every detector: the signal, the maths, where the thresholds came from |
| [`docs/COVERAGE.md`](docs/COVERAGE.md) | technique → detector → fixture matrix, generated from the code |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | production checks, Docker, Render, and the remaining gaps |
