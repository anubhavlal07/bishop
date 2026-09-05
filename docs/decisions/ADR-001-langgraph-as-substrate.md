# ADR-001 — LangGraph as the orchestration substrate

**Status:** accepted

## Context

Bishop needs to dispatch several investigators concurrently, fuse their output, run a bounded
self-critique, pause for human approval with editable state, and be inspectable after the fact.

Four capabilities drive the choice: **parallel fan-out**, **a real pause-and-resume** where the
human can edit state and the edit is what proceeds, **checkpointing** good enough to inspect and
fork a past run, and **streaming** granular enough to animate a live topology in a console.

## Decision

Use LangGraph, and make the `StateGraph` the single source of truth. The FastAPI layer only
streams graph events; the console only renders them. If a behaviour is not expressed in the
graph, it does not exist.

Investigators are dispatched with the `Send` API. The human gate is a real `interrupt()` with
`Command(resume=...)`. Every run is checkpointed.

## Consequences

**Good.** Parallelism, interrupts and checkpointing come from the framework rather than from
bespoke async and state-machine code — which is where the subtle bugs would otherwise live. The
graph is legible as a diagram, so the architecture doc and the console topology describe the
same object. Time-travel and forking fall out of the checkpointer.

**Bad.** A framework dependency on a fast-moving library, and `interrupt()` semantics are
specific enough that they leak into how nodes are written. State shape changes can invalidate
existing checkpoints, so a migration is a real concern once runs are persisted.

**Mitigation.** Nodes call a provider wrapper, never an SDK, and each is independently runnable
against a hand-built state object — so a framework change is contained to the wiring layer, not
the reasoning.

## Alternatives considered

**Plain `asyncio` with a hand-rolled state machine.** Fewest dependencies and total control. But
`interrupt()`-equivalent resumption with editable state, plus a checkpoint store that supports
forking, is a genuinely hard thing to build correctly and it would have consumed the whole
budget. Rejected on cost, not on principle.

**CrewAI / AutoGen.** Higher-level agent abstractions, but the coordination model is largely
model-driven. Bishop needs control flow to be deterministic and inspectable — an auditor has to
be able to point at the code that decides what runs next. Rejected.

**Temporal or a durable workflow engine.** Genuinely correct for durability and human-in-the-loop
at enterprise scale, and the natural answer if this were production. Too much operational
surface for the scope, and it does not solve the LLM-specific parts. Revisit if this ever
becomes real.
