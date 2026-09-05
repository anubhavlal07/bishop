# ADR-002 — Deterministic detectors beneath the model

**Status:** accepted

## Context

The obvious way to build an LLM SOC analyst is to hand the model an alert and ask what it
thinks. It produces fluent, plausible security analysis immediately, which is exactly the
problem: there is no way to tell a correct verdict from a confident one, no way to test it, and
no number to cite when a human asks why.

A security tool has to be able to answer "what specifically made you say that".

## Decision

**The LLM reasons and narrates; unit-tested Python decides.**

Every signal contributing to a verdict comes from a pure function in `src/bishop/detectors/`:

- no LLM call, no network call, no clock read, no randomness — "now" is a parameter
- returns a structured finding, never a bare bool: the signal value, the threshold compared
  against, the evidence locator, a severity
- thresholds are named constants with a written rationale
- every detector ships with its test in the same change, including boundary cases and a
  realistic benign case that must not fire

Detectors emit **signals**, not verdicts. `is_credential_dumping()` is a verdict wearing a
costume; the correct primitives are a parent/child pair anomaly, a rare process hash, and a
handle-access pattern. Correlation into intent happens once, in synthesis, where it can cite
each contributing signal.

## Consequences

**Good.** Every verdict traces to a number a human can check. Detectors are fast, free, and
testable in milliseconds, so the eval harness is cheap to run. It bounds the blast radius of
prompt injection: a model that has been fully talked over still cannot manufacture a haversine
distance or erase a jitter coefficient — it can bias the narrative, not the evidence. And the
detector layer works identically under the mock model, which is what makes offline demos
possible.

**Bad.** Real work per detector, and coverage is limited to techniques someone wrote a detector
for. Novel or low-and-slow behaviour that no primitive captures is invisible no matter how
capable the model is. Thresholds need justification and will need tuning against a corpus larger
than twenty alerts.

**Accepted tradeoff.** Narrower coverage that can be measured beats broader coverage that
cannot. A tool that misses things it never claimed to catch is honest; one that confidently
mis-triages is dangerous.

## Alternatives considered

**Pure LLM triage.** Fastest to build, broadest apparent coverage, and completely unevaluable.
Rejected.

**Sigma rules as the runtime engine.** Real detection content, community-maintained. But Sigma
matches patterns and returns a boolean — Bishop needs the underlying continuous signal (how far,
how regular, how rare) to compute confidence and to explain itself. Sigma is used as a reference
for what to detect, not as the engine.

**Train a classifier.** No labelled data at anything like the required scale, and a model that
cannot explain which feature fired is worse here than one that can. Rejected.
