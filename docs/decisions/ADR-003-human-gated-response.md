# ADR-003 — Human-gated response with mocked executors

**Status:** accepted

## Context

Bishop reaches a verdict and proposes containment: isolate a host, disable an account, block an
IP, revoke tokens. Every one of those is disruptive when right and an outage when wrong.

There is also an adversarial angle. Two of the five attacker goals in
[`docs/THREAT-MODEL.md`](../THREAT-MODEL.md) are about response, not verdict: get a containment
action silently dropped, or get an *unrelated* host isolated. The second turns Bishop into a
denial-of-service tool aimed at its own organisation. Both require the response path to be
autonomous to pay off.

## Decision

**No autonomous containment, at any confidence level.**

- Every response action passes a LangGraph `interrupt()` gate presenting an editable plan with a
  blast-radius estimate.
- The **edited** plan is what executes. The resumed value is consumed; the original proposal is
  not silently preferred.
- Rejection terminates cleanly and is recorded. Nothing partially executes.
- Timeout or crash at the gate defaults to **not acting**.
- No env var, config flag, CLI switch or test hook disables the gate outside the test suite.
- Every executor sits behind an interface and the shipped implementation is a mock that writes
  to `outbox/`. No real API client, SSH, WinRM, cloud SDK or subprocess exists in any response
  path.

## Consequences

**Good.** The worst outcome of a fully successful prompt injection is wasted analyst attention,
not adversary-controlled infrastructure — that is a real, bounded security property, not a
disclaimer. Every irreversible action has a named human and a recorded decision in the audit
chain, which is what a compliance conversation actually needs. The mocked executors also mean
the demo is safe to run anywhere, including on stage.

**Bad.** Bishop is not autonomous, so it does not close the loop and does not deliver
mean-time-to-contain improvements. Human review is the throughput ceiling. In a real SOC, an
analyst approving without reading is the weakest and least testable link in the design — the
control is procedural at the last step, and no code can fix that.

**Rejected framing.** "Auto-contain above 0.95 confidence" sounds reasonable and is where most
implementations end up. It fails because confidence is computed from evidence the attacker
partially controls. Any confidence threshold becomes a target: the attacker's job stops being
"evade detection" and becomes "clear the bar for automatic action against a host I choose".
Introducing an autonomous path introduces that entire attack class for a latency win that a
portfolio project does not need.

## Consequences for how it is reviewed

This is why `evidence-auditor` reviews only and never edits, and why a BLOCKER in the gate or
executor-isolation checks stops a ship outright. A control that can be waived under deadline
pressure is not a control.

## Alternatives considered

**Tiered autonomy** — auto-execute reversible actions (block an IP), gate irreversible ones
(disable an account). Genuinely defensible and probably correct at production scale. Rejected
here because "reversible" is contextual: blocking an IP is trivially reversible unless it is a
VPN concentrator, in which case it is an outage. Deciding that correctly needs asset context
Bishop does not have.

**Auto-execute into a sandbox / dry-run mode.** This is effectively what the mocked executors
are, minus the pretence that it is autonomy.
