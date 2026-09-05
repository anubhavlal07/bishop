# Console

The analyst console. Next.js App Router, React Flow, Tailwind.

```bash
npm install
npm run dev          # http://localhost:3000
```

It needs the API running:

```bash
just api             # from the repo root, http://localhost:8000
```

Point it elsewhere with `NEXT_PUBLIC_BISHOP_API`.

---

## What each page is for

**Alerts** — the labelled corpus. Clicking one starts a run and takes you to it.
The expected verdict is shown because it makes the demo readable; Bishop never
sees it.

**Run view** — the live one. The React Flow graph animates from the SSE stream,
and the five investigators sit in one column so the fan-out reads as parallel,
which is the architectural claim the view exists to demonstrate. Below it: the
verdict with its counter-arguments, evidence grouped by investigator, the
proposed response, the timeline and the audit chain.

**Coverage** — the ATT&CK matrix, tactics left to right in intrusion order.
Covered and untested are shown differently on purpose: a detector with no
fixture behind it is real coverage and unproven coverage, and collapsing the two
would be the kind of green dashboard this project is arguing against.

**Detectors** — every deterministic primitive and what it measures.

**Scorecard** — the measured numbers, with the caveats rendered *above* them.

---

## Three deliberate choices

**The approval modal is the product, not a confirmation dialog.** Irreversible
actions start unchecked — approving everything should take a deliberate click,
and the default should be the option you can walk back. The blast radius sits at
the same visual weight as the action, because an approval prompt that says
"isolate DC-01?" without saying what stops working is a rubber stamp rather than
informed consent. There is no "approve all and remember this", because Bishop
does not have one.

**The console fails loudly.** An unreachable API and an empty alert list look
identical on screen, and the second one is the analyst's problem to know about.
`ApiDown` says which it is.

**Dark by default.** This is a tool read at 3am. `prefers-color-scheme: light`
still works.

---

## Notes on the stream

The API closes the SSE stream when a run settles — including at
`awaiting_approval`, which is a pause rather than an end — so `useRunStream`
re-subscribes after a decision is submitted. Each subscription replays
everything that already happened before going live, which is why the hook clears
its event list on reconnect rather than appending: a console opened halfway
through a run renders the whole run, and reconnecting must not duplicate it.

`EventSource` has no `onmessage` here because the server names every event, so
the hook registers a listener per event kind.
