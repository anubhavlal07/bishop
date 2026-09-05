# Detectors

Every signal that contributes to a verdict starts here.

A detector is a pure function from an `Alert` to a `DetectorResult`. Pure means
what it says: no model call, no network, no database, **no clock read, no
randomness**. Given the same alert it returns the same result on any machine in
any year. That is what makes `just test-detectors` a meaningful gate and what
lets an analyst re-derive a finding by hand.

The clock rule is the one that gets broken by accident. A detector calling
`datetime.now()` produces a different answer when the golden set is replayed
next week, and the scorecard quietly rots. Every time reference comes out of the
alert.

Each detector returns:

- `fired` — whether it has anything to say
- `score` — its own confidence on 0..1, not a probability and not a verdict
- `facts` — every number it computed. **This is what makes a finding checkable.**
- `rationale` — one sentence, plain English, no hedging
- `mitigating` — whether firing argues *against* malice rather than for it
- `technique_hints` — proposals, validated in `bishop.attck` before they ship

Three outcomes are distinguished on purpose. `miss()` means the detector had
nothing to work with. `clear()` means it ran and found nothing suspicious — and
it returns the facts anyway, because "no beaconing" and "nobody checked for
beaconing" are different things an analyst needs to tell apart. Firing is the
third.

`docs/COVERAGE.md` maps these onto ATT&CK and is generated from the registry, so
it cannot drift.

---

## identity

### `impossible_travel` — T1078

Great-circle distance between one account's consecutive successful logins over
the time between them, against airliner cruising speed (900 km/h).

The velocity is a lower bound twice over: great-circle distance understates real
travel, and it uses the shortest gap between the two sightings. If it says
4,000 km/h, the true implied speed is higher.

Three cases are separated rather than collapsed, because a single "impossible
travel" label would be wrong for two of them:

- **Under 300 seconds** cannot be travel at any speed, so it is not reported as
  travel and the detector does **not** fire. This is the largest source of false
  positives in real deployments — a VPN reconnecting to a different egress — and
  firing would put grounded evidence behind an explanation the detector itself
  disbelieves. The facts are retained under `suppressed_as_network_artefact`.
- **A non-positive gap** is concurrent sessions, capped at 0.55. An infinite
  implied velocity is an artefact of dividing by zero, not a measurement, and
  duplicated events and collector clock skew produce this as often as an
  intrusion does.
- **A positive gap implying superhuman speed** is the real finding, scored on how
  physically absurd it is.

Grouping by principal is the whole correctness of this detector. One alert
routinely carries events for several accounts, and comparing alice-in-London
against bob-in-Singapore manufactures travel nobody did.

Findings carry `from_event_index` / `to_event_index` so a reader can point at the
exact entries.

### `mfa_fatigue` — T1621

A burst of denied MFA prompts ending in an approval. The signal is not the
denials — users misfire prompts constantly — it is the shape: several denials
close together, then an acceptance. Denials with no approval still fire, lower,
as push-bombing the user held out against.

### `password_spray` — T1110.003

Many accounts, few attempts each, one source. Per-account lockout does not fire
on this by design, which is why it needs a detector counting *across* accounts.
Deep and narrow is brute force — a different technique and a different detector —
so more than five attempts against one account disqualifies it.

### `account_manipulation` — T1098, T1136

Privileged group additions and account creation.

**On trusting command lines.** A command line is attacker-authored, which cuts
both ways. The obvious risk is an attacker hiding a real change; the subtler one
is *manufacturing* a finding — writing `net localgroup administrators /add` into
a filename so a lexical match reports an escalation that never happened.
Fabricated evidence pointed at an innocent account wastes an analyst's night,
and if Bishop proposed containment on it, disables the wrong person.

Two things bound it. Directory change events (`raw.group_changes`) are preferred
and weighted higher, because the domain controller wrote them rather than
whoever started the process. Where a command line is the only source, the
*executable* must actually be a group-management binary — `notepad.exe
"…administrators /add.txt"` no longer matches. `facts["evidence_source"]` says
which path produced the finding.

That does not make the command-line path trustworthy. It makes it bounded.

---

### `kerberoasting` — T1558.003

Harvesting service tickets to crack offline. Written after the held-out set
caught Bishop escalating one of these with an empty evidence table.

**The rate is the signal, not the request.** Every workstation requests service
tickets constantly; that is how Kerberos works. What no ordinary client does is
ask for dozens in a couple of minutes, because a client requests a ticket for a
service it is about to use and does not suddenly need forty.

**RC4 is the part that shows intent.** An RC4 ticket is encrypted under the
service account's NTLM hash and cracks offline at speed; an AES ticket is far
more expensive to attack. A modern domain issues AES, so asking for RC4 is asking
for the crackable version — the same rate scores higher with it than without.

It reads a summary the sensor already computed rather than counting raw 4769
events, because the alert schema carries no ticket-event type. A sensor that
reports no count leaves nothing to measure, and that is a `miss()`, not a
`clear()`.

---

### `token_replay` — T1550.001, T1528

A cloud session credential presented by something that is not the user's
browser. Written after the held-out set caught Bishop closing a refresh-token
replay as a false positive at 0.95 confidence.

**Impossible travel deliberately misses this.** Both logins were from Dublin,
ten minutes apart, so distance and speed have nothing to say. Geography is not
the signal when a token is replayed from the victim's own city, or from a
hosting provider that geolocates to it.

**The signal is the client.** A browser session does not become
`python-requests/2.31.0`. When one account succeeds twice inside a session's
lifetime and the second success comes from a scripted client where the first
came from a browser, the credential is being presented by something other than
the thing that obtained it. A changed source IP means it is not the same browser
on a new tab; a dropped MFA factor means no fresh authentication happened, which
is what makes this reuse rather than a second login.

**What defeats it, stated plainly.** A user agent is attacker-controlled, and
tooling that sends a browser string evades this completely. That bounds what it
catches and cannot be fixed by reading the same field harder — only by an ASN
or token-binding field the alert schema does not carry. The inverse abuse is not
available: manufacturing a finding would mean controlling the victim's own
browser string. It caps at 0.85 for the same reason — one lexical read of one
attacker-influenced field should not carry a verdict alone.

---

## endpoint

The recurring shape here is *context beats identity*. `rundll32.exe` is not
suspicious; `rundll32.exe` with `comsvcs.dll MiniDump` against the LSASS process
id is.

### `lolbin_abuse` — T1218 and sub-techniques

Signed Microsoft binaries used as execution proxies, from the LOLBAS catalogue.
Scored on the **arguments**, not the binary: mere presence scores 0.25 and should
never carry a verdict, because `rundll32.exe` runs constantly on a healthy
Windows host. Argument patterns with no benign reading — `scrobj.dll`,
`-urlcache`, `comsvcs.dll` — score much higher.

### `suspicious_parent_child` — T1059, T1566.001

Process lineage that does not occur in normal operation. Two rules in decreasing
confidence: a document reader spawning a shell (0.8, close to unambiguous), and a
system binary with a parent outside its usual set (0.45, because management
agents do odd things).

### `credential_dumping` — T1003 and sub-techniques

Three independent routes to the same tactic: a tool by name, a command-line
pattern, or a raw handle to LSASS with an access mask permitting memory reads.
The third is the one that survives renaming the binary.

### `persistence` — T1547.001, T1543.003, T1053.005 and others

Anything written that will run again after a reboot: Run keys, service
registration, scheduled tasks, logon scripts, COM hijacks, IFEO. Fires on the
mechanism and leaves "was it legitimate" to synthesis, where the rest of the
context lives. Persistence pointing into a world-writable directory scores
higher than persistence pointing into Program Files.

### `encoded_command` — T1027, T1140, T1059.001

Command lines built to be unreadable. Where a base64 payload decodes cleanly the
decoded text is returned in the facts — that is the single most useful thing this
detector produces, because an analyst gets the actual command rather than a note
that one was encoded. Handles UTF-16LE, which is what PowerShell's
`-EncodedCommand` uses.

Each individual switch has a legitimate use; three together in one command line
is a deliberate attempt not to be read.

### `masquerading` — T1036.002, .005, .007

Names chosen to be misread. The right-to-left override case is the one worth
knowing: a file named `invoice‮gpj.exe` displays as `invoiceexe.jpg` in every
Windows file listing, and the extension a user sees is not the one that executes.
Also double extensions, and system binaries outside the directories they only
ever live in.

### `data_staging` — T1560.001, T1074.001

Archive creation, weighted by destination and password protection. Backup
software does this all day, so the detector reports the shape and leaves the
judgement to synthesis.

### `suspicious_execution_path` — T1204.002

Execution from a world-writable directory. Installed software lives under Program
Files; a binary in `%TEMP%` or `/dev/shm` was put there by something.

### `abused_hosting_contact` — T1102

Contact with services hosting arbitrary user content. Explicitly weak at 0.35 —
plenty of legitimate traffic goes to GitHub and Discord. It exists so synthesis
can raise the weight of a connection that is already suspicious for another
reason.

---

### `recovery_destruction` — T1490, T1070.001

Deleting the way back before encrypting. Written after the held-out set caught
Bishop closing a shadow-copy deletion as a false positive.

**One mechanism is suspicion; several is intent.** An administrator reclaiming
disk on a full server genuinely runs `vssadmin delete shadows`, so one match
scores 0.55 and the rationale says so. Shadow copies *and* the backup catalogue
*and* boot recovery destroyed in one command line is 0.9 — nobody frees disk
space by disabling `bcdedit` recovery.

`/quiet` and `-quiet` add to the score. Those flags exist to skip the
confirmation prompt, and nobody standing at the console needs to skip it.

It reads scheduled-task actions as well as command lines, because persistence
runs the command later and the task action is the carrier.

---

## network

Both work on timing and structure rather than payload, because that is what
survives TLS.

### `beaconing` — T1071.001

Inter-arrival regularity across repeated connections to one destination.

Regularity is the coefficient of variation of the gaps, measured **after
dropping the largest fifth (at most two)** as missed check-ins. That trimming is
what lets a laptop that slept through three check-ins still look like a beacon
without letting ordinary bursty browsing look like one.

Median absolute deviation was the obvious tool and is the wrong one. It tolerates
a *majority* of irregular values, so browsing traffic with gaps of 5 s, 900 s and
3600 s scored as a clean beacon; and it collapses to exactly zero on an
alternating two-valued series. Both measures are still reported in the facts
because they are informative, but the decision no longer rests on them.

Small jitter is *more* suspicious than none: modern C2 randomises the interval by
design, so a perfectly flat series often means a cron job and a 10-20% wobble
often means an implant.

### `dns_exfiltration` — T1071.004

Three signals combined: subdomain labels that look encoded rather than written
(high Shannon entropy), close to the length limit, and many distinct ones under
one parent. Any one alone has benign causes — CDNs generate high-entropy
hostnames all day — so it requires at least two of the three legs.

The public-suffix handling is deliberately simple, covering common two-part TLDs
and treating everything else as `domain.tld`. Accurate enough for a tunnelling
heuristic and honest about its limits.

### `outbound_volume` — T1041

Asymmetry between bytes sent and received. Browsing is inbound-heavy; a session
sending far more than it receives is an upload. Requires 10 MB and a 10:1 ratio.

---

## threatintel

### `ioc_reputation`

Reputation lookup for every IP, domain, URL and hash in the alert, against a
cache fetched *ahead of* the run.

Bishop never calls a feed during triage. Three reasons, in order: a detector that
makes a network call is not reproducible, so the scorecard stops meaning
anything; resolving attacker infrastructure at triage time tells the attacker
their payload was received; and `just demo` has to run with no credentials.

The facts carry the feed name and the first-seen date, because an indicator that
was malicious in 2019 and has since been reclaimed is a different thing from one
seen last week, and the analyst gets to make that call.

The committed cache is **synthetic** and says so in its own metadata and in every
rationale it produces. `just intel` populates a real one from abuse.ch, whose
terms permit use but not redistribution.

---

## context

These are the only detectors that can argue a verdict *down*. They exist because
the first scorecard run got every benign true positive wrong: nothing in the
pipeline could represent "this happened, and someone approved it", so an
authorised red-team exercise read as a genuine intrusion.

Two detectors, because they support different verdicts and conflating them would
lose the distinction that makes the label worth having.

### `authorised_activity`

*The technique really was used, by someone entitled to use it.* The red team on
their range, the platform admin inside a change window, an automation account
doing its documented job. That is a **benign true positive** — the detection was
correct and the activity was approved, which is a paperwork answer.

**Authorisation is scoped.** `max_privilege` in the policy is the point of the
design: knowing an account is not the same as that account being allowed to do
the specific thing observed. `svc_helpdesk` is a known automation account and is
still not permitted to touch Domain Admins. An unscoped allowlist excused exactly
that, and produced a missed true positive on `TP-05` — the worst failure
direction there is. A known account exceeding its remit now fires as an
*aggravating* signal instead, because it is worse than an unknown account doing
the same thing.

### `routine_software`

*The rule's premise is wrong.* A signed vendor binary in a trusted install path,
a sanctioned monitoring destination, persistence pointing back into Program
Files, a known scanner source. That is a **false positive** — a tuning answer.

Each finding names the detectors it *explains*, in `facts["explains"]`. That is
how an analyst actually reasons: "the beaconing is the monitoring agent checking
in" is a specific rebuttal of a specific observation, and it is much stronger
than a general sense that the host looks fine. Synthesis uses it to decide
whether every suspicious signal has an innocent account of it, rather than
comparing two aggregate scores that measure different things.

### Where the trust comes from

Both read [`fixtures/environment/policy.json`](../fixtures/environment/policy.json),
which is inventory data — CMDB, identity provider, change calendar. It is **not**
attacker-controlled, which is the whole reason it can be used to exonerate. An
attacker who can write into an alert cannot add themselves to the automation
account list.

The limitation is the obvious one: anyone who can write to that file can
exonerate themselves. In a real deployment it inherits the CMDB's access control,
and therefore its weaknesses.

Without the file Bishop still runs — it simply cannot tell authorised from
malicious, so everything authorised reads as an intrusion. That is the correct
failure direction.

The same file carries two lists no detector reads and the executor does.

`never_block` is the only bound on one specific attack: an adversary who sends
high-entropy DNS queries to a domain they do **not** own gets the tunnelling
detector to name it, and Bishop proposes cutting the estate off from it. The
evidence is real, the detector is right, and the analyst approving is being
reasonable — so the answer cannot come from the alert. It has to come from here,
where an attacker cannot write.

`public_suffixes` names any registry boundaries specific to this organisation —
an internal TLD, a lab namespace. The world's boundaries come from the committed
Public Suffix List in `src/bishop/graph/public_suffixes.json`.

That file exists because `_registrable_parts` above was briefly used as an
authorisation boundary, and its seven-entry two-part-TLD table made `x.y.co.za`
parent to `co.za` — so blocking a national registry passed the check. It is fine
for grouping queries, which is what it says it is for; it was never meant to
decide what may be cut off. See `docs/THREAT-MODEL.md` §6.

---

## The injection scanner

Not a registered detector, because quarantine is a boundary rather than a
surface. It runs at ingest, before any investigator, and its findings reach
synthesis on their own path — an alert whose only notable feature is a payload
produces no detector hits at all, and routing its finding through the
investigator reports would lose it.

Twelve techniques, each a named pattern set with a weight: instruction override,
role hijack, delimiter break, verdict manipulation, tool coercion, exfiltration
lure, prompt disclosure, encoding evasion, invisible text, homoglyph,
multilingual instruction, oversized field. Weights combine with a probabilistic
OR, so two 0.6 signals give 0.84 rather than certainty.

Every field is scanned in four forms — raw, invisible-characters-stripped,
de-spaced, and anything that base64/hex/percent/unicode-escape decodes out of it
— because `ign​ore previous instructions` and its base64 equivalent are the
same attack. A payload that had to be encoded to get here scores *higher*, not
lower: encoding is evidence of intent.

Patterns are phrase-shaped rather than keyword-shaped. "ignore" appears in benign
log text constantly; "ignore the above instructions" does not.

`tests/injection/` is the regression corpus.

---

## Thresholds, and where they came from

Honestly: from reading the technique documentation and from tuning against the
33-alert development corpus. They are not derived from a labelled production
dataset, because there isn't one here.

The ones with an actual physical justification are worth separating out:

| Threshold | Value | Why |
|---|---|---|
| Plausible travel speed | 900 km/h | airliner cruising speed |
| Network-artefact window | 300 s | below this, no travel explains 50+ km at any speed |
| Same-metro floor | 50 km | consumer geolocation is city-accurate at best |
| Beacon regularity | CV ≤ 0.25 | below this, too regular for a human at a keyboard |
| DNS entropy band | 3.2–4.3 bits/char | encoded data sits above English hostnames |
| Outbound asymmetry | 10 MB and 10:1 | below either, ordinary application traffic |
| Injection threshold | 0.5 | tuned on `fixtures/injection/` |

The rest are judgement calls, and the scorecard is the only evidence they are
reasonable ones. Since the corpus was written before the thresholds were tuned
against it, that evidence is weaker than the numbers make it look.

The held-out set puts a number on how much weaker. `just eval-holdout` runs
fifteen alerts written after these thresholds were fixed, and it scored 33%
against the development set's 100%. Most of that gap is coverage — alert types
no detector here reads — but one part of it was a genuine defect in how the
thresholds were being applied, and it is the kind only an untuned set finds:
when *every* detector returned "nothing to work with", the empty evidence table
was being read as evidence of innocence rather than as an absence of evidence.
See the README's evaluation section for the breakdown.
