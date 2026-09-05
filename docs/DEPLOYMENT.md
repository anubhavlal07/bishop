# Deploying Bishop

Bishop's defaults are laptop defaults: SQLite, no authentication, CORS open to
everything, the deterministic model. Every one of those is wrong for a
deployment real users reach, and the failure mode is silent — an
unauthenticated API serving security incidents looks exactly like an
authenticated one until somebody finds it.

So `BISHOP_ENVIRONMENT=production` turns those from defaults into **startup
checks**. Bishop refuses to serve rather than warning, because a warning in a
log nobody reads is not a control. Run `bishop config` to see what it would do
with the current environment.

---

## 1. What production enforces

`src/bishop/config.py` is the whole list, and it is short on purpose:

| Setting | Requirement in production | Why |
|---|---|---|
| `BISHOP_API_KEYS` | at least one key, ≥32 chars | the API serves hostnames, accounts, command lines, and Bishop's own view of which are compromised |
| `BISHOP_CORS_ORIGINS` | a named origin, never `*` | a wildcard lets any page read incident data from a browser holding a key |
| `BISHOP_RATE_LIMIT_PER_MINUTE` | above zero | every run costs model tokens, so an unlimited API is an unlimited bill |
| `DATABASE_URL` | Postgres, never SQLite | an audit chain that does not survive a container restart is not an audit chain |

Bishop will not generate a key for you. A secret that appears in a deploy log is
not a secret, so you generate it and put it in the platform's secret store:

```bash
uv run bishop keygen
```

---

## 2. Render, with the committed blueprint

`render.yaml` describes a Postgres instance and a Docker web service. Two values
are marked `sync: false` and must be set in the dashboard before the first
deploy comes up — that is deliberate, so they are never committed:

- `BISHOP_API_KEYS` — from `bishop keygen`
- `BISHOP_CORS_ORIGINS` — the console's origin, e.g. `https://bishop.netlify.app`

The health check points at `/health/ready`, not `/health/live`. The two are
separate because a liveness probe that also checks the database restarts a
healthy container every time the database blips, turning a recoverable outage
into a crash loop.

---

## 3. Anywhere else, with Docker

```bash
docker build -t bishop .
docker run -p 8000:8000 \
  -e BISHOP_ENVIRONMENT=production \
  -e BISHOP_API_KEYS="$(uv run bishop keygen --quiet)" \
  -e BISHOP_CORS_ORIGINS="https://console.example.com" \
  -e DATABASE_URL="postgresql+psycopg://user:pass@host/bishop" \
  bishop
```

The image runs as a non-root user, carries no build toolchain, and is built
from the committed lockfile with `--frozen` — a security tool that silently
picks up a new transitive dependency on rebuild is a supply-chain problem.

---

## 4. The console

Static Next.js, deployed separately. It needs two environment variables at
**build** time, because `NEXT_PUBLIC_` values are baked into the bundle:

```
NEXT_PUBLIC_BISHOP_API=https://bishop-api.example.com
NEXT_PUBLIC_BISHOP_API_KEY=<a key from bishop keygen>
```

**Be clear about what that key is.** Baked into a client bundle means anyone who
opens devtools can read it. That is acceptable only because of what it is: a
shared read-and-triage credential for one deployment, rotatable from the
dashboard. It is not a user identity, and Bishop has no per-user login — see
§7.

---

## 5. Running against a real model

The deterministic model is the default and it is not a stub: the detectors, the
ATT&CK validation, the injection scanning, the correlation and the audit chain
are the same code in both modes. What it replaces is *judgement* — the
narrative is assembled from detector rationales and the fusion is arithmetic,
so it will not notice the thing nobody wrote a detector for.

To run live:

```
BISHOP_MODEL_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

and build the image or sync with the `live` extra. Bishop refuses to start a
live provider without a key rather than silently falling back, because a
scorecard that quietly changed provider would be meaningless.

Budget for it. Every triage run makes several model calls — one per dispatched
investigator, one for synthesis, one for the critic, one for the response plan.
`/health` reports `live.ready` and exactly what is missing when it is not.

---

## 6. Operating it

**Logs.** `BISHOP_JSON_LOGS=true` emits one JSON object per line for an
aggregator. Every request carries an `X-Request-ID`, echoed to the client and
present on every log line for that request, so a user reporting "it failed at
14:32" can be matched to a trace without guessing.

No alert content is ever logged. Bishop's inputs are attacker-controlled by
construction, and a log line is a place where that text would escape the
quarantine boundary the rest of the system maintains. The access log carries
identifiers, not content.

**Verifying an audit chain.** The chain head is stored beside each incident, so
truncation is detectable — verifying a chain against itself cannot see that its
tail was removed.

```bash
uv run bishop verify storage/chain.jsonl --expect-head <the incident's audit_head>
```

---

## 7. What is still missing, stated plainly

These are real gaps, not stylistic ones. If any of them matters to your
deployment, it needs building before Bishop is the right tool for it.

- **No per-user accounts, and no roles.** Every valid API key has identical
  authority, including approving containment. The audit chain records
  `decided_by` as whatever string the client supplied, so it attributes a
  decision but does not authenticate the person who made it. For a single
  trusted team this is workable; for anything with separation of duties it is
  not.
- **Rate limiting is per-instance, in memory.** With two instances the
  effective limit is double, and a restart clears the window. It is a guard
  against a runaway loop and a cost blowout, not a defence against a determined
  attacker. Put a real limiter at the edge.
- **No SSO, no SCIM, no tenancy.** One deployment serves one team.
- **No secret rotation flow.** Rotating a key means setting the new one
  alongside the old (both are accepted), redeploying the console, then removing
  the old one.
- **No SIEM connector.** Alerts arrive by API call or by paste. There is no
  poller for Splunk, Sentinel or Elastic.
- **Bishop covers 31 ATT&CK techniques of 823.** Outside those it escalates
  rather than guessing, which is correct behaviour and still means a human does
  the work. The held-out evaluation measures this directly and scores 33%.
- **The API has no request signing or replay protection.** Behind TLS with a
  bearer key, which is the same posture as most internal tools, and worth
  knowing.
