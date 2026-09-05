# Bishop — task runner.
#
# Everything here runs offline by default: the deterministic mock model, the
# committed corpus, the committed ATT&CK catalogue. No task in this file needs
# a credential unless its name says otherwise.

set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

_default:
    @just --list --unsorted

# ── the ones you want first ─────────────────────────────────────────────────

# Triage an alert end to end and print the incident report.
demo *args:
    uv run bishop demo {{args}}

# The full scorecard against the development corpus. Tuned against; gated.
eval *args:
    uv run bishop eval {{args}}

# The held-out set: written after the thresholds were fixed, never tuned
# against, deliberately not gated. This is the number that speaks to unseen
# data, and it is meant to be worse than `just eval` — see
# scripts/build_holdout.py for the protocol.
eval-holdout *args:
    uv run bishop eval --holdout {{args}}

# List the labelled corpus.
alerts:
    uv run bishop alerts

# Triage an alert of your own — Sysmon, ECS, or any JSON with usable field
# names. Prints what Bishop understood before what it concluded.
#   just triage path/to/alert.json
triage path *args:
    uv run bishop triage {{path}} {{args}}

# The alert shapes the normaliser recognises.
formats:
    uv run bishop formats

# Triage one alert by id, e.g. `just run TP-01`.
run alert *args:
    uv run bishop run {{alert}} {{args}}

# List the detector library and what each one measures.
detectors:
    uv run bishop detectors

# ── development ─────────────────────────────────────────────────────────────

install:
    uv sync --extra dev

test *args:
    uv run pytest {{args}}

# Only the deterministic detection primitives.
test-detectors:
    uv run pytest tests/detectors -q

# The red-team corpus. These are the tests that matter most.
test-injection:
    uv run pytest tests/injection tests/quarantine -q

lint:
    uv run ruff check src tests scripts
    uv run ruff format --check src tests scripts

fmt:
    uv run ruff check src tests scripts --fix
    uv run ruff format src tests scripts

# Everything CI runs, in the order CI runs it.
check: lint test
    uv run bishop eval --gate
    uv run bishop coverage

# ── data ────────────────────────────────────────────────────────────────────

# Regenerate the development corpus from scripts/build_corpus.py.
corpus:
    uv run python scripts/build_corpus.py

# Regenerate the held-out set. Rarely — regenerating it after reading its
# results is how a held-out set quietly becomes a training set.
holdout:
    uv run python scripts/build_holdout.py

# Regenerate docs/COVERAGE.md from the detector registry and the corpus.
coverage:
    uv run bishop coverage

# Fetch the ATT&CK STIX bundle into data/ (gitignored) and rebuild the catalogue.
attack:
    uv run python scripts/fetch_attack.py
    uv run python scripts/build_attck_catalogue.py

# Fetch the public SOC datasets into data/. Large, gitignored, optional.
datasets:
    bash scripts/fetch_datasets.sh

# Populate the indicator cache from abuse.ch. Needs a free ABUSECH_AUTH_KEY.
# Without it Bishop uses the committed synthetic cache, which says it is synthetic.
intel:
    uv run python scripts/fetch_intel.py

# ── serving ─────────────────────────────────────────────────────────────────

api:
    uv run uvicorn bishop.api.app:app --reload --port 8000

console:
    cd console && npm run dev

# Verify a saved audit chain file.
verify path:
    uv run bishop verify {{path}}

# Stored incidents, each verified against the head recorded with it.
history:
    uv run bishop history

# How the corpus correlates into incidents.
incidents:
    uv run bishop incidents

# ── live model (opt in, costs money) ────────────────────────────────────────

# Same as `just demo` but against the configured live provider.
demo-live *args:
    BISHOP_MODEL_PROVIDER=anthropic uv run bishop demo {{args}}

eval-live:
    BISHOP_MODEL_PROVIDER=anthropic uv run bishop eval --save
