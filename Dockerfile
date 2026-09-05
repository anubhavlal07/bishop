# Bishop's API, built for a container platform.
#
# Two stages so the runtime image carries no build toolchain and no uv. The
# result runs as a non-root user with a read-only-friendly layout: nothing is
# written outside /app/storage, which is where a volume mounts if SQLite is
# ever used (it is refused in production — see src/bishop/config.py).

# ── build ───────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS build

# uv resolves and installs far faster than pip here, and `--frozen` means the
# image is built from the committed lockfile rather than from whatever resolves
# today. A security tool that silently picks up a new transitive dependency on
# rebuild is a supply-chain problem.
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# Dependencies first, as their own layer: application code changes on every
# commit, the lockfile rarely, so this layer survives most rebuilds.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project --extra postgres --extra live

COPY src/ ./src/
COPY fixtures/ ./fixtures/
RUN uv sync --frozen --no-dev --no-editable --extra postgres --extra live

# ── runtime ─────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Patch the base, then drop apt's lists — they are 40MB of nothing useful in a
# running container and a needless surface for a scanner to flag.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root. A container that runs as root has no barrier left if the process is
# compromised, and nothing Bishop does needs privilege.
RUN useradd --create-home --uid 10001 bishop

WORKDIR /app
COPY --from=build --chown=bishop:bishop /app/.venv /app/.venv
COPY --from=build --chown=bishop:bishop /app/fixtures /app/fixtures
COPY --chown=bishop:bishop src/ /app/src/

# The committed scorecard baseline, and only that one file: the dated run files
# beside it are gitignored, so copying the directory would put different content
# in a local image than in a build from a clean checkout. `/scorecard` reports
# the number `just eval` produced rather than running the corpus on a web
# request, so the file has to be in the image — without it the endpoint 404s
# and the console's scorecard page is blank in production, which is how this was
# found.
COPY --chown=bishop:bishop eval/results/baseline.json /app/eval/results/baseline.json

RUN mkdir -p /app/storage && chown bishop:bishop /app/storage

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    BISHOP_ENVIRONMENT=production \
    BISHOP_JSON_LOGS=true

USER bishop
EXPOSE 8000

# Readiness rather than liveness: the platform should not route traffic here
# until the store is reachable. See the two endpoints in api/app.py for why
# they are separate.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health/ready || exit 1

# No --reload, and workers left to the platform: on a single-core container an
# extra worker costs memory and buys nothing, and Bishop's run state is
# in-process, so scaling out needs the store rather than more workers.
CMD ["uvicorn", "bishop.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
