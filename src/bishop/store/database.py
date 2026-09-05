"""Persistence for incidents and audit chains.

SQLite by default, Postgres when `DATABASE_URL` says so. The same schema either
way — nothing here uses a dialect-specific feature, because a store that only
works on the deployment target is a store you cannot test.

**Why this exists.** Bishop kept incidents in memory, so a restart lost every
in-flight run and there was no way to verify an audit chain from last week. For
a security tool the audit chain in particular is not a cache: the whole argument
for hash-chaining it is that someone can come back to it later and check.

**What is deliberately not here.** No ORM relationships and no lazy loading. An
incident is stored as one row with its JSON body, because the thing being
persisted is a document that was already assembled and validated by Pydantic,
and re-normalising it into tables would mean two schemas that can disagree.
Queries that need structure use the indexed columns beside the blob.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    delete,
    insert,
    select,
)
from sqlalchemy.engine import Engine

from bishop.audit import AuditChain, AuditEntry, verify_entries
from bishop.schema import Incident

#: Where SQLite lands when no `DATABASE_URL` is set. Under `storage/`, which is
#: gitignored — a database of triage results is not repository content.
DEFAULT_SQLITE_PATH = Path("storage") / "bishop.db"

metadata = MetaData()

incidents = Table(
    "incidents",
    metadata,
    Column("incident_id", String(128), primary_key=True),
    Column("entity_key", String(512), index=True),
    Column("verdict", String(32), index=True),
    Column("confidence", Float),
    Column("severity", String(32)),
    Column("alert_count", Integer),
    Column("escalated", Boolean, index=True),
    Column("created_at", DateTime(timezone=True), index=True),
    # The chain head at the time the incident was written. Verifying a stored
    # chain against a stored head is what makes truncation detectable later.
    # The run that produced this incident. Stored rather than derived: the
    # chain lookup used to guess `cli-{incident_id}` from a naming
    # convention, and a verification path that guesses is a verification
    # path that reports CHAIN BROKEN when someone renames something.
    Column("run_id", String(128), index=True),
    Column("audit_head", String(64)),
    Column("audit_length", Integer),
    Column("body", JSON),
)

audit_entries = Table(
    "audit_entries",
    metadata,
    Column("run_id", String(128), primary_key=True),
    Column("seq", Integer, primary_key=True),
    Column("timestamp", String(64)),
    Column("actor", String(128)),
    Column("action", String(64), index=True),
    Column("payload", JSON),
    Column("payload_hash", String(64)),
    Column("prev_hash", String(64)),
    Column("entry_hash", String(64)),
)

alerts_seen = Table(
    "alerts_seen",
    metadata,
    Column("alert_id", String(128), primary_key=True),
    Column("incident_id", String(128), index=True),
    Column("detected_at", DateTime(timezone=True), index=True),
    Column("rule_name", Text),
)


def database_url() -> str:
    """Resolve the connection string.

    Absent `DATABASE_URL`, SQLite under `storage/`. Postgres URLs written with
    the bare `postgres://` scheme are rewritten — several hosting providers
    hand that out and SQLAlchemy requires the driver name.
    """
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        DEFAULT_SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{DEFAULT_SQLITE_PATH}"
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


_engine: Engine | None = None


def get_engine(url: str | None = None, *, echo: bool = False) -> Engine:
    """The process-wide engine, created once."""
    global _engine
    if url is not None:
        return create_engine(url, echo=echo, future=True)
    if _engine is None:
        _engine = create_engine(database_url(), echo=echo, future=True)
    return _engine


def reset_engine() -> None:
    """Drop the cached engine. For tests that switch databases."""
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = None


def init_db(engine: Engine | None = None) -> Engine:
    """Create tables if absent. Safe to call on every start."""
    target = engine or get_engine()
    metadata.create_all(target)
    return target


@contextmanager
def connection(engine: Engine | None = None) -> Iterator[Any]:
    target = engine or get_engine()
    with target.begin() as conn:
        yield conn


# ── writing ─────────────────────────────────────────────────────────────────


def save_incident(
    incident: Incident, *, chain: AuditChain | None = None, engine: Engine | None = None
) -> None:
    """Persist an incident and, if given, the chain that covers it.

    Written as a single transaction: an incident whose audit chain did not land
    is worse than neither, because it looks complete.
    """
    verdict = incident.verdict
    body = incident.model_dump(mode="json")

    with connection(engine) as conn:
        conn.execute(delete(incidents).where(incidents.c.incident_id == incident.incident_id))
        conn.execute(
            insert(incidents).values(
                incident_id=incident.incident_id,
                entity_key=incident.entity_key,
                verdict=str(verdict.label) if verdict else None,
                confidence=verdict.confidence if verdict else None,
                severity=str(verdict.assessed_severity) if verdict else None,
                alert_count=len(incident.alerts),
                escalated=bool(verdict and str(verdict.label) == "escalate"),
                created_at=incident.created_at,
                run_id=chain.run_id if chain else None,
                audit_head=chain.head if chain else incident.audit_head,
                audit_length=len(chain) if chain else None,
                body=body,
            )
        )

        for alert in incident.alerts:
            conn.execute(delete(alerts_seen).where(alerts_seen.c.alert_id == alert.alert_id))
            conn.execute(
                insert(alerts_seen).values(
                    alert_id=alert.alert_id,
                    incident_id=incident.incident_id,
                    detected_at=alert.detected_at,
                    rule_name=alert.rule_name,
                )
            )

        if chain is not None:
            conn.execute(delete(audit_entries).where(audit_entries.c.run_id == chain.run_id))
            for entry in chain:
                conn.execute(insert(audit_entries).values(**entry.to_dict()))


# ── reading ─────────────────────────────────────────────────────────────────


def load_incident(incident_id: str, *, engine: Engine | None = None) -> Incident | None:
    with connection(engine) as conn:
        row = conn.execute(
            select(incidents.c.body).where(incidents.c.incident_id == incident_id)
        ).first()
    if row is None:
        return None
    body = row[0]
    return Incident.model_validate(json.loads(body) if isinstance(body, str) else body)


def list_incidents(*, limit: int = 50, engine: Engine | None = None) -> list[dict[str, Any]]:
    with connection(engine) as conn:
        rows = conn.execute(
            select(
                incidents.c.incident_id,
                incidents.c.entity_key,
                incidents.c.verdict,
                incidents.c.confidence,
                incidents.c.alert_count,
                incidents.c.created_at,
                incidents.c.audit_head,
                incidents.c.run_id,
            )
            .order_by(incidents.c.created_at.desc())
            .limit(limit)
        ).all()
    return [
        {
            "incident_id": r[0],
            "entity_key": r[1],
            "verdict": r[2],
            "confidence": r[3],
            "alert_count": r[4],
            "created_at": r[5].isoformat() if r[5] else None,
            "audit_head": r[6],
            "run_id": r[7],
        }
        for r in rows
    ]


def load_chain(run_id: str, *, engine: Engine | None = None) -> list[AuditEntry]:
    with connection(engine) as conn:
        rows = (
            conn.execute(
                select(audit_entries)
                .where(audit_entries.c.run_id == run_id)
                .order_by(audit_entries.c.seq)
            )
            .mappings()
            .all()
        )
    return [AuditEntry.from_dict(dict(row)) for row in rows]


def verify_stored_chain(incident_id: str, *, engine: Engine | None = None) -> tuple[bool, str]:
    """Verify a stored chain against the head recorded with its incident.

    This is the reason the head is stored beside the incident rather than only
    inside the chain: verifying a chain against itself cannot detect that its
    tail was removed.
    """
    from bishop.audit import ChainBroken

    with connection(engine) as conn:
        row = conn.execute(
            select(
                incidents.c.audit_head,
                incidents.c.audit_length,
                incidents.c.run_id,
            ).where(incidents.c.incident_id == incident_id)
        ).first()
    if row is None:
        return False, f"no incident {incident_id}"

    head, length, run_id = row
    # Looked up by the stored run id, not by guessing it from the incident id.
    # The guess (`cli-{incident_id}`) was wrong for every run whose incident id
    # was not derived from its run id, and reported CHAIN BROKEN on a chain
    # that was intact — the worst possible failure for a verification path,
    # because it teaches people to ignore it.
    stored = load_chain(run_id, engine=engine) if run_id else []
    if not stored:
        return False, "no audit entries stored for this incident"
    try:
        verify_entries(stored, expected_head=head, expected_length=length)
    except ChainBroken as exc:
        return False, str(exc)
    return True, f"{len(stored)} entries verified against the recorded head"


def prune(before: datetime, *, engine: Engine | None = None) -> int:
    """Delete incidents older than `before`. Returns how many went.

    Audit entries are deliberately *not* pruned with them: the retention
    decision for a triage result and for its chain of custody are not the same
    decision, and defaulting them together is how the second one gets made by
    accident.
    """
    with connection(engine) as conn:
        result = conn.execute(delete(incidents).where(incidents.c.created_at < before))
    return int(result.rowcount or 0)


def health(engine: Engine | None = None) -> dict[str, Any]:
    """Connectivity and a row count, for `/health`.

    Reported rather than raised: a console should be able to say the database
    is unreachable, and triage against the in-memory path still works without
    it.
    """
    try:
        target = engine or get_engine()
        with target.begin() as conn:
            count = len(conn.execute(select(incidents.c.incident_id)).all())
        return {"connected": True, "dialect": target.dialect.name, "incidents": count}
    except Exception as exc:
        return {"connected": False, "error": f"{type(exc).__name__}: {exc}"}


__all__ = [
    "audit_entries",
    "database_url",
    "get_engine",
    "health",
    "incidents",
    "init_db",
    "list_incidents",
    "load_chain",
    "load_incident",
    "prune",
    "reset_engine",
    "save_incident",
    "verify_stored_chain",
]
