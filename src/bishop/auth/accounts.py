"""Accounts, roles and sessions.

In-house, with no identity provider. That is a deliberate trade: Bishop stores
password hashes and owns the session lifecycle, which is more responsibility
than delegating to an IdP, in exchange for a deployment that needs no external
account and no redirect URI registered anywhere.

**Why this exists at all.** Before it, every API key had identical authority,
including approving containment, and the audit chain recorded `decided_by` as
whatever string the client happened to send. That *attributes* a decision
without *authenticating* it — for a tool whose whole argument is chain of
custody, it was the gap that undercut the argument. `require_role` and the
approver check on the gate are the point of this module; everything else is
plumbing to make them possible.

**Sessions are server-side.** The cookie holds a random token and nothing else;
the row in `sessions` holds a *hash* of it, so a database read does not yield a
usable session. No JWT: a stateless token cannot be revoked, and "log this user
out now" is a thing a security tool has to be able to do.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    String,
    Table,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine

from bishop.auth.passwords import hash_password, needs_rehash, verify_password
from bishop.store.database import DB_SCHEMA, connection, metadata

__all__ = [
    "Account",
    "AuthError",
    "Role",
    "authenticate",
    "create_account",
    "current_account",
    "end_session",
    "list_accounts",
    "set_role",
    "start_session",
]

#: How long a session lasts without being used again. Short enough that a stolen
#: cookie has a bounded life, long enough for a shift.
SESSION_LIFETIME = timedelta(hours=12)


class Role(StrEnum):
    """What an account may do. Ordered least to most authority.

    Three, not more. `approver` exists because approving containment is the one
    irreversible thing Bishop can be asked to do, and separating it from
    `analyst` is the separation of duties the audit chain was always implying
    but never enforced.
    """

    VIEWER = "viewer"
    ANALYST = "analyst"
    APPROVER = "approver"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return list(Role).index(self)

    def can(self, required: Role) -> bool:
        """Whether this role satisfies a requirement. Admin satisfies all."""
        return self.rank >= required.rank


accounts = Table(
    "accounts",
    metadata,
    Column("email", String(320), primary_key=True),
    Column("password_hash", String(256), nullable=False),
    Column("role", String(32), nullable=False),
    Column("display_name", String(128)),
    Column("created_at", DateTime(timezone=True)),
    Column("disabled", Boolean, default=False),
    schema=DB_SCHEMA,
    extend_existing=True,
)

sessions = Table(
    "sessions",
    metadata,
    # The SHA-256 of the cookie value, never the value. A database read must not
    # yield a usable session.
    Column("token_hash", String(64), primary_key=True),
    Column("email", String(320), nullable=False, index=True),
    Column("created_at", DateTime(timezone=True)),
    Column("expires_at", DateTime(timezone=True), index=True),
    schema=DB_SCHEMA,
    extend_existing=True,
)


class AuthError(Exception):
    """Authentication or authorisation failed. Message is safe to show."""


@dataclass(frozen=True, slots=True)
class Account:
    email: str
    role: Role
    display_name: str = ""
    disabled: bool = False

    def describe(self) -> dict[str, Any]:
        """Safe to log, return, and write to the audit chain. No hash."""
        return {
            "email": self.email,
            "role": str(self.role),
            "display_name": self.display_name,
        }


def _normalise(email: str) -> str:
    return email.strip().lower()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_account(
    email: str,
    password: str,
    role: Role = Role.VIEWER,
    *,
    display_name: str = "",
    engine: Engine | None = None,
) -> Account:
    """Create an account. Raises if the address is already taken."""
    address = _normalise(email)
    if not address or "@" not in address:
        raise AuthError("an account needs an email address")

    stored = hash_password(password)
    with connection(engine) as conn:
        existing = conn.execute(select(accounts.c.email).where(accounts.c.email == address)).first()
        if existing:
            raise AuthError("an account with that address already exists")
        conn.execute(
            insert(accounts).values(
                email=address,
                password_hash=stored,
                role=str(role),
                display_name=display_name or address.split("@")[0],
                created_at=datetime.now(UTC),
                disabled=False,
            )
        )
    return Account(email=address, role=role, display_name=display_name)


def authenticate(email: str, password: str, *, engine: Engine | None = None) -> Account:
    """Check a password. Raises `AuthError` on any failure.

    One message for every failure mode — unknown address, wrong password,
    disabled account. Distinguishing them tells whoever is guessing which half
    they got right, which turns a password guess into an account enumeration.
    """
    address = _normalise(email)
    with connection(engine) as conn:
        row = conn.execute(
            select(
                accounts.c.email,
                accounts.c.password_hash,
                accounts.c.role,
                accounts.c.display_name,
                accounts.c.disabled,
            ).where(accounts.c.email == address)
        ).first()

    if row is None:
        # Hash anyway. Returning early on an unknown address makes the response
        # measurably faster than a wrong password, and that timing difference is
        # an account-enumeration oracle.
        verify_password(password, "scrypt$16384$8$1$" + "A" * 24 + "$" + "A" * 44)
        raise AuthError("that email address and password do not match an account")

    stored_email, stored_hash, role, display_name, disabled = row
    if not verify_password(password, stored_hash) or disabled:
        raise AuthError("that email address and password do not match an account")

    if needs_rehash(stored_hash):
        # The only moment the plaintext is available to re-derive from.
        with connection(engine) as conn:
            conn.execute(
                update(accounts)
                .where(accounts.c.email == stored_email)
                .values(password_hash=hash_password(password))
            )

    return Account(
        email=stored_email,
        role=Role(role),
        display_name=display_name or "",
        disabled=bool(disabled),
    )


def start_session(account: Account, *, engine: Engine | None = None) -> str:
    """Open a session and return the token to put in the cookie.

    The token is returned once and never stored; only its hash is written.
    """
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    with connection(engine) as conn:
        conn.execute(
            insert(sessions).values(
                token_hash=_token_hash(token),
                email=account.email,
                created_at=now,
                expires_at=now + SESSION_LIFETIME,
            )
        )
    return token


def current_account(token: str | None, *, engine: Engine | None = None) -> Account | None:
    """Resolve a session token to an account, or None.

    Expired rows are deleted on the way past rather than by a scheduled job:
    the check has to read the row anyway, and a cleanup that depends on a cron
    job running is a cleanup that silently stops.
    """
    if not token:
        return None
    digest = _token_hash(token)
    now = datetime.now(UTC)

    with connection(engine) as conn:
        row = conn.execute(
            select(sessions.c.email, sessions.c.expires_at).where(sessions.c.token_hash == digest)
        ).first()
        if row is None:
            return None
        email, expires_at = row
        if expires_at is not None and _aware(expires_at) <= now:
            conn.execute(delete(sessions).where(sessions.c.token_hash == digest))
            return None

        account_row = conn.execute(
            select(
                accounts.c.email,
                accounts.c.role,
                accounts.c.display_name,
                accounts.c.disabled,
            ).where(accounts.c.email == email)
        ).first()

    if account_row is None or account_row[3]:
        return None
    return Account(
        email=account_row[0],
        role=Role(account_row[1]),
        display_name=account_row[2] or "",
    )


def end_session(token: str | None, *, engine: Engine | None = None) -> None:
    """Revoke one session. Idempotent."""
    if not token:
        return
    with connection(engine) as conn:
        conn.execute(delete(sessions).where(sessions.c.token_hash == _token_hash(token)))


def set_role(email: str, role: Role, *, engine: Engine | None = None) -> None:
    """Change an account's role, and drop its sessions.

    The session drop is the point. Without it a demotion does not take effect
    until the existing session expires, so the person keeps the authority you
    just removed for up to twelve hours.
    """
    address = _normalise(email)
    with connection(engine) as conn:
        conn.execute(update(accounts).where(accounts.c.email == address).values(role=str(role)))
        conn.execute(delete(sessions).where(sessions.c.email == address))


def list_accounts(*, engine: Engine | None = None) -> list[dict[str, Any]]:
    """Every account, without hashes."""
    with connection(engine) as conn:
        rows = conn.execute(
            select(
                accounts.c.email,
                accounts.c.role,
                accounts.c.display_name,
                accounts.c.disabled,
                accounts.c.created_at,
            ).order_by(accounts.c.email)
        ).all()
    return [
        {
            "email": r[0],
            "role": r[1],
            "display_name": r[2] or "",
            "disabled": bool(r[3]),
            "created_at": r[4].isoformat() if r[4] else None,
        }
        for r in rows
    ]


def _aware(value: datetime) -> datetime:
    """SQLite hands back naive datetimes; Postgres does not."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)
