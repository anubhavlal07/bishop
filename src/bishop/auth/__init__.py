"""Accounts, roles and sessions, without an identity provider.

`accounts.py` is the store and the role model; `passwords.py` is the KDF. The
part that matters is `Role.APPROVER` and the check on the response gate: before
this, every credential could approve containment and the audit chain recorded
whatever name the client sent.
"""

from bishop.auth.accounts import (
    Account,
    AuthError,
    Role,
    authenticate,
    create_account,
    current_account,
    end_session,
    list_accounts,
    set_role,
    start_session,
)
from bishop.auth.passwords import (
    MIN_PASSWORD_LENGTH,
    PasswordError,
    hash_password,
    needs_rehash,
    verify_password,
)

__all__ = [
    "MIN_PASSWORD_LENGTH",
    "Account",
    "AuthError",
    "PasswordError",
    "Role",
    "authenticate",
    "create_account",
    "current_account",
    "end_session",
    "hash_password",
    "list_accounts",
    "needs_rehash",
    "set_role",
    "start_session",
    "verify_password",
]
