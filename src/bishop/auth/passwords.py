"""Password hashing, on the standard library.

No new dependency. `hashlib.scrypt` is a memory-hard KDF in Python's own
standard library, and adding `argon2-cffi` or `bcrypt` to a security tool buys
a marginally better KDF at the cost of another package in the supply chain of
the thing doing the securing. scrypt at these parameters is not the weak link
in any realistic attack on this system.

**The format.** `scrypt$n$r$p$<salt-b64>$<hash-b64>`. Parameters are stored with
the hash rather than read from configuration, so raising the cost later does not
invalidate every existing password — an old hash still verifies under the
parameters it was written with, and `needs_rehash()` says when to upgrade it.

**What this module refuses to do.** It does not log, return, or accept a
password in any structure that gets serialised. The only thing that leaves here
is a hash.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

__all__ = [
    "MAX_PASSWORD_BYTES",
    "MIN_PASSWORD_LENGTH",
    "PasswordError",
    "hash_password",
    "needs_rehash",
    "verify_password",
]

#: Cost parameters. n is the memory/CPU cost, and 2**14 lands around 65 ms on a
#: modest machine — slow enough to make offline guessing expensive, fast enough
#: that a login does not feel broken.
_N = 2**14
_R = 8
_P = 1
_DKLEN = 32
_SALT_BYTES = 16

#: Below this, a password is not worth hashing. Deliberately a length floor and
#: nothing else: composition rules ("one capital, one symbol") push people to
#: predictable patterns and measurably reduce entropy.
MIN_PASSWORD_LENGTH = 12

#: scrypt reads the whole password, so an arbitrarily long one is an
#: arbitrarily expensive hash — a denial-of-service through the login form.
MAX_PASSWORD_BYTES = 1024


class PasswordError(ValueError):
    """A password was rejected. The message is safe to show a user."""


def hash_password(password: str) -> str:
    """Hash a password for storage. Never returns the password."""
    _check(password)
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN)
    return "$".join(
        [
            "scrypt",
            str(_N),
            str(_R),
            str(_P),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(derived).decode("ascii"),
        ]
    )


def verify_password(password: str, stored: str) -> bool:
    """Check a password against a stored hash, in constant time.

    Returns False rather than raising on a malformed stored value. A corrupt
    row should fail the login, not take the process down — and it must fail
    closed, which returning False does.
    """
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(candidate, expected)


def needs_rehash(stored: str) -> bool:
    """Whether a stored hash was made with weaker parameters than current.

    Checked on a successful login, which is the only moment the plaintext is
    available to re-derive from.
    """
    try:
        scheme, n, r, p, _, _ = stored.split("$")
    except ValueError:
        return True
    return scheme != "scrypt" or (int(n), int(r), int(p)) != (_N, _R, _P)


def _check(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordError(
            f"a password must be at least {MIN_PASSWORD_LENGTH} characters. "
            f"Length is the only rule here — composition rules push people "
            f"towards predictable patterns."
        )
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise PasswordError(f"a password may be at most {MAX_PASSWORD_BYTES} bytes")
