"""Argon2id password hashing and the password policy.

Parameters follow argon2-cffi's RFC 9106 low-memory profile (Argon2id, t=3, m=64 MiB, p=4).
`dummy_verify` spends the same effort as a real verification so that unknown accounts
cannot be distinguished by response time.
"""

from __future__ import annotations

from argon2 import PasswordHasher as _Argon2Hasher
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


class PasswordHasher:
    def __init__(self, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4):
        self._hasher = _Argon2Hasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism,
                                     type=Type.ID)
        self._dummy_hash = self._hasher.hash("fabulous-remote-dummy-password")

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password_hash: str | None, password: str) -> bool:
        if not password_hash:
            self.dummy_verify(password)
            return False
        try:
            return self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def dummy_verify(self, password: str) -> None:
        try:
            self._hasher.verify(self._dummy_hash, password)
        except VerificationError:
            pass

    def needs_rehash(self, password_hash: str) -> bool:
        return self._hasher.check_needs_rehash(password_hash)


def password_policy_issue(password: str, email: str | None = None) -> str | None:
    """Return a short issue code if the password is unacceptable, else None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return "too_short"
    if len(password) > MAX_PASSWORD_LENGTH:
        return "too_long"
    if not password.strip() or len(set(password)) < 4:
        return "too_simple"
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 3 and local in password.lower():
            return "contains_email"
    return None
