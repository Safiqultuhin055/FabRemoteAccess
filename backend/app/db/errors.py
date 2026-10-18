"""Translation of database driver errors into domain errors.

Conventions:
- constraint violations  -> ConflictError(constraint=<name>), mapped to specific codes by services;
- stale row_version      -> ConcurrencyError;
- connectivity/timeouts  -> DependencyUnavailableError;
- anything else propagates unchanged (becomes a 500 with no details exposed).
Original exceptions are chained for server-side logs (which are redacted).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.exc import DBAPIError, IntegrityError, InterfaceError, OperationalError
from sqlalchemy.orm.exc import StaleDataError

from app.domain.errors import ConcurrencyError, ConflictError, DependencyUnavailableError

_CONSTRAINT = re.compile(r"(?:constraint|unique index)\s+[\"']([A-Za-z0-9_]+)[\"']", re.IGNORECASE)


def constraint_name(exc: BaseException) -> str | None:
    match = _CONSTRAINT.search(str(getattr(exc, "orig", exc)))
    return match.group(1) if match else None


def translate(exc: BaseException) -> BaseException | None:
    """Domain error for a database exception, or None if it should propagate unchanged."""
    if isinstance(exc, IntegrityError):
        return ConflictError(constraint=constraint_name(exc))
    if isinstance(exc, StaleDataError):
        return ConcurrencyError()
    if isinstance(exc, (OperationalError, InterfaceError)):
        return DependencyUnavailableError()
    if isinstance(exc, DBAPIError) and exc.connection_invalidated:
        return DependencyUnavailableError()
    return None


@contextmanager
def translate_errors() -> Iterator[None]:
    try:
        yield
    except (DBAPIError, StaleDataError) as exc:
        domain = translate(exc)
        if domain is None:
            raise
        raise domain from exc
