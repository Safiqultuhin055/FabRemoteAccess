"""Database error translation conventions (no database needed)."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError, ProgrammingError
from sqlalchemy.orm.exc import StaleDataError

from app.db.errors import constraint_name, translate, translate_errors
from app.domain.errors import ConcurrencyError, ConflictError, DependencyUnavailableError


class Orig(Exception):
    pass


def wrap(cls, message):
    return cls("INSERT ...", None, Orig(message))


@pytest.mark.parametrize("message, expected", [
    ("Violation of UNIQUE KEY constraint 'UQ_users_email'. Cannot insert duplicate key", "UQ_users_email"),
    ("Cannot insert duplicate key row in object 'fr.sessions' with unique index 'UX_sessions_live_target'.",
     "UX_sessions_live_target"),
    ('The INSERT statement conflicted with the CHECK constraint "CK_users_email_lowercase".', "CK_users_email_lowercase"),
    ('The INSERT statement conflicted with the FOREIGN KEY constraint "FK_devices_owner_user_id".',
     "FK_devices_owner_user_id"),
    ("something else", None),
])
def test_constraint_name_extraction(message, expected):
    assert constraint_name(wrap(IntegrityError, message)) == expected


def test_translation_rules():
    conflict = translate(wrap(IntegrityError, "Violation of PRIMARY KEY constraint 'PK_users'."))
    assert isinstance(conflict, ConflictError) and conflict.constraint == "PK_users"
    assert isinstance(translate(StaleDataError("stale")), ConcurrencyError)
    assert isinstance(translate(wrap(OperationalError, "Login timeout expired")), DependencyUnavailableError)
    invalidated = DBAPIError("SELECT 1", None, Orig("link failure"), connection_invalidated=True)
    assert isinstance(translate(invalidated), DependencyUnavailableError)
    assert translate(wrap(ProgrammingError, "Invalid object name")) is None


def test_translate_errors_chains_and_passes_through():
    with pytest.raises(ConflictError) as info:
        with translate_errors():
            raise wrap(IntegrityError, "constraint 'UQ_x'")
    assert isinstance(info.value.__cause__, IntegrityError)
    with pytest.raises(ProgrammingError):
        with translate_errors():
            raise wrap(ProgrammingError, "syntax")
