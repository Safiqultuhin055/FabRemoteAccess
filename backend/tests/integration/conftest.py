"""Integration fixtures: migrated LocalDB scratch databases from database/tests/localdb.py.

The shared fixtures keep their refusal to run against anything that is not LocalDB.
Helpers live in db_support.py (imported by tests), not here.
"""

from __future__ import annotations

import pytest

from app.db.engine import Database
from db_support import impersonate, localdb, localdb_settings

# Re-exported shared fixtures.
server = localdb.server
db_factory = localdb.db_factory


@pytest.fixture(scope="module")
def migrated(db_factory):
    return db_factory("migrated")


@pytest.fixture(scope="module")
def runtime_db(migrated):
    """Backend Database bound to a migrated scratch DB, acting as the runtime role only."""
    database = Database(localdb_settings(migrated.name), connect_hook=impersonate(localdb.RUNTIME))
    yield database
    database.dispose()
