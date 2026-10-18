"""Readiness and connection-failure behaviour against real (local) SQL Server targets."""

from __future__ import annotations

import logging
import time
import uuid

import pytest

from app.db.engine import Database, Readiness
from app.domain.errors import DependencyUnavailableError
from db_support import impersonate, localdb, localdb_settings


def test_ready_on_migrated_database_as_runtime_user(runtime_db):
    assert runtime_db.check_readiness() == Readiness("ok", "ok")


def test_schema_unknown_before_migrations(db_factory):
    bootstrapped = db_factory("bootstrapped")
    database = Database(localdb_settings(bootstrapped.name), connect_hook=impersonate(localdb.RUNTIME))
    try:
        assert database.check_readiness() == Readiness("ok", "unknown")
    finally:
        database.dispose()


def test_schema_mismatch_is_not_ready(migrated, runtime_db):
    migrated.execute("INSERT INTO fr.schema_migrations (version, description) VALUES (99, N'future')")
    try:
        result = runtime_db.check_readiness()
        assert result == Readiness("ok", "mismatch") and not result.ready
    finally:
        migrated.execute("DELETE FROM fr.schema_migrations WHERE version = 99")


@pytest.fixture
def unreachable():
    # Port 1 on the loopback interface refuses connections immediately; nothing leaves this machine.
    database = Database(localdb_settings("FabRemotesDB", db_host="127.0.0.1", db_port=1, db_user="fr_probe",
                                         db_password="Probe-Secret-1", db_login_timeout_seconds=2))
    yield database
    database.dispose()


def test_unreachable_database_reports_error_quickly_without_secrets(unreachable, caplog):
    caplog.set_level(logging.WARNING)
    started = time.monotonic()
    assert unreachable.check_readiness() == Readiness("error", "unknown")
    assert time.monotonic() - started < 30
    assert "Probe-Secret-1" not in caplog.text


def test_unit_of_work_raises_dependency_unavailable(unreachable):
    with pytest.raises(DependencyUnavailableError) as info:
        with unreachable.unit_of_work() as uow:
            uow.users.get(uuid.uuid4())
    assert "Probe-Secret-1" not in str(info.value) and "Probe-Secret-1" not in repr(info.value.__cause__)


def test_engine_url_never_contains_credentials(unreachable):
    rendered = repr(unreachable.engine.url) + str(unreachable.engine.url) + repr(unreachable.engine)
    assert "Probe-Secret-1" not in rendered and "127.0.0.1" not in rendered
