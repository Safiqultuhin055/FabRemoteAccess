"""Rollback scripts and permission teardown."""

from __future__ import annotations

import pyodbc
import pytest

from localdb import MIGRATOR, P001, P002, PR001, ROLLBACKS, sql_error


def test_full_rollback_and_teardown_restores_original_state(db_factory):
    db = db_factory("legacy")
    before = db.legacy_snapshot()
    principals_before = db.execute("SELECT name FROM sys.database_principals ORDER BY name")

    db.run(P001)
    db.execute(f"CREATE USER [{MIGRATOR}] WITHOUT LOGIN; ALTER ROLE fr_migrator ADD MEMBER [{MIGRATOR}];")
    db.migrate()
    db.run(P002)
    for path in ROLLBACKS:
        db.run(path, as_user=MIGRATOR)
    assert db.scalar("SELECT COUNT(*) FROM sys.objects WHERE schema_id = SCHEMA_ID('fr')") == 0

    db.run(PR001)
    db.execute(f"DROP USER [{MIGRATOR}]")
    assert db.scalar("SELECT SCHEMA_ID('fr')") is None
    assert db.execute("SELECT name FROM sys.database_principals ORDER BY name") == principals_before
    assert db.legacy_snapshot() == before


def test_rollback_out_of_order_is_rejected(migrated_db):
    r0003 = next(p for p in ROLLBACKS if p.name.startswith("R0003"))
    with pytest.raises(pyodbc.Error, match=sql_error(51010)):
        migrated_db.run(r0003, as_user=MIGRATOR)
    assert migrated_db.scalar("SELECT OBJECT_ID('fr.devices')") is not None


def test_rollback_refuses_to_destroy_data(db_factory):
    db = db_factory("migrated")
    db.execute("INSERT INTO fr.users (email, display_name) VALUES ('keep@example.com', 'Keep')")
    r0002 = next(p for p in ROLLBACKS if p.name.startswith("R0002"))
    for path in ROLLBACKS[:ROLLBACKS.index(r0002)]:  # newer rollbacks succeed: those tables are empty
        db.run(path, as_user=MIGRATOR)
    with pytest.raises(pyodbc.Error, match=sql_error(51011)):
        db.run(r0002, as_user=MIGRATOR)
    assert db.versions() == [1, 2]
    assert db.scalar("SELECT COUNT(*) FROM fr.users") == 1


def test_rollback_of_unapplied_version_is_a_no_op(db_factory):
    db = db_factory("bootstrapped")
    messages = db.run(ROLLBACKS[0], as_user=MIGRATOR)
    assert any("nothing to roll back" in m for m in messages)


def test_teardown_refuses_while_objects_remain(migrated_db):
    with pytest.raises(pyodbc.Error, match=sql_error(51230)):
        migrated_db.run(PR001)
    assert migrated_db.scalar("SELECT SCHEMA_ID('fr')") is not None
