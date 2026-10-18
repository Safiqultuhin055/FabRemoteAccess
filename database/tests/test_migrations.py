"""Migration behaviour against a LocalDB scratch database."""

from __future__ import annotations

import pyodbc
import pytest

from localdb import MIGRATIONS, MIGRATOR, P001, PERMISSION_ERROR, ROLLBACKS, sql_error

EXPECTED_TABLES = {
    "schema_migrations", "roles", "users", "user_roles", "user_invitations", "devices",
    "device_keys", "device_auth_challenges", "auth_sessions", "auth_tokens",
    "blocked_requesters", "connection_requests", "sessions", "address_book_entries", "audit_events",
    "remote_id_registry", "device_registration_challenges",
}


def test_all_migrations_apply_in_order_as_migrator(migrated_db):
    assert migrated_db.versions() == list(range(1, len(MIGRATIONS) + 1))
    tables = {r[0] for r in migrated_db.execute(
        "SELECT name FROM sys.tables WHERE schema_id = SCHEMA_ID('fr')")}
    assert tables == EXPECTED_TABLES
    assert migrated_db.scalar("SELECT OBJECT_ID('fr.usp_purge_expired_data', 'P')") is not None
    assert {r[0] for r in migrated_db.execute("SELECT code FROM fr.roles")} == {"user", "admin", "auditor"}


def test_rerunning_migrations_is_a_no_op(db_factory):
    db = db_factory("bootstrapped")
    db.migrate()
    before = db.fr_objects()
    for path in MIGRATIONS:
        messages = db.run(path, as_user=MIGRATOR)
        assert any("already applied" in m for m in messages), path.name
    assert db.fr_objects() == before
    assert db.versions() == list(range(1, len(MIGRATIONS) + 1))
    assert db.scalar("SELECT COUNT(*) FROM fr.roles") == 3


def test_migration_requires_bootstrap(db_factory):
    db = db_factory("legacy")
    with pytest.raises(pyodbc.Error, match=sql_error(51000)):
        db.run(MIGRATIONS[0])
    assert db.scalar("SELECT SCHEMA_ID('fr')") is None


def test_schema_with_wrong_owner_is_rejected(db_factory):
    db = db_factory("legacy")
    db.execute("CREATE SCHEMA fr AUTHORIZATION dbo;")
    with pytest.raises(pyodbc.Error, match=sql_error(51203)):
        db.run(P001)
    with pytest.raises(pyodbc.Error, match=sql_error(51000)):
        db.run(MIGRATIONS[0])


def test_out_of_order_migration_is_rejected(db_factory):
    db = db_factory("bootstrapped")
    db.run(MIGRATIONS[0], as_user=MIGRATOR)
    with pytest.raises(pyodbc.Error, match=sql_error(51002)):
        db.run(MIGRATIONS[2], as_user=MIGRATOR)
    assert db.versions() == [1]
    assert db.scalar("SELECT OBJECT_ID('fr.devices')") is None


def test_conflicting_object_aborts_without_partial_changes(db_factory):
    db = db_factory("bootstrapped")
    db.run(MIGRATIONS[0], as_user=MIGRATOR)
    db.execute("CREATE TABLE fr.users (id INT NOT NULL);")  # pre-existing, unexpected object
    with pytest.raises(pyodbc.Error, match=sql_error(51003)):
        db.run(MIGRATIONS[1], as_user=MIGRATOR)
    assert db.versions() == [1]
    assert db.scalar("SELECT OBJECT_ID('fr.roles')") is None
    assert db.scalar("SELECT COUNT(*) FROM sys.columns WHERE object_id = OBJECT_ID('fr.users')") == 1


def test_failure_mid_migration_rolls_back_everything(db_factory):
    db = db_factory("bootstrapped")
    for path in MIGRATIONS[:2]:
        db.run(path, as_user=MIGRATOR)
    # A constraint name V0003 needs is taken, so V0003 fails after creating fr.devices.
    db.execute("CREATE TABLE fr.blocker (id INT CONSTRAINT PK_device_keys PRIMARY KEY);")
    with pytest.raises(pyodbc.Error):
        db.run(MIGRATIONS[2], as_user=MIGRATOR)
    assert db.versions() == [1, 2]
    assert db.scalar("SELECT OBJECT_ID('fr.devices')") is None
    assert db.scalar("SELECT @@TRANCOUNT") == 0


def test_rerun_after_fixing_a_partial_failure_succeeds(db_factory):
    db = db_factory("bootstrapped")
    for path in MIGRATIONS[:2]:
        db.run(path, as_user=MIGRATOR)
    db.execute("CREATE TABLE fr.blocker (id INT CONSTRAINT PK_device_keys PRIMARY KEY);")
    with pytest.raises(pyodbc.Error):
        db.run(MIGRATIONS[2], as_user=MIGRATOR)
    db.execute("DROP TABLE fr.blocker;")
    for path in MIGRATIONS[2:]:
        db.run(path, as_user=MIGRATOR)
    assert db.versions() == list(range(1, len(MIGRATIONS) + 1))


@pytest.mark.parametrize("level", [110, 130])  # SQL Server 2012 and 2016 language rules
def test_full_lifecycle_at_older_compatibility_levels(db_factory, level):
    db = db_factory("migrated", compatibility_level=level)
    assert db.scalar("SELECT compatibility_level FROM sys.databases WHERE database_id = DB_ID()") == level
    assert db.versions() == list(range(1, len(MIGRATIONS) + 1))
    for path in ROLLBACKS:
        db.run(path, as_user=MIGRATOR)
    assert db.scalar("SELECT COUNT(*) FROM sys.objects WHERE schema_id = SCHEMA_ID('fr')") == 0


def test_bootstrap_is_idempotent(db_factory):
    db = db_factory("bootstrapped")
    db.run(P001)
    assert db.scalar("SELECT COUNT(*) FROM sys.database_principals WHERE name LIKE 'fr[_]%' AND type = 'R'") == 3


def test_existing_objects_outside_fr_are_untouched(db_factory):
    db = db_factory("legacy")
    before = db.legacy_snapshot()
    db.run(P001)
    db.execute(f"CREATE USER [{MIGRATOR}] WITHOUT LOGIN; ALTER ROLE fr_migrator ADD MEMBER [{MIGRATOR}];")
    db.migrate()
    assert db.legacy_snapshot() == before


def test_naming_conventions(migrated_db):
    rows = migrated_db.execute("""
        SELECT o.name, o.type, OBJECT_NAME(o.parent_object_id)
        FROM sys.objects o
        WHERE o.schema_id = SCHEMA_ID('fr') AND o.parent_object_id <> 0""")
    prefixes = {"PK": "PK", "F": "FK", "UQ": "UQ", "C": "CK", "D": "DF"}
    for name, obj_type, table in rows:
        assert name.startswith(f"{prefixes[obj_type.strip()]}_{table}"), name
    for name, table, is_unique in migrated_db.execute("""
            SELECT i.name, OBJECT_NAME(i.object_id), i.is_unique FROM sys.indexes i
            JOIN sys.tables t ON t.object_id = i.object_id AND t.schema_id = SCHEMA_ID('fr')
            WHERE i.is_primary_key = 0 AND i.is_unique_constraint = 0 AND i.name IS NOT NULL"""):
        assert name.startswith(("UX_" if is_unique else "IX_") + table), name
    assert migrated_db.scalar("""
        SELECT COUNT(*) FROM sys.key_constraints WHERE schema_id = SCHEMA_ID('fr') AND is_system_named = 1""") == 0
    assert migrated_db.scalar("""
        SELECT COUNT(*) FROM sys.default_constraints WHERE schema_id = SCHEMA_ID('fr') AND is_system_named = 1""") == 0


def test_timestamps_are_datetime2_utc(migrated_db):
    bad = migrated_db.execute("""
        SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = 'fr' AND (DATA_TYPE IN ('datetime', 'smalldatetime', 'datetimeoffset')
           OR (COLUMN_NAME LIKE '%[_]at' AND NOT (DATA_TYPE = 'datetime2' AND DATETIME_PRECISION = 3)))""")
    assert bad == []
    defaults = migrated_db.execute("""
        SELECT definition FROM sys.default_constraints
        WHERE schema_id = SCHEMA_ID('fr') AND definition LIKE '%date%'""")
    assert defaults and all("sysutcdatetime" in d[0].lower() for d in defaults)


def test_foreign_key_columns_on_computed_values_are_not_nullable(migrated_db):
    """Regression: a NULL in any referencing column would silently skip the session -> request FK."""
    assert migrated_db.scalar("""
        SELECT is_nullable FROM sys.columns
        WHERE object_id = OBJECT_ID('fr.sessions') AND name = 'request_approved'""") is False


def test_objects_are_owned_by_fr_owner_and_foreign_keys_stay_in_fr(migrated_db):
    owner = migrated_db.scalar(
        "SELECT p.name FROM sys.schemas s JOIN sys.database_principals p ON p.principal_id = s.principal_id WHERE s.name = 'fr'")
    assert owner == "fr_owner"
    assert migrated_db.scalar(
        "SELECT COUNT(*) FROM sys.objects WHERE schema_id = SCHEMA_ID('fr') AND principal_id IS NOT NULL") == 0
    assert migrated_db.scalar("""
        SELECT COUNT(*) FROM sys.foreign_keys fk JOIN sys.tables t ON t.object_id = fk.referenced_object_id
        WHERE fk.schema_id = SCHEMA_ID('fr') AND t.schema_id <> SCHEMA_ID('fr')""") == 0


def test_migrator_is_confined_to_schema_fr(migrated_db):
    for sql in (
        "CREATE TABLE dbo.migrator_probe (id INT);",
        "SELECT * FROM dbo.legacy_customers;",
        "INSERT INTO dbo.legacy_customers VALUES (99, N'x');",
        "ALTER ROLE fr_app_runtime ADD MEMBER t_maintenance;",
        "GRANT SELECT ON fr.users TO public;",
        "CREATE SCHEMA probe;",
    ):
        with pytest.raises(pyodbc.Error, match=PERMISSION_ERROR):
            migrated_db.execute(sql, as_user=MIGRATOR)
