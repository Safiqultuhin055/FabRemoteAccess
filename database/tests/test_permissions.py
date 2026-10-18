"""Separation between the migrator, runtime and maintenance identities."""

from __future__ import annotations

import secrets

import pyodbc
import pytest

from localdb import MAINTENANCE, P002, P003, PERMISSION_ERROR, RUNTIME, sql_error
from test_retention import purge


def denied(db, sql, user):
    with pytest.raises(pyodbc.Error, match=PERMISSION_ERROR):
        db.execute(sql, as_user=user)


def test_runtime_has_dml_but_no_ddl_or_foreign_access(migrated_db):
    db = migrated_db
    db.execute("INSERT INTO fr.audit_events (event_type, outcome) VALUES ('test.event', 'success')", as_user=RUNTIME)
    assert db.scalar("SELECT COUNT(*) FROM fr.audit_events", as_user=RUNTIME) >= 1
    for sql in (
        "UPDATE fr.audit_events SET outcome = 'failure'",
        "DELETE FROM fr.audit_events",
        "DELETE FROM fr.users",
        "DELETE FROM fr.devices",
        "DELETE FROM fr.sessions",
        "INSERT INTO fr.schema_migrations (version, description) VALUES (999, N'x')",
        "INSERT INTO fr.roles (code, description) VALUES ('superuser', N'x')",
        "CREATE TABLE fr.runtime_probe (id INT)",
        "ALTER TABLE fr.users ADD probe INT",
        "SELECT * FROM dbo.legacy_customers",
        purge(),
    ):
        denied(db, sql, RUNTIME)


def test_audit_deny_survives_broader_grants(migrated_db):
    """Even if someone later adds the runtime login to db_datawriter, audit stays append-only."""
    db = migrated_db
    db.execute(f"ALTER ROLE db_datawriter ADD MEMBER [{RUNTIME}]")
    try:
        denied(db, "DELETE FROM fr.audit_events", RUNTIME)
        denied(db, "UPDATE fr.audit_events SET outcome = 'failure'", RUNTIME)
    finally:
        db.execute(f"ALTER ROLE db_datawriter DROP MEMBER [{RUNTIME}]")


def test_maintenance_can_only_execute_retention(migrated_db):
    db = migrated_db
    db.execute(purge(dry_run=1), as_user=MAINTENANCE)
    denied(db, "SELECT * FROM fr.users", MAINTENANCE)
    denied(db, "DELETE FROM fr.audit_events", MAINTENANCE)


def test_ownership_chaining_cannot_reach_other_schemas(migrated_db):
    """A view in fr over a dbo table must not leak data, because fr is owned by fr_owner, not dbo."""
    db = migrated_db
    db.execute("CREATE VIEW fr.v_probe AS SELECT name FROM dbo.legacy_customers;", as_user="t_migrator")
    db.execute(f"GRANT SELECT ON fr.v_probe TO [{RUNTIME}]")
    try:
        denied(db, "SELECT * FROM fr.v_probe", RUNTIME)
    finally:
        db.execute("DROP VIEW fr.v_probe")


def test_p002_requires_migrations(db_factory):
    db = db_factory("bootstrapped")
    with pytest.raises(pyodbc.Error, match=sql_error(51211)):
        db.run(P002)


def test_p002_is_idempotent(migrated_db):
    migrated_db.run(P002)


@pytest.fixture
def logins(server, db_factory):
    """Three throwaway SQL logins on the LocalDB instance (random passwords, never printed)."""
    suffix = secrets.token_hex(3)
    names = {k: f"fr_t_{k}_{suffix}" for k in ("migrator", "app", "maint", "writer")}
    for name in names.values():
        password = secrets.token_urlsafe(24) + "aA1!"
        server.execute(f"CREATE LOGIN [{name}] WITH PASSWORD = N'{password}', CHECK_POLICY = OFF")
    db = db_factory("bootstrapped")
    yield db, names
    db.conn.execute("SELECT 1")
    for name in names.values():
        # Database users go away with the scratch database; drop server logins now.
        for row in server.execute("SELECT session_id FROM sys.dm_exec_sessions WHERE login_name = ?", name).fetchall():
            server.execute(f"KILL {row[0]}")
        server.execute(f"DROP LOGIN [{name}]")


def p003_vars(migrator, app, maint):
    return {"MigratorLogin": migrator, "AppLogin": app, "MaintenanceLogin": maint}


def test_p003_maps_logins_and_is_idempotent(logins):
    db, n = logins
    for _ in range(2):
        db.run(P003, variables=p003_vars(n["migrator"], n["app"], n["maint"]))
    members = set(db.execute("""
        SELECT r.name, m.name FROM sys.database_role_members rm
        JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
        JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id
        WHERE r.name LIKE 'fr[_]%' AND m.name LIKE 'fr[_]t[_]%'"""))
    assert members == {("fr_migrator", n["migrator"]), ("fr_app_runtime", n["app"]), ("fr_maintenance", n["maint"])}


def test_p003_allows_shared_runtime_and_maintenance_login(logins):
    db, n = logins
    db.run(P003, variables=p003_vars(n["migrator"], n["app"], n["app"]))
    assert db.scalar("SELECT IS_ROLEMEMBER('fr_maintenance', ?)", n["app"]) == 1


@pytest.mark.parametrize("case, code", [
    ("same_migrator_and_app", 51220),
    ("sa", 51222),
    ("sysadmin", 51222),
    ("missing", 51221),
    ("fixed_role_member", 51224),
])
def test_p003_rejects_unsafe_mappings(logins, case, code):
    db, n = logins
    migrator, app, maint = n["migrator"], n["app"], n["maint"]
    if case == "same_migrator_and_app":
        app = migrator
    elif case == "sa":
        app = "sa"
    elif case == "sysadmin":
        app = db.scalar("SELECT SUSER_SNAME()")  # the developer's own login is sysadmin on LocalDB
    elif case == "missing":
        app = "fr_no_such_login"
    elif case == "fixed_role_member":
        db.execute(f"CREATE USER [{n['writer']}] FOR LOGIN [{n['writer']}]; ALTER ROLE db_datawriter ADD MEMBER [{n['writer']}];")
        app = n["writer"]
    with pytest.raises(pyodbc.Error, match=sql_error(code)):
        db.run(P003, variables=p003_vars(migrator, app, maint))
    assert db.scalar("SELECT COUNT(*) FROM sys.database_role_members rm "
                     "JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id "
                     "WHERE r.name IN ('fr_migrator', 'fr_app_runtime', 'fr_maintenance') "
                     "AND rm.member_principal_id NOT IN (USER_ID('t_migrator'), USER_ID('t_runtime'), USER_ID('t_maintenance'))") == 0
