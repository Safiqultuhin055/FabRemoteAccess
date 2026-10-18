"""LocalDB test helpers and fixtures (shared by database/tests and backend/tests/integration).

These tests run ONLY against a SQL Server LocalDB instance on the developer machine
(default `(localdb)\\FabRemoteTest`, override with FR_TEST_SQL_SERVER). Every test
database is created with a random name and dropped afterwards. The fixtures refuse
to run against anything that is not LocalDB, so the shared server can never be hit.
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

import pytest

from sqlrunner import run_script

try:
    import pyodbc

    pyodbc.pooling = False  # pooled connections would block DROP DATABASE
except ImportError:  # static tests still run without the driver
    pyodbc = None

DATABASE_DIR = Path(__file__).resolve().parents[1]
MIGRATIONS = sorted((DATABASE_DIR / "migrations").glob("V*.sql"))
ROLLBACKS = sorted((DATABASE_DIR / "migrations" / "rollback").glob("R*.sql"), reverse=True)
PERMISSIONS = DATABASE_DIR / "permissions"
P001 = PERMISSIONS / "P001_bootstrap_schema_and_roles.sql"
P002 = PERMISSIONS / "P002_grant_runtime_permissions.sql"
P003 = PERMISSIONS / "P003_map_logins_to_roles.sql"
PR001 = PERMISSIONS / "PR001_remove_schema_and_roles.sql"

SERVER = os.environ.get("FR_TEST_SQL_SERVER", r"(localdb)\FabRemoteTest")
DRIVER = os.environ.get("FR_DB_DRIVER", "ODBC Driver 18 for SQL Server")

MIGRATOR, RUNTIME, MAINTENANCE = "t_migrator", "t_runtime", "t_maintenance"

PERMISSION_ERROR = re.compile(
    r"permission|\((229|230|262|297|300|916|2760|15151|15247)\)", re.IGNORECASE)

LEGACY_SQL = """
CREATE TABLE dbo.legacy_customers (id INT NOT NULL PRIMARY KEY, name NVARCHAR(50) NOT NULL);
INSERT INTO dbo.legacy_customers VALUES (1, N'Alpha'), (2, N'Beta'), (3, N'Gamma');
CREATE TABLE dbo.users (id INT NOT NULL PRIMARY KEY, login NVARCHAR(50) NOT NULL);
INSERT INTO dbo.users VALUES (1, N'legacy');
"""
LEGACY_VIEW_SQL = "CREATE VIEW dbo.legacy_customer_names AS SELECT name FROM dbo.legacy_customers;"


def sql_error(code: int) -> str:
    """Regex matching a SQL Server native error number in a pyodbc message."""
    return rf"\({code}\)"


def connect(database: str = "master"):
    conn = pyodbc.connect(
        f"DRIVER={{{DRIVER}}};SERVER={SERVER};DATABASE={database};"
        "Trusted_Connection=yes;Encrypt=optional",
        autocommit=True, timeout=30)
    if conn.execute("SELECT CAST(SERVERPROPERTY('IsLocalDB') AS INT)").fetchval() != 1:
        conn.close()
        pytest.exit(f"Refusing to run database tests: {SERVER} is not a LocalDB instance.", returncode=2)
    return conn


class ScratchDatabase:
    def __init__(self, name: str, conn):
        self.name = name
        self.conn = conn

    def _as(self, user: str | None):
        if user:
            self.conn.execute("EXECUTE AS USER = ?", user)

    def _revert(self, user: str | None):
        if user:
            self.conn.execute("REVERT")

    def run(self, path: Path, as_user: str | None = None, variables: dict[str, str] | None = None) -> list[str]:
        self._as(as_user)
        try:
            return run_script(self.conn, path, variables)
        finally:
            self._revert(as_user)

    def execute(self, sql: str, *params, as_user: str | None = None) -> list[tuple]:
        self._as(as_user)
        try:
            cursor = self.conn.execute(sql, *params)
            rows = []
            while True:
                if cursor.description:
                    rows.extend(tuple(r) for r in cursor.fetchall())
                if not cursor.nextset():
                    break
            return rows
        finally:
            self._revert(as_user)

    def scalar(self, sql: str, *params, as_user: str | None = None):
        rows = self.execute(sql, *params, as_user=as_user)
        return rows[0][0] if rows else None

    def migrate(self, as_user: str = MIGRATOR) -> None:
        for path in MIGRATIONS:
            self.run(path, as_user=as_user)

    def versions(self) -> list[int]:
        return [r[0] for r in self.execute("SELECT version FROM fr.schema_migrations ORDER BY version")]

    def fr_objects(self) -> list[tuple]:
        return self.execute(
            "SELECT name, type, create_date, modify_date FROM sys.objects "
            "WHERE schema_id = SCHEMA_ID('fr') ORDER BY name")

    def legacy_snapshot(self) -> dict:
        """Everything outside schema fr that the scripts must never change."""
        return {
            "objects": self.execute(
                "SELECT SCHEMA_NAME(schema_id), name, type, create_date, modify_date FROM sys.objects "
                "WHERE is_ms_shipped = 0 AND schema_id <> ISNULL(SCHEMA_ID('fr'), -1) ORDER BY 1, 2"),
            "customers": self.execute("SELECT id, name FROM dbo.legacy_customers ORDER BY id"),
            "users": self.execute("SELECT id, login FROM dbo.users ORDER BY id"),
            "permissions": self.execute(
                "SELECT major_id, grantee_principal_id, permission_name, state FROM sys.database_permissions "
                "WHERE class = 1 AND major_id IN (OBJECT_ID('dbo.legacy_customers'), OBJECT_ID('dbo.users'), "
                "OBJECT_ID('dbo.legacy_customer_names')) ORDER BY 1, 2, 3"),
        }


@pytest.fixture(scope="session")
def server():
    if pyodbc is None:
        pytest.skip("pyodbc is not installed")
    try:
        conn = connect()
    except pyodbc.Error as exc:
        pytest.skip(f"LocalDB test instance {SERVER} not available: {exc.args[-1]}")
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def db_factory(server):
    created: list[ScratchDatabase] = []

    def make(stage: str = "empty", compatibility_level: int | None = None) -> ScratchDatabase:
        """stage: empty | legacy | bootstrapped | migrated (each includes the previous)."""
        name = f"fr_test_{secrets.token_hex(4)}"
        server.execute(f"CREATE DATABASE [{name}]")
        if compatibility_level:
            server.execute(f"ALTER DATABASE [{name}] SET COMPATIBILITY_LEVEL = {int(compatibility_level)}")
        db = ScratchDatabase(name, connect(name))
        created.append(db)
        if stage == "empty":
            return db
        db.execute(LEGACY_SQL)
        db.execute(LEGACY_VIEW_SQL)
        if stage == "legacy":
            return db
        db.run(P001)
        for user, role in ((MIGRATOR, "fr_migrator"), (RUNTIME, "fr_app_runtime"), (MAINTENANCE, "fr_maintenance")):
            db.execute(f"CREATE USER [{user}] WITHOUT LOGIN; ALTER ROLE [{role}] ADD MEMBER [{user}];")
        if stage == "bootstrapped":
            return db
        db.migrate()
        db.run(P002)
        return db

    yield make

    for db in created:
        db.conn.close()
        server.execute(f"ALTER DATABASE [{db.name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE")
        server.execute(f"DROP DATABASE [{db.name}]")


@pytest.fixture(scope="module")
def migrated_db(db_factory) -> ScratchDatabase:
    """Shared, fully migrated database for tests that only add rows."""
    return db_factory("migrated")
