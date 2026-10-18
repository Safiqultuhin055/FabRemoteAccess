"""Offline tests for the read-only inventory tool, using a fake pyodbc module."""

from __future__ import annotations

import importlib.util
import re
import sys
import types
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS_DIR.parent
spec = importlib.util.spec_from_file_location("inspect_db_schema", TOOLS_DIR / "inspect_db_schema.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

PASSWORD = "Sup3r}Secret"
WRITE_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|DROP|ALTER|CREATE|EXEC|EXECUTE|GRANT|REVOKE|DENY|TRUNCATE|BACKUP|RESTORE)\b",
    re.IGNORECASE)


@pytest.fixture
def env(monkeypatch, tmp_path):
    for key in list(sys.modules.get("os").environ):
        if key.startswith("FR_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("FR_DB_HOST", "db.invalid")
    monkeypatch.setenv("FR_DB_NAME", "FabRemotesDB")
    monkeypatch.setenv("FR_DB_USER", "fr_reader")
    monkeypatch.setenv("FR_DB_PASSWORD", PASSWORD)
    monkeypatch.setattr(sys, "argv", ["inspect_db_schema.py", "--env-file", str(tmp_path / "none.env")])
    return monkeypatch


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = None

    def fetchone(self):
        return self.conn.identity

    def execute(self, sql):
        self.conn.executed.append(sql)
        if "dm_exec_connections" in sql:
            raise FakePyodbc.Error("42000", "VIEW SERVER STATE permission denied")
        self.description = [("col_a",), ("col_b",)]

    def fetchall(self):
        return [("value|1", None)]


class FakeConnection:
    def __init__(self, identity=("FabRemotesDB", "SQLSRV01")):
        self.executed: list[str] = []
        self.identity = identity
        self.rolled_back = self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class FakePyodbc(types.ModuleType):
    class Error(Exception):
        pass

    def __init__(self, fail_with: str | None = None, identity=("FabRemotesDB", "SQLSRV01")):
        super().__init__("pyodbc")
        self.fail_with = fail_with
        self.calls: list[tuple] = []
        self.connection = FakeConnection(identity)

    def connect(self, conn_str, **kwargs):
        self.calls.append((conn_str, kwargs))
        if self.fail_with:
            raise self.Error("08001", self.fail_with)
        return self.connection


def test_all_queries_are_read_only_selects():
    for title, sql in {**tool.QUERIES, "identity": tool.IDENTITY_QUERY}.items():
        assert sql.strip().upper().startswith("SELECT"), title
        assert not WRITE_KEYWORDS.search(sql), title
        assert ";" not in sql, title


def test_reserved_names_cover_every_object_the_migrations_create():
    created = set()
    for path in (REPO_ROOT / "database" / "migrations").glob("V*.sql"):
        created |= set(re.findall(r"CREATE (?:TABLE|PROCEDURE) fr\.(\w+)", path.read_text(encoding="utf-8")))
    assert created and created <= set(tool.RESERVED_OBJECT_NAMES)
    permissions = (REPO_ROOT / "database" / "permissions" / "P001_bootstrap_schema_and_roles.sql").read_text(encoding="utf-8")
    for principal in tool.RESERVED_PRINCIPALS:
        assert principal in permissions


def test_successful_run_is_read_only_and_redacted(env, tmp_path, capsys):
    fake = FakePyodbc()
    env.setitem(sys.modules, "pyodbc", fake)
    out = tmp_path / "inventory.md"
    env.setattr(sys, "argv", sys.argv + ["--out", str(out)])

    assert tool.main() == 0

    conn_str, kwargs = fake.calls[0]
    assert kwargs == {"autocommit": False, "readonly": True}
    assert "ApplicationIntent=ReadOnly" in conn_str and "TrustServerCertificate=no" in conn_str
    assert "PWD={Sup3r}}Secret}" in conn_str  # ODBC brace escaping
    assert fake.connection.rolled_back and fake.connection.closed
    assert fake.connection.executed[0] == tool.IDENTITY_QUERY  # target confirmed first
    assert len(fake.connection.executed) == len(tool.QUERIES) + 1
    report = out.read_text(encoding="utf-8")
    assert "_Not available: VIEW SERVER STATE permission denied_" in report
    assert "value\\|1" in report
    captured = capsys.readouterr()
    assert "Connected to server 'SQLSRV01', database 'FabRemotesDB'" in captured.err
    for text in (report, captured.out, captured.err):
        assert PASSWORD not in text


@pytest.mark.parametrize("identity, expected_server, message", [
    (("master", "SQLSRV01"), None, "expected 'FabRemotesDB'"),
    (("FabRemotesDB", "OTHERSRV"), "SQLSRV01", "expected 'SQLSRV01'"),
])
def test_wrong_target_aborts_before_reading_metadata(env, identity, expected_server, message):
    fake = FakePyodbc(identity=identity)
    env.setitem(sys.modules, "pyodbc", fake)
    if expected_server:
        env.setenv("FR_DB_EXPECTED_SERVER", expected_server)
    with pytest.raises(SystemExit, match=message):
        tool.main()
    assert fake.connection.executed == [tool.IDENTITY_QUERY]
    assert fake.connection.rolled_back and fake.connection.closed


def test_connection_failure_does_not_echo_password(env, capsys):
    env.setitem(sys.modules, "pyodbc", FakePyodbc(fail_with="Login failed for user 'fr_reader'."))
    with pytest.raises(SystemExit) as exc:
        tool.main()
    assert "Login failed" in str(exc.value)
    assert PASSWORD not in str(exc.value) + "".join(capsys.readouterr())


def test_trusting_server_certificate_outside_development_is_refused(env):
    env.setenv("FR_ENV", "production")
    env.setenv("FR_DB_TRUST_SERVER_CERT", "yes")
    with pytest.raises(SystemExit, match="only allowed when FR_ENV=development"):
        tool.build_connection_string()


def test_trusting_certificate_of_remote_server_is_refused_even_in_development(env):
    env.setenv("FR_ENV", "development")
    env.setenv("FR_DB_TRUST_SERVER_CERT", "yes")
    with pytest.raises(SystemExit, match="only allowed for a local development server"):
        tool.build_connection_string()


def test_trusting_certificate_of_local_server_allowed_in_development(env):
    env.setenv("FR_DB_HOST", "localhost")
    env.setenv("FR_DB_TRUST_SERVER_CERT", "yes")
    assert "TrustServerCertificate=yes" in tool.build_connection_string()


def test_certificate_pinning_options_keep_validation_on(env):
    env.setenv("FR_DB_SERVER_CERTIFICATE", r"C:\certs\sql.cer")
    env.setenv("FR_DB_HOST_NAME_IN_CERTIFICATE", "sql01.corp.example")
    conn_str = tool.build_connection_string()
    assert "TrustServerCertificate=no" in conn_str
    assert r"ServerCertificate={C:\certs\sql.cer}" in conn_str
    assert "HostNameInCertificate=sql01.corp.example" in conn_str


def test_sa_login_triggers_warning(env, capsys):
    env.setenv("FR_DB_USER", "SA")
    tool.build_connection_string()
    assert "least-privilege" in capsys.readouterr().err


def test_missing_settings_reported(env):
    env.delenv("FR_DB_HOST")
    with pytest.raises(SystemExit, match="FR_DB_HOST"):
        tool.build_connection_string()


def test_windows_authentication_when_no_user(env):
    env.delenv("FR_DB_USER")
    env.delenv("FR_DB_PASSWORD")
    conn_str = tool.build_connection_string()
    assert "Trusted_Connection=yes" in conn_str and "PWD" not in conn_str
