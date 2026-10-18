"""The bootstrap CLI and the test suite cannot reach the shared server.

These tests use a remote documentation address (RFC 5737) to prove that any non-local
server is refused before a connection is attempted.
"""

from __future__ import annotations

import pyodbc
import pytest

import app.cli as cli

# A remote (non-local) address from RFC 5737; stands in for any shared server.
SHARED_HOST = "192.0.2.10"


@pytest.fixture
def no_database(monkeypatch):
    """Fail loudly if the CLI gets as far as building a database or opening a connection."""
    def explode(*args, **kwargs):
        raise AssertionError("a database connection was attempted")
    monkeypatch.setattr(cli, "Database", explode)
    monkeypatch.setattr(pyodbc, "connect", explode)


def test_test_suite_guard_blocks_non_local_connections():
    # The autouse guard in tests/conftest.py wraps pyodbc.connect for every backend test.
    with pytest.raises(pytest.fail.Exception, match="non-local server"):
        pyodbc.connect(f"DRIVER={{ODBC Driver 18 for SQL Server}};SERVER=tcp:{SHARED_HOST},1433;"
                       "DATABASE=FabRemotesDB;Trusted_Connection=yes", timeout=1)


def test_cli_refuses_remote_database_without_explicit_flag(monkeypatch, capsys, no_database):
    monkeypatch.setenv("FR_DB_HOST", SHARED_HOST)
    assert cli.main(["bootstrap-admin", "--email", "admin@example.com"]) == cli.EXIT_CONFIG
    assert "--allow-remote-database" in capsys.readouterr().err


def test_cli_refuses_sa_even_with_flag(monkeypatch, capsys, no_database):
    monkeypatch.setenv("FR_DB_HOST", SHARED_HOST)
    monkeypatch.setenv("FR_DB_USER", "sa")
    monkeypatch.setenv("FR_DB_PASSWORD", "Not-The-Real-Password-1")
    assert cli.main(["bootstrap-admin", "--email", "admin@example.com", "--allow-remote-database"]) == cli.EXIT_CONFIG
    captured = capsys.readouterr()
    assert "Configuration rejected" in captured.err
    assert "Not-The-Real-Password-1" not in captured.err + captured.out


def test_cli_refuses_relaxed_tls_for_remote_server(monkeypatch, no_database):
    monkeypatch.setenv("FR_DB_HOST", SHARED_HOST)
    monkeypatch.setenv("FR_DB_TRUST_SERVER_CERT", "yes")
    assert cli.main(["bootstrap-admin", "--email", "a@example.com", "--allow-remote-database"]) == cli.EXIT_CONFIG


def test_cli_with_repository_style_env_file_is_refused(tmp_path, monkeypatch, no_database):
    """A .env like the repository root's (shared host, Windows auth) must not lead to a connection."""
    (tmp_path / ".env").write_text(f"FR_DB_HOST={SHARED_HOST}\nFR_DB_NAME=FabRemotesDB\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    from app.config import Settings
    monkeypatch.setitem(Settings.model_config, "env_file", ".env")
    assert cli.main(["bootstrap-admin", "--email", "admin@example.com"]) == cli.EXIT_CONFIG


def test_cli_requires_configured_database(no_database):
    assert cli.main(["bootstrap-admin", "--email", "admin@example.com"]) == cli.EXIT_CONFIG


def test_cli_rejects_invalid_email(monkeypatch, no_database):
    monkeypatch.setenv("FR_DB_HOST", "(localdb)\\FabRemoteTest")
    monkeypatch.setenv("FR_DB_ENCRYPT", "optional")
    assert cli.main(["bootstrap-admin", "--email", "not-an-email"]) == cli.EXIT_CONFIG
