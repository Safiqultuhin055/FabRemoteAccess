"""Safety guards for every backend test.

- FR_* environment variables are cleared and `.env` is never loaded, so the developer's
  local configuration (which points at the shared server) cannot leak into tests.
- pyodbc.connect is wrapped: any server other than LocalDB or 127.0.0.1 fails the test
  before a connection is attempted.
"""

from __future__ import annotations

import os
import re

import pytest

from app.config import Settings

ALLOWED_SERVER = re.compile(r"SERVER=(\(localdb\)\\[^;]+|tcp:127\.0\.0\.1,\d+);", re.IGNORECASE)


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch):
    for key in list(os.environ):
        if key.startswith("FR_") and key != "FR_TEST_SQL_SERVER":
            monkeypatch.delenv(key)
    monkeypatch.setitem(Settings.model_config, "env_file", None)


@pytest.fixture(autouse=True)
def _local_connections_only(monkeypatch):
    try:
        import pyodbc
    except ImportError:
        return
    real_connect = pyodbc.connect

    def guarded_connect(conn_str, *args, **kwargs):
        if not ALLOWED_SERVER.search(conn_str + ";"):
            pytest.fail("Test attempted a database connection to a non-local server")
        return real_connect(conn_str, *args, **kwargs)

    monkeypatch.setattr(pyodbc, "connect", guarded_connect)


@pytest.fixture
def make_settings():
    def make(**overrides) -> Settings:
        return Settings(_env_file=None, **overrides)
    return make
