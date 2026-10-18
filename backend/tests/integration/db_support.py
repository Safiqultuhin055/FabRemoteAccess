"""Helpers for backend integration tests on LocalDB scratch databases (see database/tests/localdb.py)."""

from __future__ import annotations

import sys
from pathlib import Path

DB_TESTS = Path(__file__).resolve().parents[3] / "database" / "tests"
if str(DB_TESTS) not in sys.path:
    sys.path.insert(0, str(DB_TESTS))

import localdb  # noqa: E402  (needs the path above)

from app.config import Settings  # noqa: E402


def impersonate(user: str):
    """Run every pooled connection as a database user WITHOUT LOGIN (e.g. the runtime role member)."""
    def hook(conn):
        conn.execute("EXECUTE AS USER = ?", user)
        conn.commit()
    return hook


def localdb_settings(database_name: str, **overrides) -> Settings:
    values = {"env": "test", "db_host": localdb.SERVER, "db_name": database_name, "db_encrypt": "optional"}
    return Settings(_env_file=None, **{**values, **overrides})
