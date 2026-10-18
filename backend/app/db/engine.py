"""Database access: lazy engine, readiness check and unit-of-work factory.

Nothing connects at import or startup. The ODBC connection string (which holds the
password) is passed to pyodbc through a `creator` callable, so it never becomes part of
an SQLAlchemy URL, repr or log line; statement parameters are hidden from errors.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.db.unit_of_work import SqlAlchemyUnitOfWork

logger = logging.getLogger(__name__)

# Highest migration in database/migrations this code is written against.
EXPECTED_SCHEMA_VERSION = 8

DatabaseState = Literal["ok", "error", "not_configured"]
SchemaState = Literal["ok", "mismatch", "unknown"]


@dataclass(frozen=True)
class Readiness:
    database: DatabaseState
    schema: SchemaState

    @property
    def ready(self) -> bool:
        return self.database == "ok" and self.schema == "ok"


class Database:
    def __init__(self, settings: Settings, *, connect_hook: Callable[[Any], None] | None = None):
        self._settings = settings
        self._connect_hook = connect_hook
        self._engine: Engine | None = None
        self._sessions: sessionmaker[Session] | None = None
        self._lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return self._settings.db_configured

    def _connect(self):
        import pyodbc

        conn = pyodbc.connect(self._settings.db_connection_string,
                              timeout=self._settings.db_login_timeout_seconds, autocommit=False)
        conn.timeout = self._settings.db_query_timeout_seconds
        if self._connect_hook:
            self._connect_hook(conn)
        return conn

    @property
    def engine(self) -> Engine:
        if not self.configured:
            raise RuntimeError("Database is not configured")
        with self._lock:
            if self._engine is None:
                s = self._settings
                self._engine = create_engine(
                    "mssql+pyodbc://", creator=self._connect, pool_pre_ping=True, pool_size=s.db_pool_size,
                    max_overflow=s.db_max_overflow, pool_timeout=s.db_login_timeout_seconds,
                    pool_recycle=1800, hide_parameters=True)
                self._sessions = sessionmaker(self._engine, expire_on_commit=False, autoflush=False)
            return self._engine

    def unit_of_work(self) -> SqlAlchemyUnitOfWork:
        self.engine  # noqa: B018 - initialise lazily
        return SqlAlchemyUnitOfWork(self._sessions)

    def check_readiness(self) -> Readiness:
        if not self.configured:
            return Readiness("not_configured", "unknown")
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                try:
                    version = conn.execute(text("SELECT MAX(version) FROM fr.schema_migrations")).scalar()
                except Exception as exc:
                    logger.warning("Readiness: schema version unavailable (%s)", type(exc).__name__)
                    return Readiness("ok", "unknown")
        except Exception as exc:
            logger.warning("Readiness: database unavailable (%s: %s)", type(exc).__name__, exc)
            return Readiness("error", "unknown")
        if version is None:
            return Readiness("ok", "unknown")
        return Readiness("ok", "ok" if version == EXPECTED_SCHEMA_VERSION else "mismatch")

    def dispose(self) -> None:
        with self._lock:
            if self._engine is not None:
                self._engine.dispose()
                self._engine = None
                self._sessions = None
