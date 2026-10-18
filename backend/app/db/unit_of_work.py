"""SQLAlchemy unit of work: one session and transaction per `with` block."""

from __future__ import annotations

from typing import Self

from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm.exc import StaleDataError

from app.db.errors import translate, translate_errors
from app.db.repositories import (SqlAuditRepository, SqlAuthSessionRepository, SqlAuthTokenRepository,
                                 SqlDeviceChallengeRepository, SqlDeviceRepository, SqlInvitationRepository,
                                 SqlMigrationRepository, SqlUserRepository)


class SqlAlchemyUnitOfWork:
    def __init__(self, session_factory: sessionmaker[Session]):
        self._session_factory = session_factory
        self._session: Session | None = None

    def __enter__(self) -> Self:
        self._session = self._session_factory()
        self.migrations = SqlMigrationRepository(self._session)
        self.users = SqlUserRepository(self._session)
        self.invitations = SqlInvitationRepository(self._session)
        self.devices = SqlDeviceRepository(self._session)
        self.audit = SqlAuditRepository(self._session)
        self.auth_sessions = SqlAuthSessionRepository(self._session)
        self.auth_tokens = SqlAuthTokenRepository(self._session)
        self.device_challenges = SqlDeviceChallengeRepository(self._session)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            # Detach first: a rollback expires loaded objects, and services return them
            # after the block (read-only queries never commit). The transaction itself
            # is still rolled back, so uncommitted changes never reach the database.
            self._session.expunge_all()
            self.rollback()  # no-op after a successful commit
        finally:
            self._session.close()
            self._session = None
        if isinstance(exc, (DBAPIError, StaleDataError)):
            domain = translate(exc)
            if domain is not None:
                raise domain from exc

    def commit(self) -> None:
        with translate_errors():
            self._session.commit()

    def rollback(self) -> None:
        try:
            self._session.rollback()
        except DBAPIError:
            pass  # connection already gone; the server rolls the transaction back
