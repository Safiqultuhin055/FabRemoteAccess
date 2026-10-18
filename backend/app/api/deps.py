"""FastAPI dependencies. Tests replace app.state.database (or override these) with doubles."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from fastapi import Request

from app.config import Settings
from app.db.engine import Readiness
from app.domain.repositories import UnitOfWork


class DatabaseGateway(Protocol):
    @property
    def configured(self) -> bool: ...
    def check_readiness(self) -> Readiness: ...
    def unit_of_work(self) -> UnitOfWork: ...
    def dispose(self) -> None: ...


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_database(request: Request) -> DatabaseGateway:
    return request.app.state.database


def get_uow(request: Request) -> Iterator[UnitOfWork]:
    """One unit of work per request; the endpoint must call uow.commit() to persist."""
    with request.app.state.database.unit_of_work() as uow:
        yield uow
