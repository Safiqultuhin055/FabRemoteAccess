"""Column types shared by the ORM models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import Enum
from sqlalchemy.dialects.mssql import DATETIME2
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator):
    """DATETIME2(3) holding UTC. Accepts only timezone-aware values; returns aware UTC values."""

    impl = DATETIME2(precision=3)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Naive datetime values are not allowed; use timezone-aware UTC")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect):
        return value.replace(tzinfo=UTC) if value is not None else None


def str_enum(enum_cls: type[StrEnum], length: int) -> Enum:
    """VARCHAR column holding the enum's values. The database CHECK constraint stays authoritative."""
    return Enum(enum_cls, native_enum=False, create_constraint=False, length=length, validate_strings=True,
                values_callable=lambda members: [m.value for m in members])


def utcnow() -> datetime:
    return datetime.now(UTC)
