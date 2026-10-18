"""Injectable UTC clock, so expiry logic can be tested without sleeping."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


class Clock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FrozenClock(Clock):
    """Test clock: fixed until advanced explicitly."""

    def __init__(self, start: datetime | None = None):
        self._now = (start or datetime.now(UTC)).astimezone(UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, **delta) -> None:
        self._now += timedelta(**delta)
