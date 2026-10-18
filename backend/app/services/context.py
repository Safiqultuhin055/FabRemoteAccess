"""Values shared by services: who is acting and from where."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.domain.constants import ClientType, Role


@dataclass(frozen=True)
class RequestContext:
    ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None


@dataclass(frozen=True)
class Principal:
    """An authenticated user. Roles are loaded from the database on every request, never from the token."""
    user_id: uuid.UUID
    auth_session_id: uuid.UUID
    roles: frozenset[Role]
    client_type: ClientType
    via_cookie: bool = False
    device_id: uuid.UUID | None = None

    def has(self, role: Role) -> bool:
        return role in self.roles


@dataclass(frozen=True)
class DevicePrincipal:
    """A device that proved possession of its active key (device token). No user account implied."""
    device_id: uuid.UUID
    key_id: uuid.UUID
