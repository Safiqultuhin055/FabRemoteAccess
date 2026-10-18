"""Request and response models for the v1 API. Enums and limits come from app/domain/constants.py."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.domain.constants import DISPLAY_NAME_MAX_LENGTH, EMAIL_MAX_LENGTH, Role, UserStatus

EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
TOKEN_PATTERN = r"^[A-Za-z0-9_-]{20,128}$"

Email = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, min_length=3,
                                         max_length=EMAIL_MAX_LENGTH, pattern=EMAIL_PATTERN)]
# Upper bound protects the server from oversized Argon2 inputs; the policy (12-128) applies on accept.
Password = Annotated[str, StringConstraints(min_length=1, max_length=1024)]
OpaqueToken = Annotated[str, StringConstraints(pattern=TOKEN_PATTERN)]
DisplayName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1,
                                               max_length=DISPLAY_NAME_MAX_LENGTH)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginIn(Strict):
    email: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=EMAIL_MAX_LENGTH)]
    password: Password


class RefreshIn(Strict):
    refresh_token: OpaqueToken


class AcceptInvitationIn(Strict):
    token: OpaqueToken
    display_name: DisplayName
    password: Password


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    status: UserStatus
    email_verified_at: datetime | None
    roles: list[Role]
    created_at: datetime


class AcceptedOut(BaseModel):
    user: UserOut


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    user: UserOut


class CsrfOut(BaseModel):
    csrf_token: str


class CreateInvitationIn(Strict):
    email: Email
    role: Role = Role.USER
    expires_in_hours: int = Field(72, ge=1, le=168)


class InvitationOut(BaseModel):
    id: uuid.UUID
    email: str
    role: Role
    status: Literal["open", "accepted", "revoked", "expired"]
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None
    invited_by_user_id: uuid.UUID | None


class CreatedInvitationOut(BaseModel):
    invitation: InvitationOut
    token: str = Field(description="Shown once. Only its SHA-256 hash is stored.")
    accept_url: str | None


class InvitationPage(BaseModel):
    items: list[InvitationOut]
    next_cursor: str | None
