"""/api/v1/admin/invitations: administrators invite users (the only way to create accounts in the pilot)."""

from __future__ import annotations

import base64
import binascii
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, status

from app.api.auth_deps import AdminPrincipal, Context, enforce_rate_limit, get_invitation_service
from app.api.v1.schemas import (CreatedInvitationOut, CreateInvitationIn, InvitationOut, InvitationPage)
from app.db.models import UserInvitation
from app.domain.errors import InputRejectedError
from app.services.invitations import InvitationService, invitation_status

router = APIRouter(prefix="/admin/invitations", tags=["admin"])

Invitations = Annotated[InvitationService, Depends(get_invitation_service)]


def invitation_out(invitation: UserInvitation, now: datetime) -> InvitationOut:
    return InvitationOut(id=invitation.id, email=invitation.email, role=invitation.role_code,
                         status=invitation_status(invitation, now), created_at=invitation.created_at,
                         expires_at=invitation.expires_at, accepted_at=invitation.accepted_at,
                         revoked_at=invitation.revoked_at, invited_by_user_id=invitation.invited_by_user_id)


def _encode_cursor(invitation: UserInvitation) -> str:
    raw = f"{invitation.created_at.isoformat()}|{invitation.id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        created, _, ident = raw.partition("|")
        return datetime.fromisoformat(created), uuid.UUID(ident)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise InputRejectedError("cursor", "invalid") from None


@router.post("", status_code=status.HTTP_201_CREATED, response_model=CreatedInvitationOut,
             summary="Invite a user (token shown once)")
def create_invitation(body: CreateInvitationIn, request: Request, admin: AdminPrincipal, ctx: Context,
                      invitations: Invitations) -> CreatedInvitationOut:
    enforce_rate_limit(request, request.app.state.rate_limits.invitation_create_per_admin, "invite",
                       str(admin.user_id))
    issued = invitations.create(admin, body.email, body.role, body.expires_in_hours, ctx)
    base = request.app.state.settings.public_base_url
    # Fragment, not query: the token never reaches server or proxy logs when the link is opened.
    accept_url = f"{base.rstrip('/')}/portal/accept-invitation#token={issued.token}" if base else None
    return CreatedInvitationOut(invitation=invitation_out(issued.invitation, request.app.state.clock.now()),
                                token=issued.token, accept_url=accept_url)


@router.get("", response_model=InvitationPage, summary="List invitations")
def list_invitations(request: Request, admin: AdminPrincipal, invitations: Invitations,
                     status_: Annotated[Literal["open", "accepted", "revoked", "expired"] | None,
                                        Query(alias="status")] = None,
                     email: Annotated[str | None, Query(max_length=320)] = None,
                     limit: Annotated[int, Query(ge=1, le=200)] = 50,
                     cursor: Annotated[str | None, Query(max_length=200)] = None) -> InvitationPage:
    after = _decode_cursor(cursor) if cursor else None
    rows = invitations.list(admin, status=status_, email=email, limit=limit + 1, after=after)
    now = request.app.state.clock.now()
    page, more = rows[:limit], len(rows) > limit
    return InvitationPage(items=[invitation_out(i, now) for i in page],
                          next_cursor=_encode_cursor(page[-1]) if more else None)


@router.post("/{invitation_id}/revoke", response_model=InvitationOut, summary="Revoke an open invitation")
def revoke_invitation(invitation_id: uuid.UUID, request: Request, admin: AdminPrincipal, ctx: Context,
                      invitations: Invitations) -> InvitationOut:
    return invitation_out(invitations.revoke(admin, invitation_id, ctx), request.app.state.clock.now())
