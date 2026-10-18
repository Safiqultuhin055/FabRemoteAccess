"""/api/v1/connection-requests and /api/v1/sessions: ask, consent, end (Phase 3e).

The requester is a signed-in user (bearer or cookie) and proves its device with
X-Device-Token. The target answers with its device token only; it needs no account.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field, StringConstraints

from app.api.auth_deps import Context, CurrentDevice, CurrentPrincipal, SessionActor, enforce_rate_limit
from app.api.v1.schemas import Strict
from app.domain.constants import (DecisionReason, Permission, RequestStatus, SessionEndReason, SessionState)
from app.services.connections import ConnectionService, RequestView, SessionView

requests_router = APIRouter(prefix="/connection-requests", tags=["connection requests"])
sessions_router = APIRouter(prefix="/sessions", tags=["sessions"])

RemoteIdIn = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[1-9][0-9]{8}$")]


def get_connection_service(request: Request) -> ConnectionService:
    return request.app.state.connection_service


Connections = Annotated[ConnectionService, Depends(get_connection_service)]


# ------------------------------------------------------------------ schemas


class Requester(BaseModel):
    display_name: str
    email: str


class RequesterDevice(BaseModel):
    display_name: str
    remote_id: str


class RequestOut(BaseModel):
    id: uuid.UUID
    status: RequestStatus
    requested_permission: Permission
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    decision_reason: DecisionReason | None
    target_remote_id: str
    session_id: uuid.UUID | None
    requester: Requester | None = Field(None, description="Only in the target's view.")
    requester_device: RequesterDevice | None = Field(None, description="Only in the target's view.")


class IncomingOut(BaseModel):
    items: list[RequestOut]
    live_session_id: uuid.UUID | None = Field(description="This device's live session, if any (no new requests then).")


class CreateRequestIn(Strict):
    remote_id: RemoteIdIn
    requested_permission: Permission = Permission.VIEW


class ApproveIn(Strict):
    permission_granted: Permission | None = None


class RejectIn(Strict):
    block_requester: bool = False


class SessionController(BaseModel):
    display_name: str
    device_remote_id: str


class SessionTarget(BaseModel):
    remote_id: str
    display_name: str | None = Field(description="Hidden from the controller.")


class SessionOut(BaseModel):
    id: uuid.UUID
    connection_request_id: uuid.UUID
    state: SessionState
    requested_permission: Permission
    permission_granted: Permission
    created_at: datetime
    started_at: datetime | None
    ended_at: datetime | None
    end_reason: SessionEndReason | None
    controller: SessionController
    target: SessionTarget
    media_available: bool = Field(False, description="Screen sharing is not implemented yet (Phase 6).")


def request_out(view: RequestView) -> RequestOut:
    r = view.request
    return RequestOut(
        id=r.id, status=r.status, requested_permission=r.requested_permission, created_at=r.created_at,
        expires_at=r.expires_at, decided_at=r.decided_at, decision_reason=r.decision_reason,
        target_remote_id=view.target_remote_id, session_id=view.session_id,
        requester=Requester(display_name=view.requester.display_name, email=view.requester.email)
        if view.requester else None,
        requester_device=RequesterDevice(display_name=view.requester_device.display_name,
                                         remote_id=view.requester_device.remote_id)
        if view.requester_device else None)


def session_out(view: SessionView) -> SessionOut:
    s = view.session
    return SessionOut(
        id=s.id, connection_request_id=s.connection_request_id, state=s.state,
        requested_permission=s.requested_permission, permission_granted=s.permission_granted,
        created_at=s.created_at, started_at=s.started_at, ended_at=s.ended_at, end_reason=s.end_reason,
        controller=SessionController(display_name=view.controller.display_name,
                                     device_remote_id=view.controller_device.remote_id),
        target=SessionTarget(remote_id=view.target_device.remote_id,
                             display_name=None if view.side == "controller" else view.target_device.display_name))


# ---------------------------------------------------------------- requests


@requests_router.post("", status_code=status.HTTP_201_CREATED, response_model=RequestOut,
                      summary="Ask to connect to a Remote ID (signed-in user + this device's token)")
def create_request(body: CreateRequestIn, request: Request, principal: CurrentPrincipal, caller: CurrentDevice,
                   ctx: Context, connections: Connections) -> RequestOut:
    limits = request.app.state.rate_limits
    enforce_rate_limit(request, limits.connection_request_per_user, "connect-user", str(principal.user_id))
    enforce_rate_limit(request, limits.connection_request_per_target, "connect-target", body.remote_id)
    return request_out(connections.create(principal, caller, body.remote_id, body.requested_permission, ctx))


@requests_router.get("/incoming", response_model=IncomingOut,
                     summary="Pending requests for this device (device token); also its heartbeat")
def incoming(request: Request, caller: CurrentDevice, ctx: Context, connections: Connections) -> IncomingOut:
    enforce_rate_limit(request, request.app.state.rate_limits.connection_poll_per_caller, "incoming",
                       str(caller.device_id))
    result = connections.incoming(caller, ctx)
    return IncomingOut(items=[request_out(v) for v in result.requests], live_session_id=result.live_session_id)


@requests_router.get("/{request_id}", response_model=RequestOut, summary="A request you sent")
def get_request(request_id: uuid.UUID, request: Request, principal: CurrentPrincipal,
                connections: Connections) -> RequestOut:
    enforce_rate_limit(request, request.app.state.rate_limits.connection_poll_per_caller, "request-poll",
                       str(principal.user_id))
    return request_out(connections.get(principal, request_id))


@requests_router.post("/{request_id}/cancel", response_model=RequestOut, summary="Withdraw a pending request")
def cancel_request(request_id: uuid.UUID, principal: CurrentPrincipal, ctx: Context,
                   connections: Connections) -> RequestOut:
    return request_out(connections.cancel(principal, request_id, ctx))


@requests_router.post("/{request_id}/approve", status_code=status.HTTP_201_CREATED, response_model=SessionOut,
                      summary="Accept a request (target device token only)")
def approve_request(request_id: uuid.UUID, caller: CurrentDevice, ctx: Context, connections: Connections,
                    body: ApproveIn | None = None) -> SessionOut:
    permission = body.permission_granted if body else None
    return session_out(connections.approve(caller, request_id, permission, ctx))


@requests_router.post("/{request_id}/reject", response_model=RequestOut,
                      summary="Decline a request (target device token only)")
def reject_request(request_id: uuid.UUID, caller: CurrentDevice, ctx: Context, connections: Connections,
                   body: RejectIn | None = None) -> RequestOut:
    return request_out(connections.reject(caller, request_id, bool(body and body.block_requester), ctx))


# ---------------------------------------------------------------- sessions


@sessions_router.get("/{session_id}", response_model=SessionOut,
                     summary="A session (controller, target device, target owner, admin, auditor); also a heartbeat")
def get_session(session_id: uuid.UUID, request: Request, actor: SessionActor, connections: Connections) -> SessionOut:
    principal, caller = actor
    who = str(caller.device_id) if caller else str(principal.user_id)
    enforce_rate_limit(request, request.app.state.rate_limits.connection_poll_per_caller, "session-poll", who)
    return session_out(connections.get_session(principal, caller, session_id))


@sessions_router.post("/{session_id}/terminate", response_model=SessionOut,
                      summary="End a session (either side; target owner or admin)")
def terminate_session(session_id: uuid.UUID, actor: SessionActor, ctx: Context,
                      connections: Connections) -> SessionOut:
    principal, caller = actor
    return session_out(connections.terminate(principal, caller, session_id, ctx))
