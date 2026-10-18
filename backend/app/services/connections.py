"""Connection requests and remote sessions (Phase 3e): consent before anything else.

Rules (docs/API_CONTRACTS.md sections 5.4 and 5.5):
- Only a signed-in, verified user can ask to connect, from a device that proved its key.
  The computer being helped needs no account: it answers with its device token.
- Only the target device can approve. Approval and session creation happen in one
  transaction; the live-session index allows one live session per target.
- Every refusal for an existing target (blocked, policy, offline, busy) looks the same to
  the requester (404 target_unavailable), so a Remote ID reveals nothing about its owner.
- Requests expire after FR_CONNECTION_REQUEST_TTL_SECONDS; a session ends when either side
  is silent for FR_SESSION_PRESENCE_TIMEOUT_SECONDS. Both are applied lazily on every read
  and write that touches the row, so no background job is needed.
- The requester never sees the target device's name. The target sees who is asking.

Phase 3e has no screen or input: a session records that consent was given and lets either
side end it. It stays 'authorizing' until media exists (Phase 6).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from app.config import Settings
from app.db.models import ConnectionRequest, Device, RemoteSession, User
from app.domain.constants import (AuditOutcome, DecisionReason, DeviceStatus, IncomingPolicy, Permission,
                                  RequestStatus, Role, SessionEndReason, SessionState)
from app.domain.errors import ConflictError, GoneError, InputRejectedError, NotFoundError, PermissionDeniedError
from app.domain.repositories import UnitOfWork, UnitOfWorkFactory
from app.security.clock import Clock
from app.services.context import DevicePrincipal, Principal, RequestContext


@dataclass(frozen=True)
class RequestView:
    request: ConnectionRequest
    target_remote_id: str
    session_id: uuid.UUID | None
    requester: User | None = None              # target view only
    requester_device: Device | None = None     # target view only


@dataclass(frozen=True)
class SessionView:
    session: RemoteSession
    controller: User
    controller_device: Device
    target_device: Device
    side: str | None                           # "controller", "target", or None for owners/admins/auditors


@dataclass(frozen=True)
class Incoming:
    requests: list[RequestView]
    live_session_id: uuid.UUID | None


def _unavailable() -> NotFoundError:
    return NotFoundError("This computer is not available for a connection right now.", code="target_unavailable")


def _request_not_found() -> NotFoundError:
    return NotFoundError("The connection request was not found.", code="not_found")


def _session_not_found() -> NotFoundError:
    return NotFoundError("The session was not found.", code="not_found")


def _not_pending() -> ConflictError:
    return ConflictError("This request has already been answered.", code="request_not_pending")


class ConnectionService:
    def __init__(self, uow_factory: UnitOfWorkFactory, settings: Settings, clock: Clock):
        self._uow = uow_factory
        self._settings = settings
        self._clock = clock

    # ---------------------------------------------------------------- helpers

    def _online(self, device: Device) -> bool:
        return (device.last_seen_at is not None and
                self._clock.now() - device.last_seen_at <= timedelta(seconds=self._settings.presence_ttl_seconds))

    def _cutoff(self):
        return self._clock.now() - timedelta(seconds=self._settings.session_presence_timeout_seconds)

    @staticmethod
    def _audit(uow: UnitOfWork, event: str, outcome: AuditOutcome, ctx: RequestContext, *,
               user_id: uuid.UUID | None = None, device_id: uuid.UUID | None = None, subject_type: str | None = None,
               subject_id: uuid.UUID | None = None, **details) -> None:
        uow.audit.add(event, outcome, actor_user_id=user_id, actor_device_id=device_id, subject_type=subject_type,
                      subject_id=str(subject_id) if subject_id else None, ip_address=ctx.ip,
                      request_id=ctx.request_id, details=details or None)

    def _request_view(self, uow: UnitOfWork, request: ConnectionRequest, *, for_target: bool) -> RequestView:
        target = uow.devices.get(request.target_device_id)
        session = uow.sessions.for_request(request.id) if request.status is RequestStatus.APPROVED else None
        if not for_target:
            return RequestView(request, target.remote_id, session.id if session else None)
        return RequestView(request, target.remote_id, session.id if session else None,
                           requester=uow.users.get(request.requester_user_id),
                           requester_device=uow.devices.get(request.requester_device_id))

    def _session_view(self, uow: UnitOfWork, session: RemoteSession, side: str | None) -> SessionView:
        return SessionView(session, uow.users.get(session.controller_user_id),
                           uow.devices.get(session.controller_device_id), uow.devices.get(session.target_device_id),
                           side)

    # -------------------------------------------------------------- requester

    def create(self, principal: Principal, caller: DevicePrincipal, remote_id: str, permission: Permission,
               ctx: RequestContext) -> RequestView:
        now = self._clock.now()
        with self._uow() as uow:
            user = uow.users.get(principal.user_id)
            if user is None or user.email_verified_at is None:
                raise PermissionDeniedError("Your account must be verified before you can connect.",
                                            code="account_not_verified")
            source = uow.devices.get(caller.device_id)
            if source.remote_id == remote_id:
                error = InputRejectedError("remote_id", "self", "You cannot connect to this computer itself.")
                error.code = "cannot_connect_to_self"
                raise error
            audit = dict(user_id=user.id, device_id=source.id)
            target = uow.devices.get_by_remote_id(remote_id)
            if target is None or target.status is not DeviceStatus.ACTIVE or uow.devices.active_key(target.id) is None:
                self._audit(uow, "connection.requested", AuditOutcome.DENIED, ctx, **audit,
                            reason="unknown" if target is None else "revoked")
                uow.commit()
                raise _unavailable()

            uow.sessions.end_silent(self._cutoff(), now, target_device_id=target.id)
            uow.connections.expire_overdue(now, target_device_id=target.id)
            existing = uow.connections.find_pending(user.id, target.id, now)
            if existing is not None:              # asking again while waiting: same request
                uow.commit()
                return self._request_view(uow, existing, for_target=False)

            decided: tuple[RequestStatus, DecisionReason] | None = None
            if target.incoming_policy is IncomingPolicy.DISABLED:
                decided = (RequestStatus.REJECTED, DecisionReason.POLICY_DENIED)
            elif target.incoming_policy is IncomingPolicy.ADDRESS_BOOK_ONLY and (
                    target.owner_user_id is None
                    or not uow.connections.in_address_book(target.owner_user_id, source.remote_id)):
                decided = (RequestStatus.REJECTED, DecisionReason.POLICY_DENIED)
            elif uow.connections.is_blocked(target.id, user.id):
                decided = (RequestStatus.REJECTED, DecisionReason.BLOCKED)
            elif not self._online(target):
                decided = (RequestStatus.EXPIRED, DecisionReason.TARGET_OFFLINE)
            elif uow.sessions.live_for_target(target.id) is not None:
                self._audit(uow, "connection.requested", AuditOutcome.DENIED, ctx, **audit, subject_type="device",
                            subject_id=target.id, reason="target_busy")
                uow.commit()
                raise _unavailable()

            expires = now + timedelta(seconds=self._settings.connection_request_ttl_seconds)
            request = ConnectionRequest(requester_user_id=user.id, requester_device_id=source.id,
                                        target_device_id=target.id, requested_permission=permission,
                                        created_at=now, expires_at=expires, requester_ip=ctx.ip)
            if decided:
                # Recorded so cooldowns and the audit trail stay accurate; the requester still sees 404.
                request.status, request.decision_reason = decided
                request.decided_at = now
                uow.connections.add(request)
                self._audit(uow, "connection.requested", AuditOutcome.DENIED, ctx, **audit,
                            subject_type="connection_request", subject_id=request.id, reason=decided[1].value)
                uow.commit()
                raise _unavailable()
            uow.connections.add(request)
            self._audit(uow, "connection.requested", AuditOutcome.SUCCESS, ctx, **audit,
                        subject_type="connection_request", subject_id=request.id, permission=permission.value)
            uow.commit()
            return self._request_view(uow, request, for_target=False)

    def get(self, principal: Principal, request_id: uuid.UUID) -> RequestView:
        now = self._clock.now()
        with self._uow() as uow:
            request = uow.connections.get(request_id)
            if request is None or (request.requester_user_id != principal.user_id
                                   and not (principal.has(Role.ADMIN) or principal.has(Role.AUDITOR))):
                raise _request_not_found()
            if uow.connections.expire_overdue(now, request_id=request.id):
                request = uow.connections.get(request.id)
            view = self._request_view(uow, request, for_target=False)
            uow.commit()
            return view

    def cancel(self, principal: Principal, request_id: uuid.UUID, ctx: RequestContext) -> RequestView:
        now = self._clock.now()
        with self._uow() as uow:
            request = uow.connections.get(request_id)
            if request is None or request.requester_user_id != principal.user_id:
                raise _request_not_found()
            if not uow.connections.decide(request.id, RequestStatus.CANCELLED, DecisionReason.REQUESTER_CANCELLED,
                                          now, requester_user_id=principal.user_id):
                uow.connections.expire_overdue(now, request_id=request.id)
                uow.commit()
                raise _not_pending()
            self._audit(uow, "connection.cancelled", AuditOutcome.SUCCESS, ctx, user_id=principal.user_id,
                        subject_type="connection_request", subject_id=request.id)
            uow.commit()
            return self._request_view(uow, uow.connections.get(request.id), for_target=False)

    # ----------------------------------------------------------------- target

    def incoming(self, caller: DevicePrincipal, ctx: RequestContext) -> Incoming:
        """Pending requests for this device. Polling counts as the device's heartbeat."""
        now = self._clock.now()
        with self._uow() as uow:
            uow.devices.record_presence(caller.device_id, now, ctx.ip)
            uow.connections.expire_overdue(now, target_device_id=caller.device_id)
            uow.sessions.end_silent(self._cutoff(), now, target_device_id=caller.device_id)
            live = uow.sessions.live_for_target(caller.device_id)
            pending = [] if live else uow.connections.pending_for_target(caller.device_id, now)
            views = [self._request_view(uow, r, for_target=True) for r in pending]
            uow.commit()
            return Incoming(views, live.id if live else None)

    def _own_request(self, uow: UnitOfWork, caller: DevicePrincipal, request_id: uuid.UUID) -> ConnectionRequest:
        request = uow.connections.get(request_id)
        if request is None or request.target_device_id != caller.device_id:
            raise _request_not_found()        # the requester's own device gets 404 too
        return request

    def _refuse_decision(self, uow: UnitOfWork, request: ConnectionRequest) -> None:
        if uow.connections.expire_overdue(self._clock.now(), request_id=request.id):
            uow.commit()
            raise GoneError("This request has expired.", code="request_expired")
        raise _not_pending()

    def approve(self, caller: DevicePrincipal, request_id: uuid.UUID, permission: Permission | None,
                ctx: RequestContext) -> SessionView:
        now = self._clock.now()
        with self._uow() as uow:
            request = self._own_request(uow, caller, request_id)
            granted = permission or request.requested_permission
            if granted is Permission.VIEW_INPUT and request.requested_permission is Permission.VIEW:
                error = InputRejectedError("permission_granted", "exceeds_request",
                                           "You cannot grant more than was requested.")
                error.code = "permission_exceeds_request"
                raise error
            uow.sessions.end_silent(self._cutoff(), now, target_device_id=caller.device_id)
            if not uow.connections.decide(request.id, RequestStatus.APPROVED, DecisionReason.TARGET_APPROVED, now,
                                          target_device_id=caller.device_id):
                self._refuse_decision(uow, request)
            try:
                session = uow.sessions.add(RemoteSession(
                    connection_request_id=request.id, controller_user_id=request.requester_user_id,
                    controller_device_id=request.requester_device_id, target_device_id=request.target_device_id,
                    requested_permission=request.requested_permission, permission_granted=granted, created_at=now,
                    target_seen_at=now, last_heartbeat_at=now))
            except ConflictError as exc:
                if exc.constraint == "UX_sessions_live_target":
                    # Leaving without commit rolls the approval back: the request stays pending.
                    raise ConflictError("This computer is already in a session.", code="target_busy") from exc
                raise
            self._audit(uow, "connection.approved", AuditOutcome.SUCCESS, ctx, device_id=caller.device_id,
                        subject_type="connection_request", subject_id=request.id, permission=granted.value)
            self._audit(uow, "session.created", AuditOutcome.SUCCESS, ctx, device_id=caller.device_id,
                        subject_type="session", subject_id=session.id)
            uow.commit()
            return self._session_view(uow, uow.sessions.get(session.id), "target")

    def reject(self, caller: DevicePrincipal, request_id: uuid.UUID, block_requester: bool,
               ctx: RequestContext) -> RequestView:
        now = self._clock.now()
        with self._uow() as uow:
            request = self._own_request(uow, caller, request_id)
            if not uow.connections.decide(request.id, RequestStatus.REJECTED, DecisionReason.TARGET_REJECTED, now,
                                          target_device_id=caller.device_id):
                self._refuse_decision(uow, request)
            self._audit(uow, "connection.rejected", AuditOutcome.SUCCESS, ctx, device_id=caller.device_id,
                        subject_type="connection_request", subject_id=request.id)
            if block_requester:
                uow.connections.block(caller.device_id, request.requester_user_id)
                self._audit(uow, "device.requester_blocked", AuditOutcome.SUCCESS, ctx, device_id=caller.device_id,
                            subject_type="user", subject_id=request.requester_user_id)
            uow.commit()
            return self._request_view(uow, uow.connections.get(request.id), for_target=True)

    # --------------------------------------------------------------- sessions

    def _session_side(self, uow: UnitOfWork, session: RemoteSession, principal: Principal | None,
                      caller: DevicePrincipal | None) -> str | None:
        """Which side is asking, or None for an owner, admin or auditor. Others: not found."""
        if caller is not None and session.target_device_id == caller.device_id:
            return "target"
        if principal is not None:
            if session.controller_user_id == principal.user_id:
                return "controller"
            target = uow.devices.get(session.target_device_id)
            if (target.owner_user_id == principal.user_id or principal.has(Role.ADMIN)
                    or principal.has(Role.AUDITOR)):
                return None
        raise _session_not_found()

    def get_session(self, principal: Principal | None, caller: DevicePrincipal | None,
                    session_id: uuid.UUID) -> SessionView:
        """Reading the session is also that side's presence signal."""
        now = self._clock.now()
        with self._uow() as uow:
            session = uow.sessions.get(session_id)
            if session is None:
                raise _session_not_found()
            side = self._session_side(uow, session, principal, caller)
            if uow.sessions.end_silent(self._cutoff(), now, session_id=session.id):
                self._audit(uow, "session.ended", AuditOutcome.SUCCESS, ctx=RequestContext(),
                            subject_type="session", subject_id=session.id, reason=SessionEndReason.TIMEOUT.value)
            elif side is not None and session.state is not SessionState.ENDED:
                uow.sessions.touch(session.id, side, now)
            view = self._session_view(uow, uow.sessions.get(session.id), side)
            uow.commit()
            return view

    def terminate(self, principal: Principal | None, caller: DevicePrincipal | None, session_id: uuid.UUID,
                  ctx: RequestContext) -> SessionView:
        now = self._clock.now()
        with self._uow() as uow:
            session = uow.sessions.get(session_id)
            if session is None:
                raise _session_not_found()
            side = self._session_side(uow, session, principal, caller)
            if side == "target":
                reason, by = SessionEndReason.TARGET_DISCONNECT, {"by_device_id": caller.device_id}
            elif side == "controller":
                reason, by = SessionEndReason.CONTROLLER_DISCONNECT, {"by_user_id": principal.user_id}
            else:
                target = uow.devices.get(session.target_device_id)
                if not (target.owner_user_id == principal.user_id or principal.has(Role.ADMIN)):
                    raise PermissionDeniedError()     # auditors can look, not act
                reason, by = SessionEndReason.REVOKED, {"by_user_id": principal.user_id}
            if uow.sessions.end(session.id, reason, now, **by):
                self._audit(uow, "session.ended", AuditOutcome.SUCCESS, ctx, user_id=by.get("by_user_id"),
                            device_id=by.get("by_device_id"), subject_type="session", subject_id=session.id,
                            reason=reason.value)
            uow.commit()
            return self._session_view(uow, uow.sessions.get(session.id), side)
