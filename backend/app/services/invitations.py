"""Admin invitations (the only way to create accounts in the pilot) and the bootstrap invitation.

- Invitation tokens are 256-bit random values; only their SHA-256 is stored and the token
  is returned exactly once.
- Acceptance is single use: the invitation is marked accepted with a conditional update in
  the same transaction that creates the user, so concurrent attempts cannot both succeed.
- Only administrators can invite; the role on an invitation is the only role granted
  (plus `user`). Bootstrap works only while no administrator exists and no other
  bootstrap invitation is open, serialised by an application lock.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.db.models import User, UserInvitation
from app.domain.constants import AuditOutcome, Role, UserStatus
from app.domain.errors import ConflictError, InputRejectedError, NotFoundError, PermissionDeniedError
from app.domain.repositories import UnitOfWorkFactory
from app.security.clock import Clock
from app.security.passwords import PasswordHasher, password_policy_issue
from app.security.tokens import hash_token, new_opaque_token
from app.services.context import Principal, RequestContext

INVITATION_STATUSES = ("open", "accepted", "revoked", "expired")


def invitation_status(invitation: UserInvitation, now: datetime) -> str:
    if invitation.accepted_at is not None:
        return "accepted"
    if invitation.revoked_at is not None:
        return "revoked"
    return "open" if invitation.expires_at > now else "expired"


@dataclass(frozen=True)
class IssuedInvitation:
    invitation: UserInvitation
    token: str      # shown once, never stored


def _invalid_invitation() -> NotFoundError:
    return NotFoundError("The invitation is invalid, expired or already used.", code="invitation_invalid")


class InvitationService:
    def __init__(self, uow_factory: UnitOfWorkFactory, hasher: PasswordHasher, clock: Clock):
        self._uow = uow_factory
        self._hasher = hasher
        self._clock = clock

    def _require_admin(self, principal: Principal) -> None:
        if not principal.has(Role.ADMIN):
            raise PermissionDeniedError()

    def _issue(self, uow, email: str, role: Role, expires_in: timedelta, invited_by: uuid.UUID | None,
               ) -> IssuedInvitation:
        now = self._clock.now()
        email = email.strip().lower()
        if uow.users.get_by_email(email) is not None:
            raise ConflictError("An account with this email already exists.", code="account_exists")
        if uow.invitations.find_open_by_email(email) is not None:
            raise ConflictError("An open invitation for this email already exists.", code="invitation_exists")
        token = new_opaque_token()
        try:
            invitation = uow.invitations.add(UserInvitation(
                email=email, role_code=role, token_hash=hash_token(token), invited_by_user_id=invited_by,
                created_at=now, expires_at=now + expires_in))
        except ConflictError as exc:
            if exc.constraint == "UX_user_invitations_open_email":
                raise ConflictError("An open invitation for this email already exists.",
                                    code="invitation_exists") from exc
            raise
        return IssuedInvitation(invitation, token)

    def create(self, admin: Principal, email: str, role: Role, expires_in_hours: int,
               ctx: RequestContext) -> IssuedInvitation:
        self._require_admin(admin)
        with self._uow() as uow:
            issued = self._issue(uow, email, role, timedelta(hours=expires_in_hours), admin.user_id)
            uow.audit.add("admin.invitation_created", AuditOutcome.SUCCESS, actor_user_id=admin.user_id,
                          subject_type="invitation", subject_id=str(issued.invitation.id), ip_address=ctx.ip,
                          request_id=ctx.request_id, details={"role": role.value})
            uow.commit()
        return issued

    def bootstrap(self, email: str, expires_in_hours: int, ctx: RequestContext) -> IssuedInvitation:
        now = self._clock.now()
        with self._uow() as uow:
            uow.invitations.lock_bootstrap()
            if uow.users.any_with_role(Role.ADMIN):
                raise ConflictError("An administrator already exists; use an admin invitation instead.",
                                    code="admin_exists")
            if uow.invitations.find_open_bootstrap(now) is not None:
                raise ConflictError("A bootstrap invitation is already open; accept or revoke it first.",
                                    code="bootstrap_pending")
            issued = self._issue(uow, email, Role.ADMIN, timedelta(hours=expires_in_hours), None)
            uow.audit.add("admin.bootstrap_invitation", AuditOutcome.SUCCESS, subject_type="invitation",
                          subject_id=str(issued.invitation.id), ip_address=ctx.ip, request_id=ctx.request_id)
            uow.commit()
        return issued

    def list(self, admin: Principal, *, status: str | None, email: str | None, limit: int,
             after: tuple[datetime, uuid.UUID] | None) -> list[UserInvitation]:
        self._require_admin(admin)
        with self._uow() as uow:
            return uow.invitations.list(self._clock.now(), status=status, email=email, limit=limit, after=after)

    def revoke(self, admin: Principal, invitation_id: uuid.UUID, ctx: RequestContext) -> UserInvitation:
        self._require_admin(admin)
        now = self._clock.now()
        with self._uow() as uow:
            invitation = uow.invitations.get(invitation_id)
            if invitation is None:
                raise NotFoundError()
            if not uow.invitations.revoke(invitation_id, now):
                raise ConflictError("Only open invitations can be revoked.", code="conflict")
            invitation.revoked_at = now
            uow.audit.add("admin.invitation_revoked", AuditOutcome.SUCCESS, actor_user_id=admin.user_id,
                          subject_type="invitation", subject_id=str(invitation_id), ip_address=ctx.ip,
                          request_id=ctx.request_id)
            uow.commit()
            return invitation

    def accept(self, token: str, display_name: str, password: str, ctx: RequestContext) -> tuple[User, frozenset[Role]]:
        now = self._clock.now()
        with self._uow() as uow:
            invitation = uow.invitations.find_open_by_token_hash(hash_token(token), now)
            # A stale bootstrap invitation must never create a second administrator.
            if invitation is not None and invitation.invited_by_user_id is None and uow.users.any_with_role(Role.ADMIN):
                invitation = None
            if invitation is None:
                uow.audit.add("user.invitation_accepted", AuditOutcome.FAILURE, ip_address=ctx.ip,
                              request_id=ctx.request_id, details={"reason": "invalid"})
                uow.commit()
                raise _invalid_invitation()
            issue = password_policy_issue(password, invitation.email)
            if issue:
                raise InputRejectedError("password", issue, "The password does not meet the policy.")
            if uow.users.get_by_email(invitation.email) is not None:
                raise ConflictError("An account with this email already exists.", code="account_exists")
            try:
                user = uow.users.add(User(email=invitation.email, display_name=display_name.strip(),
                                          password_hash=self._hasher.hash(password), status=UserStatus.ACTIVE,
                                          email_verified_at=now, password_changed_at=now))
            except ConflictError as exc:
                if exc.constraint == "UQ_users_email":
                    raise ConflictError("An account with this email already exists.", code="account_exists") from exc
                raise
            roles = {Role.USER, invitation.role_code}
            for role in sorted(roles):
                uow.users.grant_role(user.id, role, invitation.invited_by_user_id)
            if not uow.invitations.mark_accepted(invitation.id, user.id, now):
                raise _invalid_invitation()   # lost a race: everything above rolls back
            uow.audit.add("user.invitation_accepted", AuditOutcome.SUCCESS, actor_user_id=user.id,
                          subject_type="invitation", subject_id=str(invitation.id), ip_address=ctx.ip,
                          request_id=ctx.request_id, details={"role": invitation.role_code.value})
            uow.commit()
            return user, frozenset(roles)
