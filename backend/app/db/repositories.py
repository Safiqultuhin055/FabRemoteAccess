"""SQL Server implementations of the repository interfaces in app/domain/repositories.py.

State transitions that must be race-free (consuming a refresh token, accepting or revoking
an invitation, revoking a session) are single conditional UPDATEs whose row count decides
the outcome, so two concurrent requests can never both succeed.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, delete, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.errors import translate_errors
from app.db.models import (AuditEvent, AuthSession, AuthToken, Device, DeviceAuthChallenge, DeviceKey,
                           DeviceRegistrationChallenge, RemoteIdAllocation, SchemaMigration, User, UserInvitation,
                           UserRole)
from app.domain import constants as c
from app.log import SENSITIVE_KEY


class _Repository:
    def __init__(self, session: Session):
        self._session = session

    def flush(self) -> None:
        with translate_errors():
            self._session.flush()

    def _update(self, statement) -> int:
        with translate_errors():
            return self._session.execute(statement.execution_options(synchronize_session=False)).rowcount


class SqlMigrationRepository(_Repository):
    def current_version(self) -> int | None:
        with translate_errors():
            return self._session.scalar(select(func.max(SchemaMigration.version)))


class SqlUserRepository(_Repository):
    def get(self, user_id: uuid.UUID) -> User | None:
        with translate_errors():
            return self._session.get(User, user_id)

    def get_by_email(self, email: str) -> User | None:
        with translate_errors():
            return self._session.scalar(select(User).where(User.email == email.strip().lower()))

    def add(self, user: User) -> User:
        user.email = user.email.strip().lower()
        self._session.add(user)
        self.flush()
        return user

    def roles(self, user_id: uuid.UUID) -> set[c.Role]:
        with translate_errors():
            return set(self._session.scalars(select(UserRole.role_code).where(UserRole.user_id == user_id)))

    def grant_role(self, user_id: uuid.UUID, role: c.Role, granted_by: uuid.UUID | None = None) -> None:
        self._session.add(UserRole(user_id=user_id, role_code=role, granted_by_user_id=granted_by))
        self.flush()

    def any_with_role(self, role: c.Role) -> bool:
        with translate_errors():
            return self._session.scalar(select(func.count()).select_from(UserRole).where(UserRole.role_code == role)) > 0

    def record_login_failure(self, user_id: uuid.UUID, now: datetime, threshold: int, lock_minutes: int) -> None:
        self._update(update(User).where(User.id == user_id).values(
            failed_login_count=User.failed_login_count + 1,
            locked_until=case((User.failed_login_count + 1 >= threshold, now + timedelta(minutes=lock_minutes)),
                              else_=User.locked_until)))

    def record_login_success(self, user_id: uuid.UUID, now: datetime) -> None:
        self._update(update(User).where(User.id == user_id).values(
            failed_login_count=0, locked_until=None, last_login_at=now))

    def replace_password_hash(self, user_id: uuid.UUID, password_hash: str, now: datetime) -> None:
        self._update(update(User).where(User.id == user_id).values(
            password_hash=password_hash, password_changed_at=now, updated_at=now))


class SqlInvitationRepository(_Repository):
    def add(self, invitation: UserInvitation) -> UserInvitation:
        invitation.email = invitation.email.strip().lower()
        self._session.add(invitation)
        self.flush()
        return invitation

    def get(self, invitation_id: uuid.UUID) -> UserInvitation | None:
        with translate_errors():
            return self._session.get(UserInvitation, invitation_id)

    @staticmethod
    def _open(now: datetime):
        return and_(UserInvitation.accepted_at.is_(None), UserInvitation.revoked_at.is_(None),
                    UserInvitation.expires_at > now)

    def find_open_by_token_hash(self, token_hash: bytes, now: datetime) -> UserInvitation | None:
        with translate_errors():
            return self._session.scalar(select(UserInvitation).where(
                UserInvitation.token_hash == token_hash, self._open(now)))

    def find_open_by_email(self, email: str) -> UserInvitation | None:
        """Not accepted and not revoked (expired ones still block the email until revoked)."""
        with translate_errors():
            return self._session.scalar(select(UserInvitation).where(
                UserInvitation.email == email.strip().lower(), UserInvitation.accepted_at.is_(None),
                UserInvitation.revoked_at.is_(None)))

    def find_open_bootstrap(self, now: datetime) -> UserInvitation | None:
        with translate_errors():
            return self._session.scalar(select(UserInvitation).where(
                UserInvitation.invited_by_user_id.is_(None), UserInvitation.role_code == c.Role.ADMIN,
                self._open(now)))

    def mark_accepted(self, invitation_id: uuid.UUID, user_id: uuid.UUID, now: datetime) -> bool:
        return self._update(update(UserInvitation).where(
            UserInvitation.id == invitation_id, self._open(now)).values(
            accepted_at=now, accepted_user_id=user_id)) == 1

    def revoke(self, invitation_id: uuid.UUID, now: datetime) -> bool:
        return self._update(update(UserInvitation).where(
            UserInvitation.id == invitation_id, UserInvitation.accepted_at.is_(None),
            UserInvitation.revoked_at.is_(None)).values(revoked_at=now)) == 1

    def list(self, now: datetime, *, status: str | None = None, email: str | None = None, limit: int = 50,
             after: tuple[datetime, uuid.UUID] | None = None) -> list[UserInvitation]:
        query = select(UserInvitation)
        if email:
            query = query.where(UserInvitation.email == email.strip().lower())
        if status == "open":
            query = query.where(self._open(now))
        elif status == "accepted":
            query = query.where(UserInvitation.accepted_at.is_not(None))
        elif status == "revoked":
            query = query.where(UserInvitation.revoked_at.is_not(None))
        elif status == "expired":
            query = query.where(UserInvitation.accepted_at.is_(None), UserInvitation.revoked_at.is_(None),
                                UserInvitation.expires_at <= now)
        if after:
            created, last_id = after
            query = query.where(or_(UserInvitation.created_at < created,
                                    and_(UserInvitation.created_at == created, UserInvitation.id < last_id)))
        with translate_errors():
            return list(self._session.scalars(
                query.order_by(UserInvitation.created_at.desc(), UserInvitation.id.desc()).limit(limit)))

    def lock_bootstrap(self) -> None:
        """Serialise bootstrap attempts for the rest of the transaction (sp_getapplock)."""
        with translate_errors():
            result = self._session.execute(text(
                "DECLARE @r INT; EXEC @r = sp_getapplock @Resource = N'fr.bootstrap_admin', "
                "@LockMode = N'Exclusive', @LockOwner = N'Transaction', @LockTimeout = 10000; SELECT @r")).scalar()
        if result is None or result < 0:
            raise RuntimeError("Could not acquire the bootstrap lock")


class SqlAuthSessionRepository(_Repository):
    def add(self, auth_session: AuthSession) -> AuthSession:
        self._session.add(auth_session)
        self.flush()
        return auth_session

    def get(self, auth_session_id: uuid.UUID) -> AuthSession | None:
        with translate_errors():
            return self._session.get(AuthSession, auth_session_id)

    def revoke(self, auth_session_id: uuid.UUID, reason: c.AuthSessionRevokedReason, now: datetime) -> bool:
        """Revoke the session and every token in it. Returns False if it was already revoked."""
        changed = self._update(update(AuthSession).where(
            AuthSession.id == auth_session_id, AuthSession.revoked_at.is_(None)).values(
            revoked_at=now, revoked_reason=reason))
        self._update(update(AuthToken).where(
            AuthToken.auth_session_id == auth_session_id, AuthToken.revoked_at.is_(None)).values(revoked_at=now))
        return changed == 1

    def touch(self, auth_session_id: uuid.UUID, now: datetime) -> None:
        self._update(update(AuthSession).where(AuthSession.id == auth_session_id).values(last_used_at=now))

    def bind_device(self, auth_session_id: uuid.UUID, device_id: uuid.UUID) -> None:
        self._update(update(AuthSession).where(AuthSession.id == auth_session_id).values(device_id=device_id))

    def revoke_for_device(self, device_id: uuid.UUID, now: datetime) -> int:
        ids = list(self._session.scalars(select(AuthSession.id).where(
            AuthSession.device_id == device_id, AuthSession.revoked_at.is_(None))))
        for auth_session_id in ids:
            self.revoke(auth_session_id, c.AuthSessionRevokedReason.DEVICE_REVOKED, now)
        return len(ids)


class SqlAuthTokenRepository(_Repository):
    def add(self, token: AuthToken) -> AuthToken:
        self._session.add(token)
        self.flush()
        return token

    def find_by_hash(self, token_hash: bytes) -> AuthToken | None:
        with translate_errors():
            return self._session.scalar(select(AuthToken).where(AuthToken.token_hash == token_hash))

    def consume(self, token_id: uuid.UUID, now: datetime) -> bool:
        """Atomically mark a live token as used. Exactly one concurrent caller can win."""
        return self._update(update(AuthToken).where(
            AuthToken.id == token_id, AuthToken.consumed_at.is_(None), AuthToken.revoked_at.is_(None),
            AuthToken.expires_at > now).values(consumed_at=now)) == 1


class SqlDeviceRepository(_Repository):
    def lock_owner(self, owner_user_id: uuid.UUID) -> None:
        """Serialise registrations per user for the rest of the transaction (device limit)."""
        with translate_errors():
            result = self._session.execute(text(
                "DECLARE @r INT; EXEC @r = sp_getapplock @Resource = :resource, @LockMode = N'Exclusive', "
                "@LockOwner = N'Transaction', @LockTimeout = 10000; SELECT @r"),
                {"resource": f"fr.device_owner:{owner_user_id}"}).scalar()
        if result is None or result < 0:
            raise RuntimeError("Could not acquire the device registration lock")

    def reserve_remote_id(self, remote_id: str) -> bool:
        """Permanently allocate a Remote ID. False if it was ever issued before (never reused)."""
        try:
            with self._session.begin_nested():          # savepoint: a collision keeps the transaction
                self._session.add(RemoteIdAllocation(remote_id=remote_id))
                self._session.flush()
        except IntegrityError:
            return False
        return True

    def add(self, device: Device, public_key: bytes, algorithm: c.KeyAlgorithm = c.KeyAlgorithm.ED25519) -> DeviceKey:
        if algorithm is c.KeyAlgorithm.ED25519 and len(public_key) != c.ED25519_PUBLIC_KEY_BYTES:
            raise ValueError("Ed25519 public keys are 32 bytes")
        self._session.add(device)
        self.flush()  # obtain device.id before inserting the key
        key = DeviceKey(device_id=device.id, algorithm=algorithm, public_key=public_key)
        self._session.add(key)
        self.flush()
        return key

    def get(self, device_id: uuid.UUID) -> Device | None:
        with translate_errors():
            return self._session.get(Device, device_id)

    def get_by_remote_id(self, remote_id: str) -> Device | None:
        with translate_errors():
            return self._session.scalar(select(Device).where(Device.remote_id == remote_id))

    def list_for_owner(self, owner_user_id: uuid.UUID, *, status: c.DeviceStatus | None = None,
                       limit: int = 50) -> list[Device]:
        query = select(Device).where(Device.owner_user_id == owner_user_id)
        if status is not None:
            query = query.where(Device.status == status)
        with translate_errors():
            return list(self._session.scalars(query.order_by(Device.created_at.desc(), Device.id).limit(limit)))

    def count_active_for_owner(self, owner_user_id: uuid.UUID) -> int:
        with translate_errors():
            return self._session.scalar(select(func.count()).select_from(Device).where(
                Device.owner_user_id == owner_user_id, Device.status == c.DeviceStatus.ACTIVE))

    def active_key(self, device_id: uuid.UUID) -> DeviceKey | None:
        with translate_errors():
            return self._session.scalar(select(DeviceKey).where(
                DeviceKey.device_id == device_id, DeviceKey.revoked_at.is_(None)))

    def active_keys_for(self, device_ids: list[uuid.UUID]) -> dict[uuid.UUID, DeviceKey]:
        if not device_ids:
            return {}
        with translate_errors():
            keys = self._session.scalars(select(DeviceKey).where(
                DeviceKey.device_id.in_(device_ids), DeviceKey.revoked_at.is_(None)))
            return {k.device_id: k for k in keys}

    def find_key_by_fingerprint(self, fingerprint: bytes) -> DeviceKey | None:
        with translate_errors():
            return self._session.scalar(select(DeviceKey).where(DeviceKey.fingerprint == fingerprint))

    def add_key(self, device_id: uuid.UUID, public_key: bytes,
                algorithm: c.KeyAlgorithm = c.KeyAlgorithm.ED25519) -> DeviceKey:
        key = DeviceKey(device_id=device_id, algorithm=algorithm, public_key=public_key)
        self._session.add(key)
        self.flush()
        return key

    def revoke_keys(self, device_id: uuid.UUID, reason: c.KeyRevokedReason, now: datetime) -> int:
        return self._update(update(DeviceKey).where(
            DeviceKey.device_id == device_id, DeviceKey.revoked_at.is_(None)).values(
            revoked_at=now, revoked_reason=reason))

    def revoke(self, device_id: uuid.UUID, reason: c.DeviceRevokedReason, by_user_id: uuid.UUID,
               now: datetime) -> bool:
        return self._update(update(Device).where(
            Device.id == device_id, Device.status == c.DeviceStatus.ACTIVE).values(
            status=c.DeviceStatus.REVOKED, revoked_at=now, revoked_reason=reason, revoked_by_user_id=by_user_id,
            updated_at=now)) == 1

    def record_presence(self, device_id: uuid.UUID, now: datetime, ip: str | None) -> None:
        values = {"last_seen_at": now}
        if ip:
            values.update(last_ip=ip[:45], last_ip_at=now)
        self._update(update(Device).where(Device.id == device_id, Device.status == c.DeviceStatus.ACTIVE)
                     .values(**values))


class SqlDeviceChallengeRepository(_Repository):
    """Registration challenges (V0008) and per-device challenges for presence and key rotation."""

    def add_registration(self, challenge: DeviceRegistrationChallenge) -> DeviceRegistrationChallenge:
        self._session.add(challenge)
        self.flush()
        return challenge

    def consume_registration(self, challenge_id: uuid.UUID, user_id: uuid.UUID,
                             now: datetime) -> DeviceRegistrationChallenge | None:
        """Atomically use a live challenge of this user. Exactly one concurrent caller gets it."""
        won = self._update(update(DeviceRegistrationChallenge).where(
            DeviceRegistrationChallenge.id == challenge_id, DeviceRegistrationChallenge.user_id == user_id,
            DeviceRegistrationChallenge.consumed_at.is_(None),
            DeviceRegistrationChallenge.expires_at > now).values(consumed_at=now)) == 1
        if not won:
            return None
        with translate_errors():
            return self._session.scalar(select(DeviceRegistrationChallenge).where(
                DeviceRegistrationChallenge.id == challenge_id).execution_options(populate_existing=True))

    def purge_registration(self, user_id: uuid.UUID, before: datetime) -> int:
        with translate_errors():
            return self._session.execute(delete(DeviceRegistrationChallenge).where(
                DeviceRegistrationChallenge.user_id == user_id,
                or_(DeviceRegistrationChallenge.expires_at < before,
                    DeviceRegistrationChallenge.consumed_at < before)).execution_options(
                synchronize_session=False)).rowcount

    def add_device(self, challenge: DeviceAuthChallenge) -> DeviceAuthChallenge:
        self._session.add(challenge)
        self.flush()
        return challenge

    def consume_device(self, challenge_id: uuid.UUID, device_id: uuid.UUID, now: datetime) -> DeviceAuthChallenge | None:
        won = self._update(update(DeviceAuthChallenge).where(
            DeviceAuthChallenge.id == challenge_id, DeviceAuthChallenge.device_id == device_id,
            DeviceAuthChallenge.used_at.is_(None), DeviceAuthChallenge.expires_at > now).values(used_at=now)) == 1
        if not won:
            return None
        with translate_errors():
            return self._session.scalar(select(DeviceAuthChallenge).where(
                DeviceAuthChallenge.id == challenge_id).execution_options(populate_existing=True))


class SqlAuditRepository(_Repository):
    _EVENT_TYPE = re.compile(c.AUDIT_EVENT_TYPE_PATTERN)

    def add(self, event_type: str, outcome: c.AuditOutcome, *, actor_user_id: uuid.UUID | None = None,
            actor_device_id: uuid.UUID | None = None, subject_type: str | None = None,
            subject_id: str | None = None, ip_address: str | None = None, request_id: str | None = None,
            details: Mapping[str, Any] | None = None) -> AuditEvent:
        if not self._EVENT_TYPE.fullmatch(event_type) or len(event_type) > c.EVENT_TYPE_MAX_LENGTH:
            raise ValueError(f"Invalid audit event type: {event_type!r}")
        encoded = None
        if details:
            # Defence in depth: services build details from allow-lists; secrets never belong here.
            leaked = [k for k in details if SENSITIVE_KEY.search(str(k))]
            if leaked:
                raise ValueError(f"Audit details must not contain sensitive keys: {sorted(leaked)}")
            encoded = json.dumps(details, sort_keys=True, separators=(",", ":"), default=str)
            if len(encoded) > c.AUDIT_DETAILS_MAX_LENGTH:
                raise ValueError("Audit details exceed the maximum length")
        event = AuditEvent(event_type=event_type, outcome=outcome, actor_user_id=actor_user_id,
                           actor_device_id=actor_device_id, subject_type=subject_type, subject_id=subject_id,
                           ip_address=ip_address, request_id=request_id, details=encoded)
        self._session.add(event)
        self.flush()
        return event

    def list_between(self, start: datetime, end: datetime, *, limit: int = 50) -> list[AuditEvent]:
        with translate_errors():
            return list(self._session.scalars(
                select(AuditEvent).where(AuditEvent.occurred_at >= start, AuditEvent.occurred_at < end)
                .order_by(AuditEvent.id.desc()).limit(limit)))
