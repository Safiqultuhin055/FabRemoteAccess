"""ORM mapping of the draft `fr` schema (database/migrations V0001-V0008).

The SQL migrations are the source of truth; these models never create or alter tables.
backend/tests/integration/test_model_drift.py compares them with a migrated database.

Conventions: server-generated values (NEWSEQUENTIALID keys, SYSUTCDATETIME defaults,
computed columns, ROWVERSION) are marked FetchedValue/Computed and read back on insert
(eager_defaults). Tables with `row_version` use it for optimistic concurrency.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (BigInteger, Computed, FetchedValue, ForeignKey, Identity, Integer, MetaData, String,
                        Unicode, Uuid)
from sqlalchemy.dialects.mssql import BINARY, BIT, CHAR, ROWVERSION, VARBINARY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.db.column_types import UTCDateTime, str_enum
from app.domain import constants as c

SCHEMA = "fr"


class Base(DeclarativeBase):
    metadata = MetaData(schema=SCHEMA)
    __mapper_args__ = {"eager_defaults": True}


def _pk() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid, primary_key=True, server_default=FetchedValue())


def _created() -> Mapped[datetime]:
    return mapped_column(UTCDateTime, nullable=False, server_default=FetchedValue())


def _row_version() -> Mapped[bytes]:
    return mapped_column(ROWVERSION, nullable=False, server_default=FetchedValue(), server_onupdate=FetchedValue())


def _versioning(row_version) -> dict:
    """Optimistic concurrency on the server-maintained ROWVERSION column."""
    return {"eager_defaults": True, "version_id_col": row_version, "version_id_generator": False}


class SchemaMigration(Base):
    __tablename__ = "schema_migrations"
    version: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    description: Mapped[str] = mapped_column(Unicode(200))
    applied_at: Mapped[datetime] = _created()
    applied_by: Mapped[str] = mapped_column(Unicode(128), server_default=FetchedValue())


class RoleRow(Base):
    __tablename__ = "roles"
    code: Mapped[c.Role] = mapped_column(str_enum(c.Role, 32), primary_key=True)
    description: Mapped[str] = mapped_column(Unicode(200))


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = _pk()
    email: Mapped[str] = mapped_column(Unicode(c.EMAIL_MAX_LENGTH))
    display_name: Mapped[str] = mapped_column(Unicode(c.DISPLAY_NAME_MAX_LENGTH))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    password_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    email_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[c.UserStatus] = mapped_column(str_enum(c.UserStatus, 16), server_default=FetchedValue())
    failed_login_count: Mapped[int] = mapped_column(Integer, server_default=FetchedValue())
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _created()
    row_version: Mapped[bytes] = _row_version()
    __mapper_args__ = _versioning(row_version)


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.users.id"), primary_key=True)
    role_code: Mapped[c.Role] = mapped_column(str_enum(c.Role, 32), ForeignKey("fr.roles.code"), primary_key=True)
    granted_at: Mapped[datetime] = _created()
    granted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("fr.users.id"))


class UserInvitation(Base):
    __tablename__ = "user_invitations"
    id: Mapped[uuid.UUID] = _pk()
    email: Mapped[str] = mapped_column(Unicode(c.EMAIL_MAX_LENGTH))
    role_code: Mapped[c.Role] = mapped_column(str_enum(c.Role, 32), ForeignKey("fr.roles.code"),
                                              server_default=FetchedValue())
    token_hash: Mapped[bytes] = mapped_column(BINARY(32))
    invited_by_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("fr.users.id"))
    created_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    accepted_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    accepted_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("fr.users.id"))
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[uuid.UUID] = _pk()
    owner_user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.users.id"))
    remote_id: Mapped[str] = mapped_column(CHAR(9), ForeignKey("fr.remote_id_registry.remote_id"))
    display_name: Mapped[str] = mapped_column(Unicode(c.DISPLAY_NAME_MAX_LENGTH))
    os_name: Mapped[str | None] = mapped_column(Unicode(c.OS_NAME_MAX_LENGTH))
    os_version: Mapped[str | None] = mapped_column(Unicode(c.OS_VERSION_MAX_LENGTH))
    client_version: Mapped[str | None] = mapped_column(String(c.CLIENT_VERSION_MAX_LENGTH))
    incoming_policy: Mapped[c.IncomingPolicy] = mapped_column(str_enum(c.IncomingPolicy, 24),
                                                              server_default=FetchedValue())
    status: Mapped[c.DeviceStatus] = mapped_column(str_enum(c.DeviceStatus, 16), server_default=FetchedValue())
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _created()
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_ip: Mapped[str | None] = mapped_column(String(45))
    last_ip_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("fr.users.id"))
    revoked_reason: Mapped[c.DeviceRevokedReason | None] = mapped_column(str_enum(c.DeviceRevokedReason, 32))
    row_version: Mapped[bytes] = _row_version()
    __mapper_args__ = _versioning(row_version)


class DeviceKey(Base):
    __tablename__ = "device_keys"
    id: Mapped[uuid.UUID] = _pk()
    device_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.devices.id"))
    algorithm: Mapped[c.KeyAlgorithm] = mapped_column(str_enum(c.KeyAlgorithm, 16), server_default=FetchedValue())
    public_key: Mapped[bytes] = mapped_column(VARBINARY(64))
    fingerprint: Mapped[bytes] = mapped_column(
        BINARY(32), Computed("CAST(HASHBYTES('SHA2_256', public_key) AS BINARY(32))", persisted=True))
    created_at: Mapped[datetime] = _created()
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_reason: Mapped[c.KeyRevokedReason | None] = mapped_column(str_enum(c.KeyRevokedReason, 32))


class RemoteIdAllocation(Base):
    """Permanent record of every Remote ID ever issued (V0008). Insert-only for the application."""
    __tablename__ = "remote_id_registry"
    remote_id: Mapped[str] = mapped_column(CHAR(9), primary_key=True)
    allocated_at: Mapped[datetime] = _created()


class DeviceRegistrationChallenge(Base):
    """Single-use registration attempt bound to user, auth session and proposed public key (V0008)."""
    __tablename__ = "device_registration_challenges"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.users.id"))
    auth_session_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.auth_sessions.id"))
    algorithm: Mapped[c.KeyAlgorithm] = mapped_column(str_enum(c.KeyAlgorithm, 16), server_default=FetchedValue())
    public_key: Mapped[bytes] = mapped_column(VARBINARY(64))
    key_fingerprint: Mapped[bytes] = mapped_column(
        BINARY(32), Computed("CAST(HASHBYTES('SHA2_256', public_key) AS BINARY(32))", persisted=True))
    device_name: Mapped[str] = mapped_column(Unicode(c.DISPLAY_NAME_MAX_LENGTH))
    os_name: Mapped[str | None] = mapped_column(Unicode(c.OS_NAME_MAX_LENGTH))
    os_version: Mapped[str | None] = mapped_column(Unicode(c.OS_VERSION_MAX_LENGTH))
    client_version: Mapped[str | None] = mapped_column(String(c.CLIENT_VERSION_MAX_LENGTH))
    nonce: Mapped[bytes] = mapped_column(BINARY(32))
    created_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class DeviceAuthChallenge(Base):
    __tablename__ = "device_auth_challenges"
    id: Mapped[uuid.UUID] = _pk()
    device_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.devices.id"))
    nonce: Mapped[bytes] = mapped_column(BINARY(32))
    created_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.users.id"))
    client_type: Mapped[c.ClientType] = mapped_column(str_enum(c.ClientType, 16))
    device_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("fr.devices.id"))
    created_at: Mapped[datetime] = _created()
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_reason: Mapped[c.AuthSessionRevokedReason | None] = mapped_column(str_enum(c.AuthSessionRevokedReason, 32))
    user_agent: Mapped[str | None] = mapped_column(Unicode(c.USER_AGENT_MAX_LENGTH))
    created_ip: Mapped[str | None] = mapped_column(String(45))
    row_version: Mapped[bytes] = _row_version()
    __mapper_args__ = _versioning(row_version)


class AuthToken(Base):
    __tablename__ = "auth_tokens"
    id: Mapped[uuid.UUID] = _pk()
    auth_session_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.auth_sessions.id"))
    token_type: Mapped[c.TokenType] = mapped_column(str_enum(c.TokenType, 16))
    token_hash: Mapped[bytes] = mapped_column(BINARY(32))
    issued_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class BlockedRequester(Base):
    __tablename__ = "blocked_requesters"
    target_device_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.devices.id"), primary_key=True)
    blocked_user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.users.id"), primary_key=True)
    created_at: Mapped[datetime] = _created()


class ConnectionRequest(Base):
    __tablename__ = "connection_requests"
    id: Mapped[uuid.UUID] = _pk()
    requester_user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.users.id"))
    requester_device_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.devices.id"))
    target_device_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.devices.id"))
    requested_permission: Mapped[c.Permission] = mapped_column(str_enum(c.Permission, 16),
                                                               server_default=FetchedValue())
    status: Mapped[c.RequestStatus] = mapped_column(str_enum(c.RequestStatus, 16), server_default=FetchedValue())
    created_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    decision_reason: Mapped[c.DecisionReason | None] = mapped_column(str_enum(c.DecisionReason, 32))
    requester_ip: Mapped[str | None] = mapped_column(String(45))
    approved_flag: Mapped[bool | None] = mapped_column(
        BIT, Computed("CAST(CASE WHEN status = 'approved' THEN 1 END AS BIT)", persisted=True))
    row_version: Mapped[bytes] = _row_version()
    __mapper_args__ = _versioning(row_version)


class RemoteSession(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = _pk()
    connection_request_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.connection_requests.id"))
    controller_user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.users.id"))
    controller_device_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.devices.id"))
    target_device_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.devices.id"))
    requested_permission: Mapped[c.Permission] = mapped_column(str_enum(c.Permission, 16))
    permission_granted: Mapped[c.Permission] = mapped_column(str_enum(c.Permission, 16))
    request_approved: Mapped[bool] = mapped_column(BIT, Computed("CAST(1 AS BIT)", persisted=True))
    state: Mapped[c.SessionState] = mapped_column(str_enum(c.SessionState, 16), server_default=FetchedValue())
    created_at: Mapped[datetime] = _created()
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    end_reason: Mapped[c.SessionEndReason | None] = mapped_column(str_enum(c.SessionEndReason, 32))
    ended_by_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("fr.users.id"))
    ended_by_device_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("fr.devices.id"))
    row_version: Mapped[bytes] = _row_version()
    __mapper_args__ = _versioning(row_version)


class AddressBookEntry(Base):
    __tablename__ = "address_book_entries"
    id: Mapped[uuid.UUID] = _pk()
    owner_user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("fr.users.id"))
    remote_id: Mapped[str] = mapped_column(CHAR(9))
    alias: Mapped[str | None] = mapped_column(Unicode(c.ALIAS_MAX_LENGTH))
    notes: Mapped[str | None] = mapped_column(Unicode(c.NOTES_MAX_LENGTH))
    is_favorite: Mapped[bool] = mapped_column(BIT, server_default=FetchedValue())
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _created()
    row_version: Mapped[bytes] = _row_version()
    __mapper_args__ = _versioning(row_version)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    occurred_at: Mapped[datetime] = _created()
    event_type: Mapped[str] = mapped_column(String(c.EVENT_TYPE_MAX_LENGTH))
    outcome: Mapped[c.AuditOutcome] = mapped_column(str_enum(c.AuditOutcome, 16))
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_device_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    subject_type: Mapped[str | None] = mapped_column(String(32))
    subject_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    request_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[str | None] = mapped_column(Unicode(c.AUDIT_DETAILS_MAX_LENGTH))
