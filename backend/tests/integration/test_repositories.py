"""Repositories and unit-of-work conventions, running as the least-privilege runtime role."""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import StatementError

from app.db.models import Device, User, UserInvitation
from app.domain import constants as c
from app.domain.errors import ConcurrencyError, ConflictError

HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"


def unique_email() -> str:
    return f"User.{uuid.uuid4().hex[:10]}@Example.com"


def unique_remote_id() -> str:
    return str(100_000_000 + int.from_bytes(os.urandom(4), "big") % 899_999_999)


def create_user(db, **fields) -> User:
    with db.unit_of_work() as uow:
        user = uow.users.add(User(email=fields.pop("email", unique_email()), display_name="Test",
                                  password_hash=HASH, status=c.UserStatus.ACTIVE, **fields))
        uow.commit()
    return user


def create_device(db, owner_id, remote_id=None, key=None) -> tuple[Device, bytes]:
    key = key or os.urandom(32)
    with db.unit_of_work() as uow:
        remote_id = remote_id or unique_remote_id()
        uow.devices.reserve_remote_id(remote_id)   # may already exist (duplicate test): registry is shared
        device = Device(owner_user_id=owner_id, remote_id=remote_id, display_name="PC")
        uow.devices.add(device, key)
        uow.commit()
    return device, key


def test_migration_version(runtime_db):
    with runtime_db.unit_of_work() as uow:
        assert uow.migrations.current_version() == 9


def test_user_add_normalises_email_and_reads_server_defaults(runtime_db):
    email = unique_email()
    user = create_user(runtime_db, email=email)
    assert user.email == email.lower()
    assert isinstance(user.id, uuid.UUID) and user.created_at.tzinfo is UTC
    assert user.failed_login_count == 0 and user.row_version
    with runtime_db.unit_of_work() as uow:
        assert uow.users.get_by_email(email.upper()).id == user.id
        assert uow.users.get(uuid.uuid4()) is None


def test_roles(runtime_db):
    admin = create_user(runtime_db)
    user = create_user(runtime_db)
    with runtime_db.unit_of_work() as uow:
        uow.users.grant_role(user.id, c.Role.USER)
        uow.users.grant_role(user.id, c.Role.AUDITOR, granted_by=admin.id)
        uow.commit()
    with runtime_db.unit_of_work() as uow:
        assert uow.users.roles(user.id) == {c.Role.USER, c.Role.AUDITOR}


def test_duplicate_email_is_a_conflict_with_constraint_name(runtime_db):
    email = unique_email()
    create_user(runtime_db, email=email)
    with pytest.raises(ConflictError) as info:
        create_user(runtime_db, email=email)
    assert info.value.constraint == "UQ_users_email"


def test_nothing_persists_without_commit_or_after_an_error(runtime_db):
    email = unique_email()
    with runtime_db.unit_of_work() as uow:
        uow.users.add(User(email=email, display_name="Ghost"))
        # no commit
    with pytest.raises(RuntimeError):
        with runtime_db.unit_of_work() as uow:
            uow.users.add(User(email=email, display_name="Ghost"))
            raise RuntimeError("service failure after flush")
    with runtime_db.unit_of_work() as uow:
        assert uow.users.get_by_email(email) is None


def test_conflict_inside_unit_of_work_rolls_back_earlier_changes(runtime_db):
    taken = create_user(runtime_db).email
    fresh = unique_email()
    with pytest.raises(ConflictError):
        with runtime_db.unit_of_work() as uow:
            uow.users.add(User(email=fresh, display_name="First"))
            uow.users.add(User(email=taken, display_name="Duplicate"))
            uow.commit()
    with runtime_db.unit_of_work() as uow:
        assert uow.users.get_by_email(fresh) is None


def test_invitations(runtime_db):
    token_hash = hashlib.sha256(os.urandom(32)).digest()
    now = datetime.now(UTC)
    with runtime_db.unit_of_work() as uow:
        invitation = uow.invitations.add(UserInvitation(email=unique_email(), token_hash=token_hash,
                                                        expires_at=now + timedelta(days=3)))
        uow.commit()
    assert invitation.role_code is c.Role.USER  # server default read back
    with runtime_db.unit_of_work() as uow:
        assert uow.invitations.find_open_by_token_hash(token_hash, now).id == invitation.id
        assert uow.invitations.find_open_by_token_hash(token_hash, now + timedelta(days=4)) is None
        assert uow.invitations.find_open_by_email(invitation.email.upper()).id == invitation.id


def test_device_registration_with_key(runtime_db):
    owner = create_user(runtime_db)
    device, key = create_device(runtime_db, owner.id)
    assert device.status is c.DeviceStatus.ACTIVE and device.incoming_policy is c.IncomingPolicy.VERIFIED_USERS
    with runtime_db.unit_of_work() as uow:
        active = uow.devices.active_key(device.id)
        assert bytes(active.fingerprint) == hashlib.sha256(key).digest()
        assert uow.devices.get_by_remote_id(device.remote_id).id == device.id
        assert uow.devices.count_active_for_owner(owner.id) == 1
        assert [d.id for d in uow.devices.list_for_owner(owner.id, status=c.DeviceStatus.ACTIVE)] == [device.id]


def test_duplicate_remote_id_and_duplicate_key_are_conflicts(runtime_db):
    owner = create_user(runtime_db)
    device, key = create_device(runtime_db, owner.id)
    with pytest.raises(ConflictError) as remote:
        create_device(runtime_db, owner.id, remote_id=device.remote_id)
    assert remote.value.constraint == "UQ_devices_remote_id"
    with pytest.raises(ConflictError) as dup_key:
        create_device(runtime_db, owner.id, key=key)
    assert dup_key.value.constraint == "UQ_device_keys_fingerprint"


def test_invalid_key_length_rejected_before_database(runtime_db):
    owner = create_user(runtime_db)
    with pytest.raises(ValueError):
        with runtime_db.unit_of_work() as uow:
            uow.devices.add(Device(owner_user_id=owner.id, remote_id=unique_remote_id(), display_name="PC"),
                            os.urandom(31))


def test_optimistic_concurrency_on_row_version(runtime_db):
    owner = create_user(runtime_db)
    device, _ = create_device(runtime_db, owner.id)
    first, second = runtime_db.unit_of_work(), runtime_db.unit_of_work()
    with first, second:
        a = first.devices.get(device.id)
        b = second.devices.get(device.id)
        a.display_name = "Renamed by A"
        first.commit()
        b.display_name = "Renamed by B"
        with pytest.raises(ConcurrencyError):
            second.commit()
    with runtime_db.unit_of_work() as uow:
        assert uow.devices.get(device.id).display_name == "Renamed by A"


def test_audit_events(runtime_db):
    actor = create_user(runtime_db)
    start = datetime.now(UTC) - timedelta(seconds=5)
    with runtime_db.unit_of_work() as uow:
        event = uow.audit.add("device.registered", c.AuditOutcome.SUCCESS, actor_user_id=actor.id,
                              subject_type="device", subject_id="abc", request_id="req-1",
                              details={"remote_id": "123456789", "os": "Windows"})
        uow.commit()
    assert isinstance(event.id, int) and event.details == '{"os":"Windows","remote_id":"123456789"}'
    with runtime_db.unit_of_work() as uow:
        assert event.id in [e.id for e in uow.audit.list_between(start, datetime.now(UTC) + timedelta(seconds=5))]


@pytest.mark.parametrize("event_type, details", [
    ("Auth.Login", None),
    ("auth login", None),
    ("auth.login", {"password": "x"}),
    ("auth.login", {"refresh_token": "x"}),
    ("auth.login", {"note": "x" * 3000}),
])
def test_audit_rejects_invalid_or_sensitive_content(runtime_db, event_type, details):
    with pytest.raises(ValueError):
        with runtime_db.unit_of_work() as uow:
            uow.audit.add(event_type, c.AuditOutcome.FAILURE, details=details)


def test_naive_datetimes_are_rejected(runtime_db):
    with pytest.raises(StatementError):
        with runtime_db.unit_of_work() as uow:
            uow.invitations.add(UserInvitation(email=unique_email(), token_hash=os.urandom(32),
                                               expires_at=datetime.now() + timedelta(days=1)))
