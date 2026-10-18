"""Key, uniqueness and CHECK constraints, exercised through the runtime role."""

from __future__ import annotations

import hashlib
import os
import uuid

import pyodbc
import pytest

from localdb import RUNTIME

HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"


@pytest.fixture(scope="module")
def db(migrated_db):
    return migrated_db


def new_user(db, email=None, status="active"):
    email = email or f"u{uuid.uuid4().hex[:10]}@example.com"
    return db.scalar(
        "INSERT INTO fr.users (email, display_name, password_hash, status) OUTPUT inserted.id VALUES (?, ?, ?, ?)",
        email, "Test", HASH, status, as_user=RUNTIME)


def new_device(db, owner, remote_id=None):
    remote_id = remote_id or str(100_000_000 + int.from_bytes(os.urandom(4), "big") % 899_999_999)
    # Every Remote ID must first be allocated in the permanent registry (V0008).
    return db.scalar(
        "INSERT INTO fr.remote_id_registry (remote_id) VALUES (?); "
        "INSERT INTO fr.devices (owner_user_id, remote_id, display_name) OUTPUT inserted.id VALUES (?, ?, ?)",
        remote_id, owner, remote_id, "PC", as_user=RUNTIME)


REASON_FOR = {"approved": "target_approved", "rejected": "target_rejected", "expired": "timeout",
              "cancelled": "requester_cancelled", "pending": None}


def new_request(db, user, source, target, status="approved", permission="view"):
    decided = "SYSUTCDATETIME()" if status != "pending" else "NULL"
    return db.scalar(
        "INSERT INTO fr.connection_requests (requester_user_id, requester_device_id, target_device_id, status, "
        "requested_permission, expires_at, decided_at, decision_reason) OUTPUT inserted.id VALUES (?, ?, ?, ?, ?, "
        f"DATEADD(SECOND, 60, SYSUTCDATETIME()), {decided}, ?)",
        user, source, target, status, permission, REASON_FOR[status], as_user=RUNTIME)


SESSION_INSERT = (
    "INSERT INTO fr.sessions (connection_request_id, controller_user_id, controller_device_id, target_device_id, "
    "requested_permission, permission_granted, state, ended_at, end_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")


def new_session(db, request, user, controller, target, requested="view", granted="view", state="authorizing"):
    db.execute(SESSION_INSERT, request, user, controller, target, requested, granted, state, None, None,
               as_user=RUNTIME)


def session_rejected(db, request, user, controller, target, requested="view", granted="view", state="authorizing"):
    rejects(db, SESSION_INSERT, request, user, controller, target, requested, granted, state, None, None)


def rejects(db, sql, *params):
    with pytest.raises(pyodbc.IntegrityError):
        db.execute(sql, *params, as_user=RUNTIME)


def test_valid_rows_are_accepted(db):
    user = new_user(db)
    a, b = new_device(db, user), new_device(db, user)
    new_session(db, new_request(db, user, a, b), user, a, b)
    db.execute("INSERT INTO fr.audit_events (event_type, outcome, actor_user_id) VALUES ('session.created', 'success', ?)",
               user, as_user=RUNTIME)


@pytest.mark.parametrize("email", ["Upper@Example.com", "no-at-sign", "a@b"])
def test_invalid_emails_rejected(db, email):
    rejects(db, "INSERT INTO fr.users (email, display_name) VALUES (?, 'x')", email)


def test_duplicate_email_rejected(db):
    new_user(db, "dup@example.com")
    rejects(db, "INSERT INTO fr.users (email, display_name) VALUES ('dup@example.com', 'x')")


def test_plaintext_password_rejected(db):
    rejects(db, "INSERT INTO fr.users (email, display_name, password_hash) VALUES ('p@example.com', 'x', 'hunter2')")


def test_active_user_requires_password_hash(db):
    rejects(db, "INSERT INTO fr.users (email, display_name, status) VALUES ('nohash@example.com', 'x', 'active')")


@pytest.mark.parametrize("remote_id", ["12345678A", "012345678", "1234 5678"])
def test_invalid_remote_id_rejected(db, remote_id):
    user = new_user(db)
    rejects(db, "INSERT INTO fr.devices (owner_user_id, remote_id, display_name) VALUES (?, ?, 'x')", user, remote_id)


def test_remote_id_unique_even_after_revocation(db):
    user = new_user(db)
    device = new_device(db, user, "555444333")
    db.execute("UPDATE fr.devices SET status = 'revoked', revoked_at = SYSUTCDATETIME(), revoked_reason = 'owner_removed' "
               "WHERE id = ?", device, as_user=RUNTIME)
    rejects(db, "INSERT INTO fr.devices (owner_user_id, remote_id, display_name) VALUES (?, '555444333', 'x')", user)


def test_device_requires_existing_owner(db):
    db.execute("INSERT INTO fr.remote_id_registry (remote_id) VALUES ('777666555')", as_user=RUNTIME)
    rejects(db, "INSERT INTO fr.devices (owner_user_id, remote_id, display_name) VALUES (?, '777666555', 'x')",
            str(uuid.uuid4()))


def test_device_requires_registered_remote_id(db):
    """V0008: a Remote ID that was never allocated in the registry cannot be used."""
    rejects(db, "INSERT INTO fr.devices (owner_user_id, remote_id, display_name) VALUES (?, '777666544', 'x')",
            new_user(db))


def test_remote_id_registry_is_append_only_for_runtime(db):
    import pyodbc
    from localdb import PERMISSION_ERROR
    db.execute("INSERT INTO fr.remote_id_registry (remote_id) VALUES ('888777666')", as_user=RUNTIME)
    for sql in ("DELETE FROM fr.remote_id_registry WHERE remote_id = '888777666'",
                "UPDATE fr.remote_id_registry SET remote_id = '888777667' WHERE remote_id = '888777666'"):
        with pytest.raises(pyodbc.Error, match=PERMISSION_ERROR):
            db.execute(sql, as_user=RUNTIME)
    rejects(db, "INSERT INTO fr.remote_id_registry (remote_id) VALUES ('888777666')")   # never twice


def test_one_active_key_per_device_and_ed25519_length(db):
    device = new_device(db, new_user(db))
    insert = "INSERT INTO fr.device_keys (device_id, public_key) VALUES (?, CAST(? AS VARBINARY(64)))"
    db.execute(insert, device, os.urandom(32), as_user=RUNTIME)
    rejects(db, insert, device, os.urandom(32))
    rejects(db, insert, new_device(db, new_user(db)), os.urandom(16))


def test_fingerprint_is_derived_from_public_key_and_unique(db):
    key = os.urandom(32)
    insert = "INSERT INTO fr.device_keys (device_id, public_key) VALUES (?, CAST(? AS VARBINARY(64)))"
    device = new_device(db, new_user(db))
    db.execute(insert, device, key, as_user=RUNTIME)
    stored = db.scalar("SELECT fingerprint FROM fr.device_keys WHERE device_id = ?", device, as_user=RUNTIME)
    assert bytes(stored) == hashlib.sha256(key).digest()
    # The same public key cannot be registered for another device.
    rejects(db, insert, new_device(db, new_user(db)), key)


def test_request_to_self_rejected(db):
    user = new_user(db)
    device = new_device(db, user)
    with pytest.raises(pyodbc.IntegrityError):
        new_request(db, user, device, device)


def test_pending_request_cannot_have_decision(db):
    user = new_user(db)
    a, b = new_device(db, user), new_device(db, user)
    rejects(db, "INSERT INTO fr.connection_requests (requester_user_id, requester_device_id, target_device_id, "
                "expires_at, decided_at) VALUES (?, ?, ?, DATEADD(SECOND, 60, SYSUTCDATETIME()), SYSUTCDATETIME())",
            user, a, b)


def test_session_rules(db):
    user = new_user(db)
    a, b, c = new_device(db, user), new_device(db, user), new_device(db, user)
    first = new_request(db, user, a, b)
    new_session(db, first, user, a, b)
    # Same request cannot back two sessions; a second live session on the same target is refused.
    session_rejected(db, first, user, a, b)
    session_rejected(db, new_request(db, user, c, b), user, c, b)
    # Ended sessions need an end time and reason; active sessions need a start time.
    session_rejected(db, new_request(db, user, a, c), user, a, c, state="ended")
    session_rejected(db, new_request(db, user, a, c), user, a, c, state="active")


@pytest.mark.parametrize("status", ["pending", "rejected", "expired", "cancelled"])
def test_session_requires_an_approved_request(db, status):
    user = new_user(db)
    a, b = new_device(db, user), new_device(db, user)
    session_rejected(db, new_request(db, user, a, b, status=status), user, a, b)


def test_session_must_match_its_request(db):
    user, other = new_user(db), new_user(db)
    a, b, c = new_device(db, user), new_device(db, user), new_device(db, user)
    request = new_request(db, user, a, b)
    for controller_user, controller, target in ((other, a, b), (user, c, b), (user, a, c)):
        session_rejected(db, request, controller_user, controller, target)
    # The copied requested_permission must match the request too.
    session_rejected(db, request, user, a, b, requested="view_input")


def test_session_cannot_grant_more_than_requested(db):
    user = new_user(db)
    a, b, c = new_device(db, user), new_device(db, user), new_device(db, user)
    session_rejected(db, new_request(db, user, a, b), user, a, b, granted="view_input")
    new_session(db, new_request(db, user, a, c, permission="view_input"), user, a, c,
                requested="view_input", granted="view_input")


def test_approved_request_is_final_once_a_session_exists(db):
    user = new_user(db)
    a, b = new_device(db, user), new_device(db, user)
    request = new_request(db, user, a, b)
    new_session(db, request, user, a, b)
    rejects(db, "UPDATE fr.connection_requests SET status = 'expired', decision_reason = 'timeout' WHERE id = ?", request)


@pytest.mark.parametrize("status, reason, valid", [
    ("approved", "target_approved", True), ("approved", "timeout", False),
    ("rejected", "blocked", True), ("rejected", "target_approved", False),
    ("expired", "target_offline", True), ("expired", "requester_cancelled", False),
    ("cancelled", "requester_cancelled", True), ("cancelled", "timeout", False),
])
def test_request_status_and_reason_must_agree(db, status, reason, valid):
    user = new_user(db)
    a, b = new_device(db, user), new_device(db, user)
    sql = ("INSERT INTO fr.connection_requests (requester_user_id, requester_device_id, target_device_id, status, "
           "expires_at, decided_at, decision_reason) VALUES (?, ?, ?, ?, DATEADD(SECOND, 60, SYSUTCDATETIME()), "
           "SYSUTCDATETIME(), ?)")
    if valid:
        db.execute(sql, user, a, b, status, reason, as_user=RUNTIME)
    else:
        rejects(db, sql, user, a, b, status, reason)


def test_audit_event_values_checked(db):
    rejects(db, "INSERT INTO fr.audit_events (event_type, outcome) VALUES ('login', 'maybe')")
    rejects(db, "INSERT INTO fr.audit_events (event_type, outcome) VALUES ('Login Failed!', 'failure')")
    # Regression: upper case slipped through under the case-insensitive database collation.
    rejects(db, "INSERT INTO fr.audit_events (event_type, outcome) VALUES ('Auth.Login', 'success')")


def test_role_codes_are_lower_case(migrated_db):
    with pytest.raises(pyodbc.IntegrityError):
        migrated_db.execute("INSERT INTO fr.roles (code, description) VALUES ('Admin2', N'x')")


def test_address_book_entry_unique_per_owner(db):
    user = new_user(db)
    insert = "INSERT INTO fr.address_book_entries (owner_user_id, remote_id) VALUES (?, '123123123')"
    db.execute(insert, user, as_user=RUNTIME)
    rejects(db, insert, user)


def test_one_open_invitation_per_email(db):
    insert = ("INSERT INTO fr.user_invitations (email, token_hash, expires_at) "
              "VALUES ('invitee@example.com', CAST(? AS BINARY(32)), DATEADD(DAY, 7, SYSUTCDATETIME()))")
    db.execute(insert, os.urandom(32), as_user=RUNTIME)
    rejects(db, insert, os.urandom(32))
