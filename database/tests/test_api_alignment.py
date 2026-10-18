"""The backend's domain constants must match the database constraints exactly."""

from __future__ import annotations

import importlib.util
import re
import uuid

import pytest

from localdb import DATABASE_DIR

spec = importlib.util.spec_from_file_location(
    "fr_domain_constants", DATABASE_DIR.parent / "backend" / "app" / "domain" / "constants.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

ENUM_CONSTRAINTS = {
    "CK_users_status": c.UserStatus,
    "CK_devices_status": c.DeviceStatus,
    "CK_devices_incoming_policy": c.IncomingPolicy,
    "CK_devices_revoked_reason": c.DeviceRevokedReason,
    "CK_device_keys_algorithm": c.KeyAlgorithm,
    "CK_device_keys_revoked_reason": c.KeyRevokedReason,
    "CK_auth_sessions_client_type": c.ClientType,
    "CK_auth_sessions_revoked_reason": c.AuthSessionRevokedReason,
    "CK_auth_tokens_token_type": c.TokenType,
    "CK_connection_requests_requested_permission": c.Permission,
    "CK_sessions_permission_granted": c.Permission,
    "CK_connection_requests_status": c.RequestStatus,
    "CK_connection_requests_decision_reason": c.DecisionReason,
    "CK_sessions_state": c.SessionState,
    "CK_sessions_end_reason": c.SessionEndReason,
    "CK_audit_events_outcome": c.AuditOutcome,
}

COLUMN_LENGTHS = {
    ("users", "email"): c.EMAIL_MAX_LENGTH,
    ("user_invitations", "email"): c.EMAIL_MAX_LENGTH,
    ("users", "display_name"): c.DISPLAY_NAME_MAX_LENGTH,
    ("devices", "display_name"): c.DISPLAY_NAME_MAX_LENGTH,
    ("devices", "os_name"): c.OS_NAME_MAX_LENGTH,
    ("devices", "os_version"): c.OS_VERSION_MAX_LENGTH,
    ("devices", "client_version"): c.CLIENT_VERSION_MAX_LENGTH,
    ("address_book_entries", "alias"): c.ALIAS_MAX_LENGTH,
    ("address_book_entries", "notes"): c.NOTES_MAX_LENGTH,
    ("auth_sessions", "user_agent"): c.USER_AGENT_MAX_LENGTH,
    ("audit_events", "event_type"): c.EVENT_TYPE_MAX_LENGTH,
    ("audit_events", "details"): c.AUDIT_DETAILS_MAX_LENGTH,
}


@pytest.fixture(scope="module")
def db(migrated_db):
    return migrated_db


def test_enum_constants_match_check_constraints(db):
    definitions = dict(db.execute(
        "SELECT name, definition FROM sys.check_constraints WHERE schema_id = SCHEMA_ID('fr')"))
    for name, enum in ENUM_CONSTRAINTS.items():
        assert set(re.findall(r"'([^']*)'", definitions[name])) == {m.value for m in enum}, name


def test_roles_match_seed_rows(db):
    assert {r[0] for r in db.execute("SELECT code FROM fr.roles")} == {r.value for r in c.Role}


def test_column_lengths_match(db):
    for (table, column), expected in COLUMN_LENGTHS.items():
        actual = db.scalar("SELECT CHARACTER_MAXIMUM_LENGTH FROM INFORMATION_SCHEMA.COLUMNS "
                           "WHERE TABLE_SCHEMA = 'fr' AND TABLE_NAME = ? AND COLUMN_NAME = ?", table, column)
        assert actual == expected, f"{table}.{column}"


def _accepted(db, sql: str, *params) -> bool:
    row = db.execute(
        "SET XACT_ABORT OFF; BEGIN TRANSACTION; "
        f"BEGIN TRY {sql}; SELECT 1; END TRY BEGIN CATCH SELECT 0; END CATCH; "
        "ROLLBACK TRANSACTION;", *params)
    return row[-1][0] == 1


@pytest.fixture(scope="module")
def two_devices(db):
    user = db.scalar("INSERT INTO fr.users (email, display_name) OUTPUT inserted.id VALUES (?, 'A')",
                     f"align{uuid.uuid4().hex[:8]}@example.com")
    devices = [db.scalar("INSERT INTO fr.remote_id_registry (remote_id) VALUES (?); "
                         "INSERT INTO fr.devices (owner_user_id, remote_id, display_name) OUTPUT inserted.id "
                         "VALUES (?, ?, 'D')", rid, user, rid) for rid in ("987654321", "987654322")]
    return user, *devices


def test_status_reason_matrix_matches_database(db, two_devices):
    user, a, b = two_devices
    for status in c.RequestStatus:
        for reason in [None, *c.DecisionReason]:
            expected = (reason in c.DECISION_REASONS_BY_STATUS[status]) if reason else status is c.RequestStatus.PENDING
            decided = "NULL" if status is c.RequestStatus.PENDING else "SYSUTCDATETIME()"
            accepted = _accepted(
                db,
                "INSERT INTO fr.connection_requests (requester_user_id, requester_device_id, target_device_id, "
                "status, expires_at, decided_at, decision_reason) VALUES (?, ?, ?, ?, "
                f"DATEADD(SECOND, 60, SYSUTCDATETIME()), {decided}, ?)",
                user, a, b, status.value, reason.value if reason else None)
            assert accepted == expected, (status, reason)


@pytest.mark.parametrize("value", ["123456789", "999999999", "012345678", "12345678", "1234567890", "12345678a"])
def test_remote_id_pattern_matches_database(db, two_devices, value):
    user, _, _ = two_devices
    accepted = _accepted(db, "INSERT INTO fr.address_book_entries (owner_user_id, remote_id) VALUES (?, ?)",
                         user, value)
    # CHAR(9) pads short values with spaces, which the digit check rejects; long values fail truncation.
    assert accepted == bool(re.fullmatch(c.REMOTE_ID_PATTERN, value)), value


@pytest.mark.parametrize("value", ["session.ended", "auth.login_failed", "Auth.Login", "auth login", "auth-login"])
def test_audit_event_type_pattern_matches_database(db, value):
    accepted = _accepted(db, "INSERT INTO fr.audit_events (event_type, outcome) VALUES (?, 'success')", value)
    assert accepted == bool(re.fullmatch(c.AUDIT_EVENT_TYPE_PATTERN, value)), value
