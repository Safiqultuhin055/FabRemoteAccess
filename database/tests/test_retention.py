"""fr.usp_purge_expired_data behaviour."""

from __future__ import annotations

import os

import pyodbc
import pytest

from localdb import MAINTENANCE, sql_error

HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"

# Proposed periods (pending approval); the procedure has no defaults, so tests pass them explicitly.
PERIODS = {"session_retention_days": 365, "request_retention_days": 90, "audit_retention_days": 365,
           "ip_retention_days": 90, "token_grace_days": 7}


def purge(**overrides) -> str:
    params = {**PERIODS, **overrides}
    return "EXEC fr.usp_purge_expired_data " + ", ".join(f"@{k} = {v}" for k, v in params.items())

SEED = """
DECLARE @u UNIQUEIDENTIFIER = NEWID(), @a UNIQUEIDENTIFIER = NEWID(), @b UNIQUEIDENTIFIER = NEWID(),
        @old_s UNIQUEIDENTIFIER = NEWID(), @new_s UNIQUEIDENTIFIER = NEWID(),
        @old_r UNIQUEIDENTIFIER = NEWID(), @new_r UNIQUEIDENTIFIER = NEWID(), @kept_r UNIQUEIDENTIFIER = NEWID(),
        @long_ago DATETIME2(3) = DATEADD(DAY, -400, SYSUTCDATETIME()),
        @recent DATETIME2(3) = DATEADD(DAY, -1, SYSUTCDATETIME());

INSERT fr.users (id, email, display_name, password_hash, status) VALUES (@u, 'r@example.com', 'R', ?, 'active');
INSERT fr.remote_id_registry (remote_id) VALUES ('111111111'), ('222222222');
INSERT fr.devices (id, owner_user_id, remote_id, display_name, last_ip, last_ip_at)
VALUES (@a, @u, '111111111', 'A', '10.0.0.1', @long_ago), (@b, @u, '222222222', 'B', '10.0.0.2', @recent);

INSERT fr.auth_sessions (id, user_id, client_type, created_at, expires_at, created_ip)
VALUES (@old_s, @u, 'web', @long_ago, DATEADD(DAY, 1, @long_ago), '10.0.0.3'),
       (@new_s, @u, 'web', @recent, DATEADD(DAY, 30, @recent), '10.0.0.4');
INSERT fr.auth_tokens (auth_session_id, token_type, token_hash, issued_at, expires_at)
VALUES (@old_s, 'web', CAST(? AS BINARY(32)), @long_ago, DATEADD(DAY, 1, @long_ago)),
       (@new_s, 'web', CAST(? AS BINARY(32)), @recent, DATEADD(DAY, 30, @recent));

-- old_r: decided long ago, ended session long ago -> both purged.
-- kept_r: decided long ago but its session is recent -> request kept while session exists.
-- new_r: recent -> kept.
INSERT fr.connection_requests (id, requester_user_id, requester_device_id, target_device_id, status, created_at,
                               expires_at, decided_at, decision_reason, requester_ip)
VALUES (@old_r, @u, @a, @b, 'approved', @long_ago, DATEADD(MINUTE, 1, @long_ago), @long_ago, 'target_approved', '10.0.0.5'),
       (@kept_r, @u, @b, @a, 'approved', @long_ago, DATEADD(MINUTE, 1, @long_ago), @long_ago, 'target_approved', NULL),
       (@new_r, @u, @a, @b, 'rejected', @recent, DATEADD(MINUTE, 1, @recent), @recent, 'target_rejected', '10.0.0.6');
INSERT fr.sessions (connection_request_id, controller_user_id, controller_device_id, target_device_id,
                    requested_permission, permission_granted, state, created_at, started_at, ended_at, end_reason)
VALUES (@old_r, @u, @a, @b, 'view', 'view', 'ended', @long_ago, @long_ago, @long_ago, 'controller_disconnect'),
       (@kept_r, @u, @b, @a, 'view', 'view', 'ended', @recent, @recent, @recent, 'target_disconnect');

INSERT fr.audit_events (occurred_at, event_type, outcome, ip_address)
VALUES (@long_ago, 'auth.login', 'success', '10.0.0.7'),
       (DATEADD(DAY, -100, SYSUTCDATETIME()), 'auth.login', 'success', '10.0.0.8'),
       (@recent, 'auth.login', 'success', '10.0.0.9');
"""


@pytest.fixture
def seeded(db_factory):
    db = db_factory("migrated")
    db.execute(SEED, HASH, os.urandom(32), os.urandom(32))
    return db


def table_counts(db) -> dict[str, int]:
    tables = ("auth_tokens", "auth_sessions", "sessions", "connection_requests", "audit_events")
    return {t: db.scalar(f"SELECT COUNT(*) FROM fr.{t}") for t in tables}


def test_dry_run_reports_but_changes_nothing(seeded):
    before = table_counts(seeded)
    report = dict(seeded.execute(purge(), as_user=MAINTENANCE))
    assert report["deleted.sessions"] == 1
    assert report["deleted.connection_requests"] == 1
    assert report["deleted.audit_events"] == 1
    assert table_counts(seeded) == before
    assert seeded.scalar("SELECT COUNT(*) FROM fr.devices WHERE last_ip IS NOT NULL") == 2


def test_purge_removes_only_expired_data(seeded):
    report = dict(seeded.execute(purge(dry_run=0), as_user=MAINTENANCE))
    assert report == {
        "deleted.auth_tokens": 1, "deleted.auth_sessions": 1, "deleted.device_auth_challenges": 0,
        "deleted.user_invitations": 0, "deleted.sessions": 1, "deleted.connection_requests": 1,
        "deleted.audit_events": 1, "cleared_ip.devices": 1, "cleared_ip.auth_sessions": 0,
        "cleared_ip.connection_requests": 0, "cleared_ip.audit_events": 1,
    }
    assert table_counts(seeded) == {
        "auth_tokens": 1, "auth_sessions": 1, "sessions": 1, "connection_requests": 2,
        "audit_events": 3,  # 2 remaining + the retention.purge event itself
    }
    assert seeded.scalar("SELECT last_ip FROM fr.devices WHERE remote_id = '111111111'") is None
    assert seeded.scalar("SELECT last_ip FROM fr.devices WHERE remote_id = '222222222'") == "10.0.0.2"
    assert seeded.scalar("SELECT COUNT(*) FROM fr.audit_events WHERE event_type = 'retention.purge'") == 1
    # Second run finds nothing left to delete (safe to repeat).
    again = dict(seeded.execute(purge(dry_run=0), as_user=MAINTENANCE))
    assert all(v == 0 for v in again.values())


def test_small_batches_give_same_result(seeded):
    report = dict(seeded.execute(purge(dry_run=0, batch_size=1), as_user=MAINTENANCE))
    assert report["deleted.sessions"] == 1 and report["deleted.audit_events"] == 1


@pytest.mark.parametrize("override", [
    {"audit_retention_days": 30},
    {"session_retention_days": 1},
    {"batch_size": 0},
    {"ip_retention_days": "NULL"},
    {"dry_run": "NULL"},
])
def test_unsafe_parameters_rejected(seeded, override):
    with pytest.raises(pyodbc.Error, match=sql_error(51100)):
        seeded.execute(purge(**override), as_user=MAINTENANCE)


def test_retention_periods_have_no_defaults(seeded):
    """Unapproved periods can never be applied implicitly: every period must be passed."""
    with pytest.raises(pyodbc.Error, match=sql_error(201)):
        seeded.execute("EXEC fr.usp_purge_expired_data @dry_run = 1", as_user=MAINTENANCE)
    assert seeded.scalar("SELECT COUNT(*) FROM fr.sessions") == 2
