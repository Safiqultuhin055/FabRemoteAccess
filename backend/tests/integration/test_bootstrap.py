"""Bootstrap CLI and service on a fresh database (no administrator yet)."""

from __future__ import annotations

import re

import pytest

import app.cli as cli
from app.db.engine import Database
from app.domain.constants import Role
from app.domain.errors import ConflictError
from app.security.clock import Clock
from app.services.context import RequestContext
from app.services.invitations import InvitationService
from auth_support import FAST_HASHER, make_env
from db_support import impersonate, localdb, localdb_settings
from test_auth_concurrency import race


@pytest.fixture
def fresh(db_factory):
    """A brand-new migrated database with no users, accessed as the runtime role."""
    scratch = db_factory("migrated")
    database = Database(localdb_settings(scratch.name), connect_hook=impersonate(localdb.RUNTIME))
    yield scratch, database
    database.dispose()


def run_cli(scratch, database, email, capsys) -> tuple[int, str, str]:
    code = cli.main(["bootstrap-admin", "--email", email], settings=localdb_settings(scratch.name),
                    database=database)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_bootstrap_flow_and_refusals(fresh, capsys):
    scratch, database = fresh
    code, out, _ = run_cli(scratch, database, "First.Admin@Example.com", capsys)
    assert code == cli.EXIT_OK
    token = re.search(r"token \(shown once\): (\S+)", out).group(1)
    assert scratch.scalar("SELECT COUNT(*) FROM fr.user_invitations WHERE invited_by_user_id IS NULL "
                          "AND role_code = 'admin' AND email = 'first.admin@example.com'") == 1

    # A second bootstrap while the first is open is refused (even for another email).
    code, _, err = run_cli(scratch, database, "second@example.com", capsys)
    assert code == cli.EXIT_REFUSED and "bootstrap_pending" in err

    env = make_env(database)
    accepted = env.client.post("/api/v1/auth/invitations/accept",
                               json={"token": token, "display_name": "First Admin", "password": "Admin-Password-2026"})
    assert accepted.status_code == 201 and accepted.json()["user"]["roles"] == ["admin", "user"]

    # Once an administrator exists, bootstrap is permanently closed.
    code, _, err = run_cli(scratch, database, "third@example.com", capsys)
    assert code == cli.EXIT_REFUSED and "admin_exists" in err
    assert scratch.scalar("SELECT COUNT(*) FROM fr.audit_events WHERE event_type = 'admin.bootstrap_invitation'") == 1


def test_stale_bootstrap_invitation_cannot_create_second_admin(fresh, capsys):
    scratch, database = fresh
    _, out, _ = run_cli(scratch, database, "boot@example.com", capsys)
    stale = re.search(r"token \(shown once\): (\S+)", out).group(1)
    env = make_env(database)
    # An administrator appears by another route (simulated directly in the database).
    env.account(Role.ADMIN)
    response = env.client.post("/api/v1/auth/invitations/accept",
                               json={"token": stale, "display_name": "Late", "password": "Late-Password-2026"})
    assert response.status_code == 404 and response.json()["error"]["code"] == "invitation_invalid"


def test_concurrent_bootstrap_yields_one_invitation(fresh):
    scratch, database = fresh
    service = InvitationService(database.unit_of_work, FAST_HASHER, Clock())
    counter = iter(range(100))
    results = race(lambda: service.bootstrap(f"boot{next(counter)}@example.com", 24, RequestContext()))
    assert sum(kind == "ok" for kind, _ in results) == 1
    assert all(isinstance(r, ConflictError) for kind, r in results if kind == "error")
    assert scratch.scalar("SELECT COUNT(*) FROM fr.user_invitations WHERE invited_by_user_id IS NULL") == 1
