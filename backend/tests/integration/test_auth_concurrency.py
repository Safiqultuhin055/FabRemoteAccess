"""Races: concurrent refresh with one token, and concurrent acceptance of one invitation."""

from __future__ import annotations

import threading
import uuid

import pytest

from app.domain.constants import Role
from app.domain.errors import AuthenticationError, ConflictError, NotFoundError
from app.services.context import RequestContext
from auth_support import make_env

ATTEMPTS = 4


def race(target, attempts: int = ATTEMPTS) -> list:
    barrier = threading.Barrier(attempts)
    results: list = [None] * attempts

    def run(i):
        barrier.wait()
        try:
            results[i] = ("ok", target())
        except Exception as exc:  # noqa: BLE001 - recorded for assertions
            results[i] = ("error", exc)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(attempts)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    return results


@pytest.fixture
def env(runtime_db):
    return make_env(runtime_db)


def test_concurrent_refresh_with_one_token_never_yields_two_sessions(env):
    tokens = env.login(env.account())
    service = env.app.state.auth_service
    results = race(lambda: service.refresh(tokens["refresh_token"], RequestContext()))
    successes = [r for kind, r in results if kind == "ok"]
    failures = [r for kind, r in results if kind == "error"]
    assert len(successes) <= 1
    assert failures and all(isinstance(f, AuthenticationError) for f in failures)
    assert any(f.code == "token_reused" for f in failures)
    # Reuse detected: the session is revoked, so even the winner's new tokens are dead.
    for winner in successes:
        with pytest.raises(AuthenticationError):
            service.refresh(winner.refresh_token, RequestContext())


def test_concurrent_acceptance_creates_exactly_one_account(env):
    admin = env.bearer(env.account(Role.ADMIN))
    email = f"race.{uuid.uuid4().hex[:8]}@example.com"
    token = env.client.post("/api/v1/admin/invitations", headers=admin, json={"email": email}).json()["token"]
    service = env.app.state.invitation_service
    results = race(lambda: service.accept(token, "Racer", "Race-Password-2026", RequestContext()))
    assert sum(kind == "ok" for kind, _ in results) == 1
    assert all(isinstance(r, (NotFoundError, ConflictError)) for kind, r in results if kind == "error")
    with env.db.unit_of_work() as uow:
        assert uow.users.get_by_email(email) is not None
