"""Admin invitations and invitation acceptance (LocalDB, runtime role)."""

from __future__ import annotations

import uuid

import pytest

from app.domain.constants import Role
from auth_support import PASSWORD, make_env


@pytest.fixture
def env(runtime_db):
    return make_env(runtime_db)


def new_email() -> str:
    return f"invitee.{uuid.uuid4().hex[:10]}@example.com"


def invite(env, admin_headers, email=None, role="user", hours=72):
    return env.client.post("/api/v1/admin/invitations", headers=admin_headers,
                           json={"email": email or new_email(), "role": role, "expires_in_hours": hours})


def accept(env, token, password="Fresh-Password-2026", name="New Person"):
    return env.client.post("/api/v1/auth/invitations/accept",
                           json={"token": token, "display_name": name, "password": password})


def test_invite_accept_login_flow(env):
    admin = env.bearer(env.account(Role.ADMIN))
    created = invite(env, admin, role="user")
    assert created.status_code == 201
    body = created.json()
    assert body["invitation"]["status"] == "open" and body["invitation"]["role"] == "user"
    assert body["accept_url"] == f"http://localhost:8765/portal/accept-invitation#token={body['token']}"
    accepted = accept(env, body["token"])
    assert accepted.status_code == 201
    user = accepted.json()["user"]
    assert user["roles"] == ["user"] and user["email_verified_at"] is not None
    login = env.client.post("/api/v1/auth/token", json={"email": user["email"], "password": "Fresh-Password-2026"})
    assert login.status_code == 200


@pytest.mark.parametrize("case", ["reused", "expired", "revoked", "unknown"])
def test_unusable_invitations_get_the_same_answer(env, case):
    admin = env.bearer(env.account(Role.ADMIN))
    body = invite(env, admin, hours=1).json()
    token = body["token"]
    if case == "reused":
        assert accept(env, token).status_code == 201
    elif case == "expired":
        env.clock.advance(hours=2)
    elif case == "revoked":
        assert env.client.post(f"/api/v1/admin/invitations/{body['invitation']['id']}/revoke",
                               headers=admin).status_code == 200
    else:
        token = "A" * 43
    response = accept(env, token)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "invitation_invalid"


@pytest.mark.parametrize("case, issue", [("short", "too_short"), ("contains_email", "contains_email")])
def test_password_policy_on_accept(env, case, issue):
    admin = env.bearer(env.account(Role.ADMIN))
    local = f"pat{uuid.uuid4().hex[:6]}"
    body = invite(env, admin, email=f"{local}@example.com").json()
    password = "Ab1!xyz" if case == "short" else f"{local}-Secret-2026"
    response = accept(env, body["token"], password=password)
    assert response.status_code == 422
    assert response.json()["error"]["details"] == [{"field": "password", "issue": issue}]
    assert password not in response.text
    assert accept(env, body["token"]).status_code == 201  # invitation still usable after a rejected attempt


@pytest.mark.parametrize("roles", [(), (Role.AUDITOR,)])
def test_only_admins_can_invite(env, roles):
    headers = env.bearer(env.account(*roles))
    response = invite(env, headers, role="admin")
    assert response.status_code == 403 and response.json()["error"]["code"] == "forbidden"
    assert env.client.get("/api/v1/admin/invitations", headers=headers).status_code == 403


def test_unauthenticated_invite_is_401(env):
    response = env.client.post("/api/v1/admin/invitations", json={"email": new_email()})
    assert response.status_code == 401 and response.headers["WWW-Authenticate"] == "Bearer"


def test_invited_user_gets_exactly_the_invited_role(env):
    admin = env.bearer(env.account(Role.ADMIN))
    as_user = accept(env, invite(env, admin, role="user").json()["token"]).json()["user"]
    as_admin = accept(env, invite(env, admin, role="admin").json()["token"]).json()["user"]
    as_auditor = accept(env, invite(env, admin, role="auditor").json()["token"]).json()["user"]
    assert as_user["roles"] == ["user"]
    assert as_admin["roles"] == ["admin", "user"]
    assert as_auditor["roles"] == ["auditor", "user"]


def test_role_cannot_be_injected_on_accept(env):
    admin = env.bearer(env.account(Role.ADMIN))
    token = invite(env, admin, role="user").json()["token"]
    response = env.client.post("/api/v1/auth/invitations/accept",
                               json={"token": token, "display_name": "X", "password": PASSWORD, "role": "admin"})
    assert response.status_code == 422


def test_duplicate_invitation_and_existing_account(env):
    admin = env.bearer(env.account(Role.ADMIN))
    email = new_email()
    assert invite(env, admin, email=email).status_code == 201
    duplicate = invite(env, admin, email=email.upper())
    assert duplicate.status_code == 409 and duplicate.json()["error"]["code"] == "invitation_exists"
    existing = env.account()
    taken = invite(env, admin, email=existing.email)
    assert taken.status_code == 409 and taken.json()["error"]["code"] == "account_exists"


def test_list_filter_and_pagination(env):
    admin = env.bearer(env.account(Role.ADMIN))
    marker = uuid.uuid4().hex[:6]
    for i in range(3):
        invite(env, admin, email=f"page{i}.{marker}@example.com")
        env.clock.advance(seconds=1)
    first = env.client.get("/api/v1/admin/invitations?status=open&limit=2", headers=admin).json()
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = env.client.get(f"/api/v1/admin/invitations?status=open&limit=2&cursor={first['next_cursor']}",
                            headers=admin).json()
    ids = [i["id"] for i in first["items"] + second["items"]]
    assert len(ids) == len(set(ids))
    bad = env.client.get("/api/v1/admin/invitations?cursor=%%%", headers=admin)
    assert bad.status_code == 422


def test_revoke_rules(env):
    admin = env.bearer(env.account(Role.ADMIN))
    body = invite(env, admin).json()
    url = f"/api/v1/admin/invitations/{body['invitation']['id']}/revoke"
    revoked = env.client.post(url, headers=admin)
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    assert env.client.post(url, headers=admin).status_code == 409
    assert env.client.post(f"/api/v1/admin/invitations/{uuid.uuid4()}/revoke", headers=admin).status_code == 404


def test_invitation_rate_limits(env):
    for _ in range(10):
        accept(env, "B" * 43)
    response = accept(env, "B" * 43)
    assert response.status_code == 429 and "Retry-After" in response.headers
