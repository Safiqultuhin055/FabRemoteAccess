"""Login, tokens, refresh rotation, logout, /me, browser sessions and CSRF (LocalDB, runtime role)."""

from __future__ import annotations

import hashlib
import io
import logging
import uuid

import pytest
from sqlalchemy import update

from app.db.models import User
from app.domain.constants import Role, UserStatus
from app.log import configure_logging
from app.security.rate_limit import Limit, RateLimits
from auth_support import PASSWORD, SIGNING_KEY, make_env

COOKIE = "__Host-fr_session"


@pytest.fixture
def env(runtime_db):
    return make_env(runtime_db)


def error_code(response) -> str:
    return response.json()["error"]["code"]


def set_status(env, user_id, status: UserStatus):
    with env.db.unit_of_work() as uow:
        uow._session.execute(update(User).where(User.id == user_id).values(status=status)
                             .execution_options(synchronize_session=False))
        uow.commit()


# ------------------------------------------------------------------ desktop login


def test_desktop_login_and_me(env):
    account = env.account()
    tokens = env.login(account)
    assert tokens["token_type"] == "Bearer" and tokens["expires_in"] == 600
    assert 29 * 86400 < tokens["refresh_expires_in"] <= 30 * 86400
    assert tokens["user"]["email"] == account.email and tokens["user"]["roles"] == ["user"]
    assert "password_hash" not in str(tokens)
    me = env.client.get("/api/v1/auth/me", headers=env.bearer(tokens))
    assert me.status_code == 200 and me.json()["id"] == str(account.id)
    assert me.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("case", ["wrong_password", "unknown_email", "disabled", "invited"])
def test_invalid_credentials_are_indistinguishable(env, case):
    account = env.account(status=UserStatus.INVITED if case == "invited" else UserStatus.ACTIVE)
    if case == "disabled":
        set_status(env, account.id, UserStatus.DISABLED)
    email = f"nobody.{uuid.uuid4().hex}@example.com" if case == "unknown_email" else account.email
    password = "Wrong-Password-123" if case == "wrong_password" else PASSWORD
    response = env.client.post("/api/v1/auth/token", json={"email": email, "password": password})
    assert response.status_code == 401
    body = response.json()["error"]
    assert (body["code"], body["message"]) == ("invalid_credentials", "Email or password is incorrect.")
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert password not in response.text


def test_unknown_account_still_runs_password_verification(env, monkeypatch):
    hasher = env.app.state.auth_service._hasher
    calls = []
    monkeypatch.setattr(hasher, "dummy_verify", lambda pw: calls.append(1))
    env.client.post("/api/v1/auth/token", json={"email": f"x{uuid.uuid4().hex}@example.com", "password": "abc"})
    assert calls == [1]


def test_lockout_after_repeated_failures_and_recovery(env):
    env.app.state.rate_limits = RateLimits(login_per_account_ip=Limit(100, 60), login_per_ip=Limit(100, 60))
    account = env.account()
    for _ in range(10):
        env.client.post("/api/v1/auth/token", json={"email": account.email, "password": "Wrong-Password-1"})
    locked = env.client.post("/api/v1/auth/token", json={"email": account.email, "password": PASSWORD})
    assert locked.status_code == 401 and error_code(locked) == "invalid_credentials"  # no lock oracle
    env.clock.advance(minutes=16)
    assert env.client.post("/api/v1/auth/token", json={"email": account.email, "password": PASSWORD}).status_code == 200
    with env.db.unit_of_work() as uow:
        assert uow.users.get(account.id).failed_login_count == 0


def test_login_rate_limit(env):
    account = env.account()
    statuses = [env.client.post("/api/v1/auth/token",
                                json={"email": account.email, "password": "Wrong-Password-1"}).status_code
                for _ in range(6)]
    assert statuses == [401] * 5 + [429]
    limited = env.client.post("/api/v1/auth/token", json={"email": account.email, "password": PASSWORD})
    assert limited.status_code == 429 and int(limited.headers["Retry-After"]) >= 1
    assert error_code(limited) == "rate_limited"


def test_oversized_and_unknown_fields_rejected(env):
    assert env.client.post("/api/v1/auth/token", json={"email": "a@b.co", "password": "x" * 1025}).status_code == 422
    assert env.client.post("/api/v1/auth/token",
                           json={"email": "a@b.co", "password": "x", "is_admin": True}).status_code == 422


# ------------------------------------------------------------------ tokens


def test_refresh_rotation_and_reuse_detection(env):
    tokens = env.login(env.account())
    rotated = env.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert rotated.status_code == 200
    new = rotated.json()
    assert new["refresh_token"] != tokens["refresh_token"] and new["access_token"] != tokens["access_token"]

    replay = env.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401 and error_code(replay) == "token_reused"
    # Reuse revoked the whole session: the newest refresh token and live access tokens die too.
    assert error_code(env.client.post("/api/v1/auth/refresh", json={"refresh_token": new["refresh_token"]})) \
        == "invalid_token"
    assert env.client.get("/api/v1/auth/me", headers=env.bearer(new)).status_code == 401


def test_logout_revokes_access_and_refresh_immediately(env):
    tokens = env.login(env.account())
    assert env.client.post("/api/v1/auth/logout", headers=env.bearer(tokens)).status_code == 204
    assert env.client.get("/api/v1/auth/me", headers=env.bearer(tokens)).status_code == 401
    refresh = env.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401 and error_code(refresh) == "invalid_token"
    assert env.client.post("/api/v1/auth/logout", headers=env.bearer(tokens)).status_code == 401


def test_access_token_expiry_then_refresh(env):
    tokens = env.login(env.account())
    env.clock.advance(minutes=11)
    assert env.client.get("/api/v1/auth/me", headers=env.bearer(tokens)).status_code == 401
    refreshed = env.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200
    assert env.client.get("/api/v1/auth/me", headers=env.bearer(refreshed.json())).status_code == 200


def test_refresh_token_expires_with_session(env):
    tokens = env.login(env.account())
    env.clock.advance(days=31)
    refresh = env.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401 and error_code(refresh) == "invalid_token"


def test_disabled_user_loses_access_and_refresh(env):
    account = env.account()
    tokens = env.login(account)
    set_status(env, account.id, UserStatus.DISABLED)
    assert env.client.get("/api/v1/auth/me", headers=env.bearer(tokens)).status_code == 401
    assert env.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_token_for_another_users_session_is_rejected(env):
    """Privilege escalation: a validly signed token naming user B but session A must fail."""
    a, b = env.account(), env.account(Role.ADMIN)
    tokens = env.login(a)
    claims = env.app.state.auth_service._issuer.verify(tokens["access_token"])
    forged = env.app.state.auth_service._issuer.issue(b.id, claims.auth_session_id)
    response = env.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


@pytest.mark.parametrize("header", ["Bearer", "Bearer ", "Basic abc", "Bearer not.a.jwt", "Token xyz"])
def test_malformed_authorization_headers(env, header):
    response = env.client.get("/api/v1/auth/me", headers={"Authorization": header})
    assert response.status_code == 401 and response.headers["WWW-Authenticate"] == "Bearer"


def test_token_signed_with_configured_key_but_other_app_key_fails(runtime_db):
    first = make_env(runtime_db)
    other = make_env(runtime_db, jwt_signing_key="another-signing-key-0123456789abcdef")
    tokens = first.login(first.account())
    assert other.client.get("/api/v1/auth/me", headers=first.bearer(tokens)).status_code == 401


def test_web_session_token_cannot_be_used_as_refresh_or_bearer(env):
    account = env.account()
    env.client.post("/api/v1/auth/web/login", json={"email": account.email, "password": account.password})
    cookie = env.client.cookies.get(COOKIE)
    env.client.cookies.clear()
    assert env.client.post("/api/v1/auth/refresh", json={"refresh_token": cookie}).status_code == 401
    assert env.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {cookie}"}).status_code == 401
    tokens = env.login(account)
    env.client.cookies.set(COOKIE, tokens["refresh_token"], domain="testserver")
    assert env.client.get("/api/v1/auth/me").status_code == 401


# ------------------------------------------------------------------ browser sessions + CSRF


def web_login(env, account):
    response = env.client.post("/api/v1/auth/web/login", json={"email": account.email, "password": account.password})
    assert response.status_code == 204, response.text
    return response


def test_web_login_sets_hardened_cookie_and_no_token_in_body(env):
    response = web_login(env, env.account())
    cookie = response.headers["set-cookie"]
    for attribute in (f"{COOKIE}=", "HttpOnly", "Secure", "SameSite=lax", "Path=/"):
        assert attribute.lower() in cookie.lower(), attribute
    assert "domain=" not in cookie.lower() and response.content == b""
    assert env.client.get("/api/v1/auth/me").status_code == 200


def test_csrf_required_for_cookie_authenticated_unsafe_requests(env):
    web_login(env, env.account())
    csrf = env.client.get("/api/v1/auth/csrf").json()["csrf_token"]
    missing = env.client.post("/api/v1/auth/logout")
    assert missing.status_code == 403 and error_code(missing) == "csrf_failed"
    assert env.client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "forged"}).status_code == 403
    cross = env.client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"})
    assert cross.status_code == 403
    assert env.client.post("/api/v1/auth/logout",
                           headers={"X-CSRF-Token": csrf, "Sec-Fetch-Site": "cross-site"}).status_code == 403
    ok = env.client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"})
    assert ok.status_code == 204 and f"{COOKIE}=" in ok.headers["set-cookie"]
    env.client.cookies.clear()
    assert env.client.get("/api/v1/auth/me").status_code == 401


@pytest.mark.parametrize("headers", [{"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}])
def test_cross_site_browser_login_is_refused(env, headers):
    """Login CSRF: another site must not sign the browser into an attacker-chosen account."""
    account = env.account()
    response = env.client.post("/api/v1/auth/web/login", headers=headers,
                               json={"email": account.email, "password": account.password})
    assert response.status_code == 403 and error_code(response) == "csrf_failed"
    assert "set-cookie" not in response.headers


def test_csrf_token_from_another_session_is_rejected(env):
    web_login(env, env.account())
    other = make_env(env.db)
    web_login(other, other.account())
    foreign = other.client.get("/api/v1/auth/csrf").json()["csrf_token"]
    assert env.client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": foreign}).status_code == 403


def test_bearer_requests_need_no_csrf_and_bearer_wins_over_cookie(env):
    admin = env.account(Role.ADMIN)
    headers = env.bearer(admin)
    created = env.client.post("/api/v1/admin/invitations", json={"email": f"n{uuid.uuid4().hex[:8]}@example.com"},
                              headers=headers)
    assert created.status_code == 201
    web_login(env, env.account())  # valid cookie present
    assert env.client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_web_session_idle_and_absolute_expiry(env):
    account = env.account()
    web_login(env, account)
    env.clock.advance(hours=11)
    assert env.client.get("/api/v1/auth/me").status_code == 200     # activity refreshes the idle timer
    env.clock.advance(hours=11)
    assert env.client.get("/api/v1/auth/me").status_code == 200
    env.clock.advance(hours=13)
    assert env.client.get("/api/v1/auth/me").status_code == 401     # idle > 12 h
    web_login(env, account)
    for _ in range(8):                                               # stay active, but beyond 7 days
        env.clock.advance(hours=23)
        env.client.get("/api/v1/auth/me")
    assert env.client.get("/api/v1/auth/me").status_code == 401


def test_csrf_endpoint_requires_cookie_session(env):
    assert env.client.get("/api/v1/auth/csrf", headers=env.bearer(env.account())).status_code == 401


# ------------------------------------------------------------------ secret leakage


def test_no_secrets_in_logs_audit_or_storage(env, migrated):
    stream = io.StringIO()
    handler = configure_logging("DEBUG", "json", stream=stream)
    try:
        admin = env.account(Role.ADMIN)
        bad = env.client.post("/api/v1/auth/token", json={"email": admin.email, "password": "Leaky-Wrong-Pass-77"})
        tokens = env.login(admin)
        invite = env.client.post("/api/v1/admin/invitations", headers=env.bearer(tokens),
                                 json={"email": f"leak.{uuid.uuid4().hex[:8]}@example.com"}).json()
        new_password = "Brand-New-Password-55"
        accepted = env.client.post("/api/v1/auth/invitations/accept",
                                   json={"token": invite["token"], "display_name": "Leak", "password": new_password})
        rotated = env.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).json()
        web_login(env, admin)
        cookie = env.client.cookies.get(COOKIE)
    finally:
        logging.getLogger().removeHandler(handler)
    assert bad.status_code == 401 and accepted.status_code == 201

    secrets = [admin.password, "Leaky-Wrong-Pass-77", new_password, tokens["access_token"], tokens["refresh_token"],
               rotated["refresh_token"], rotated["access_token"], invite["token"], cookie, SIGNING_KEY]
    logs = stream.getvalue()
    assert logs  # something was logged
    audit = " ".join(str(r) for r in migrated.execute(
        "SELECT event_type, details, subject_id, request_id FROM fr.audit_events"))
    stored = " ".join(str(r) for r in migrated.execute(
        "SELECT ISNULL(user_agent, ''), ISNULL(created_ip, '') FROM fr.auth_sessions"))
    for secret in secrets:
        assert secret not in logs and secret not in audit and secret not in stored
    assert "$argon2id$" not in logs and "$argon2id$" not in audit
    # Only hashes are stored for opaque tokens.
    for token in (tokens["refresh_token"], rotated["refresh_token"], cookie):
        assert migrated.scalar("SELECT COUNT(*) FROM fr.auth_tokens WHERE token_hash = ?",
                               hashlib.sha256(token.encode()).digest()) == 1
    assert migrated.scalar("SELECT COUNT(*) FROM fr.user_invitations WHERE token_hash = ?",
                           hashlib.sha256(invite["token"].encode()).digest()) == 1
