"""Password hashing, tokens, CSRF and rate limiting (no database)."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import timedelta

import jwt
import pytest

from app.security.clock import FrozenClock
from app.security.csrf import csrf_token, csrf_valid
from app.security.passwords import PasswordHasher, password_policy_issue
from app.security.rate_limit import Limit, RateLimiter
from app.security.tokens import AccessTokenIssuer, InvalidAccessToken, hash_token, new_opaque_token

KEY = b"k" * 32


@pytest.fixture(scope="module")
def hasher():
    return PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)


def test_production_parameters_are_argon2id_rfc9106():
    encoded = PasswordHasher().hash("correct horse battery staple")
    assert encoded.startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_hash_and_verify(hasher):
    encoded = hasher.hash("Correct-Horse-9")
    assert encoded.startswith("$argon2id$") and "Correct-Horse-9" not in encoded
    assert hasher.verify(encoded, "Correct-Horse-9")
    assert not hasher.verify(encoded, "correct-horse-9")
    assert not hasher.verify("not-a-hash", "x") and not hasher.verify(None, "x")
    assert hasher.hash("same") != hasher.hash("same")  # salted


def test_missing_hash_still_spends_verification_effort(hasher, monkeypatch):
    calls = []
    monkeypatch.setattr(hasher, "dummy_verify", lambda pw: calls.append(pw))
    assert hasher.verify(None, "guess") is False and calls == ["guess"]


@pytest.mark.parametrize("password, email, issue", [
    ("short", None, "too_short"),
    ("x" * 129, None, "too_long"),
    ("aaaaaaaaaaaaaaaa", None, "too_simple"),
    ("            !!!!", None, "too_simple"),
    ("Spaces are fine 4u", None, None),
    ("alice-Secret-2026", "alice@example.com", "contains_email"),
    ("Tr0ub4dor&3-long", "bo@example.com", None),
    ("Correct-Horse-Battery", "alice@example.com", None),
])
def test_password_policy(password, email, issue):
    assert password_policy_issue(password, email) == issue


def test_opaque_tokens():
    tokens = {new_opaque_token() for _ in range(200)}
    assert len(tokens) == 200 and all(len(t) == 43 for t in tokens)
    assert len(hash_token("abc")) == 32 and hash_token("abc") == hash_token("abc") != hash_token("abd")


def test_access_token_round_trip():
    clock = FrozenClock()
    issuer = AccessTokenIssuer(KEY, 600, clock)
    user, sid, did = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    claims = issuer.verify(issuer.issue(user, sid, did))
    assert (claims.user_id, claims.auth_session_id, claims.device_id) == (user, sid, did)


def test_access_token_expiry_uses_injected_clock():
    clock = FrozenClock()
    issuer = AccessTokenIssuer(KEY, 600, clock)
    token = issuer.issue(uuid.uuid4(), uuid.uuid4())
    clock.advance(seconds=600 + 29)
    issuer.verify(token)                      # within leeway
    clock.advance(seconds=2)
    with pytest.raises(InvalidAccessToken):
        issuer.verify(token)


def _forge(claims: dict, key: bytes = KEY, algorithm: str = "HS256") -> str:
    return jwt.encode(claims, key, algorithm=algorithm)


def _base_claims(clock) -> dict:
    now = int(clock.now().timestamp())
    return {"iss": "fabremote", "aud": "fabremote-api", "typ": "access", "sub": str(uuid.uuid4()),
            "sid": str(uuid.uuid4()), "iat": now, "exp": now + 600, "jti": "x"}


@pytest.mark.parametrize("mutate", [
    lambda c: {**c, "typ": "device"},
    lambda c: {**c, "aud": "someone-else"},
    lambda c: {**c, "iss": "attacker"},
    lambda c: {k: v for k, v in c.items() if k != "sid"},
    lambda c: {**c, "sub": "not-a-uuid"},
    lambda c: {**c, "iat": c["iat"] + 3600, "exp": c["exp"] + 3600},   # issued in the future
])
def test_access_token_rejects_bad_claims(mutate):
    clock = FrozenClock()
    issuer = AccessTokenIssuer(KEY, 600, clock)
    with pytest.raises(InvalidAccessToken):
        issuer.verify(_forge(mutate(_base_claims(clock))))


def test_access_token_rejects_wrong_key_tampering_and_alg_none():
    clock = FrozenClock()
    issuer = AccessTokenIssuer(KEY, 600, clock)
    claims = _base_claims(clock)
    with pytest.raises(InvalidAccessToken):
        issuer.verify(_forge(claims, key=b"x" * 32))
    header, payload, signature = issuer.issue(uuid.uuid4(), uuid.uuid4()).split(".")
    evil = base64.urlsafe_b64encode(json.dumps({**claims, "sub": str(uuid.uuid4())}).encode()).decode().rstrip("=")
    with pytest.raises(InvalidAccessToken):
        issuer.verify(f"{header}.{evil}.{signature}")
    unsigned = (base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=") + "."
                + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".")
    with pytest.raises(InvalidAccessToken):
        issuer.verify(unsigned)
    with pytest.raises(ValueError):
        AccessTokenIssuer(b"short", 600, clock)


def test_csrf_tokens_bind_to_session_and_key():
    sid = uuid.uuid4()
    token = csrf_token(KEY, sid)
    assert csrf_valid(KEY, sid, token)
    assert not csrf_valid(KEY, uuid.uuid4(), token)
    assert not csrf_valid(b"z" * 32, sid, token)
    assert not csrf_valid(KEY, sid, None) and not csrf_valid(KEY, sid, "")


def test_rate_limiter_window_and_retry_after():
    now = [1000.0]
    limiter = RateLimiter(monotonic=lambda: now[0])
    limit = Limit(3, 60)
    key = limiter.key("login", "alice@example.com", "10.0.0.1")
    assert "alice" not in key and len(key) == 64
    assert [limiter.hit(key, limit) for _ in range(3)] == [None, None, None]
    retry = limiter.hit(key, limit)
    assert retry is not None and 1 <= retry <= 60
    now[0] += 61
    assert limiter.hit(key, limit) is None
    assert limiter.hit(limiter.key("other"), limit) is None   # independent keys


def test_rate_limiter_memory_is_bounded():
    limiter = RateLimiter(max_keys=10)
    for i in range(50):
        limiter.hit(f"k{i}", Limit(1, 60))
    assert len(limiter._hits) == 10


def test_frozen_clock_advances():
    clock = FrozenClock()
    start = clock.now()
    clock.advance(minutes=5)
    assert clock.now() - start == timedelta(minutes=5)
