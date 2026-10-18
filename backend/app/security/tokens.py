"""Opaque tokens (refresh, web session, invitation) and signed access tokens.

Opaque tokens are 256-bit random values; only their SHA-256 is ever stored. Access tokens
are HS256 JWTs (docs/API_CONTRACTS.md section 3). Expiry is checked against the injected
clock, not the system clock, so tests can move time deliberately.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt

from app.security.clock import Clock

ISSUER = "fabremote"
AUDIENCE = "fabremote-api"
ALGORITHM = "HS256"
LEEWAY_SECONDS = 30
ACCESS = "access"
DEVICE = "device"


def new_opaque_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


class InvalidAccessToken(Exception):
    """Raised for any unusable access token; the reason is never sent to the client."""


@dataclass(frozen=True)
class AccessClaims:
    user_id: uuid.UUID
    auth_session_id: uuid.UUID
    device_id: uuid.UUID | None
    expires_at: datetime


class AccessTokenIssuer:
    def __init__(self, signing_key: bytes, ttl_seconds: int, clock: Clock):
        if len(signing_key) < 32:
            raise ValueError("Signing key must be at least 32 bytes")
        self._key = signing_key
        self._ttl = ttl_seconds
        self._clock = clock

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def issue(self, user_id: uuid.UUID, auth_session_id: uuid.UUID, device_id: uuid.UUID | None = None) -> str:
        now = self._clock.now()
        claims = {
            "iss": ISSUER, "aud": AUDIENCE, "typ": ACCESS, "sub": str(user_id), "sid": str(auth_session_id),
            "iat": int(now.timestamp()), "exp": int((now + timedelta(seconds=self._ttl)).timestamp()),
            "jti": secrets.token_hex(16),
        }
        if device_id:
            claims["did"] = str(device_id)
        return jwt.encode(claims, self._key, algorithm=ALGORITHM)

    def verify(self, token: str) -> AccessClaims:
        try:
            claims = jwt.decode(
                token, self._key, algorithms=[ALGORITHM], audience=AUDIENCE, issuer=ISSUER,
                options={"require": ["iss", "aud", "typ", "sub", "sid", "iat", "exp", "jti"],
                         "verify_exp": False, "verify_iat": False})
        except jwt.PyJWTError as exc:
            raise InvalidAccessToken("malformed or wrongly signed") from exc
        if claims.get("typ") != ACCESS:
            raise InvalidAccessToken("wrong token type")
        now = self._clock.now().timestamp()
        if claims["exp"] + LEEWAY_SECONDS < now or claims["iat"] - LEEWAY_SECONDS > now:
            raise InvalidAccessToken("expired or not yet valid")
        try:
            return AccessClaims(
                user_id=uuid.UUID(claims["sub"]), auth_session_id=uuid.UUID(claims["sid"]),
                device_id=uuid.UUID(claims["did"]) if claims.get("did") else None,
                expires_at=datetime.fromtimestamp(claims["exp"], self._clock.now().tzinfo))
        except (ValueError, TypeError) as exc:
            raise InvalidAccessToken("bad identifiers") from exc


@dataclass(frozen=True)
class DeviceClaims:
    device_id: uuid.UUID
    key_id: uuid.UUID
    expires_at: datetime


class DeviceTokenIssuer:
    """Short-lived device-only tokens, issued after the device signs a challenge with its key.

    They carry the key ID, so rotating or revoking the key ends them; every request still
    checks the device and key against the database. A separate key and token type from
    access tokens, so neither can stand in for the other.
    """

    def __init__(self, signing_key: bytes, ttl_seconds: int, clock: Clock):
        if len(signing_key) < 32:
            raise ValueError("Signing key must be at least 32 bytes")
        self._key = signing_key
        self._ttl = ttl_seconds
        self._clock = clock

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def issue(self, device_id: uuid.UUID, key_id: uuid.UUID) -> str:
        now = self._clock.now()
        claims = {"iss": ISSUER, "aud": AUDIENCE, "typ": DEVICE, "sub": str(device_id), "kid": str(key_id),
                  "iat": int(now.timestamp()), "exp": int((now + timedelta(seconds=self._ttl)).timestamp()),
                  "jti": secrets.token_hex(16)}
        return jwt.encode(claims, self._key, algorithm=ALGORITHM)

    def verify(self, token: str) -> DeviceClaims:
        try:
            claims = jwt.decode(
                token, self._key, algorithms=[ALGORITHM], audience=AUDIENCE, issuer=ISSUER,
                options={"require": ["iss", "aud", "typ", "sub", "kid", "iat", "exp", "jti"],
                         "verify_exp": False, "verify_iat": False})
        except jwt.PyJWTError as exc:
            raise InvalidAccessToken("malformed or wrongly signed") from exc
        if claims.get("typ") != DEVICE:
            raise InvalidAccessToken("wrong token type")
        now = self._clock.now().timestamp()
        if claims["exp"] + LEEWAY_SECONDS < now or claims["iat"] - LEEWAY_SECONDS > now:
            raise InvalidAccessToken("expired or not yet valid")
        try:
            return DeviceClaims(device_id=uuid.UUID(claims["sub"]), key_id=uuid.UUID(claims["kid"]),
                                expires_at=datetime.fromtimestamp(claims["exp"], self._clock.now().tzinfo))
        except (ValueError, TypeError) as exc:
            raise InvalidAccessToken("bad identifiers") from exc
