"""CSRF tokens for cookie-authenticated browser requests.

The token is an HMAC of the auth session ID (stateless; changes with every login). It is
required in `X-CSRF-Token` on unsafe methods when the request is authenticated by cookie.
Bearer-authenticated requests are not exposed to CSRF and do not need it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid


def csrf_token(key: bytes, auth_session_id: uuid.UUID) -> str:
    digest = hmac.new(key, b"fabremote-csrf-v1:" + auth_session_id.bytes, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def csrf_valid(key: bytes, auth_session_id: uuid.UUID, presented: str | None) -> bool:
    if not presented:
        return False
    return hmac.compare_digest(csrf_token(key, auth_session_id), presented)
