"""Authentication dependencies: who is calling, and are they allowed to make this request.

Credential handling (docs/API_CONTRACTS.md section 3):
- `Authorization: Bearer <access token>`: desktop client. Cookies are ignored when this
  header is present, and CSRF does not apply.
- `__Host-fr_session` cookie: browser. Unsafe methods additionally need a matching
  `X-CSRF-Token` header, and a cross-origin `Origin` / `Sec-Fetch-Site` is refused.
- `X-Device-Token: <device token>`: a device that signed a challenge with its key. Used by
  the computer being helped (no account) and, next to the bearer token, by a requester to
  prove which device it is asking from. Never a cookie, so CSRF does not apply.
"""

from __future__ import annotations

from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, Request

from app.domain.constants import Role
from app.domain.errors import AuthenticationError, PermissionDeniedError, RateLimitedError
from app.log import request_id_var
from app.security.csrf import csrf_valid
from app.security.rate_limit import Limit
from app.services.auth import AuthService
from app.services.context import DevicePrincipal, Principal, RequestContext
from app.services.invitations import InvitationService

SESSION_COOKIE = "__Host-fr_session"
CSRF_HEADER = "X-CSRF-Token"
DEVICE_TOKEN_HEADER = "X-Device-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def request_context(request: Request) -> RequestContext:
    user_agent = request.headers.get("user-agent")
    return RequestContext(ip=request.client.host if request.client else None,
                          user_agent=user_agent[:256] if user_agent else None,
                          request_id=request_id_var.get())


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def get_invitation_service(request: Request) -> InvitationService:
    return request.app.state.invitation_service


def enforce_rate_limit(request: Request, limit: Limit, *parts: str) -> None:
    limiter = request.app.state.rate_limiter
    retry_after = limiter.hit(limiter.key(*parts), limit)
    if retry_after is not None:
        raise RateLimitedError(retry_after)


def same_origin(request: Request) -> bool:
    """False for cross-site requests (Sec-Fetch-Site) or a foreign Origin header."""
    if request.headers.get("sec-fetch-site") == "cross-site":
        return False
    origin = request.headers.get("origin")
    return origin is None or urlsplit(origin).netloc == request.headers.get("host")


def current_principal(request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]) -> Principal:
    header = request.headers.get("authorization")
    if header is not None:
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise AuthenticationError("The token is invalid or has expired.", code="invalid_token")
        return auth.authenticate_bearer(token.strip())
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        raise AuthenticationError()
    principal = auth.authenticate_cookie(cookie)
    if request.method not in SAFE_METHODS:
        if not same_origin(request) or not csrf_valid(request.app.state.csrf_key, principal.auth_session_id,
                                                       request.headers.get(CSRF_HEADER)):
            raise PermissionDeniedError("CSRF validation failed.", code="csrf_failed")
    return principal


def require_admin(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
    if not principal.has(Role.ADMIN):
        raise PermissionDeniedError()
    return principal


def _device_token(request: Request) -> str | None:
    value = request.headers.get(DEVICE_TOKEN_HEADER)
    return value.strip() if value and value.strip() else None


def current_device(request: Request) -> DevicePrincipal:
    """The calling device, proven by a device token (`X-Device-Token`). Needs no user account."""
    token = _device_token(request)
    if token is None:
        raise AuthenticationError("A device token is required.", code="device_token_required")
    return request.app.state.device_service.authenticate_device(token)


def session_actor(request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]
                  ) -> tuple[Principal | None, DevicePrincipal | None]:
    """A signed-in user, a device, or both. At least one is required."""
    has_user = request.headers.get("authorization") is not None or bool(request.cookies.get(SESSION_COOKIE))
    principal = current_principal(request, auth) if has_user else None
    device = current_device(request) if _device_token(request) else None
    if principal is None and device is None:
        raise AuthenticationError()
    return principal, device


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]
AdminPrincipal = Annotated[Principal, Depends(require_admin)]
CurrentDevice = Annotated[DevicePrincipal, Depends(current_device)]
SessionActor = Annotated[tuple[Principal | None, DevicePrincipal | None], Depends(session_actor)]
Context = Annotated[RequestContext, Depends(request_context)]
