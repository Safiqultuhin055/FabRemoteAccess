"""/api/v1/auth: invitation acceptance, desktop tokens, browser sessions, logout, current user."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.auth_deps import (SESSION_COOKIE, Context, CurrentPrincipal, enforce_rate_limit, get_auth_service,
                               get_invitation_service, same_origin)
from app.api.v1.schemas import (AcceptedOut, AcceptInvitationIn, CsrfOut, LoginIn, RefreshIn, TokenOut, UserOut)
from app.domain.errors import AuthenticationError, PermissionDeniedError
from app.security.csrf import csrf_token
from app.services.auth import AuthenticatedUser, AuthService, DesktopTokens
from app.services.invitations import InvitationService

router = APIRouter(prefix="/auth", tags=["auth"])

Auth = Annotated[AuthService, Depends(get_auth_service)]
Invitations = Annotated[InvitationService, Depends(get_invitation_service)]


def user_out(account: AuthenticatedUser) -> UserOut:
    u = account.user
    return UserOut(id=u.id, email=u.email, display_name=u.display_name, status=u.status,
                   email_verified_at=u.email_verified_at, roles=sorted(account.roles), created_at=u.created_at)


def token_out(tokens: DesktopTokens) -> TokenOut:
    return TokenOut(access_token=tokens.access_token, expires_in=tokens.access_expires_in,
                    refresh_token=tokens.refresh_token, refresh_expires_in=tokens.refresh_expires_in,
                    user=user_out(tokens.account))


def _limit_login(request: Request, email: str, ctx) -> None:
    limits = request.app.state.rate_limits
    enforce_rate_limit(request, limits.login_per_ip, "login-ip", ctx.ip or "")
    enforce_rate_limit(request, limits.login_per_account_ip, "login-account", email.strip().lower(), ctx.ip or "")


@router.post("/invitations/accept", status_code=status.HTTP_201_CREATED, response_model=AcceptedOut,
             summary="Accept an invitation and create the account")
def accept_invitation(body: AcceptInvitationIn, request: Request, ctx: Context, invitations: Invitations) -> AcceptedOut:
    enforce_rate_limit(request, request.app.state.rate_limits.invitation_accept_per_ip, "accept-ip", ctx.ip or "")
    user, roles = invitations.accept(body.token, body.display_name, body.password, ctx)
    return AcceptedOut(user=user_out(AuthenticatedUser(user, roles)))


@router.post("/token", response_model=TokenOut, summary="Desktop login: access + refresh token")
def desktop_login(body: LoginIn, request: Request, ctx: Context, auth: Auth) -> TokenOut:
    _limit_login(request, body.email, ctx)
    return token_out(auth.login_desktop(body.email, body.password, ctx))


@router.post("/refresh", response_model=TokenOut, summary="Rotate a desktop refresh token")
def refresh(body: RefreshIn, request: Request, ctx: Context, auth: Auth) -> TokenOut:
    limits = request.app.state.rate_limits
    enforce_rate_limit(request, limits.refresh_per_ip, "refresh-ip", ctx.ip or "")
    enforce_rate_limit(request, limits.refresh_per_token, "refresh-token", body.refresh_token)
    return token_out(auth.refresh(body.refresh_token, ctx))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="End the current session")
def logout(principal: CurrentPrincipal, ctx: Context, auth: Auth) -> Response:
    auth.logout(principal, ctx)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    if principal.via_cookie:
        response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response


@router.post("/web/login", status_code=status.HTTP_204_NO_CONTENT, summary="Browser login: session cookie")
def web_login(body: LoginIn, request: Request, ctx: Context, auth: Auth) -> Response:
    # Login CSRF: a foreign site must not be able to sign the browser into another account.
    if not same_origin(request):
        raise PermissionDeniedError("CSRF validation failed.", code="csrf_failed")
    _limit_login(request, body.email, ctx)
    session = auth.login_web(body.email, body.password, ctx)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    max_age = int((session.expires_at - request.app.state.clock.now()).total_seconds())
    response.set_cookie(SESSION_COOKIE, session.session_token, max_age=max_age, path="/", secure=True,
                        httponly=True, samesite="lax")
    return response


@router.post("/web/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Browser logout")
def web_logout(principal: CurrentPrincipal, ctx: Context, auth: Auth) -> Response:
    if not principal.via_cookie:
        raise AuthenticationError()
    auth.logout(principal, ctx)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response


@router.get("/csrf", response_model=CsrfOut, summary="CSRF token for the browser session")
def csrf(principal: CurrentPrincipal, request: Request) -> CsrfOut:
    if not principal.via_cookie:
        raise AuthenticationError()
    return CsrfOut(csrf_token=csrf_token(request.app.state.csrf_key, principal.auth_session_id))


@router.get("/me", response_model=UserOut, summary="The signed-in user")
def me(principal: CurrentPrincipal, auth: Auth) -> UserOut:
    return user_out(auth.current_user(principal))
