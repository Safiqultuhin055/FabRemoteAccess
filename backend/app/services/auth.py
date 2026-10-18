"""Authentication: login, refresh-token rotation with reuse detection, logout, request authentication.

Rules (docs/API_CONTRACTS.md sections 3 and 5.2):
- Unknown account, wrong password, locked or inactive account all give the same
  `invalid_credentials`; unknown accounts still pay for one Argon2 verification.
- Refresh tokens are single use. Presenting a consumed token (replay, or a concurrent
  refresh with the same token) revokes the whole auth session (`token_reuse`).
- Access tokens are checked against their auth session on every request, so logout and
  revocation take effect immediately, not when the token expires.
- Failure paths commit their audit event and counters before raising.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.config import Settings
from app.db.models import AuthSession, AuthToken, User
from app.domain.constants import AuditOutcome, AuthSessionRevokedReason, ClientType, Role, TokenType, UserStatus
from app.domain.constants import EMAIL_MAX_LENGTH, USER_AGENT_MAX_LENGTH
from app.domain.errors import AuthenticationError
from app.domain.repositories import UnitOfWork, UnitOfWorkFactory
from app.security.clock import Clock
from app.security.passwords import PasswordHasher
from app.security.tokens import AccessTokenIssuer, InvalidAccessToken, hash_token, new_opaque_token
from app.services.context import Principal, RequestContext

TOUCH_INTERVAL = timedelta(seconds=60)


@dataclass(frozen=True)
class AuthenticatedUser:
    user: User
    roles: frozenset[Role]


@dataclass(frozen=True)
class DesktopTokens:
    access_token: str
    access_expires_in: int
    refresh_token: str
    refresh_expires_in: int
    account: AuthenticatedUser


@dataclass(frozen=True)
class WebSession:
    session_token: str
    auth_session_id: uuid.UUID
    expires_at: datetime
    account: AuthenticatedUser


def _invalid_credentials() -> AuthenticationError:
    return AuthenticationError("Email or password is incorrect.", code="invalid_credentials")


def _invalid_token() -> AuthenticationError:
    return AuthenticationError("The token is invalid or has expired.", code="invalid_token")


class AuthService:
    def __init__(self, uow_factory: UnitOfWorkFactory, settings: Settings, hasher: PasswordHasher,
                 issuer: AccessTokenIssuer, clock: Clock):
        self._uow = uow_factory
        self._settings = settings
        self._hasher = hasher
        self._issuer = issuer
        self._clock = clock

    # ------------------------------------------------------------------ login

    def _check_credentials(self, uow: UnitOfWork, email: str, password: str, client_type: ClientType,
                           ctx: RequestContext) -> AuthenticatedUser:
        now = self._clock.now()
        email = email.strip().lower()
        user = uow.users.get_by_email(email) if 0 < len(email) <= EMAIL_MAX_LENGTH else None

        def fail(reason: str, actor: uuid.UUID | None = None):
            # The attempted email is never recorded: people sometimes type a password into it.
            uow.audit.add("auth.login", AuditOutcome.FAILURE, actor_user_id=actor, ip_address=ctx.ip,
                          request_id=ctx.request_id, details={"reason": reason, "client": client_type.value})
            uow.commit()
            raise _invalid_credentials()

        if user is None:
            self._hasher.dummy_verify(password)
            fail("unknown_account")
        if user.locked_until and user.locked_until > now:
            self._hasher.dummy_verify(password)
            fail("locked", user.id)
        if not self._hasher.verify(user.password_hash, password):
            uow.users.record_login_failure(user.id, now, self._settings.login_lockout_threshold,
                                           self._settings.login_lockout_minutes)
            fail("bad_password", user.id)
        if user.status is not UserStatus.ACTIVE:
            fail("account_inactive", user.id)

        uow.users.record_login_success(user.id, now)
        if self._hasher.needs_rehash(user.password_hash):
            uow.users.replace_password_hash(user.id, self._hasher.hash(password), now)
        return AuthenticatedUser(user, frozenset(uow.users.roles(user.id)))

    def _open_session(self, uow: UnitOfWork, user_id: uuid.UUID, client_type: ClientType, lifetime: timedelta,
                      token_type: TokenType, ctx: RequestContext) -> tuple[AuthSession, str]:
        now = self._clock.now()
        auth_session = uow.auth_sessions.add(AuthSession(
            user_id=user_id, client_type=client_type, created_at=now, last_used_at=now, expires_at=now + lifetime,
            user_agent=(ctx.user_agent or "")[:USER_AGENT_MAX_LENGTH] or None, created_ip=ctx.ip))
        token = new_opaque_token()
        uow.auth_tokens.add(AuthToken(auth_session_id=auth_session.id, token_type=token_type,
                                      token_hash=hash_token(token), issued_at=now,
                                      expires_at=auth_session.expires_at))
        uow.audit.add("auth.login", AuditOutcome.SUCCESS, actor_user_id=user_id, subject_type="auth_session",
                      subject_id=str(auth_session.id), ip_address=ctx.ip, request_id=ctx.request_id,
                      details={"client": client_type.value})
        return auth_session, token

    def login_desktop(self, email: str, password: str, ctx: RequestContext) -> DesktopTokens:
        lifetime = timedelta(days=self._settings.refresh_token_ttl_days)
        with self._uow() as uow:
            account = self._check_credentials(uow, email, password, ClientType.DESKTOP, ctx)
            auth_session, refresh = self._open_session(uow, account.user.id, ClientType.DESKTOP, lifetime,
                                                       TokenType.REFRESH, ctx)
            uow.commit()
        return self._desktop_tokens(account, auth_session, refresh)

    def login_web(self, email: str, password: str, ctx: RequestContext) -> WebSession:
        lifetime = timedelta(days=self._settings.web_session_absolute_days)
        with self._uow() as uow:
            account = self._check_credentials(uow, email, password, ClientType.WEB, ctx)
            auth_session, token = self._open_session(uow, account.user.id, ClientType.WEB, lifetime,
                                                     TokenType.WEB, ctx)
            uow.commit()
        return WebSession(token, auth_session.id, auth_session.expires_at, account)

    def _desktop_tokens(self, account: AuthenticatedUser, auth_session: AuthSession, refresh: str) -> DesktopTokens:
        refresh_in = int((auth_session.expires_at - self._clock.now()).total_seconds())
        return DesktopTokens(self._issuer.issue(account.user.id, auth_session.id, auth_session.device_id),
                             self._issuer.ttl_seconds, refresh, max(refresh_in, 0), account)

    # ---------------------------------------------------------------- refresh

    def refresh(self, refresh_token: str, ctx: RequestContext) -> DesktopTokens:
        now = self._clock.now()
        with self._uow() as uow:
            token = uow.auth_tokens.find_by_hash(hash_token(refresh_token))
            if token is None or token.token_type is not TokenType.REFRESH:
                uow.audit.add("auth.refresh", AuditOutcome.FAILURE, ip_address=ctx.ip, request_id=ctx.request_id,
                              details={"reason": "unknown_token"})
                uow.commit()
                raise _invalid_token()
            auth_session = uow.auth_sessions.get(token.auth_session_id)

            dead = (token.revoked_at is not None or token.expires_at <= now
                    or auth_session.revoked_at is not None or auth_session.expires_at <= now)
            if token.consumed_at is not None or (not dead and not uow.auth_tokens.consume(token.id, now)):
                # Replay of a used token, or a concurrent refresh that lost the race: treat as theft.
                uow.auth_sessions.revoke(auth_session.id, AuthSessionRevokedReason.TOKEN_REUSE, now)
                uow.audit.add("auth.token_reuse", AuditOutcome.DENIED, actor_user_id=auth_session.user_id,
                              subject_type="auth_session", subject_id=str(auth_session.id), ip_address=ctx.ip,
                              request_id=ctx.request_id)
                uow.commit()
                raise AuthenticationError("The refresh token was already used; the session has been revoked.",
                                          code="token_reused")
            if dead:
                uow.audit.add("auth.refresh", AuditOutcome.FAILURE, actor_user_id=auth_session.user_id,
                              subject_type="auth_session", subject_id=str(auth_session.id), ip_address=ctx.ip,
                              request_id=ctx.request_id, details={"reason": "expired_or_revoked"})
                uow.commit()
                raise _invalid_token()

            user = uow.users.get(auth_session.user_id)
            if user is None or user.status is not UserStatus.ACTIVE:
                uow.auth_sessions.revoke(auth_session.id, AuthSessionRevokedReason.USER_DISABLED, now)
                uow.commit()
                raise _invalid_token()

            new_refresh = new_opaque_token()
            uow.auth_tokens.add(AuthToken(auth_session_id=auth_session.id, token_type=TokenType.REFRESH,
                                          token_hash=hash_token(new_refresh), issued_at=now,
                                          expires_at=auth_session.expires_at))
            uow.auth_sessions.touch(auth_session.id, now)
            account = AuthenticatedUser(user, frozenset(uow.users.roles(user.id)))
            uow.commit()
        return self._desktop_tokens(account, auth_session, new_refresh)

    # ----------------------------------------------------------------- logout

    def logout(self, principal: Principal, ctx: RequestContext) -> None:
        now = self._clock.now()
        with self._uow() as uow:
            if uow.auth_sessions.revoke(principal.auth_session_id, AuthSessionRevokedReason.LOGOUT, now):
                uow.audit.add("auth.logout", AuditOutcome.SUCCESS, actor_user_id=principal.user_id,
                              subject_type="auth_session", subject_id=str(principal.auth_session_id),
                              ip_address=ctx.ip, request_id=ctx.request_id)
            uow.commit()

    # --------------------------------------------------------- authentication

    def _principal(self, uow: UnitOfWork, auth_session: AuthSession | None, via_cookie: bool) -> Principal:
        now = self._clock.now()
        if auth_session is None or auth_session.revoked_at is not None or auth_session.expires_at <= now:
            raise _invalid_token()
        user = uow.users.get(auth_session.user_id)
        if user is None or user.status is not UserStatus.ACTIVE:
            raise _invalid_token()
        return Principal(user.id, auth_session.id, frozenset(uow.users.roles(user.id)), auth_session.client_type,
                         via_cookie=via_cookie, device_id=auth_session.device_id)

    def authenticate_bearer(self, access_token: str) -> Principal:
        try:
            claims = self._issuer.verify(access_token)
        except InvalidAccessToken:
            raise _invalid_token() from None
        with self._uow() as uow:
            auth_session = uow.auth_sessions.get(claims.auth_session_id)
            if auth_session is not None and auth_session.user_id != claims.user_id:
                raise _invalid_token()
            return self._principal(uow, auth_session, via_cookie=False)

    def authenticate_cookie(self, session_token: str) -> Principal:
        now = self._clock.now()
        idle = timedelta(hours=self._settings.web_session_idle_hours)
        with self._uow() as uow:
            token = uow.auth_tokens.find_by_hash(hash_token(session_token))
            if (token is None or token.token_type is not TokenType.WEB or token.revoked_at is not None
                    or token.expires_at <= now):
                raise _invalid_token()
            auth_session = uow.auth_sessions.get(token.auth_session_id)
            principal = self._principal(uow, auth_session, via_cookie=True)
            last_used = auth_session.last_used_at or auth_session.created_at
            if last_used + idle <= now:
                raise _invalid_token()
            if now - last_used >= TOUCH_INTERVAL:
                uow.auth_sessions.touch(auth_session.id, now)
                uow.commit()
            return principal

    def current_user(self, principal: Principal) -> AuthenticatedUser:
        with self._uow() as uow:
            user = uow.users.get(principal.user_id)
            if user is None:
                raise _invalid_token()
            return AuthenticatedUser(user, frozenset(uow.users.roles(user.id)))
