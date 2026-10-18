"""FastAPI application factory.

Run locally (see backend/README.md):
    uvicorn --factory app.main:create_app --app-dir backend --no-access-log
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api import health
from app.api import v1
from app.api.deps import DatabaseGateway
from app.api.errors import register_error_handlers
from app.api.middleware import RequestContextMiddleware
from app.config import Environment, Settings
from app.db.engine import Database
from app.log import configure_logging
from app.security.clock import Clock
from app.security.passwords import PasswordHasher
from app.security.rate_limit import RateLimiter, RateLimits
from app.security.tokens import AccessTokenIssuer, DeviceTokenIssuer
from app.services.auth import AuthService
from app.services.connections import ConnectionService
from app.services.devices import DeviceService
from app.services.invitations import InvitationService

logger = logging.getLogger(__name__)


def _derive_keys(settings: Settings) -> tuple[bytes, bytes, bytes]:
    """Separate JWT, CSRF and device-token keys derived from FR_JWT_SIGNING_KEY (key separation)."""
    if settings.jwt_signing_key:
        master = settings.jwt_signing_key.get_secret_value().encode("utf-8")
    else:
        # Settings validation guarantees this only happens in development or test.
        logger.warning("FR_JWT_SIGNING_KEY is not set: using an ephemeral key; tokens end on restart")
        master = secrets.token_bytes(32)
    derive = lambda label: hmac.new(master, label, hashlib.sha256).digest()  # noqa: E731
    return derive(b"fabremote-jwt-v1"), derive(b"fabremote-csrf-v1"), derive(b"fabremote-device-token-v1")


def create_app(settings: Settings | None = None, database: DatabaseGateway | None = None, *,
               configure_logs: bool = True, clock: Clock | None = None,
               password_hasher: PasswordHasher | None = None) -> FastAPI:
    settings = settings or Settings()
    if configure_logs:
        configure_logging(settings.log_level, settings.log_format)
    database = database or Database(settings)
    clock = clock or Clock()
    hasher = password_hasher or PasswordHasher()
    jwt_key, csrf_key, device_key = _derive_keys(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # No database connection here: readiness is checked on demand by /health/ready.
        logger.info("Starting Fabulous Remote API", extra={"version": __version__, "env": settings.env.value,
                                                           "database": settings.describe_database()})
        yield
        database.dispose()

    app = FastAPI(
        title="Fabulous Remote API",
        version=__version__,
        summary="Consent-based remote assistance: accounts, devices, connection requests and audit.",
        openapi_url="/openapi.json" if settings.openapi_enabled else None,
        docs_url="/docs" if settings.openapi_enabled else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.clock = clock
    app.state.csrf_key = csrf_key
    app.state.rate_limiter = RateLimiter()
    app.state.rate_limits = RateLimits()
    issuer = AccessTokenIssuer(jwt_key, settings.access_token_ttl_seconds, clock)
    app.state.auth_service = AuthService(database.unit_of_work, settings, hasher, issuer, clock)
    app.state.invitation_service = InvitationService(database.unit_of_work, hasher, clock)
    device_tokens = DeviceTokenIssuer(device_key, settings.device_token_ttl_seconds, clock)
    app.state.device_service = DeviceService(database.unit_of_work, settings, clock, device_tokens)
    app.state.connection_service = ConnectionService(database.unit_of_work, settings, clock)

    register_error_handlers(app)
    hsts = settings.env not in (Environment.DEVELOPMENT, Environment.TEST)
    app.add_middleware(RequestContextMiddleware, hsts=hsts)
    app.include_router(health.router)
    app.include_router(v1.router)

    if settings.site_dir:
        # Landing page (web/site) at "/"; mounted last so API routes always take precedence.
        app.mount("/", StaticFiles(directory=settings.site_dir, html=True), name="site")
    else:
        @app.get("/", include_in_schema=False)
        def root():
            # Development: send people to the interactive docs. Elsewhere: name only, no version or links.
            if settings.openapi_enabled:
                return RedirectResponse("/docs", status_code=307)
            return {"service": "Fabulous Remote API"}

    return app
