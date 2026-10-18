"""Request ID, security headers, caching policy, access logging and last-resort error handling."""

from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.api.errors import internal_error_response
from app.log import request_id_var

logger = logging.getLogger("app.access")

REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
DOCS_PATHS = ("/docs", "/openapi.json")
API_PATHS = ("/api/", "/health")
API_CSP = "default-src 'none'; frame-ancestors 'none'"
# Landing page: own origin plus the SRI-pinned Bootstrap files; no inline scripts or styles.
SITE_CSP = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'; "
            "font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")


class RequestContextMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, hsts: bool):
        super().__init__(app)
        self._hsts = hsts

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if REQUEST_ID.fullmatch(incoming) else str(uuid.uuid4())
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        try:
            try:
                response = await call_next(request)
            except Exception:
                logger.exception("Unhandled error")
                response = internal_error_response()
            self._apply_headers(request, response, request_id)
            # Path only: query strings are never logged.
            logger.info("request", extra={"method": request.method, "path": request.url.path,
                                          "status": response.status_code,
                                          "duration_ms": round((time.perf_counter() - started) * 1000, 1)})
            return response
        finally:
            request_id_var.reset(token)

    def _apply_headers(self, request: Request, response: Response, request_id: str) -> None:
        h = response.headers
        h["X-Request-ID"] = request_id
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "no-referrer"
        h["X-Frame-Options"] = "DENY"
        path = request.url.path
        if path.startswith(API_PATHS):
            h["Content-Security-Policy"] = API_CSP
            h["Cache-Control"] = "no-store"
        elif not path.startswith(DOCS_PATHS):
            h["Content-Security-Policy"] = SITE_CSP
        if self._hsts:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
