"""Uniform error envelope (docs/API_CONTRACTS.md section 2.1).

Messages are generic and never include exception text, SQL, input values or stack traces.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.domain.errors import (AuthenticationError, ConcurrencyError, ConflictError, DependencyUnavailableError,
                               DomainError, GoneError, InputRejectedError, NotFoundError, PermissionDeniedError,
                               PreconditionRequiredError, ProofRejectedError, RateLimitedError)
from app.log import request_id_var

logger = logging.getLogger(__name__)

DOMAIN_STATUS: dict[type[DomainError], int] = {
    ProofRejectedError: 400,
    AuthenticationError: 401,
    PermissionDeniedError: 403,
    NotFoundError: 404,
    ConflictError: 409,
    ConcurrencyError: 412,
    GoneError: 410,
    PreconditionRequiredError: 428,
    InputRejectedError: 422,
    RateLimitedError: 429,
    DependencyUnavailableError: 503,
}

HTTP_CODES = {
    400: ("bad_request", "The request is malformed."),
    401: ("unauthenticated", "Authentication is required."),
    403: ("forbidden", "This action is not allowed."),
    404: ("not_found", "The requested resource was not found."),
    405: ("method_not_allowed", "The method is not allowed for this resource."),
    406: ("not_acceptable", "The requested representation is not available."),
    413: ("payload_too_large", "The request body is too large."),
    415: ("unsupported_media_type", "The request content type is not supported."),
    429: ("rate_limited", "Too many requests."),
}


def error_response(status: int, code: str, message: str, details: list[dict] | None = None,
                   headers: dict[str, str] | None = None) -> JSONResponse:
    body: dict = {"code": code, "message": message, "request_id": request_id_var.get()}
    if details:
        body["details"] = details
    return JSONResponse({"error": body}, status_code=status, headers=headers)


def internal_error_response() -> JSONResponse:
    return error_response(500, "internal_error", "An unexpected error occurred.")


async def _domain_error(request: Request, exc: DomainError) -> JSONResponse:
    status = next((s for cls, s in DOMAIN_STATUS.items() if isinstance(exc, cls)), 400)
    if isinstance(exc, ConflictError) and exc.constraint:
        logger.info("Constraint conflict", extra={"constraint": exc.constraint})
    headers, details = None, None
    if isinstance(exc, AuthenticationError):
        headers = {"WWW-Authenticate": "Bearer"}
    elif isinstance(exc, RateLimitedError):
        headers = {"Retry-After": str(exc.retry_after)}
    elif isinstance(exc, InputRejectedError):
        details = [{"field": exc.field, "issue": exc.issue}]
    return error_response(status, exc.code, exc.message, details, headers)


async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    details = [{"field": ".".join(str(p) for p in err.get("loc", ())[1:]) or str(err.get("loc", ("",))[0]),
                "issue": err.get("type", "invalid")} for err in exc.errors()]
    return error_response(422, "validation_error", "Request validation failed.", details)


async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code, message = HTTP_CODES.get(exc.status_code, ("http_error", "The request could not be completed."))
    return error_response(exc.status_code, code, message, headers=getattr(exc, "headers", None))


async def _unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error")
    return internal_error_response()


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(DomainError, _domain_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(Exception, _unexpected_error)
