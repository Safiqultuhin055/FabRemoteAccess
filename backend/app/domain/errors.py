"""Domain exceptions. The API layer maps each class to an HTTP status (app/api/errors.py)."""

from __future__ import annotations


class DomainError(Exception):
    code = "error"
    default_message = "The request could not be completed."

    def __init__(self, message: str | None = None, *, code: str | None = None):
        super().__init__(message or self.default_message)
        self.message = message or self.default_message
        if code:
            self.code = code


class NotFoundError(DomainError):
    code = "not_found"
    default_message = "The requested resource was not found."


class ConflictError(DomainError):
    """A uniqueness, foreign-key or check rule rejected the change.

    `constraint` carries the database constraint name (e.g. UQ_users_email) so services
    can translate it into a specific code such as `account_exists`.
    """

    code = "conflict"
    default_message = "The request conflicts with the current state of the resource."

    def __init__(self, message: str | None = None, *, code: str | None = None, constraint: str | None = None):
        super().__init__(message, code=code)
        self.constraint = constraint


class ConcurrencyError(DomainError):
    code = "precondition_failed"
    default_message = "The resource was modified by another request."


class DependencyUnavailableError(DomainError):
    code = "dependency_unavailable"
    default_message = "A required service is temporarily unavailable."


class AuthenticationError(DomainError):
    """401. Codes: unauthenticated, invalid_credentials, invalid_token, token_reused."""
    code = "unauthenticated"
    default_message = "Authentication is required."


class PermissionDeniedError(DomainError):
    """403. Codes: forbidden, csrf_failed."""
    code = "forbidden"
    default_message = "This action is not allowed."


class RateLimitedError(DomainError):
    code = "rate_limited"
    default_message = "Too many requests. Try again later."

    def __init__(self, retry_after: int, message: str | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class ProofRejectedError(DomainError):
    """400. A device challenge or signature was not accepted. Codes: invalid_challenge, invalid_signature."""
    code = "invalid_challenge"
    default_message = "The device could not prove its identity. Request a new challenge and try again."


class PreconditionRequiredError(DomainError):
    code = "precondition_required"
    default_message = "This request needs an If-Match header with the resource's ETag."


class InputRejectedError(DomainError):
    """422 for a value that passed schema validation but breaks a business rule."""
    code = "validation_error"
    default_message = "Request validation failed."

    def __init__(self, field: str, issue: str, message: str | None = None):
        super().__init__(message)
        self.field = field
        self.issue = issue
