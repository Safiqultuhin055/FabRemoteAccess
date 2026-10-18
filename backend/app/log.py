"""Structured logging with secret redaction and request correlation.

Every record passes through RedactionFilter before any handler formats it, so
passwords, tokens, cookies, connection-string secrets and keys are masked in
messages, arguments, extra fields and exception text alike.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

REDACTED = "[REDACTED]"

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

SENSITIVE_KEY = re.compile(
    r"pass(word)?|pwd|secret|token|authorization|cookie|signing_key|private|credential|api_key|nonce|signature",
    re.IGNORECASE)

SENSITIVE_PATTERNS = (
    # ODBC / connection strings: PWD=...; Password=...;
    (re.compile(r"(?i)\b(pwd|password)\s*=\s*(\{(?:[^}]|\}\})*\}|[^;\s]*)"), r"\1=" + REDACTED),
    # Authorization headers
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), r"\1 " + REDACTED),
    # JSON / key=value style secrets: "password": "x", token=x
    (re.compile(r"(?i)([\"']?(?:password|passwd|secret|token|refresh_token|access_token|device_token|"
                r"csrf_token|signing_key|api_key)[\"']?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;}&]+)"),
     r"\1" + REDACTED),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), REDACTED),
    # Argon2 hashes
    (re.compile(r"\$argon2id\$[A-Za-z0-9$=,+/.-]+"), REDACTED),   # PHC strings contain commas
)

_STANDARD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime"}


def redact_text(text: str) -> str:
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_value(key: str, value):
    if SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(key, v) for v in value)
    return value


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Render the message once, redact it, and drop the args so nothing unredacted survives.
        try:
            message = record.getMessage()
        except Exception:  # malformed format string: keep the raw template
            message = str(record.msg)
        record.msg = redact_text(message)
        record.args = None
        for key, value in list(vars(record).items()):
            if key not in _STANDARD_ATTRS:
                setattr(record, key, redact_value(key, value))
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact_text(record.exc_text)
            record.exc_info = None   # formatter must use the redacted text
        record.request_id = request_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
        }
        extra = {k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS and k != "request_id"}
        if extra:
            payload["extra"] = extra
        if record.exc_text:
            payload["exception"] = record.exc_text
        return json.dumps(payload, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    def __init__(self):
        super().__init__("%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        extra = {k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS and k != "request_id"}
        return text + "".join(f" {k}={v}" for k, v in extra.items()) if extra else text


def configure_logging(level: str = "INFO", fmt: str = "json", stream=None) -> logging.Handler:
    """Install one redacting handler on the root logger (idempotent)."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_fabremote", False):
            root.removeHandler(handler)
    handler = logging.StreamHandler(stream or sys.stdout)
    handler._fabremote = True
    handler.addFilter(RedactionFilter())
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    # Server loggers propagate to root so they are redacted and formatted the same way.
    for name in ("uvicorn", "uvicorn.error", "sqlalchemy"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    # uvicorn's access log includes query strings; the app writes its own access line
    # (path only, with request ID), so the server's is always off, with or without --no-access-log.
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.propagate = False
    access.disabled = True
    return handler
