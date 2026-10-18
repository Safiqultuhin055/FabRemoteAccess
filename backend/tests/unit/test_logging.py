from __future__ import annotations

import io
import json
import logging

import pytest

from app.log import REDACTED, configure_logging, redact_text, request_id_var

SECRET = "Sup3r-Secret-Value"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJlLXZhbHVl"


@pytest.fixture
def capture():
    stream = io.StringIO()
    handler = configure_logging("DEBUG", "json", stream=stream)
    logger = logging.getLogger("test.redaction")

    def lines() -> list[dict]:
        return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]

    yield logger, lines, stream
    logging.getLogger().removeHandler(handler)


@pytest.mark.parametrize("text", [
    f"DRIVER={{ODBC}};SERVER=x;UID=fr_app;PWD={SECRET};",
    f"DRIVER={{ODBC}};PWD={{{SECRET};x}};Encrypt=yes",
    f"Password={SECRET};",
    f"Authorization: Bearer {SECRET}",
    f'{{"password": "{SECRET}"}}',
    f"refresh_token={SECRET}&x=1",
    f"device_token: '{SECRET}'",
    f"token is {JWT}",
    f"hash $argon2id$v=19$m=65536,t=3,p=4${SECRET}",
])
def test_redact_text_patterns(text):
    redacted = redact_text(text)
    assert SECRET not in redacted and JWT not in redacted
    assert REDACTED in redacted


def test_messages_args_and_extra_are_redacted(capture):
    logger, lines, stream = capture
    logger.info("connecting with %s", f"PWD={SECRET};", extra={"password": SECRET, "user": "fr_app",
                                                              "nested": {"api_key": SECRET, "ok": 1}})
    record = lines()[0]
    assert SECRET not in stream.getvalue()
    assert record["extra"]["password"] == REDACTED
    assert record["extra"]["nested"] == {"api_key": REDACTED, "ok": 1}
    assert record["extra"]["user"] == "fr_app"


def test_exception_text_is_redacted(capture):
    logger, lines, stream = capture
    try:
        raise RuntimeError(f"login failed: PWD={SECRET}; Bearer {JWT}")
    except RuntimeError:
        logger.exception("failure")
    assert SECRET not in stream.getvalue() and JWT not in stream.getvalue()
    assert "RuntimeError" in lines()[0]["exception"]


def test_json_lines_include_request_id_and_level(capture):
    logger, lines, _ = capture
    token = request_id_var.set("req-123")
    try:
        logger.warning("hello")
    finally:
        request_id_var.reset(token)
    record = lines()[0]
    assert record["request_id"] == "req-123" and record["level"] == "WARNING" and record["message"] == "hello"
    assert record["ts"].endswith("Z")


def test_server_access_log_with_query_strings_is_suppressed(capture):
    """Regression: configure_logging re-enabled uvicorn.access, undoing --no-access-log."""
    _, _, stream = capture
    access = logging.getLogger("uvicorn.access")
    access.propagate = True  # what uvicorn's default config leaves behind
    configure_logging("DEBUG", "json", stream=stream)
    access.info('127.0.0.1 - "GET /x?refresh=abc123 HTTP/1.1" 200')
    assert "refresh=abc123" not in stream.getvalue()


def test_text_format_includes_extra_fields():
    stream = io.StringIO()
    handler = configure_logging("INFO", "text", stream=stream)
    try:
        logging.getLogger("app.access").info("request", extra={"method": "GET", "path": "/health/live",
                                                              "status": 200, "token": SECRET})
        line = stream.getvalue()
        assert "method=GET path=/health/live status=200" in line and SECRET not in line
    finally:
        logging.getLogger().removeHandler(handler)


def test_text_format_and_idempotent_configuration():
    stream = io.StringIO()
    configure_logging("INFO", "text", stream=stream)
    handler = configure_logging("INFO", "text", stream=stream)
    try:
        assert sum(getattr(h, "_fabremote", False) for h in logging.getLogger().handlers) == 1
        logging.getLogger("test.text").info("token=%s", SECRET)
        assert SECRET not in stream.getvalue() and "INFO test.text" in stream.getvalue()
    finally:
        logging.getLogger().removeHandler(handler)
