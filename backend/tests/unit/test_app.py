"""Health endpoints, middleware, error envelope and OpenAPI exposure (no database)."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.db.engine import Readiness
from app.domain.errors import ConcurrencyError, ConflictError, DependencyUnavailableError, NotFoundError
from app.main import create_app


@dataclass
class FakeDatabase:
    readiness: Readiness = Readiness("ok", "ok")
    raises: Exception | None = None
    calls: list[str] = field(default_factory=list)
    configured: bool = True

    def check_readiness(self) -> Readiness:
        self.calls.append("check_readiness")
        if self.raises:
            raise self.raises
        return self.readiness

    def unit_of_work(self):
        self.calls.append("unit_of_work")
        raise AssertionError("not used in these tests")

    def dispose(self) -> None:
        self.calls.append("dispose")


class Item(BaseModel):
    name: str
    count: int


def make_client(make_settings, database=None, raise_server_exceptions=True, **settings):
    db = database or FakeDatabase()
    app = create_app(make_settings(**settings), db, configure_logs=False)
    probe = APIRouter(prefix="/api/v1/_probe")

    @probe.post("/items")
    def create_item(item: Item) -> Item:
        return item

    @probe.get("/boom")
    def boom():
        raise RuntimeError("internal detail PWD=hunter2; SELECT * FROM fr.users")

    @probe.get("/conflict")
    def conflict():
        raise ConflictError(constraint="UQ_users_email")

    @probe.get("/missing")
    def missing():
        raise NotFoundError()

    @probe.get("/stale")
    def stale():
        raise ConcurrencyError()

    @probe.get("/down")
    def down():
        raise DependencyUnavailableError()

    app.include_router(probe)
    return TestClient(app, raise_server_exceptions=raise_server_exceptions), db


def test_live_needs_no_database(make_settings):
    client, db = make_client(make_settings)
    with client:
        response = client.get("/health/live")
    assert response.status_code == 200 and response.json() == {"status": "ok"}
    assert "check_readiness" not in db.calls  # startup and liveness never touch the database
    assert db.calls == ["dispose"]


def test_ready_when_database_and_schema_verified(make_settings):
    client, _ = make_client(make_settings)
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": "ok", "schema": "ok"}}


@pytest.mark.parametrize("readiness, body", [
    (Readiness("not_configured", "unknown"), {"database": "not_configured", "schema": "unknown"}),
    (Readiness("error", "unknown"), {"database": "error", "schema": "unknown"}),
    (Readiness("ok", "mismatch"), {"database": "ok", "schema": "mismatch"}),
    (Readiness("ok", "unknown"), {"database": "ok", "schema": "unknown"}),
])
def test_not_ready_states_return_503(make_settings, readiness, body):
    client, _ = make_client(make_settings, FakeDatabase(readiness=readiness))
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "checks": body}


def test_ready_without_configured_database_uses_real_gateway(make_settings):
    app = create_app(make_settings(), configure_logs=False)  # real Database, FR_DB_HOST unset
    response = TestClient(app).get("/health/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["database"] == "not_configured"


def test_unexpected_readiness_failure_is_a_generic_500(make_settings):
    client, _ = make_client(make_settings, FakeDatabase(raises=RuntimeError("PWD=hunter2 at 10.1.2.3")),
                            raise_server_exceptions=False)
    response = client.get("/health/ready")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "hunter2" not in response.text and "10.1.2.3" not in response.text


def test_request_id_is_echoed_or_generated(make_settings):
    client, _ = make_client(make_settings)
    assert client.get("/health/live", headers={"X-Request-ID": "abc-123"}).headers["X-Request-ID"] == "abc-123"
    generated = client.get("/health/live", headers={"X-Request-ID": "bad id\n<script>"}).headers["X-Request-ID"]
    assert generated != "bad id\n<script>" and len(generated) == 36


def test_security_and_cache_headers(make_settings):
    client, _ = make_client(make_settings)
    h = client.get("/health/live").headers
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer" and h["Cache-Control"] == "no-store"
    assert "default-src 'none'" in h["Content-Security-Policy"]
    assert "Strict-Transport-Security" not in h  # development: no HSTS


def test_hsts_outside_development(make_settings):
    client, _ = make_client(make_settings, env="production", jwt_signing_key="k" * 32)
    assert "Strict-Transport-Security" in client.get("/health/live").headers


def test_error_envelope_for_unknown_route_and_method(make_settings):
    client, _ = make_client(make_settings)
    not_found = client.get("/api/v1/does-not-exist", headers={"X-Request-ID": "r-1"})
    assert not_found.status_code == 404
    assert not_found.json() == {"error": {"code": "not_found", "message": "The requested resource was not found.",
                                          "request_id": "r-1"}}
    assert not_found.headers["Cache-Control"] == "no-store"
    assert client.post("/health/live").json()["error"]["code"] == "method_not_allowed"


def test_validation_errors_never_echo_input(make_settings):
    client, _ = make_client(make_settings)
    response = client.post("/api/v1/_probe/items", json={"name": "x", "count": "secret-not-a-number"})
    body = response.json()["error"]
    assert response.status_code == 422 and body["code"] == "validation_error"
    assert body["details"] == [{"field": "count", "issue": "int_parsing"}]
    assert "secret-not-a-number" not in response.text


def test_unhandled_exception_returns_generic_500_with_request_id(make_settings):
    client, _ = make_client(make_settings, raise_server_exceptions=False)
    response = client.get("/api/v1/_probe/boom", headers={"X-Request-ID": "r-500"})
    assert response.status_code == 500
    assert response.json() == {"error": {"code": "internal_error", "message": "An unexpected error occurred.",
                                         "request_id": "r-500"}}
    assert "hunter2" not in response.text and "fr.users" not in response.text
    assert response.headers["X-Request-ID"] == "r-500"


@pytest.mark.parametrize("path, status, code", [
    ("/api/v1/_probe/conflict", 409, "conflict"),
    ("/api/v1/_probe/missing", 404, "not_found"),
    ("/api/v1/_probe/stale", 412, "precondition_failed"),
    ("/api/v1/_probe/down", 503, "dependency_unavailable"),
])
def test_domain_errors_map_to_status(make_settings, path, status, code):
    client, _ = make_client(make_settings)
    response = client.get(path)
    assert response.status_code == status and response.json()["error"]["code"] == code
    assert "UQ_users_email" not in response.text  # constraint names stay server-side


def test_openapi_only_in_development(make_settings):
    dev, _ = make_client(make_settings)
    spec = dev.get("/openapi.json").json()
    assert {"/health/live", "/health/ready"} <= set(spec["paths"])
    assert spec["info"]["title"] == "Fabulous Remote API"
    assert dev.get("/docs").status_code == 200
    prod, _ = make_client(make_settings, env="production", jwt_signing_key="k" * 32)
    assert prod.get("/openapi.json").status_code == 404 and prod.get("/docs").status_code == 404


def test_root_redirects_to_docs_in_development(make_settings):
    client, _ = make_client(make_settings)
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307 and response.headers["location"] == "/docs"


def test_root_reveals_only_the_service_name_outside_development(make_settings):
    client, _ = make_client(make_settings, env="production", jwt_signing_key="k" * 32)
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 200 and response.json() == {"service": "Fabulous Remote API"}


def test_api_is_versioned(make_settings):
    client, _ = make_client(make_settings)
    assert client.post("/api/v1/_probe/items", json={"name": "a", "count": 1}).status_code == 200
    assert client.post("/api/v2/_probe/items", json={"name": "a", "count": 1}).status_code == 404
