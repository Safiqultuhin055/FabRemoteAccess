"""API client against a mocked transport (no network)."""

from __future__ import annotations

import json
import threading

import httpx
import pytest

from fabremote.api_client import ApiClient, ApiError, validate_base_url

USER = {"id": "u1", "email": "a@example.com", "display_name": "Alex Doe", "roles": ["user"]}


class FakeServer:
    """Minimal stand-in for the auth API with rotating tokens."""

    def __init__(self):
        self.access, self.refresh = "access-1", "refresh-1"
        self.counter = 1
        self.expired = False
        self.refresh_calls = 0
        self.logout_calls = 0
        self.lock = threading.Lock()

    def tokens(self) -> dict:
        return {"access_token": self.access, "refresh_token": self.refresh, "token_type": "Bearer",
                "expires_in": 600, "refresh_expires_in": 86400, "user": USER}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/health/live":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/api/v1/auth/token":
            body = json.loads(request.content)
            if body["password"] != "right":
                return httpx.Response(401, json={"error": {"code": "invalid_credentials", "message": "x"}})
            return httpx.Response(200, json=self.tokens())
        if path == "/api/v1/auth/refresh":
            with self.lock:
                self.refresh_calls += 1
                if json.loads(request.content)["refresh_token"] != self.refresh:
                    return httpx.Response(401, json={"error": {"code": "token_reused", "message": "x"}})
                self.counter += 1
                self.access, self.refresh = f"access-{self.counter}", f"refresh-{self.counter}"
                self.expired = False
                return httpx.Response(200, json=self.tokens())
        auth = request.headers.get("authorization", "")
        if path == "/api/v1/auth/logout":
            self.logout_calls += 1
            return httpx.Response(204)
        if path == "/api/v1/auth/me":
            if self.expired or auth != f"Bearer {self.access}":
                return httpx.Response(401, json={"error": {"code": "invalid_token", "message": "x"}})
            return httpx.Response(200, json=USER)
        return httpx.Response(404, json={"error": {"code": "not_found", "message": "x"}})


@pytest.fixture
def server():
    return FakeServer()


@pytest.fixture
def client(server):
    return ApiClient("http://127.0.0.1:8765", transport=httpx.MockTransport(server.handler))


def test_login_stores_tokens_and_returns_user(client):
    assert client.login("a@example.com", "right") == USER
    assert client.signed_in and client.me()["email"] == "a@example.com"


def test_wrong_password_maps_to_api_error(client):
    with pytest.raises(ApiError) as info:
        client.login("a@example.com", "wrong")
    assert info.value.status == 401 and info.value.code == "invalid_credentials"
    assert not client.signed_in


def test_expired_access_token_is_refreshed_once_and_retried(client, server):
    client.login("a@example.com", "right")
    server.expired = True
    assert client.me() == USER
    assert server.refresh_calls == 1


def test_failed_refresh_ends_the_session(client, server):
    client.login("a@example.com", "right")
    server.expired = True
    server.refresh = "rotated-elsewhere"
    with pytest.raises(ApiError) as info:
        client.me()
    assert info.value.code == "session_expired" and not client.signed_in


def test_concurrent_requests_share_one_refresh(client, server):
    """The server revokes a session when one refresh token is used twice; the client must serialise."""
    client.login("a@example.com", "right")
    server.expired = True
    results, barrier = [], threading.Barrier(4)

    def call():
        barrier.wait()
        results.append(client.me())

    threads = [threading.Thread(target=call) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert results == [USER] * 4 and server.refresh_calls == 1


def test_logout_always_discards_tokens(client, server):
    client.login("a@example.com", "right")
    client.logout()
    assert not client.signed_in and server.logout_calls == 1
    with pytest.raises(ApiError):
        client.me()


def test_network_failure_is_reported_without_details():
    def boom(request):
        raise httpx.ConnectError("refused")
    client = ApiClient("http://127.0.0.1:1", transport=httpx.MockTransport(boom))
    with pytest.raises(ApiError) as info:
        client.login("a@example.com", "right")
    assert info.value.code == "network_error"
    assert client.health() is False


@pytest.mark.parametrize("url, ok", [
    ("https://remote.example.com", True), ("http://127.0.0.1:8765", True), ("http://localhost:8765/", True),
    ("http://192.0.2.10:8765", False), ("ftp://example.com", False), ("example.com", False),
])
def test_server_address_rules(url, ok):
    if ok:
        assert validate_base_url(url) == url.rstrip("/")
    else:
        with pytest.raises(ValueError):
            validate_base_url(url)


def test_tokens_never_appear_in_repr(client):
    client.login("a@example.com", "right")
    assert "access-1" not in repr(client) and "refresh-1" not in repr(client)
