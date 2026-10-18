"""HTTP client for the Fabulous Remote API.

Two independent credentials, both kept in memory only:
- the user's bearer access + refresh token (signing in; needed to ask for a connection);
- this computer's device token (X-Device-Token), obtained by signing a challenge with the
  device key; needs no account. Signing out keeps the device token, because the computer
  stays registered and reachable for requests.

Persisting the refresh token belongs in Windows Credential Manager (planned). Refresh calls
are serialised because the server treats two refreshes with the same token as theft.
"""

from __future__ import annotations

import os
import ssl
import threading
from urllib.parse import urlsplit

import httpx
import truststore

from fabremote import __version__

LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
# 401 codes about this computer's device token, not the user's sign-in: never refresh or sign out for them.
DEVICE_TOKEN_ERRORS = ("invalid_device_token", "device_token_required")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def tls_context() -> ssl.SSLContext:
    """Certificate verification is always on.

    Default: the Windows certificate store (truststore), so a company or internal CA that is
    installed on the PC is trusted, exactly like in a browser. FR_DESKTOP_CA_BUNDLE may name
    an extra PEM file with the internal CA instead. There is deliberately no way to disable
    verification.
    """
    bundle = os.environ.get("FR_DESKTOP_CA_BUNDLE")
    if bundle:
        return ssl.create_default_context(cafile=bundle)
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def validate_base_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url.rstrip("/")
    if parts.scheme == "http" and parts.hostname in LOCAL_HOSTS:
        return url.rstrip("/")
    raise ValueError("The server address must use https (http is allowed only for this computer).")


class ApiClient:
    def __init__(self, base_url: str, *, transport: httpx.BaseTransport | None = None, timeout: float = 10.0):
        self.base_url = validate_base_url(base_url)
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport, verify=tls_context(),
                                  headers={"User-Agent": f"FabulousRemote-Desktop/{__version__}"})
        self._lock = threading.Lock()
        self._access: str | None = None
        self._refresh: str | None = None
        self._device_token: str | None = None

    def __repr__(self) -> str:   # never expose tokens
        return f"ApiClient(base_url={self.base_url!r}, signed_in={self.signed_in})"

    @property
    def signed_in(self) -> bool:
        return self._access is not None

    @property
    def has_device_token(self) -> bool:
        return self._device_token is not None

    def clear_device_token(self) -> None:
        self._device_token = None

    # ------------------------------------------------------------- transport

    def _send(self, method: str, path: str, **kwargs) -> httpx.Response:
        try:
            return self._http.request(method, path, **kwargs)
        except httpx.HTTPError:
            raise ApiError(0, "network_error", f"Cannot reach the server at {self.base_url}.") from None

    @staticmethod
    def _raise_for(response: httpx.Response) -> None:
        if response.is_success:
            return
        try:
            error = response.json()["error"]
            code, message = error.get("code", "error"), error.get("message", "Request failed.")
        except (ValueError, KeyError, TypeError):
            code, message = "error", f"Request failed ({response.status_code})."
        raise ApiError(response.status_code, code, message)

    def _store(self, tokens: dict) -> None:
        self._access = tokens["access_token"]
        self._refresh = tokens["refresh_token"]

    def _clear(self) -> None:
        self._access = self._refresh = None

    def _refresh_tokens(self, stale_access: str | None) -> None:
        with self._lock:
            if self._access != stale_access:      # another thread already refreshed
                return
            if not self._refresh:
                raise ApiError(401, "session_expired", "Your session has ended. Please sign in again.")
            response = self._send("POST", "/api/v1/auth/refresh", json={"refresh_token": self._refresh})
            if not response.is_success:
                self._clear()
                raise ApiError(401, "session_expired", "Your session has ended. Please sign in again.")
            self._store(response.json())

    def _device_headers(self) -> dict:
        if self._device_token is None:
            raise ApiError(401, "device_token_required", "This computer has not proved its identity yet.")
        return {"X-Device-Token": self._device_token}

    def _authorized(self, method: str, path: str, *, device: bool = False, **kwargs) -> httpx.Response:
        """Bearer request (refreshing once on 401); `device` adds this computer's device token."""
        if not self.signed_in:
            raise ApiError(401, "unauthenticated", "Please sign in.")
        extra = self._device_headers() if device else {}
        access = self._access
        response = self._send(method, path, headers={"Authorization": f"Bearer {access}", **extra}, **kwargs)
        if response.status_code == 401 and self._error_code(response) not in DEVICE_TOKEN_ERRORS:
            self._refresh_tokens(access)
            response = self._send(method, path, headers={"Authorization": f"Bearer {self._access}", **extra},
                                  **kwargs)
            if response.status_code == 401 and self._error_code(response) not in DEVICE_TOKEN_ERRORS:
                self._clear()
        self._raise_for(response)
        return response

    def _as_device(self, method: str, path: str, **kwargs) -> httpx.Response:
        response = self._send(method, path, headers=self._device_headers(), **kwargs)
        self._raise_for(response)
        return response

    @staticmethod
    def _error_code(response: httpx.Response) -> str | None:
        try:
            return response.json()["error"]["code"]
        except (ValueError, KeyError, TypeError):
            return None

    # ------------------------------------------------------------------ API

    def health(self) -> bool:
        try:
            response = self._send("GET", "/health/live")
        except ApiError:
            return False
        return response.is_success and response.json().get("status") == "ok"

    def login(self, email: str, password: str) -> dict:
        response = self._send("POST", "/api/v1/auth/token", json={"email": email, "password": password})
        self._raise_for(response)
        tokens = response.json()
        self._store(tokens)
        return tokens["user"]

    def me(self) -> dict:
        return self._authorized("GET", "/api/v1/auth/me").json()

    # -------------------------------------------------------------- devices

    def registration_challenge(self, public_key_b64: str, device_name: str, os_name: str | None,
                               os_version: str | None, client_version: str | None) -> dict:
        body = {"public_key": public_key_b64, "device_name": device_name, "os_name": os_name,
                "os_version": os_version, "client_version": client_version}
        return self._authorized("POST", "/api/v1/devices/registration-challenge", json=body).json()

    def register_device(self, challenge_id: str, signature_b64: str) -> dict:
        return self._authorized("POST", "/api/v1/devices/register",
                                json={"challenge_id": challenge_id, "signature": signature_b64}).json()

    def get_device(self, device_id: str) -> dict:
        return self._authorized("GET", f"/api/v1/devices/{device_id}").json()

    def list_devices(self) -> list[dict]:
        return self._authorized("GET", "/api/v1/devices").json()["items"]

    def device_challenge(self, device_id: str) -> dict:
        return self._authorized("POST", f"/api/v1/devices/{device_id}/challenge").json()

    def device_presence(self, device_id: str, challenge_id: str, signature_b64: str) -> dict:
        return self._authorized("POST", f"/api/v1/devices/{device_id}/presence",
                                json={"challenge_id": challenge_id, "signature": signature_b64}).json()

    # --------------------------------------------- this computer, no account (device token)

    def anonymous_registration_challenge(self, public_key_b64: str, device_name: str, os_name: str | None,
                                         os_version: str | None, client_version: str | None) -> dict:
        body = {"public_key": public_key_b64, "device_name": device_name, "os_name": os_name,
                "os_version": os_version, "client_version": client_version}
        response = self._send("POST", "/api/v1/devices/anonymous/registration-challenge", json=body)
        self._raise_for(response)
        return response.json()

    def anonymous_register(self, challenge_id: str, signature_b64: str) -> dict:
        response = self._send("POST", "/api/v1/devices/anonymous/register",
                              json={"challenge_id": challenge_id, "signature": signature_b64})
        self._raise_for(response)
        return response.json()

    def token_challenge(self, device_id: str) -> dict:
        response = self._send("POST", "/api/v1/devices/token-challenge", json={"device_id": device_id})
        self._raise_for(response)
        return response.json()

    def device_token(self, device_id: str, challenge_id: str, signature_b64: str) -> dict:
        """Exchange a signed challenge for a device token, which is kept for later calls."""
        response = self._send("POST", "/api/v1/devices/token",
                              json={"device_id": device_id, "challenge_id": challenge_id, "signature": signature_b64})
        self._raise_for(response)
        body = response.json()
        token = body.get("device_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise ApiError(502, "unexpected_response", "The server sent an unexpected response.")
        self._device_token = token
        return body

    def device_self(self) -> dict:
        return self._as_device("GET", "/api/v1/devices/self").json()

    def device_heartbeat(self) -> dict:
        return self._as_device("POST", "/api/v1/devices/self/heartbeat").json()

    # ---------------------------------------------------- connection requests and sessions

    def incoming_requests(self) -> dict:
        return self._as_device("GET", "/api/v1/connection-requests/incoming").json()

    def approve_request(self, request_id: str) -> dict:
        return self._as_device("POST", f"/api/v1/connection-requests/{request_id}/approve").json()

    def reject_request(self, request_id: str, block_requester: bool = False) -> dict:
        return self._as_device("POST", f"/api/v1/connection-requests/{request_id}/reject",
                               json={"block_requester": block_requester}).json()

    def target_session(self, session_id: str) -> dict:
        return self._as_device("GET", f"/api/v1/sessions/{session_id}").json()

    def end_target_session(self, session_id: str) -> dict:
        return self._as_device("POST", f"/api/v1/sessions/{session_id}/terminate").json()

    def create_request(self, remote_id: str) -> dict:
        return self._authorized("POST", "/api/v1/connection-requests", device=True,
                                json={"remote_id": remote_id, "requested_permission": "view"}).json()

    def request_status(self, request_id: str) -> dict:
        return self._authorized("GET", f"/api/v1/connection-requests/{request_id}").json()

    def cancel_request(self, request_id: str) -> dict:
        return self._authorized("POST", f"/api/v1/connection-requests/{request_id}/cancel").json()

    def controller_session(self, session_id: str) -> dict:
        return self._authorized("GET", f"/api/v1/sessions/{session_id}").json()

    def end_controller_session(self, session_id: str) -> dict:
        return self._authorized("POST", f"/api/v1/sessions/{session_id}/terminate").json()

    def logout(self) -> None:
        """Ends the server session when possible; local tokens are always discarded."""
        try:
            if self.signed_in:
                self._send("POST", "/api/v1/auth/logout", headers={"Authorization": f"Bearer {self._access}"})
        finally:
            self._clear()

    def close(self) -> None:
        self._http.close()
