"""HTTP client for the Fabulous Remote API (desktop credentials: bearer access + refresh token).

Tokens are kept in memory only in this preview; persisting the refresh token belongs in
Windows Credential Manager (planned). Refresh calls are serialised because the server
treats two refreshes with the same token as theft and revokes the session.
"""

from __future__ import annotations

import threading
from urllib.parse import urlsplit

import httpx

from fabremote import __version__

LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


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
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport,
                                  headers={"User-Agent": f"FabulousRemote-Desktop/{__version__}"})
        self._lock = threading.Lock()
        self._access: str | None = None
        self._refresh: str | None = None

    def __repr__(self) -> str:   # never expose tokens
        return f"ApiClient(base_url={self.base_url!r}, signed_in={self.signed_in})"

    @property
    def signed_in(self) -> bool:
        return self._access is not None

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

    def _authorized(self, method: str, path: str, **kwargs) -> httpx.Response:
        if not self.signed_in:
            raise ApiError(401, "unauthenticated", "Please sign in.")
        access = self._access
        response = self._send(method, path, headers={"Authorization": f"Bearer {access}"}, **kwargs)
        if response.status_code == 401:
            self._refresh_tokens(access)
            response = self._send(method, path, headers={"Authorization": f"Bearer {self._access}"}, **kwargs)
            if response.status_code == 401:
                self._clear()
        self._raise_for(response)
        return response

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

    def logout(self) -> None:
        """Ends the server session when possible; local tokens are always discarded."""
        try:
            if self.signed_in:
                self._send("POST", "/api/v1/auth/logout", headers={"Authorization": f"Bearer {self._access}"})
        finally:
            self._clear()

    def close(self) -> None:
        self._http.close()
