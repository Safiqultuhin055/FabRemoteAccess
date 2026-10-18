"""This-device state model and the gateways that supply it.

The state object refuses combinations the server could never confirm (a malformed Remote
ID, "Online" without a verified identity), so the UI cannot display them by accident.

Gateways:
- ApiDeviceGateway: the real server. Registers without an account (V0009) and signs
  challenges with the local device key; every server response is validated before it
  reaches the UI.
- PreviewDeviceGateway: sample data for reviewing the UI states. Only used when the app is
  started with --preview-device-states; everything it returns is marked as preview.
"""

from __future__ import annotations

import base64
import hashlib
import platform
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from fabremote import __version__
from fabremote import remote_id as rid
from fabremote.api_client import DEVICE_TOKEN_ERRORS, ApiClient, ApiError
from fabremote.device_identity import DeviceIdentity, anonymous_registration_message, token_message

PHASE_3D_REASON = ("This server does not offer device registration yet. "
                   "Your Remote ID will appear here once registration is available.")
UNREACHABLE = "Cannot reach the server. Check your connection and try again."
UNEXPECTED = "The server sent an unexpected response. Try again later."
SESSION_ENDED = "Your session has ended. Please sign in again."


class DeviceStatus(Enum):
    NOT_REGISTERED = "not_registered"
    PENDING = "registration_pending"
    VERIFYING = "verifying_identity"
    ONLINE = "online"
    OFFLINE = "offline"
    FAILED = "registration_failed"


@dataclass(frozen=True)
class DeviceState:
    status: DeviceStatus
    remote_id: str | None = None           # server-assigned only
    device_name: str | None = None
    identity_verified: bool = False         # set only after the server confirms the device key
    message: str | None = None
    can_register: bool = True
    preview: bool = False

    def __post_init__(self):
        if self.remote_id is not None and not rid.is_valid(self.remote_id):
            raise ValueError("Remote ID must be a server-assigned 9-digit ID")
        if self.identity_verified and self.remote_id is None:
            raise ValueError("A verified identity requires a registered device")
        if self.status in (DeviceStatus.ONLINE, DeviceStatus.OFFLINE) and not self.identity_verified:
            raise ValueError("Presence is shown only for a registered device with a verified identity")
        if self.status is DeviceStatus.VERIFYING and (self.remote_id is None or self.identity_verified):
            raise ValueError("Verifying requires a server-assigned ID that is not yet verified")
        if self.status in (DeviceStatus.NOT_REGISTERED, DeviceStatus.PENDING, DeviceStatus.FAILED) and self.remote_id:
            raise ValueError("No Remote ID is shown before registration completes")


@dataclass(frozen=True)
class Registration:
    remote_id: str
    device_name: str


class GatewayError(Exception):
    """A failure with a message that is safe to show to the user."""

    def __init__(self, user_message: str, retryable: bool = True):
        super().__init__(user_message)
        self.user_message = user_message
        self.retryable = retryable


class AuthRequiredError(GatewayError):
    """The user's session ended: the app must return to the sign-in screen."""

    def __init__(self):
        super().__init__(SESSION_ENDED, retryable=False)


class DeviceGateway(Protocol):
    supported: bool
    unsupported_reason: str
    preview: bool

    def has_local_device(self) -> bool: ...
    def existing(self) -> Registration | None: ...
    def register(self, device_name: str) -> Registration: ...
    def verify_identity(self) -> bool: ...
    def is_online(self) -> bool: ...


# ------------------------------------------------------------------ real server

_UUID = re.compile(r"^[0-9a-fA-F-]{36}$")


def _map_error(error: ApiError, *, missing_api: bool = False, device: bool = False) -> GatewayError:
    if error.status == 0:
        return GatewayError(UNREACHABLE)
    if error.status == 401 and device:   # this computer's proof failed; signing in would not help
        return GatewayError("This computer's identity could not be confirmed. Try again.")
    if error.status == 401:
        return AuthRequiredError()
    if error.status == 404 and missing_api:
        return GatewayError(PHASE_3D_REASON, retryable=False)
    if error.code == "device_limit_reached":
        return GatewayError("You have reached the maximum number of registered devices. "
                            "Remove one you no longer use and try again.", retryable=False)
    if error.status == 429:
        return GatewayError("Too many attempts. Wait a minute and try again.")
    if error.status >= 500:
        return GatewayError("The server is temporarily unavailable. Try again.")
    if error.code in ("invalid_challenge", "invalid_signature"):
        return GatewayError("This computer's identity could not be confirmed. Try again.")
    return GatewayError("Registration failed. Try again.")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise GatewayError(UNEXPECTED)
    try:
        return base64.b64decode(value, validate=True)
    except ValueError:
        raise GatewayError(UNEXPECTED) from None


def _challenge(response: dict) -> tuple[uuid.UUID, bytes]:
    try:
        challenge_id = uuid.UUID(str(response["challenge_id"]))
    except (KeyError, ValueError, TypeError):
        raise GatewayError(UNEXPECTED) from None
    nonce = _unb64(response.get("nonce"))
    if len(nonce) != 32:
        raise GatewayError(UNEXPECTED)
    return challenge_id, nonce


def _device(response: object) -> dict:
    """Accept a device record only if it looks exactly like what the server documents."""
    if not isinstance(response, dict):
        raise GatewayError(UNEXPECTED)
    remote_id, device_id = response.get("remote_id"), response.get("id")
    if (not isinstance(remote_id, str) or not rid.is_valid(remote_id) or not isinstance(device_id, str)
            or not _UUID.fullmatch(device_id) or response.get("status") not in ("active", "revoked")
            or not isinstance(response.get("identity_verified"), bool) or not isinstance(response.get("online"), bool)):
        raise GatewayError(UNEXPECTED)
    return response


class ApiDeviceGateway:
    """The real server. Registering this computer needs no account: it proves its key and gets
    a Remote ID; afterwards a signed challenge yields a short-lived device token for every call."""

    supported = True
    unsupported_reason = ""
    preview = False

    def __init__(self, client: ApiClient, identity: DeviceIdentity):
        self._client = client
        self._identity = identity

    def has_local_device(self) -> bool:
        return self._identity.device_id is not None

    def _fingerprint(self) -> str:
        return hashlib.sha256(self._identity.public_key()).hexdigest()

    def _forget(self) -> None:
        self._identity.forget()
        self._client.clear_device_token()

    def _sign_in_device(self) -> dict:
        """Sign a fresh challenge with the device key; the client keeps the resulting token."""
        device_id = self._identity.device_id
        if device_id is None:
            raise GatewayError(UNEXPECTED)
        challenge_id, nonce = _challenge(self._client.token_challenge(str(device_id)))
        signature = self._identity.sign(token_message(challenge_id, nonce, device_id))
        response = self._client.device_token(str(device_id), str(challenge_id), _b64(signature))
        return _device(response.get("device") if isinstance(response, dict) else None)

    def with_device_token(self, call):
        """Run `call` with a valid device token, obtaining a new one once if it was missing or expired."""
        try:
            if not self._client.has_device_token:
                self._sign_in_device()
            return call()
        except ApiError as error:
            if error.code not in DEVICE_TOKEN_ERRORS:
                raise
        self._sign_in_device()
        return call()

    def existing(self) -> Registration | None:
        if self._identity.device_id is None:
            return None
        try:
            device = self._sign_in_device()
        except ApiError as error:
            if error.status == 404 or error.code in ("invalid_challenge", "invalid_signature"):
                self._forget()                 # unknown or revoked here, or the key no longer matches
                return None
            raise _map_error(error, device=True) from None
        if device["status"] != "active" or device.get("key_fingerprint") != self._fingerprint():
            self._forget()
            return None
        return Registration(device["remote_id"], device["display_name"])

    def register(self, device_name: str) -> Registration:
        public_key = self._identity.ensure_key()   # created once and kept, so a retry reuses it
        try:
            challenge_id, nonce = _challenge(self._client.anonymous_registration_challenge(
                _b64(public_key), device_name, platform.system() or None, platform.release() or None, __version__))
            signature = self._identity.sign(anonymous_registration_message(challenge_id, nonce, public_key))
            device = _device(self._client.anonymous_register(str(challenge_id), _b64(signature)))
        except ApiError as error:
            if error.code == "key_already_registered":
                # An earlier attempt succeeded but its answer was lost. Without the device ID that key
                # cannot be used, so start over with a new key (the old Remote ID is never reissued).
                self._forget()
                raise GatewayError("Registration did not complete. Try again.") from None
            raise _map_error(error, missing_api=True, device=True) from None
        if device["status"] != "active" or not device["identity_verified"]:
            raise GatewayError(UNEXPECTED)
        self._identity.remember_device(uuid.UUID(device["id"]))
        return Registration(device["remote_id"], device["display_name"])

    def verify_identity(self) -> bool:
        """The server accepts this computer's signature and reports an active, verified device."""
        try:
            device = self._sign_in_device()
        except ApiError as error:
            raise _map_error(error, device=True) from None
        return (device["status"] == "active" and device["identity_verified"] is True
                and device.get("key_fingerprint") == self._fingerprint())

    def is_online(self) -> bool:
        """Heartbeat with the device token; the server decides whether the device counts as online."""
        try:
            device = _device(self.with_device_token(self._client.device_heartbeat))
        except ApiError as error:
            raise _map_error(error, device=True) from None
        return device["online"] is True


# ------------------------------------------------------------------ preview

PREVIEW_MODES = ("success", "failure", "offline", "verify-failure")
SAMPLE_REMOTE_ID = "123456789"   # obviously sample; shown only with the PREVIEW label


@dataclass
class PreviewDeviceGateway:
    """Sample data for UI review. `failure` fails the first attempt so Retry can be shown."""

    mode: str = "success"
    latency: float = 0.8
    supported: bool = True
    unsupported_reason: str = ""
    preview: bool = True
    attempts: int = field(default=0, init=False)

    def __post_init__(self):
        if self.mode not in PREVIEW_MODES:
            raise ValueError(f"Unknown preview mode: {self.mode}")

    def _wait(self):
        if self.latency:
            time.sleep(self.latency)

    def has_local_device(self) -> bool:
        return False

    def existing(self) -> Registration | None:
        return None

    def register(self, device_name: str) -> Registration:
        self.attempts += 1
        self._wait()
        if self.mode == "failure" and self.attempts == 1:
            raise GatewayError("Preview: the server could not be reached. Check your connection and try again.")
        return Registration(SAMPLE_REMOTE_ID, device_name)

    def verify_identity(self) -> bool:
        self._wait()
        return not (self.mode == "verify-failure" and self.attempts == 1)

    def is_online(self) -> bool:
        return self.mode != "offline"
