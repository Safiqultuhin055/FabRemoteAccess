"""/api/v1/devices: registration with proof of key possession (signed in, or without an account),
device tokens, management, verified presence, rotation."""

from __future__ import annotations

import base64
import binascii
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from pydantic import BaseModel, Field, StringConstraints

from app.api.auth_deps import Context, CurrentDevice, CurrentPrincipal, enforce_rate_limit
from app.api.v1.schemas import DisplayName, Strict
from app.domain.constants import (CLIENT_VERSION_MAX_LENGTH, OS_NAME_MAX_LENGTH, OS_VERSION_MAX_LENGTH,
                                  DeviceRevokedReason, DeviceStatus, IncomingPolicy)
from app.domain.errors import InputRejectedError, PreconditionRequiredError
from app.security import device_proof
from app.services.devices import DeviceService, DeviceView

router = APIRouter(prefix="/devices", tags=["devices"])

Base64 = Annotated[str, StringConstraints(min_length=4, max_length=200, pattern=r"^[A-Za-z0-9+/]+={0,2}$")]
OptionalText = lambda n: Annotated[str | None, StringConstraints(strip_whitespace=True, max_length=n)]  # noqa: E731


def get_device_service(request: Request) -> DeviceService:
    return request.app.state.device_service


Devices = Annotated[DeviceService, Depends(get_device_service)]


def b64decode(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise InputRejectedError(field, "invalid_base64") from None


def b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def etag(view: DeviceView) -> str:
    return '"' + base64.urlsafe_b64encode(bytes(view.device.row_version)).decode().rstrip("=") + '"'


def parse_etag(value: str) -> bytes:
    """Unreadable tags never match (412), but only after the ownership check (404 for strangers)."""
    raw = value.strip().removeprefix("W/").strip('"')
    try:
        return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (binascii.Error, ValueError):
        return b""


# ------------------------------------------------------------------ schemas


class DeviceOut(BaseModel):
    id: uuid.UUID
    remote_id: str = Field(description="Server-assigned 9-digit identifier. An identifier only, never a credential.")
    display_name: str
    os_name: str | None
    os_version: str | None
    client_version: str | None
    incoming_policy: IncomingPolicy
    status: DeviceStatus
    identity_verified: bool = Field(description="Active device with an active, server-verified key.")
    online: bool = Field(description="Computed by the server from the last signed heartbeat.")
    last_seen_at: datetime | None
    key_fingerprint: str | None = Field(description="SHA-256 of the active public key (hex).")
    created_at: datetime
    updated_at: datetime
    revoked_at: datetime | None
    revoked_reason: DeviceRevokedReason | None


class DeviceList(BaseModel):
    items: list[DeviceOut]


class RegistrationChallengeIn(Strict):
    public_key: Base64 = Field(description="Ed25519 public key, 32 bytes, base64.")
    key_algorithm: Literal["ed25519"] = "ed25519"
    device_name: DisplayName
    os_name: OptionalText(OS_NAME_MAX_LENGTH) = None
    os_version: OptionalText(OS_VERSION_MAX_LENGTH) = None
    client_version: OptionalText(CLIENT_VERSION_MAX_LENGTH) = None


class ChallengeOut(BaseModel):
    challenge_id: uuid.UUID
    nonce: str = Field(description="32 random bytes, base64. Sign the documented message, not the nonce alone.")
    expires_at: datetime
    message_format: str


class SignedChallengeIn(Strict):
    challenge_id: uuid.UUID
    signature: Base64 = Field(description="Ed25519 signature, 64 bytes, base64.")


class RotateKeyIn(Strict):
    challenge_id: uuid.UUID
    new_public_key: Base64
    signature_current: Base64
    signature_new: Base64


class DeviceUpdateIn(Strict):
    display_name: DisplayName | None = None
    incoming_policy: IncomingPolicy | None = None


class RevokeIn(Strict):
    reason: Literal["owner_removed", "admin_revoked", "key_compromised"] | None = None


def device_out(view: DeviceView) -> DeviceOut:
    d = view.device
    return DeviceOut(id=d.id, remote_id=d.remote_id, display_name=d.display_name, os_name=d.os_name,
                     os_version=d.os_version, client_version=d.client_version, incoming_policy=d.incoming_policy,
                     status=d.status, identity_verified=view.identity_verified, online=view.online,
                     last_seen_at=d.last_seen_at,
                     key_fingerprint=bytes(view.active_key.fingerprint).hex() if view.active_key else None,
                     created_at=d.created_at, updated_at=d.updated_at, revoked_at=d.revoked_at,
                     revoked_reason=d.revoked_reason)


def with_etag(view: DeviceView, response: Response) -> DeviceOut:
    response.headers["ETag"] = etag(view)
    return device_out(view)


# ---------------------------------------------------------------- endpoints


@router.post("/registration-challenge", status_code=status.HTTP_201_CREATED, response_model=ChallengeOut,
             summary="Start registering this device (proposes its public key)")
def registration_challenge(body: RegistrationChallengeIn, request: Request, principal: CurrentPrincipal,
                           devices: Devices) -> ChallengeOut:
    enforce_rate_limit(request, request.app.state.rate_limits.device_registration_per_user,
                       "device-register", str(principal.user_id))
    challenge = devices.create_registration_challenge(
        principal, b64decode(body.public_key, "public_key"), body.device_name, body.os_name, body.os_version,
        body.client_version)
    return ChallengeOut(challenge_id=challenge.id, nonce=b64encode(challenge.nonce), expires_at=challenge.expires_at,
                        message_format=device_proof.REGISTER.decode().rstrip("\x00"))


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=DeviceOut,
             summary="Complete registration with the signed challenge; the server assigns the Remote ID")
def register(body: SignedChallengeIn, request: Request, response: Response, principal: CurrentPrincipal,
             ctx: Context, devices: Devices) -> DeviceOut:
    enforce_rate_limit(request, request.app.state.rate_limits.device_registration_per_user,
                       "device-register-complete", str(principal.user_id))
    view = devices.register(principal, body.challenge_id, b64decode(body.signature, "signature"), ctx)
    response.headers["Location"] = f"/api/v1/devices/{view.device.id}"
    return with_etag(view, response)


# ------------------------------------------- without an account (V0009); before /{device_id}


@router.post("/anonymous/registration-challenge", status_code=status.HTTP_201_CREATED, response_model=ChallengeOut,
             summary="Start registering this computer without an account (proposes its public key)")
def anonymous_registration_challenge(body: RegistrationChallengeIn, request: Request, ctx: Context,
                                     devices: Devices) -> ChallengeOut:
    enforce_rate_limit(request, request.app.state.rate_limits.anonymous_registration_per_ip,
                       "device-register-anonymous", ctx.ip or "")
    challenge = devices.create_anonymous_challenge(
        b64decode(body.public_key, "public_key"), body.device_name, body.os_name, body.os_version, body.client_version)
    return ChallengeOut(challenge_id=challenge.id, nonce=b64encode(challenge.nonce), expires_at=challenge.expires_at,
                        message_format=device_proof.REGISTER_ANONYMOUS.decode().rstrip("\x00"))


@router.post("/anonymous/register", status_code=status.HTTP_201_CREATED, response_model=DeviceOut,
             summary="Complete registration without an account; the server assigns the Remote ID")
def anonymous_register(body: SignedChallengeIn, request: Request, response: Response, ctx: Context,
                       devices: Devices) -> DeviceOut:
    enforce_rate_limit(request, request.app.state.rate_limits.anonymous_registration_per_ip,
                       "device-register-anonymous-complete", ctx.ip or "")
    view = devices.register_anonymous(body.challenge_id, b64decode(body.signature, "signature"), ctx)
    response.headers["Location"] = f"/api/v1/devices/{view.device.id}"
    return with_etag(view, response)


class TokenChallengeIn(Strict):
    device_id: uuid.UUID


class DeviceTokenIn(Strict):
    device_id: uuid.UUID
    challenge_id: uuid.UUID
    signature: Base64


class DeviceTokenOut(BaseModel):
    device_token: str = Field(description="Send as X-Device-Token. Short-lived; never stored by the server.")
    token_type: Literal["device"] = "device"
    expires_in: int
    device: DeviceOut


@router.post("/token-challenge", status_code=status.HTTP_201_CREATED, response_model=ChallengeOut,
             summary="Nonce for a device token (sign it with the device key)")
def token_challenge(body: TokenChallengeIn, request: Request, ctx: Context, devices: Devices) -> ChallengeOut:
    limits = request.app.state.rate_limits
    enforce_rate_limit(request, limits.device_token_per_ip, "device-token-ip", ctx.ip or "")
    enforce_rate_limit(request, limits.device_token_per_device, "device-token-challenge", str(body.device_id))
    challenge = devices.token_challenge(body.device_id)
    return ChallengeOut(challenge_id=challenge.id, nonce=b64encode(challenge.nonce), expires_at=challenge.expires_at,
                        message_format=device_proof.TOKEN.decode().rstrip("\x00"))


@router.post("/token", response_model=DeviceTokenOut, summary="Exchange a signed challenge for a device token")
def device_token(body: DeviceTokenIn, request: Request, ctx: Context, devices: Devices) -> DeviceTokenOut:
    enforce_rate_limit(request, request.app.state.rate_limits.device_token_per_device, "device-token",
                       str(body.device_id))
    token, view = devices.issue_token(body.device_id, body.challenge_id, b64decode(body.signature, "signature"), ctx)
    return DeviceTokenOut(device_token=token, expires_in=request.app.state.settings.device_token_ttl_seconds,
                          device=device_out(view))


@router.get("/self", response_model=DeviceOut, summary="This device (device token)")
def device_self(caller: CurrentDevice, devices: Devices) -> DeviceOut:
    return device_out(devices.device_self(caller))


@router.post("/self/heartbeat", response_model=DeviceOut, summary="Presence heartbeat (device token)")
def device_heartbeat(request: Request, caller: CurrentDevice, ctx: Context, devices: Devices) -> DeviceOut:
    enforce_rate_limit(request, request.app.state.rate_limits.connection_poll_per_caller, "device-heartbeat",
                       str(caller.device_id))
    return device_out(devices.device_heartbeat(caller, ctx))


# ------------------------------------------------------------- signed-in owner


@router.get("/me", response_model=DeviceOut, summary="The device bound to the current session")
def my_device(response: Response, principal: CurrentPrincipal, devices: Devices) -> DeviceOut:
    return with_etag(devices.current(principal), response)


@router.get("", response_model=DeviceList, summary="List devices (own; administrators may name an owner)")
def list_devices(principal: CurrentPrincipal, devices: Devices,
                 owner_user_id: uuid.UUID | None = None,
                 status_: Annotated[DeviceStatus | None, Query(alias="status")] = None,
                 limit: Annotated[int, Query(ge=1, le=200)] = 50) -> DeviceList:
    return DeviceList(items=[device_out(v) for v in devices.list(principal, owner_user_id=owner_user_id,
                                                                   status=status_, limit=limit)])


@router.get("/{device_id}", response_model=DeviceOut, summary="One device (owner or administrator)")
def get_device(device_id: uuid.UUID, response: Response, principal: CurrentPrincipal, devices: Devices) -> DeviceOut:
    return with_etag(devices.get(principal, device_id), response)


@router.patch("/{device_id}", response_model=DeviceOut, summary="Rename or change the incoming policy (owner)")
def update_device(device_id: uuid.UUID, body: DeviceUpdateIn, response: Response, principal: CurrentPrincipal,
                  ctx: Context, devices: Devices,
                  if_match: Annotated[str | None, Header(alias="If-Match")] = None) -> DeviceOut:
    if not if_match:
        raise PreconditionRequiredError()
    view = devices.update(principal, device_id, parse_etag(if_match), display_name=body.display_name,
                          incoming_policy=body.incoming_policy, ctx=ctx)
    return with_etag(view, response)


@router.post("/{device_id}/revoke", response_model=DeviceOut, summary="Revoke a device (owner or administrator)")
def revoke_device(device_id: uuid.UUID, response: Response, principal: CurrentPrincipal, ctx: Context,
                  devices: Devices, body: RevokeIn | None = None) -> DeviceOut:
    reason = DeviceRevokedReason(body.reason) if body and body.reason else None
    return with_etag(devices.revoke(principal, device_id, reason, ctx), response)


@router.post("/{device_id}/challenge", status_code=status.HTTP_201_CREATED, response_model=ChallengeOut,
             summary="Fresh nonce for a presence heartbeat or key rotation (owner)")
def device_challenge(device_id: uuid.UUID, request: Request, principal: CurrentPrincipal,
                     devices: Devices) -> ChallengeOut:
    enforce_rate_limit(request, request.app.state.rate_limits.device_challenge_per_device,
                       "device-challenge", str(device_id))
    challenge = devices.device_challenge(principal, device_id)
    return ChallengeOut(challenge_id=challenge.id, nonce=b64encode(challenge.nonce), expires_at=challenge.expires_at,
                        message_format=f"{device_proof.PRESENCE.decode().rstrip(chr(0))} | "
                                       f"{device_proof.ROTATE.decode().rstrip(chr(0))}")


@router.post("/{device_id}/presence", response_model=DeviceOut, summary="Signed heartbeat (owner + device key)")
def presence(device_id: uuid.UUID, body: SignedChallengeIn, request: Request, response: Response,
             principal: CurrentPrincipal, ctx: Context, devices: Devices) -> DeviceOut:
    enforce_rate_limit(request, request.app.state.rate_limits.device_proof_per_device,
                       "device-proof", str(device_id))
    view = devices.heartbeat(principal, device_id, body.challenge_id, b64decode(body.signature, "signature"), ctx)
    return with_etag(view, response)


@router.post("/{device_id}/keys/rotate", response_model=DeviceOut,
             summary="Replace the device key (signed by the current and the new key)")
def rotate_key(device_id: uuid.UUID, body: RotateKeyIn, request: Request, response: Response,
               principal: CurrentPrincipal, ctx: Context, devices: Devices) -> DeviceOut:
    enforce_rate_limit(request, request.app.state.rate_limits.device_rotation_per_device,
                       "device-rotate", str(device_id))
    view = devices.rotate_key(principal, device_id, body.challenge_id, b64decode(body.new_public_key, "new_public_key"),
                              b64decode(body.signature_current, "signature_current"),
                              b64decode(body.signature_new, "signature_new"), ctx)
    return with_etag(view, response)
