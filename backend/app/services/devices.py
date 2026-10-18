"""Device registration, Remote ID allocation, verified presence, key rotation and revocation.

Rules (docs/API_CONTRACTS.md section 5.3):
- A Remote ID is allocated only after the device has signed a single-use registration
  challenge bound to the user, their auth session and the proposed key.
- Remote IDs come from `secrets` (100000000-999999999), are inserted into the permanent
  registry first (never reused) and collisions are retried a bounded number of times.
- "Online" is computed by the server: active device, active key, and a signed heartbeat
  younger than FR_PRESENCE_TTL_SECONDS. Clients never report their own status.
- Only the owner may operate a device; administrators may view and revoke. Devices that
  are not visible to the caller are reported as not found.
- Failed proofs commit their audit event and the consumed challenge before raising.

Without an account (V0009): the computer being helped registers with its key alone and gets
a Remote ID. It then signs a single-use challenge to obtain a short-lived device token, which
is checked against the active device and key on every request. Such a device can receive
connection requests (and must approve each one); only signed-in users can send requests.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from app.config import Settings
from app.db.models import Device, DeviceAuthChallenge, DeviceKey, DeviceRegistrationChallenge
from app.domain.constants import (AuditOutcome, DeviceRevokedReason, DeviceStatus, IncomingPolicy,
                                  KeyRevokedReason, Role)
from app.domain.errors import (AuthenticationError, ConcurrencyError, ConflictError, DependencyUnavailableError,
                               InputRejectedError, NotFoundError, PermissionDeniedError, ProofRejectedError)
from app.domain.repositories import UnitOfWork, UnitOfWorkFactory
from app.security import device_proof
from app.security.clock import Clock
from app.security.tokens import DeviceTokenIssuer, InvalidAccessToken
from app.services.context import DevicePrincipal, Principal, RequestContext

REMOTE_ID_ATTEMPTS = 10


def secure_remote_id() -> str:
    return str(100_000_000 + secrets.randbelow(900_000_000))


@dataclass(frozen=True)
class DeviceView:
    device: Device
    active_key: DeviceKey | None
    identity_verified: bool
    online: bool


def _not_found() -> NotFoundError:
    return NotFoundError("The device was not found.", code="not_found")


def _invalid_challenge() -> ProofRejectedError:
    return ProofRejectedError("The challenge is invalid, expired or already used. Request a new one.",
                              code="invalid_challenge")


def _invalid_signature() -> ProofRejectedError:
    return ProofRejectedError("The device signature could not be verified.", code="invalid_signature")


def _key_taken() -> ConflictError:
    return ConflictError("This device key is already registered.", code="key_already_registered")


def _invalid_device_token() -> AuthenticationError:
    return AuthenticationError("The device token is invalid or has expired.", code="invalid_device_token")


class DeviceService:
    def __init__(self, uow_factory: UnitOfWorkFactory, settings: Settings, clock: Clock,
                 token_issuer: DeviceTokenIssuer | None = None,
                 remote_id_generator: Callable[[], str] = secure_remote_id):
        self._uow = uow_factory
        self._settings = settings
        self._clock = clock
        self._tokens = token_issuer
        self._next_remote_id = remote_id_generator

    # ------------------------------------------------------------------ views

    def _view(self, device: Device, key: DeviceKey | None) -> DeviceView:
        active = device.status is DeviceStatus.ACTIVE and key is not None
        fresh = (device.last_seen_at is not None and
                 self._clock.now() - device.last_seen_at <= timedelta(seconds=self._settings.presence_ttl_seconds))
        return DeviceView(device, key, identity_verified=active, online=active and fresh)

    def _visible(self, uow: UnitOfWork, principal: Principal, device_id: uuid.UUID) -> Device:
        device = uow.devices.get(device_id)
        if device is None or (device.owner_user_id != principal.user_id and not principal.has(Role.ADMIN)):
            raise _not_found()
        return device

    def _owned(self, uow: UnitOfWork, principal: Principal, device_id: uuid.UUID) -> Device:
        device = uow.devices.get(device_id)
        if device is None or device.owner_user_id != principal.user_id:
            raise _not_found()
        return device

    def _audit(self, uow: UnitOfWork, event: str, outcome: AuditOutcome, principal: Principal | None,
               ctx: RequestContext, device_id: uuid.UUID | None = None, **details) -> None:
        uow.audit.add(event, outcome, actor_user_id=principal.user_id if principal else None, actor_device_id=device_id,
                      subject_type="device" if device_id else None, subject_id=str(device_id) if device_id else None,
                      ip_address=ctx.ip, request_id=ctx.request_id, details=details or None)

    # ----------------------------------------------------------- registration

    def create_registration_challenge(self, principal: Principal, public_key: bytes, device_name: str,
                                      os_name: str | None, os_version: str | None, client_version: str | None,
                                      ) -> DeviceRegistrationChallenge:
        if not device_proof.valid_public_key(public_key):
            raise InputRejectedError("public_key", "invalid", "The public key is not a valid Ed25519 key.")
        now = self._clock.now()
        with self._uow() as uow:
            uow.device_challenges.purge_registration(principal.user_id, before=now)
            if uow.devices.find_key_by_fingerprint(hashlib.sha256(public_key).digest()) is not None:
                raise _key_taken()
            if uow.devices.count_active_for_owner(principal.user_id) >= self._settings.max_devices_per_user:
                raise ConflictError("You have reached the maximum number of registered devices.",
                                    code="device_limit_reached")
            challenge = uow.device_challenges.add_registration(DeviceRegistrationChallenge(
                user_id=principal.user_id, auth_session_id=principal.auth_session_id, public_key=public_key,
                device_name=device_name, os_name=os_name, os_version=os_version, client_version=client_version,
                nonce=secrets.token_bytes(32), created_at=now,
                expires_at=now + timedelta(seconds=self._settings.device_challenge_ttl_seconds)))
            uow.commit()
            return challenge

    def _allocate_remote_id(self, uow: UnitOfWork) -> str:
        for _ in range(REMOTE_ID_ATTEMPTS):
            candidate = self._next_remote_id()
            if uow.devices.reserve_remote_id(candidate):
                return candidate
        # Practically unreachable with 900 million IDs; never reveal retry details to the client.
        raise DependencyUnavailableError("Registration is temporarily unavailable. Try again.")

    def register(self, principal: Principal, challenge_id: uuid.UUID, signature: bytes,
                 ctx: RequestContext) -> DeviceView:
        now = self._clock.now()
        with self._uow() as uow:
            uow.devices.lock_owner(principal.user_id)
            challenge = uow.device_challenges.consume_registration(challenge_id, principal.user_id, now)
            if challenge is None or challenge.auth_session_id != principal.auth_session_id:
                self._audit(uow, "device.register", AuditOutcome.FAILURE, principal, ctx, reason="invalid_challenge")
                uow.commit()
                raise _invalid_challenge()
            message = device_proof.registration_message(challenge.id, challenge.nonce, principal.user_id,
                                                        challenge.public_key)
            if not device_proof.verify(challenge.public_key, signature, message):
                self._audit(uow, "device.register", AuditOutcome.FAILURE, principal, ctx, reason="invalid_signature")
                uow.commit()   # the challenge stays consumed: one guess per challenge
                raise _invalid_signature()
            if uow.devices.count_active_for_owner(principal.user_id) >= self._settings.max_devices_per_user:
                raise ConflictError("You have reached the maximum number of registered devices.",
                                    code="device_limit_reached")
            if uow.devices.find_key_by_fingerprint(challenge.key_fingerprint) is not None:
                raise _key_taken()

            remote_id = self._allocate_remote_id(uow)
            device = Device(owner_user_id=principal.user_id, remote_id=remote_id, display_name=challenge.device_name,
                            os_name=challenge.os_name, os_version=challenge.os_version,
                            client_version=challenge.client_version, created_at=now, updated_at=now)
            try:
                key = uow.devices.add(device, challenge.public_key)
            except ConflictError as exc:
                if exc.constraint == "UQ_device_keys_fingerprint":
                    raise _key_taken() from exc
                raise
            uow.auth_sessions.bind_device(principal.auth_session_id, device.id)
            self._audit(uow, "device.registered", AuditOutcome.SUCCESS, principal, ctx, device.id, remote_id=remote_id)
            uow.commit()
            return self._view(device, key)

    # ------------------------------------------------ without an account (V0009)

    def create_anonymous_challenge(self, public_key: bytes, device_name: str, os_name: str | None,
                                   os_version: str | None, client_version: str | None) -> DeviceRegistrationChallenge:
        if not device_proof.valid_public_key(public_key):
            raise InputRejectedError("public_key", "invalid", "The public key is not a valid Ed25519 key.")
        now = self._clock.now()
        with self._uow() as uow:
            uow.device_challenges.purge_registration(None, before=now)
            if uow.devices.find_key_by_fingerprint(hashlib.sha256(public_key).digest()) is not None:
                raise _key_taken()
            challenge = uow.device_challenges.add_registration(DeviceRegistrationChallenge(
                user_id=None, auth_session_id=None, public_key=public_key, device_name=device_name,
                os_name=os_name, os_version=os_version, client_version=client_version,
                nonce=secrets.token_bytes(32), created_at=now,
                expires_at=now + timedelta(seconds=self._settings.device_challenge_ttl_seconds)))
            uow.commit()
            return challenge

    def register_anonymous(self, challenge_id: uuid.UUID, signature: bytes, ctx: RequestContext) -> DeviceView:
        now = self._clock.now()
        with self._uow() as uow:
            challenge = uow.device_challenges.consume_registration(challenge_id, None, now)
            if challenge is None:
                self._audit(uow, "device.register", AuditOutcome.FAILURE, None, ctx, reason="invalid_challenge")
                uow.commit()
                raise _invalid_challenge()
            message = device_proof.anonymous_registration_message(challenge.id, challenge.nonce, challenge.public_key)
            if not device_proof.verify(challenge.public_key, signature, message):
                self._audit(uow, "device.register", AuditOutcome.FAILURE, None, ctx, reason="invalid_signature")
                uow.commit()   # the challenge stays consumed: one guess per challenge
                raise _invalid_signature()
            if uow.devices.find_key_by_fingerprint(challenge.key_fingerprint) is not None:
                raise _key_taken()
            remote_id = self._allocate_remote_id(uow)
            device = Device(owner_user_id=None, remote_id=remote_id, display_name=challenge.device_name,
                            os_name=challenge.os_name, os_version=challenge.os_version,
                            client_version=challenge.client_version, created_at=now, updated_at=now)
            try:
                key = uow.devices.add(device, challenge.public_key)
            except ConflictError as exc:
                if exc.constraint == "UQ_device_keys_fingerprint":
                    raise _key_taken() from exc
                raise
            self._audit(uow, "device.registered", AuditOutcome.SUCCESS, None, ctx, device.id, remote_id=remote_id,
                        anonymous=True)
            uow.commit()
            return self._view(device, key)

    def token_challenge(self, device_id: uuid.UUID) -> DeviceAuthChallenge:
        """Nonce for a device token. Unknown and revoked devices look the same (not found)."""
        now = self._clock.now()
        with self._uow() as uow:
            device = uow.devices.get(device_id)
            if device is None or device.status is not DeviceStatus.ACTIVE or uow.devices.active_key(device_id) is None:
                raise _not_found()
            challenge = uow.device_challenges.add_device(DeviceAuthChallenge(
                device_id=device.id, nonce=secrets.token_bytes(32), created_at=now,
                expires_at=now + timedelta(seconds=self._settings.device_challenge_ttl_seconds)))
            uow.commit()
            return challenge

    def issue_token(self, device_id: uuid.UUID, challenge_id: uuid.UUID, signature: bytes,
                    ctx: RequestContext) -> tuple[str, DeviceView]:
        """A device token for a valid signature over the token message. Counts as a heartbeat."""
        if self._tokens is None:
            raise DependencyUnavailableError()
        now = self._clock.now()
        with self._uow() as uow:
            device = uow.devices.get(device_id)
            if device is None:
                raise _invalid_challenge()
            challenge = uow.device_challenges.consume_device(challenge_id, device.id, now)
            key = uow.devices.active_key(device.id)
            if challenge is None or key is None or device.status is not DeviceStatus.ACTIVE:
                self._audit(uow, "device.auth", AuditOutcome.FAILURE, None, ctx, device.id, reason="invalid_challenge")
                uow.commit()
                raise _invalid_challenge()
            if not device_proof.verify(key.public_key, signature,
                                       device_proof.token_message(challenge.id, challenge.nonce, device.id)):
                self._audit(uow, "device.auth", AuditOutcome.FAILURE, None, ctx, device.id, reason="invalid_signature")
                uow.commit()
                raise _invalid_signature()
            uow.devices.record_presence(device.id, now, ctx.ip)
            self._audit(uow, "device.auth", AuditOutcome.SUCCESS, None, ctx, device.id)
            uow.commit()
            device.last_seen_at = now
            return self._tokens.issue(device.id, key.id), self._view(device, key)

    def authenticate_device(self, token: str) -> DevicePrincipal:
        if self._tokens is None:
            raise _invalid_device_token()
        try:
            claims = self._tokens.verify(token)
        except InvalidAccessToken:
            raise _invalid_device_token() from None
        with self._uow() as uow:
            device = uow.devices.get(claims.device_id)
            key = uow.devices.active_key(claims.device_id) if device else None
            if device is None or device.status is not DeviceStatus.ACTIVE or key is None or key.id != claims.key_id:
                raise _invalid_device_token()   # revoked device, or the key was rotated or revoked
            return DevicePrincipal(device.id, key.id)

    def device_heartbeat(self, caller: DevicePrincipal, ctx: RequestContext) -> DeviceView:
        now = self._clock.now()
        with self._uow() as uow:
            uow.devices.record_presence(caller.device_id, now, ctx.ip)
            uow.commit()
        return self.device_self(caller)

    def device_self(self, caller: DevicePrincipal) -> DeviceView:
        with self._uow() as uow:
            device = uow.devices.get(caller.device_id)
            if device is None:
                raise _invalid_device_token()
            return self._view(device, uow.devices.active_key(device.id))

    # ------------------------------------------------------------------ reads

    def get(self, principal: Principal, device_id: uuid.UUID) -> DeviceView:
        with self._uow() as uow:
            device = self._visible(uow, principal, device_id)
            return self._view(device, uow.devices.active_key(device.id))

    def current(self, principal: Principal) -> DeviceView:
        with self._uow() as uow:
            device = uow.devices.get(principal.device_id) if principal.device_id else None
            if device is None or device.owner_user_id != principal.user_id:
                raise NotFoundError("This session has no registered device.", code="device_not_registered")
            return self._view(device, uow.devices.active_key(device.id))

    def list(self, principal: Principal, *, owner_user_id: uuid.UUID | None, status: DeviceStatus | None,
             limit: int) -> list[DeviceView]:
        owner = owner_user_id or principal.user_id
        if owner != principal.user_id and not principal.has(Role.ADMIN):
            raise PermissionDeniedError()
        with self._uow() as uow:
            devices = uow.devices.list_for_owner(owner, status=status, limit=limit)
            keys = uow.devices.active_keys_for([d.id for d in devices])
            return [self._view(d, keys.get(d.id)) for d in devices]

    # ---------------------------------------------------------------- changes

    def update(self, principal: Principal, device_id: uuid.UUID, row_version: bytes, *,
               display_name: str | None, incoming_policy: IncomingPolicy | None, ctx: RequestContext) -> DeviceView:
        now = self._clock.now()
        with self._uow() as uow:
            device = self._owned(uow, principal, device_id)
            if device.status is not DeviceStatus.ACTIVE:
                raise ConflictError("A revoked device cannot be changed.", code="device_revoked")
            if bytes(device.row_version) != row_version:
                raise ConcurrencyError()
            changed = []
            if display_name is not None and display_name != device.display_name:
                device.display_name = display_name
                changed.append("display_name")
            if incoming_policy is not None and incoming_policy is not device.incoming_policy:
                device.incoming_policy = incoming_policy
                changed.append("incoming_policy")
            if changed:
                device.updated_at = now
                uow.devices.flush()
                self._audit(uow, "device.updated", AuditOutcome.SUCCESS, principal, ctx, device.id, fields=changed)
            uow.commit()
            return self._view(device, uow.devices.active_key(device.id))

    def revoke(self, principal: Principal, device_id: uuid.UUID, reason: DeviceRevokedReason | None,
               ctx: RequestContext) -> DeviceView:
        now = self._clock.now()
        is_owner_call = False
        with self._uow() as uow:
            device = self._visible(uow, principal, device_id)
            is_owner_call = device.owner_user_id == principal.user_id
            if reason is None:
                reason = DeviceRevokedReason.OWNER_REMOVED if is_owner_call else DeviceRevokedReason.ADMIN_REVOKED
            allowed = ({DeviceRevokedReason.OWNER_REMOVED} if is_owner_call else set())
            if principal.has(Role.ADMIN):
                allowed |= {DeviceRevokedReason.ADMIN_REVOKED, DeviceRevokedReason.KEY_COMPROMISED}
            if reason not in allowed:
                raise PermissionDeniedError("This revocation reason is not allowed for you.")
            if uow.devices.revoke(device.id, reason, principal.user_id, now):
                key_reason = (KeyRevokedReason.KEY_COMPROMISED if reason is DeviceRevokedReason.KEY_COMPROMISED
                              else KeyRevokedReason.DEVICE_REVOKED)
                uow.devices.revoke_keys(device.id, key_reason, now)
                sessions = uow.auth_sessions.revoke_for_device(device.id, now)
                self._audit(uow, "device.revoked", AuditOutcome.SUCCESS, principal, ctx, device.id,
                            reason=reason.value, sessions_revoked=sessions)
            uow.commit()
        return self.get(principal, device_id)

    # ------------------------------------------------- presence and rotation

    def device_challenge(self, principal: Principal, device_id: uuid.UUID) -> DeviceAuthChallenge:
        now = self._clock.now()
        with self._uow() as uow:
            device = self._owned(uow, principal, device_id)
            if device.status is not DeviceStatus.ACTIVE or uow.devices.active_key(device.id) is None:
                raise ConflictError("This device has been revoked.", code="device_revoked")
            challenge = uow.device_challenges.add_device(DeviceAuthChallenge(
                device_id=device.id, nonce=secrets.token_bytes(32), created_at=now,
                expires_at=now + timedelta(seconds=self._settings.device_challenge_ttl_seconds)))
            uow.commit()
            return challenge

    def _consume_proof(self, uow: UnitOfWork, principal: Principal, device: Device, challenge_id: uuid.UUID,
                       event: str, ctx: RequestContext) -> tuple[DeviceAuthChallenge, DeviceKey]:
        challenge = uow.device_challenges.consume_device(challenge_id, device.id, self._clock.now())
        key = uow.devices.active_key(device.id)
        if challenge is None or key is None or device.status is not DeviceStatus.ACTIVE:
            self._audit(uow, event, AuditOutcome.FAILURE, principal, ctx, device.id, reason="invalid_challenge")
            uow.commit()
            raise _invalid_challenge()
        return challenge, key

    def heartbeat(self, principal: Principal, device_id: uuid.UUID, challenge_id: uuid.UUID, signature: bytes,
                  ctx: RequestContext) -> DeviceView:
        now = self._clock.now()
        with self._uow() as uow:
            device = self._owned(uow, principal, device_id)
            challenge, key = self._consume_proof(uow, principal, device, challenge_id, "device.presence", ctx)
            if not device_proof.verify(key.public_key, signature,
                                       device_proof.presence_message(challenge.id, challenge.nonce, device.id)):
                self._audit(uow, "device.presence", AuditOutcome.FAILURE, principal, ctx, device.id,
                            reason="invalid_signature")
                uow.commit()
                raise _invalid_signature()
            uow.devices.record_presence(device.id, now, ctx.ip)
            if principal.device_id != device.id:
                uow.auth_sessions.bind_device(principal.auth_session_id, device.id)
            uow.commit()
            device.last_seen_at = now
            return self._view(device, key)

    def rotate_key(self, principal: Principal, device_id: uuid.UUID, challenge_id: uuid.UUID, new_public_key: bytes,
                   signature_current: bytes, signature_new: bytes, ctx: RequestContext) -> DeviceView:
        if not device_proof.valid_public_key(new_public_key):
            raise InputRejectedError("new_public_key", "invalid", "The new public key is not a valid Ed25519 key.")
        now = self._clock.now()
        with self._uow() as uow:
            device = self._owned(uow, principal, device_id)
            challenge, key = self._consume_proof(uow, principal, device, challenge_id, "device.key_rotation", ctx)
            message = device_proof.rotation_message(challenge.id, challenge.nonce, device.id, new_public_key)
            if not (device_proof.verify(key.public_key, signature_current, message)
                    and device_proof.verify(new_public_key, signature_new, message)):
                self._audit(uow, "device.key_rotation", AuditOutcome.FAILURE, principal, ctx, device.id,
                            reason="invalid_signature")
                uow.commit()
                raise _invalid_signature()
            if uow.devices.find_key_by_fingerprint(hashlib.sha256(new_public_key).digest()) is not None:
                raise _key_taken()
            uow.devices.revoke_keys(device.id, KeyRevokedReason.ROTATED, now)
            try:
                new_key = uow.devices.add_key(device.id, new_public_key)
            except ConflictError as exc:
                if exc.constraint == "UQ_device_keys_fingerprint":
                    raise _key_taken() from exc
                raise
            self._audit(uow, "device.key_rotated", AuditOutcome.SUCCESS, principal, ctx, device.id)
            uow.commit()
            return self._view(device, new_key)
