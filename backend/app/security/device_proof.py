"""Device proof-of-possession: what a device signs, and how the server verifies it.

Each message starts with a distinct, versioned purpose prefix, so a signature made for one
purpose (presence) can never be replayed for another (registration or key rotation). Every
message includes a single-use server nonce and the challenge ID; registration also binds
the user and the proposed key, presence and rotation bind the device.

The desktop client builds identical messages (desktop/fabremote/device_identity.py); a test
checks both implementations byte for byte.
"""

from __future__ import annotations

import hashlib
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.domain.constants import ED25519_PUBLIC_KEY_BYTES

REGISTER = b"fabremote-device-register-v1\x00"
PRESENCE = b"fabremote-device-presence-v1\x00"
ROTATE = b"fabremote-device-rotate-v1\x00"
SIGNATURE_BYTES = 64


def registration_message(challenge_id: uuid.UUID, nonce: bytes, user_id: uuid.UUID, public_key: bytes) -> bytes:
    return REGISTER + challenge_id.bytes + nonce + user_id.bytes + hashlib.sha256(public_key).digest()


def presence_message(challenge_id: uuid.UUID, nonce: bytes, device_id: uuid.UUID) -> bytes:
    return PRESENCE + challenge_id.bytes + nonce + device_id.bytes


def rotation_message(challenge_id: uuid.UUID, nonce: bytes, device_id: uuid.UUID, new_public_key: bytes) -> bytes:
    return ROTATE + challenge_id.bytes + nonce + device_id.bytes + hashlib.sha256(new_public_key).digest()


def valid_public_key(public_key: bytes) -> bool:
    if len(public_key) != ED25519_PUBLIC_KEY_BYTES:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError:
        return False
    return True


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    if len(signature) != SIGNATURE_BYTES or not valid_public_key(public_key):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True
