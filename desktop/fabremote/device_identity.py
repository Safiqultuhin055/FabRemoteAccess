"""This computer's device identity: an Ed25519 key pair whose private half never leaves the device.

Storage: one small JSON file per server under %LOCALAPPDATA%\\Fabulous Remote\\devices\\
(or FR_DESKTOP_DATA_DIR). The private key inside is encrypted with Windows DPAPI for the
current Windows user, with application-specific entropy; only the public key and
signatures are ever sent to the server.

The signed messages must match backend/app/security/device_proof.py byte for byte; a test
compares both implementations.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REGISTER = b"fabremote-device-register-v1\x00"
PRESENCE = b"fabremote-device-presence-v1\x00"
ROTATE = b"fabremote-device-rotate-v1\x00"
DPAPI_ENTROPY = b"fabremote-device-key-v1"


def registration_message(challenge_id: uuid.UUID, nonce: bytes, user_id: uuid.UUID, public_key: bytes) -> bytes:
    return REGISTER + challenge_id.bytes + nonce + user_id.bytes + hashlib.sha256(public_key).digest()


def presence_message(challenge_id: uuid.UUID, nonce: bytes, device_id: uuid.UUID) -> bytes:
    return PRESENCE + challenge_id.bytes + nonce + device_id.bytes


def rotation_message(challenge_id: uuid.UUID, nonce: bytes, device_id: uuid.UUID, new_public_key: bytes) -> bytes:
    return ROTATE + challenge_id.bytes + nonce + device_id.bytes + hashlib.sha256(new_public_key).digest()


# ------------------------------------------------------------------ DPAPI


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _to_blob(data: bytes) -> tuple[_Blob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _dpapi(data: bytes, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise OSError("Windows DPAPI is required to store the device key")
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    source, _keep1 = _to_blob(data)
    entropy, _keep2 = _to_blob(DPAPI_ENTROPY)
    result = _Blob()
    flags = 0x01  # CRYPTPROTECT_UI_FORBIDDEN
    if protect:
        ok = crypt32.CryptProtectData(ctypes.byref(source), "Fabulous Remote device key", ctypes.byref(entropy),
                                      None, None, flags, ctypes.byref(result))
    else:
        ok = crypt32.CryptUnprotectData(ctypes.byref(source), None, ctypes.byref(entropy), None, None, flags,
                                        ctypes.byref(result))
    if not ok:
        raise OSError("DPAPI operation failed")
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(result.pbData, ctypes.c_void_p))


def dpapi_protect(data: bytes) -> bytes:
    return _dpapi(data, protect=True)


def dpapi_unprotect(data: bytes) -> bytes:
    return _dpapi(data, protect=False)


# ------------------------------------------------------------------ stores


@dataclass
class StoredIdentity:
    private_key: bytes          # 32 raw bytes, only ever held in memory
    device_id: uuid.UUID | None


class KeyStore(Protocol):
    def load(self) -> StoredIdentity | None: ...
    def save(self, identity: StoredIdentity) -> None: ...
    def clear(self) -> None: ...


def data_dir() -> Path:
    base = os.environ.get("FR_DESKTOP_DATA_DIR") or os.path.join(os.environ.get("LOCALAPPDATA", str(Path.home())),
                                                                 "Fabulous Remote")
    return Path(base)


class DpapiKeyStore:
    """Device key encrypted with DPAPI (current Windows user); one file per server address."""

    def __init__(self, path: Path):
        self.path = path

    @classmethod
    def for_server(cls, base_url: str) -> DpapiKeyStore:
        name = hashlib.sha256(base_url.rstrip("/").lower().encode()).hexdigest()[:16]
        return cls(data_dir() / "devices" / f"{name}.json")

    def load(self) -> StoredIdentity | None:
        try:
            record = json.loads(self.path.read_text(encoding="utf-8"))
            private = dpapi_unprotect(base64.b64decode(record["private_key_dpapi"]))
            device_id = uuid.UUID(record["device_id"]) if record.get("device_id") else None
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return StoredIdentity(private, device_id) if len(private) == 32 else None

    def save(self, identity: StoredIdentity) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {"version": 1, "device_id": str(identity.device_id) if identity.device_id else None,
                  "private_key_dpapi": base64.b64encode(dpapi_protect(identity.private_key)).decode()}
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(record), encoding="utf-8")
        temporary.replace(self.path)

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)


class MemoryKeyStore:
    """Test double; never touches the disk."""

    def __init__(self, identity: StoredIdentity | None = None):
        self.identity = identity

    def load(self) -> StoredIdentity | None:
        return self.identity

    def save(self, identity: StoredIdentity) -> None:
        self.identity = StoredIdentity(identity.private_key, identity.device_id)

    def clear(self) -> None:
        self.identity = None


# ------------------------------------------------------------------ identity


class DeviceIdentity:
    def __init__(self, store: KeyStore):
        self._store = store

    def _key(self, stored: StoredIdentity) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(stored.private_key)

    @property
    def device_id(self) -> uuid.UUID | None:
        stored = self._store.load()
        return stored.device_id if stored else None

    def ensure_key(self) -> bytes:
        """Public key of this device, creating and storing a key pair on first use."""
        stored = self._store.load()
        if stored is None:
            private = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            stored = StoredIdentity(private, None)
            self._store.save(stored)
        return self.public_key(stored)

    def public_key(self, stored: StoredIdentity | None = None) -> bytes:
        stored = stored or self._store.load()
        return self._key(stored).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        stored = self._store.load()
        if stored is None:
            raise RuntimeError("No device key")
        return self._key(stored).sign(message)

    def remember_device(self, device_id: uuid.UUID) -> None:
        stored = self._store.load()
        self._store.save(StoredIdentity(stored.private_key, device_id))

    def forget(self) -> None:
        """Drop the key and device ID (after revocation or when the server no longer knows the device)."""
        self._store.clear()
