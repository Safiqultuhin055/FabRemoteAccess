"""Real device gateway and key storage. The fake server verifies signatures with the backend's code."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import uuid

import pytest

from app.security import device_proof as server_proof   # backend implementation (pythonpath: backend)
from fabremote import device_identity as client_proof
from fabremote.api_client import ApiError
from fabremote.device import (PHASE_3D_REASON, UNEXPECTED, UNREACHABLE, ApiDeviceGateway, AuthRequiredError,
                              GatewayError)
from fabremote.device_identity import DeviceIdentity, DpapiKeyStore, MemoryKeyStore, StoredIdentity

USER_ID = str(uuid.uuid4())


# ------------------------------------------------------------ message format


def test_client_and_server_sign_identical_messages():
    cid, nonce, uid, did, key = uuid.uuid4(), bytes(range(32)), uuid.uuid4(), uuid.uuid4(), bytes(32)
    assert client_proof.registration_message(cid, nonce, uid, key) == server_proof.registration_message(cid, nonce, uid, key)
    assert client_proof.presence_message(cid, nonce, did) == server_proof.presence_message(cid, nonce, did)
    assert client_proof.rotation_message(cid, nonce, did, key) == server_proof.rotation_message(cid, nonce, did, key)


# ------------------------------------------------------------ key storage


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_dpapi_store_round_trip_and_never_writes_the_raw_key(tmp_path):
    store = DpapiKeyStore(tmp_path / "device.json")
    identity = DeviceIdentity(store)
    public = identity.ensure_key()
    raw = store.load().private_key
    text = (tmp_path / "device.json").read_text(encoding="utf-8")
    assert raw not in text.encode() and base64.b64encode(raw).decode() not in text
    assert identity.ensure_key() == public                      # stable across calls
    device_id = uuid.uuid4()
    identity.remember_device(device_id)
    assert DeviceIdentity(DpapiKeyStore(tmp_path / "device.json")).device_id == device_id
    identity.forget()
    assert not (tmp_path / "device.json").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_tampered_or_foreign_key_file_is_ignored(tmp_path):
    path = tmp_path / "device.json"
    DeviceIdentity(DpapiKeyStore(path)).ensure_key()
    record = json.loads(path.read_text(encoding="utf-8"))
    record["private_key_dpapi"] = base64.b64encode(b"not a dpapi blob").decode()
    path.write_text(json.dumps(record), encoding="utf-8")
    assert DpapiKeyStore(path).load() is None
    path.write_text("{broken", encoding="utf-8")
    assert DpapiKeyStore(path).load() is None


def test_store_location_is_per_server_and_overridable(tmp_path, monkeypatch):
    monkeypatch.setenv("FR_DESKTOP_DATA_DIR", str(tmp_path))
    a = DpapiKeyStore.for_server("http://127.0.0.1:8765").path
    b = DpapiKeyStore.for_server("https://remote.example.com").path
    assert a != b and a.parent == tmp_path / "devices"


# ------------------------------------------------------------ fake server


class FakeDeviceServer:
    """Implements the device endpoints the gateway uses, with real signature verification."""

    def __init__(self):
        self.devices: dict[str, dict] = {}
        self.keys: dict[str, bytes] = {}
        self.challenges: dict[str, dict] = {}
        self.requests: list[tuple[str, dict]] = []
        self.fail: dict[str, ApiError] = {}
        self.drop_register_response = False
        self.online_after_heartbeat = True

    def _check(self, name):
        if name in self.fail:
            raise self.fail[name]

    def _record(self, name, **body):
        self.requests.append((name, body))
        self._check(name)

    def registration_challenge(self, public_key_b64, device_name, os_name, os_version, client_version):
        self._record("registration_challenge", public_key=public_key_b64, device_name=device_name)
        key = base64.b64decode(public_key_b64)
        if any(k == key for k in self.keys.values()):
            raise ApiError(409, "key_already_registered", "x")
        cid = str(uuid.uuid4())
        self.challenges[cid] = {"nonce": bytes(range(32)), "key": key, "name": device_name}
        return {"challenge_id": cid, "nonce": base64.b64encode(bytes(range(32))).decode()}

    def register_device(self, challenge_id, signature_b64):
        self._record("register_device", challenge_id=challenge_id, signature=signature_b64)
        ch = self.challenges.pop(challenge_id)
        message = server_proof.registration_message(uuid.UUID(challenge_id), ch["nonce"], uuid.UUID(USER_ID), ch["key"])
        if not server_proof.verify(ch["key"], base64.b64decode(signature_b64), message):
            raise ApiError(400, "invalid_signature", "x")
        did = str(uuid.uuid4())
        self.devices[did] = {"id": did, "remote_id": "105280964", "display_name": ch["name"], "status": "active",
                             "identity_verified": True, "online": False,
                             "key_fingerprint": hashlib.sha256(ch["key"]).hexdigest()}
        self.keys[did] = ch["key"]
        if self.drop_register_response:
            raise ApiError(0, "network_error", "lost")
        return dict(self.devices[did])

    def get_device(self, device_id):
        self._record("get_device", device_id=device_id)
        if device_id not in self.devices:
            raise ApiError(404, "not_found", "x")
        return dict(self.devices[device_id])

    def list_devices(self):
        self._record("list_devices")
        return [dict(d) for d in self.devices.values()]

    def device_challenge(self, device_id):
        self._record("device_challenge", device_id=device_id)
        cid = str(uuid.uuid4())
        self.challenges[cid] = {"nonce": bytes(range(1, 33)), "device": device_id}
        return {"challenge_id": cid, "nonce": base64.b64encode(bytes(range(1, 33))).decode()}

    def device_presence(self, device_id, challenge_id, signature_b64):
        self._record("device_presence", device_id=device_id, challenge_id=challenge_id, signature=signature_b64)
        ch = self.challenges.pop(challenge_id)
        message = server_proof.presence_message(uuid.UUID(challenge_id), ch["nonce"], uuid.UUID(device_id))
        if not server_proof.verify(self.keys[device_id], base64.b64decode(signature_b64), message):
            raise ApiError(400, "invalid_signature", "x")
        self.devices[device_id]["online"] = self.online_after_heartbeat
        return dict(self.devices[device_id])


@pytest.fixture
def server():
    return FakeDeviceServer()


@pytest.fixture
def store():
    return MemoryKeyStore()


def gateway(server, store) -> ApiDeviceGateway:
    return ApiDeviceGateway(server, DeviceIdentity(store), USER_ID)


# ------------------------------------------------------------ registration


def test_register_verify_and_heartbeat(server, store):
    g = gateway(server, store)
    registration = g.register("OFFICE-PC")
    assert registration.remote_id == "105280964" and g.has_local_device()
    assert g.verify_identity() is True
    assert g.is_online() is True


def test_private_key_is_never_sent(server, store):
    g = gateway(server, store)
    g.register("OFFICE-PC")
    g.is_online()
    private = store.identity.private_key
    sent = json.dumps(server.requests)
    for form in (private.hex(), base64.b64encode(private).decode()):
        assert form not in sent


def test_lost_register_response_is_adopted_not_duplicated(server, store):
    g = gateway(server, store)
    server.drop_register_response = True
    with pytest.raises(GatewayError) as info:
        g.register("OFFICE-PC")
    assert info.value.user_message == UNREACHABLE and not g.has_local_device()
    server.drop_register_response = False
    registration = g.register("OFFICE-PC")       # retry with the same stored key
    assert registration.remote_id == "105280964" and len(server.devices) == 1


def test_key_registered_to_someone_else_is_discarded(server, store):
    g = gateway(server, store)
    public = DeviceIdentity(store).ensure_key()
    server.keys["other-account-device"] = public   # present on the server, not in this user's list
    with pytest.raises(GatewayError):
        g.register("OFFICE-PC")
    assert store.identity is None                  # a fresh key will be created next time


@pytest.mark.parametrize("error, expected", [
    (ApiError(0, "network_error", "x"), UNREACHABLE),
    (ApiError(404, "not_found", "x"), PHASE_3D_REASON),
    (ApiError(409, "device_limit_reached", "x"), "maximum number of registered devices"),
    (ApiError(429, "rate_limited", "x"), "Too many attempts"),
    (ApiError(503, "dependency_unavailable", "x"), "temporarily unavailable"),
    (ApiError(422, "validation_error", "PWD=secret internal"), "Registration failed. Try again."),
])
def test_registration_errors_map_to_safe_messages(server, store, error, expected):
    server.fail["registration_challenge"] = error
    with pytest.raises(GatewayError) as info:
        gateway(server, store).register("OFFICE-PC")
    assert expected in info.value.user_message and "secret" not in info.value.user_message


def test_expired_session_requires_sign_in(server, store):
    server.fail["registration_challenge"] = ApiError(401, "session_expired", "x")
    with pytest.raises(AuthRequiredError):
        gateway(server, store).register("OFFICE-PC")


@pytest.mark.parametrize("bad", [
    {"remote_id": "012345678"}, {"remote_id": "12345"}, {"remote_id": None}, {"id": "not-a-uuid"},
    {"status": "weird"}, {"online": "yes"}, {"identity_verified": False},
])
def test_invalid_server_responses_are_rejected(server, store, bad):
    original = server.register_device

    def tampered(challenge_id, signature_b64):
        return {**original(challenge_id, signature_b64), **bad}

    server.register_device = tampered
    with pytest.raises(GatewayError) as info:
        gateway(server, store).register("OFFICE-PC")
    assert info.value.user_message == UNEXPECTED
    assert store.identity is None or store.identity.device_id is None   # never remembered as registered


def test_malformed_challenge_is_rejected(server, store):
    server.registration_challenge = lambda *a: {"challenge_id": str(uuid.uuid4()), "nonce": "AAAA"}
    with pytest.raises(GatewayError) as info:
        gateway(server, store).register("OFFICE-PC")
    assert info.value.user_message == UNEXPECTED


# ------------------------------------------------------------ resume and presence


def test_existing_registration_is_confirmed_with_the_server(server, store):
    gateway(server, store).register("OFFICE-PC")
    fresh = gateway(server, store)          # app restart
    assert fresh.existing().remote_id == "105280964"


@pytest.mark.parametrize("change", ["deleted", "revoked", "rotated"])
def test_stale_local_registration_is_forgotten(server, store, change):
    gateway(server, store).register("OFFICE-PC")
    device_id = str(store.identity.device_id)
    if change == "deleted":
        del server.devices[device_id]
    elif change == "revoked":
        server.devices[device_id]["status"] = "revoked"
    else:
        server.devices[device_id]["key_fingerprint"] = "0" * 64
    assert gateway(server, store).existing() is None and store.identity is None


def test_offline_comes_from_the_server(server, store):
    g = gateway(server, store)
    g.register("OFFICE-PC")
    server.online_after_heartbeat = False
    assert g.is_online() is False


def test_heartbeat_with_wrong_key_fails_safely(server, store):
    g = gateway(server, store)
    g.register("OFFICE-PC")
    store.identity = StoredIdentity(bytes(32), store.identity.device_id)   # different key locally
    with pytest.raises(GatewayError) as info:
        g.is_online()
    assert "could not be confirmed" in info.value.user_message
