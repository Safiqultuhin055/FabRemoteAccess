"""Device registration, Remote IDs, verified presence, rotation, revocation (LocalDB, runtime role)."""

from __future__ import annotations

import base64
import hashlib
import re
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.domain.constants import Role
from app.domain.errors import ConflictError, ProofRejectedError
from app.security import device_proof
from app.services.context import RequestContext
from auth_support import make_env
from test_auth_concurrency import race

B = "/api/v1/devices"


class DeviceKey:
    def __init__(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(serialization.Encoding.Raw,
                                                             serialization.PublicFormat.Raw)

    @property
    def public_b64(self) -> str:
        return base64.b64encode(self.public).decode()

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.private.sign(message)).decode()


def b64(value: str) -> bytes:
    return base64.b64decode(value)


@pytest.fixture
def env(runtime_db):
    return make_env(runtime_db)


def code_of(response) -> str:
    return response.json()["error"]["code"]


def start(env, headers, key: DeviceKey, name="OFFICE-PC"):
    response = env.client.post(f"{B}/registration-challenge", headers=headers,
                               json={"public_key": key.public_b64, "device_name": name, "os_name": "Windows",
                                     "os_version": "11", "client_version": "0.4.0"})
    assert response.status_code == 201, response.text
    return response.json()


def registration_signature(challenge: dict, user_id: uuid.UUID, key: DeviceKey, signer: DeviceKey | None = None):
    message = device_proof.registration_message(uuid.UUID(challenge["challenge_id"]), b64(challenge["nonce"]),
                                                user_id, key.public)
    return (signer or key).sign(message)


def register(env, account, headers, key: DeviceKey | None = None, name="OFFICE-PC"):
    key = key or DeviceKey()
    challenge = start(env, headers, key, name)
    response = env.client.post(f"{B}/register", headers=headers, json={
        "challenge_id": challenge["challenge_id"], "signature": registration_signature(challenge, account.id, key)})
    assert response.status_code == 201, response.text
    return response.json(), key


def heartbeat(env, headers, device_id: str, key: DeviceKey, *, signer: DeviceKey | None = None):
    challenge = env.client.post(f"{B}/{device_id}/challenge", headers=headers)
    assert challenge.status_code == 201, challenge.text
    body = challenge.json()
    message = device_proof.presence_message(uuid.UUID(body["challenge_id"]), b64(body["nonce"]), uuid.UUID(device_id))
    return env.client.post(f"{B}/{device_id}/presence", headers=headers,
                           json={"challenge_id": body["challenge_id"], "signature": (signer or key).sign(message)})


def signed_in(env, *roles):
    account = env.account(*roles)
    return account, env.bearer(account)


# ------------------------------------------------------------------ registration


def test_successful_registration(env, migrated):
    account, headers = signed_in(env)
    device, key = register(env, account, headers)
    assert re.fullmatch(r"[1-9][0-9]{8}", device["remote_id"]) and 100_000_000 <= int(device["remote_id"]) <= 999_999_999
    assert device["identity_verified"] is True and device["online"] is False and device["status"] == "active"
    assert device["key_fingerprint"] == hashlib.sha256(key.public).hexdigest()
    assert device["display_name"] == "OFFICE-PC"
    me = env.client.get(f"{B}/me", headers=headers)
    assert me.status_code == 200 and me.json()["id"] == device["id"] and "ETag" in me.headers
    assert migrated.scalar("SELECT COUNT(*) FROM fr.remote_id_registry WHERE remote_id = ?", device["remote_id"]) == 1
    assert migrated.scalar("SELECT COUNT(*) FROM fr.audit_events WHERE event_type = 'device.registered' "
                           "AND subject_id = ?", device["id"]) == 1


@pytest.mark.parametrize("method, path", [
    ("post", f"{B}/registration-challenge"), ("post", f"{B}/register"), ("get", f"{B}/me"), ("get", B),
    ("get", f"{B}/{uuid.uuid4()}"), ("patch", f"{B}/{uuid.uuid4()}"), ("post", f"{B}/{uuid.uuid4()}/revoke"),
    ("post", f"{B}/{uuid.uuid4()}/challenge"), ("post", f"{B}/{uuid.uuid4()}/presence"),
    ("post", f"{B}/{uuid.uuid4()}/keys/rotate"),
])
def test_authentication_required(env, method, path):
    response = env.client.request(method.upper(), path, json=None if method == "get" else {})
    assert response.status_code == 401


@pytest.mark.parametrize("public_key", [
    base64.b64encode(b"x" * 31).decode(), base64.b64encode(b"x" * 33).decode(), "not-base64!", "AAAA",
])
def test_malformed_public_keys_rejected(env, public_key):
    _, headers = signed_in(env)
    response = env.client.post(f"{B}/registration-challenge", headers=headers,
                               json={"public_key": public_key, "device_name": "PC"})
    assert response.status_code == 422


def test_client_cannot_choose_its_remote_id_or_status(env):
    account, headers = signed_in(env)
    key = DeviceKey()
    challenge = start(env, headers, key)
    for extra in ({"remote_id": "123456789"}, {"identity_verified": True}, {"online": True}):
        response = env.client.post(f"{B}/register", headers=headers, json={
            "challenge_id": challenge["challenge_id"],
            "signature": registration_signature(challenge, account.id, key), **extra})
        assert response.status_code == 422


def test_forged_signature_burns_the_challenge(env):
    account, headers = signed_in(env)
    key = DeviceKey()
    challenge = start(env, headers, key)
    forged = env.client.post(f"{B}/register", headers=headers, json={
        "challenge_id": challenge["challenge_id"],
        "signature": registration_signature(challenge, account.id, key, signer=DeviceKey())})
    assert forged.status_code == 400 and code_of(forged) == "invalid_signature"
    retry = env.client.post(f"{B}/register", headers=headers, json={
        "challenge_id": challenge["challenge_id"], "signature": registration_signature(challenge, account.id, key)})
    assert retry.status_code == 400 and code_of(retry) == "invalid_challenge"


def test_replay_of_a_successful_registration_is_rejected(env):
    account, headers = signed_in(env)
    key = DeviceKey()
    challenge = start(env, headers, key)
    payload = {"challenge_id": challenge["challenge_id"], "signature": registration_signature(challenge, account.id, key)}
    assert env.client.post(f"{B}/register", headers=headers, json=payload).status_code == 201
    replay = env.client.post(f"{B}/register", headers=headers, json=payload)
    assert replay.status_code == 400 and code_of(replay) == "invalid_challenge"
    assert len(env.client.get(B, headers=headers).json()["items"]) == 1


def test_expired_challenge(env):
    account, headers = signed_in(env)
    key = DeviceKey()
    challenge = start(env, headers, key)
    env.clock.advance(seconds=121)
    response = env.client.post(f"{B}/register", headers=headers, json={
        "challenge_id": challenge["challenge_id"], "signature": registration_signature(challenge, account.id, key)})
    assert response.status_code == 400 and code_of(response) == "invalid_challenge"


def test_challenge_is_bound_to_user_and_session(env):
    account, headers = signed_in(env)
    key = DeviceKey()
    challenge = start(env, headers, key)
    other, other_headers = signed_in(env)
    stolen = env.client.post(f"{B}/register", headers=other_headers, json={
        "challenge_id": challenge["challenge_id"], "signature": registration_signature(challenge, other.id, key)})
    assert stolen.status_code == 400 and code_of(stolen) == "invalid_challenge"
    second_session = env.bearer(account)   # same user, different login session
    response = env.client.post(f"{B}/register", headers=second_session, json={
        "challenge_id": challenge["challenge_id"], "signature": registration_signature(challenge, account.id, key)})
    assert response.status_code == 400 and code_of(response) == "invalid_challenge"


def test_signature_for_another_purpose_is_rejected(env):
    account, headers = signed_in(env)
    key = DeviceKey()
    challenge = start(env, headers, key)
    wrong = device_proof.presence_message(uuid.UUID(challenge["challenge_id"]), b64(challenge["nonce"]), account.id)
    response = env.client.post(f"{B}/register", headers=headers,
                               json={"challenge_id": challenge["challenge_id"], "signature": key.sign(wrong)})
    assert response.status_code == 400 and code_of(response) == "invalid_signature"


def test_a_key_can_be_registered_only_once(env):
    account, headers = signed_in(env)
    _, key = register(env, account, headers)
    other, other_headers = signed_in(env)
    response = env.client.post(f"{B}/registration-challenge", headers=other_headers,
                               json={"public_key": key.public_b64, "device_name": "Copy"})
    assert response.status_code == 409 and code_of(response) == "key_already_registered"


def test_device_limit(runtime_db):
    env = make_env(runtime_db, max_devices_per_user=1)
    account, headers = signed_in(env)
    register(env, account, headers)
    response = env.client.post(f"{B}/registration-challenge", headers=headers,
                               json={"public_key": DeviceKey().public_b64, "device_name": "Second"})
    assert response.status_code == 409 and code_of(response) == "device_limit_reached"


# ------------------------------------------------------------------ Remote IDs


def test_remote_ids_are_unique_nine_digit_values(env):
    account, headers = signed_in(env)
    ids = [register(env, account, headers)[0]["remote_id"] for _ in range(6)]
    assert len(set(ids)) == 6 and all(re.fullmatch(r"[1-9][0-9]{8}", i) for i in ids)


def test_collision_is_retried_and_ids_are_never_reused_after_revocation(env):
    account, headers = signed_in(env)
    first, _ = register(env, account, headers)
    revoked = env.client.post(f"{B}/{first['id']}/revoke", headers=headers)
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    # The generator proposes the revoked device's ID first: it must be skipped, not reused.
    proposals = iter([first["remote_id"], first["remote_id"], "987650001"])
    service = env.app.state.device_service
    service._next_remote_id = lambda: next(proposals)
    account2, headers2 = signed_in(env)
    second, _ = register(env, account2, headers2)
    assert second["remote_id"] == "987650001" and second["remote_id"] != first["remote_id"]


def test_exhausted_allocation_fails_safely(env):
    account, headers = signed_in(env)
    taken, _ = register(env, account, headers)
    env.app.state.device_service._next_remote_id = lambda: taken["remote_id"]
    key = DeviceKey()
    challenge = start(env, headers, key)
    response = env.client.post(f"{B}/register", headers=headers, json={
        "challenge_id": challenge["challenge_id"], "signature": registration_signature(challenge, account.id, key)})
    assert response.status_code == 503 and code_of(response) == "dependency_unavailable"
    assert "retry" not in response.text.lower() and "registry" not in response.text.lower()
    # The failed attempt rolled back: the challenge is still usable once IDs are available again.
    env.app.state.device_service._next_remote_id = lambda: "987650099"
    again = env.client.post(f"{B}/register", headers=headers, json={
        "challenge_id": challenge["challenge_id"], "signature": registration_signature(challenge, account.id, key)})
    assert again.status_code == 201 and again.json()["remote_id"] == "987650099"


def test_concurrent_use_of_one_challenge_registers_once(env):
    account, headers = signed_in(env)
    key = DeviceKey()
    challenge = start(env, headers, key)
    principal = env.app.state.auth_service.authenticate_bearer(headers["Authorization"].split()[1])
    signature = b64(registration_signature(challenge, account.id, key))
    service = env.app.state.device_service
    results = race(lambda: service.register(principal, uuid.UUID(challenge["challenge_id"]), signature,
                                            RequestContext()))
    assert sum(kind == "ok" for kind, _ in results) == 1
    assert all(isinstance(r, (ProofRejectedError, ConflictError)) for kind, r in results if kind == "error")
    assert len(env.client.get(B, headers=headers).json()["items"]) == 1


def test_concurrent_registrations_get_distinct_ids(env):
    service = env.app.state.device_service
    jobs = []
    for _ in range(4):
        account, headers = signed_in(env)
        key = DeviceKey()
        challenge = start(env, headers, key)
        principal = env.app.state.auth_service.authenticate_bearer(headers["Authorization"].split()[1])
        jobs.append((principal, uuid.UUID(challenge["challenge_id"]), b64(registration_signature(challenge, account.id, key))))
    counter = iter(range(len(jobs)))
    results = race(lambda: service.register(*jobs[next(counter)], RequestContext()))
    ids = [r.device.remote_id for kind, r in results if kind == "ok"]
    assert len(ids) == 4 and len(set(ids)) == 4


# ------------------------------------------------------------------ authorization


def test_other_users_cannot_see_or_change_a_device(env):
    owner, owner_headers = signed_in(env)
    device, key = register(env, owner, owner_headers)
    _, stranger = signed_in(env)
    did = device["id"]
    assert env.client.get(f"{B}/{did}", headers=stranger).status_code == 404
    for tag in ('"x"', env.client.get(f"{B}/{did}", headers=owner_headers).headers["ETag"]):
        # Regression: an unreadable tag used to answer 412, revealing that the device exists.
        assert env.client.patch(f"{B}/{did}", headers={**stranger, "If-Match": tag},
                                json={"display_name": "Mine"}).status_code == 404
    assert env.client.post(f"{B}/{did}/revoke", headers=stranger).status_code == 404
    assert env.client.post(f"{B}/{did}/challenge", headers=stranger).status_code == 404
    assert env.client.get(f"{B}?owner_user_id={owner.id}", headers=stranger).status_code == 403
    assert did not in [d["id"] for d in env.client.get(B, headers=stranger).json()["items"]]


def test_admin_can_view_and_revoke_but_not_operate(env):
    owner, owner_headers = signed_in(env)
    device, key = register(env, owner, owner_headers)
    _, admin = signed_in(env, Role.ADMIN)
    assert env.client.get(f"{B}/{device['id']}", headers=admin).status_code == 200
    assert env.client.get(f"{B}?owner_user_id={owner.id}", headers=admin).json()["items"][0]["id"] == device["id"]
    assert env.client.post(f"{B}/{device['id']}/challenge", headers=admin).status_code == 404   # not the owner
    response = env.client.post(f"{B}/{device['id']}/revoke", headers=admin, json={"reason": "key_compromised"})
    assert response.status_code == 200 and response.json()["revoked_reason"] == "key_compromised"


def test_owner_cannot_use_administrator_reasons(env):
    owner, headers = signed_in(env)
    device, _ = register(env, owner, headers)
    response = env.client.post(f"{B}/{device['id']}/revoke", headers=headers, json={"reason": "admin_revoked"})
    assert response.status_code == 403


# ------------------------------------------------------------------ presence


def test_verified_heartbeat_and_expiry(env):
    owner, headers = signed_in(env)
    device, key = register(env, owner, headers)
    beat = heartbeat(env, headers, device["id"], key)
    assert beat.status_code == 200 and beat.json()["online"] is True
    env.clock.advance(seconds=91)
    assert env.client.get(f"{B}/{device['id']}", headers=headers).json()["online"] is False   # stale
    assert heartbeat(env, headers, device["id"], key).json()["online"] is True


def test_heartbeat_requires_the_device_key(env):
    owner, headers = signed_in(env)
    device, key = register(env, owner, headers)
    forged = heartbeat(env, headers, device["id"], key, signer=DeviceKey())
    assert forged.status_code == 400 and code_of(forged) == "invalid_signature"
    assert env.client.get(f"{B}/{device['id']}", headers=headers).json()["online"] is False


def test_heartbeat_challenge_is_single_use_and_device_bound(env):
    owner, headers = signed_in(env)
    a, key_a = register(env, owner, headers)
    b, key_b = register(env, owner, headers)
    body = env.client.post(f"{B}/{a['id']}/challenge", headers=headers).json()
    message = device_proof.presence_message(uuid.UUID(body["challenge_id"]), b64(body["nonce"]), uuid.UUID(a["id"]))
    payload = {"challenge_id": body["challenge_id"], "signature": key_a.sign(message)}
    assert env.client.post(f"{B}/{b['id']}/presence", headers=headers, json=payload).status_code == 400  # other device
    assert env.client.post(f"{B}/{a['id']}/presence", headers=headers, json=payload).status_code == 200
    replay = env.client.post(f"{B}/{a['id']}/presence", headers=headers, json=payload)
    assert replay.status_code == 400 and code_of(replay) == "invalid_challenge"


def test_client_cannot_claim_presence(env):
    owner, headers = signed_in(env)
    device, _ = register(env, owner, headers)
    response = env.client.post(f"{B}/{device['id']}/presence", headers=headers,
                               json={"challenge_id": str(uuid.uuid4()), "signature": "AAAA", "online": True})
    assert response.status_code == 422


def test_revoked_device_is_never_online(env):
    owner, headers = signed_in(env)
    device, key = register(env, owner, headers)
    spare_challenge = env.client.post(f"{B}/{device['id']}/challenge", headers=headers).json()
    assert heartbeat(env, headers, device["id"], key).json()["online"] is True
    _, admin = signed_in(env, Role.ADMIN)
    revoked = env.client.post(f"{B}/{device['id']}/revoke", headers=admin).json()
    assert revoked["online"] is False and revoked["identity_verified"] is False and revoked["key_fingerprint"] is None
    message = device_proof.presence_message(uuid.UUID(spare_challenge["challenge_id"]), b64(spare_challenge["nonce"]),
                                            uuid.UUID(device["id"]))
    late = env.client.post(f"{B}/{device['id']}/presence", headers=headers,
                           json={"challenge_id": spare_challenge["challenge_id"], "signature": key.sign(message)})
    assert late.status_code in (400, 401)   # 401: the owner's session bound to this device was revoked too


def test_revocation_ends_sessions_bound_to_the_device(env):
    owner, headers = signed_in(env)
    device, key = register(env, owner, headers)   # registration binds this session to the device
    other_session = env.bearer(owner)             # an unrelated session of the same user
    assert env.client.post(f"{B}/{device['id']}/revoke", headers=other_session).status_code == 200
    assert env.client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert env.client.get("/api/v1/auth/me", headers=other_session).status_code == 200


# ------------------------------------------------------------------ key rotation


def rotate(env, headers, device_id: str, current: DeviceKey, new: DeviceKey, *, forge_current=False):
    body = env.client.post(f"{B}/{device_id}/challenge", headers=headers).json()
    message = device_proof.rotation_message(uuid.UUID(body["challenge_id"]), b64(body["nonce"]),
                                            uuid.UUID(device_id), new.public)
    return env.client.post(f"{B}/{device_id}/keys/rotate", headers=headers, json={
        "challenge_id": body["challenge_id"], "new_public_key": new.public_b64,
        "signature_current": (DeviceKey() if forge_current else current).sign(message),
        "signature_new": new.sign(message)})


def test_key_rotation(env, migrated):
    owner, headers = signed_in(env)
    device, old = register(env, owner, headers)
    new = DeviceKey()
    response = rotate(env, headers, device["id"], old, new)
    assert response.status_code == 200
    assert response.json()["key_fingerprint"] == hashlib.sha256(new.public).hexdigest()
    assert response.json()["remote_id"] == device["remote_id"]          # identity kept
    assert heartbeat(env, headers, device["id"], old).status_code == 400  # old key no longer accepted
    assert heartbeat(env, headers, device["id"], new).json()["online"] is True
    assert migrated.scalar("SELECT revoked_reason FROM fr.device_keys WHERE fingerprint = ?",
                           hashlib.sha256(old.public).digest()) == "rotated"


def test_rotation_needs_both_keys_and_an_unused_key(env):
    owner, headers = signed_in(env)
    device, current = register(env, owner, headers)
    forged = rotate(env, headers, device["id"], current, DeviceKey(), forge_current=True)
    assert forged.status_code == 400 and code_of(forged) == "invalid_signature"
    _, taken = register(env, owner, headers)
    assert rotate(env, headers, device["id"], current, taken).status_code == 409


# ------------------------------------------------------------------ updates and audit


def test_patch_requires_matching_etag(env):
    owner, headers = signed_in(env)
    device, _ = register(env, owner, headers)
    url = f"{B}/{device['id']}"
    assert env.client.patch(url, headers=headers, json={"display_name": "X"}).status_code == 428
    tag = env.client.get(url, headers=headers).headers["ETag"]
    renamed = env.client.patch(url, headers={**headers, "If-Match": tag},
                               json={"display_name": "Reception PC", "incoming_policy": "address_book_only"})
    assert renamed.status_code == 200 and renamed.json()["display_name"] == "Reception PC"
    stale = env.client.patch(url, headers={**headers, "If-Match": tag}, json={"display_name": "Again"})
    assert stale.status_code == 412


def test_audit_never_contains_keys_nonces_or_signatures(env, migrated):
    owner, headers = signed_in(env)
    device, key = register(env, owner, headers)
    heartbeat(env, headers, device["id"], key, signer=DeviceKey())   # failure is audited too
    rows = " ".join(str(r) for r in migrated.execute(
        "SELECT event_type, details FROM fr.audit_events WHERE actor_user_id = ?", owner.id))
    assert "device.registered" in rows and "device.presence" in rows
    assert key.public_b64 not in rows and "signature\":" not in rows and "nonce" not in rows
