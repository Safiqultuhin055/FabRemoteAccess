"""Phase 3e: devices without an account, device tokens, connection requests, consent and sessions
(LocalDB, runtime role)."""

from __future__ import annotations

import base64
import json
import uuid

import pytest

from app.db.models import AuditEvent, User
from app.domain.errors import ConflictError
from app.security import device_proof
from app.services.context import DevicePrincipal, RequestContext
from auth_support import make_env
from test_auth_concurrency import race
from test_devices_api import DeviceKey, b64, code_of, signed_in

D = "/api/v1/devices"
R = "/api/v1/connection-requests"
S = "/api/v1/sessions"


@pytest.fixture
def env(runtime_db):
    return make_env(runtime_db)


class Computer:
    """A computer registered without an account, holding a device token."""

    def __init__(self, env, name="HELPED-PC"):
        self.env, self.key = env, DeviceKey()
        challenge = env.client.post(f"{D}/anonymous/registration-challenge", json={
            "public_key": self.key.public_b64, "device_name": name, "os_name": "Windows"})
        assert challenge.status_code == 201, challenge.text
        body = challenge.json()
        message = device_proof.anonymous_registration_message(uuid.UUID(body["challenge_id"]), b64(body["nonce"]),
                                                              self.key.public)
        device = env.client.post(f"{D}/anonymous/register", json={"challenge_id": body["challenge_id"],
                                                                   "signature": self.key.sign(message)})
        assert device.status_code == 201, device.text
        self.device = device.json()
        self.id, self.remote_id = self.device["id"], self.device["remote_id"]
        self.token = self.new_token()

    def new_token(self, signer: DeviceKey | None = None):
        challenge = self.env.client.post(f"{D}/token-challenge", json={"device_id": self.id})
        assert challenge.status_code == 201, challenge.text
        body = challenge.json()
        message = device_proof.token_message(uuid.UUID(body["challenge_id"]), b64(body["nonce"]), uuid.UUID(self.id))
        response = self.env.client.post(f"{D}/token", json={"device_id": self.id, "challenge_id": body["challenge_id"],
                                                            "signature": (signer or self.key).sign(message)})
        if signer is not None:
            return response
        assert response.status_code == 200, response.text
        return response.json()["device_token"]

    @property
    def headers(self) -> dict:
        return {"X-Device-Token": self.token}

    def incoming(self) -> dict:
        response = self.env.client.get(f"{R}/incoming", headers=self.headers)
        assert response.status_code == 200, response.text
        return response.json()


class Helper:
    """A signed-in user on a registered computer."""

    def __init__(self, env):
        self.account, bearer = signed_in(env)
        self.computer = Computer(env, "HELPER-PC")
        self.headers = {**bearer, **self.computer.headers}
        self.bearer = bearer


def ask(env, helper: Helper, remote_id: str, **extra):
    return env.client.post(R, headers=helper.headers, json={"remote_id": remote_id, **extra})


def pending(env, helper: Helper, target: Computer) -> dict:
    response = ask(env, helper, target.remote_id)
    assert response.status_code == 201, response.text
    return response.json()


# ------------------------------------------------------------------ no account, device tokens


def test_computer_registers_without_an_account_and_comes_online(env):
    target = Computer(env)
    assert target.device["identity_verified"] is True and target.device["status"] == "active"
    response = env.client.post(f"{D}/self/heartbeat", headers=target.headers)
    assert response.status_code == 200 and response.json()["online"] is True
    assert env.client.get(f"{D}/self", headers=target.headers).json()["remote_id"] == target.remote_id
    with env.db.unit_of_work() as uow:
        assert uow.devices.get(uuid.UUID(target.id)).owner_user_id is None


def test_anonymous_registration_needs_a_valid_signature_and_allows_one_guess(env):
    key, other = DeviceKey(), DeviceKey()
    body = env.client.post(f"{D}/anonymous/registration-challenge",
                           json={"public_key": key.public_b64, "device_name": "PC"}).json()
    message = device_proof.anonymous_registration_message(uuid.UUID(body["challenge_id"]), b64(body["nonce"]),
                                                          key.public)
    bad = env.client.post(f"{D}/anonymous/register", json={"challenge_id": body["challenge_id"],
                                                            "signature": other.sign(message)})
    assert bad.status_code == 400 and code_of(bad) == "invalid_signature"
    again = env.client.post(f"{D}/anonymous/register", json={"challenge_id": body["challenge_id"],
                                                              "signature": key.sign(message)})
    assert again.status_code == 400 and code_of(again) == "invalid_challenge"


def test_signed_in_registration_message_cannot_be_replayed_as_anonymous(env):
    key = DeviceKey()
    body = env.client.post(f"{D}/anonymous/registration-challenge",
                           json={"public_key": key.public_b64, "device_name": "PC"}).json()
    wrong_purpose = device_proof.registration_message(uuid.UUID(body["challenge_id"]), b64(body["nonce"]),
                                                      uuid.UUID(int=0), key.public)
    response = env.client.post(f"{D}/anonymous/register", json={"challenge_id": body["challenge_id"],
                                                                 "signature": key.sign(wrong_purpose)})
    assert response.status_code == 400


def test_device_token_requires_the_device_key_and_ends_with_revocation(env):
    target = Computer(env)
    assert target.new_token(signer=DeviceKey()).status_code == 400
    admin, admin_bearer = signed_in(env, "admin")
    assert env.client.post(f"{D}/{target.id}/revoke", headers=admin_bearer).status_code == 200
    response = env.client.get(f"{D}/self", headers=target.headers)
    assert response.status_code == 401 and code_of(response) == "invalid_device_token"
    assert env.client.post(f"{D}/token-challenge", json={"device_id": target.id}).status_code == 404


def test_access_tokens_and_device_tokens_are_not_interchangeable(env):
    helper = Helper(env)
    as_device = env.client.get(f"{D}/self", headers={"X-Device-Token": helper.bearer["Authorization"][7:]})
    assert as_device.status_code == 401
    as_user = env.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {helper.computer.token}"})
    assert as_user.status_code == 401


# ------------------------------------------------------------------ consent flow


def test_full_consent_flow_request_accept_and_disconnect(env):
    helper, target = Helper(env), Computer(env)
    request = pending(env, helper, target)
    assert request["status"] == "pending" and request["target_remote_id"] == target.remote_id
    assert request["requester"] is None                                   # the requester's own view

    incoming = target.incoming()
    assert [i["id"] for i in incoming["items"]] == [request["id"]]
    shown = incoming["items"][0]
    assert shown["requester"] == {"display_name": "Test User", "email": helper.account.email}
    assert shown["requester_device"]["remote_id"] == helper.computer.remote_id

    approved = env.client.post(f"{R}/{request['id']}/approve", headers=target.headers)
    assert approved.status_code == 201, approved.text
    session = approved.json()
    assert session["state"] == "authorizing" and session["media_available"] is False
    assert session["target"]["display_name"] == "HELPED-PC"

    status = env.client.get(f"{R}/{request['id']}", headers=helper.bearer).json()
    assert status["status"] == "approved" and status["session_id"] == session["id"]
    as_controller = env.client.get(f"{S}/{session['id']}", headers=helper.bearer).json()
    assert as_controller["target"]["display_name"] is None                # never the target's device name
    assert as_controller["controller"]["device_remote_id"] == helper.computer.remote_id
    assert target.incoming()["live_session_id"] == session["id"]

    ended = env.client.post(f"{S}/{session['id']}/terminate", headers=target.headers)
    assert ended.status_code == 200 and ended.json()["end_reason"] == "target_disconnect"
    again = env.client.post(f"{S}/{session['id']}/terminate", headers=helper.bearer)
    assert again.json()["end_reason"] == "target_disconnect"             # idempotent
    assert env.client.get(f"{S}/{session['id']}", headers=helper.bearer).json()["state"] == "ended"


def test_requesting_needs_a_signed_in_user_and_a_device_token(env):
    helper, target = Helper(env), Computer(env)
    no_user = env.client.post(R, headers=helper.computer.headers, json={"remote_id": target.remote_id})
    assert no_user.status_code == 401
    no_device = env.client.post(R, headers=helper.bearer, json={"remote_id": target.remote_id})
    assert no_device.status_code == 401 and code_of(no_device) == "device_token_required"


def test_unverified_account_cannot_request(env):
    helper, target = Helper(env), Computer(env)
    with env.db.unit_of_work() as uow:
        uow.users.get(helper.account.id).email_verified_at = None
        uow.commit()
    response = ask(env, helper, target.remote_id)
    assert response.status_code == 403 and code_of(response) == "account_not_verified"


def test_every_refusal_looks_the_same_to_the_requester(env):
    helper = Helper(env)
    offline = Computer(env)
    env.clock.advance(seconds=env.app.state.settings.presence_ttl_seconds + 5)
    helper = Helper(env)                                                  # fresh tokens after the clock moved
    blocked, disabled, busy = Computer(env), Computer(env), Computer(env)
    with env.db.unit_of_work() as uow:
        uow.connections.block(uuid.UUID(blocked.id), helper.account.id)
        uow.devices.get(uuid.UUID(disabled.id)).incoming_policy = "disabled"
        uow.commit()
    other = Helper(env)
    busy_request = pending(env, other, busy)
    assert env.client.post(f"{R}/{busy_request['id']}/approve", headers=busy.headers).status_code == 201

    bodies = []
    for remote_id in ("987654321", offline.remote_id, blocked.remote_id, disabled.remote_id, busy.remote_id):
        response = ask(env, helper, remote_id)
        assert response.status_code == 404, (remote_id, response.text)
        error = response.json()["error"]
        bodies.append((error["code"], error["message"]))
    assert len(set(bodies)) == 1 and bodies[0][0] == "target_unavailable"


def test_cannot_connect_to_this_computer_itself(env):
    helper = Helper(env)
    response = ask(env, helper, helper.computer.remote_id)
    assert response.status_code == 422 and code_of(response) == "cannot_connect_to_self"


def test_asking_again_while_waiting_returns_the_same_request(env):
    helper, target = Helper(env), Computer(env)
    assert pending(env, helper, target)["id"] == pending(env, helper, target)["id"]


def test_only_the_target_device_can_answer(env):
    helper, target, stranger = Helper(env), Computer(env), Computer(env)
    request = pending(env, helper, target)
    for headers in (helper.computer.headers, stranger.headers):
        assert env.client.post(f"{R}/{request['id']}/approve", headers=headers).status_code == 404
        assert env.client.post(f"{R}/{request['id']}/reject", headers=headers).status_code == 404
    # A user token is not a device token: users cannot approve on a computer's behalf.
    assert env.client.post(f"{R}/{request['id']}/approve", headers=helper.bearer).status_code == 401


def test_double_approve_conflicts_and_late_approve_is_gone(env):
    helper, target = Helper(env), Computer(env)
    first = pending(env, helper, target)
    assert env.client.post(f"{R}/{first['id']}/approve", headers=target.headers).status_code == 201
    again = env.client.post(f"{R}/{first['id']}/approve", headers=target.headers)
    assert again.status_code == 409 and code_of(again) == "request_not_pending"

    other_helper, other_target = Helper(env), Computer(env)
    late = pending(env, other_helper, other_target)
    env.clock.advance(seconds=env.app.state.settings.connection_request_ttl_seconds + 1)
    gone = env.client.post(f"{R}/{late['id']}/approve", headers=other_target.headers)
    assert gone.status_code == 410 and code_of(gone) == "request_expired"
    status = env.client.get(f"{R}/{late['id']}", headers=other_helper.bearer).json()
    assert status["status"] == "expired" and status["decision_reason"] == "timeout"


def test_reject_with_block_stops_the_next_request(env):
    helper, target = Helper(env), Computer(env)
    request = pending(env, helper, target)
    rejected = env.client.post(f"{R}/{request['id']}/reject", headers=target.headers, json={"block_requester": True})
    assert rejected.status_code == 200 and rejected.json()["status"] == "rejected"
    assert env.client.get(f"{R}/{request['id']}", headers=helper.bearer).json()["decision_reason"] == "target_rejected"
    assert ask(env, helper, target.remote_id).status_code == 404


def test_cancelled_request_cannot_be_approved(env):
    helper, target = Helper(env), Computer(env)
    request = pending(env, helper, target)
    assert env.client.post(f"{R}/{request['id']}/cancel", headers=helper.bearer).json()["status"] == "cancelled"
    assert env.client.post(f"{R}/{request['id']}/approve", headers=target.headers).status_code == 409
    assert target.incoming()["items"] == []


def test_target_cannot_grant_more_than_requested(env):
    helper, target = Helper(env), Computer(env)
    request = pending(env, helper, target)
    response = env.client.post(f"{R}/{request['id']}/approve", headers=target.headers,
                               json={"permission_granted": "view_input"})
    assert response.status_code == 422 and code_of(response) == "permission_exceeds_request"


def test_strangers_cannot_see_requests_or_sessions(env):
    helper, target, stranger = Helper(env), Computer(env), Helper(env)
    request = pending(env, helper, target)
    assert env.client.get(f"{R}/{request['id']}", headers=stranger.bearer).status_code == 404
    session = env.client.post(f"{R}/{request['id']}/approve", headers=target.headers).json()
    assert env.client.get(f"{S}/{session['id']}", headers=stranger.bearer).status_code == 404
    assert env.client.get(f"{S}/{session['id']}", headers=stranger.computer.headers).status_code == 404
    assert env.client.post(f"{S}/{session['id']}/terminate", headers=stranger.bearer).status_code == 404


def test_session_ends_when_one_side_goes_silent(env):
    helper, target = Helper(env), Computer(env)
    request = pending(env, helper, target)
    session = env.client.post(f"{R}/{request['id']}/approve", headers=target.headers).json()
    timeout = env.app.state.settings.session_presence_timeout_seconds
    for _ in range(3):                      # only the target keeps polling; the helper went away
        env.clock.advance(seconds=timeout // 2 + 1)
        state = env.client.get(f"{S}/{session['id']}", headers=target.headers).json()
    assert state["state"] == "ended" and state["end_reason"] == "timeout"
    # The computer is free again for a new request.
    assert pending(env, Helper(env), target)["status"] == "pending"


def test_concurrent_approvals_for_one_computer_create_exactly_one_session(env):
    target = Computer(env)
    requests = [pending(env, Helper(env), target) for _ in range(4)]
    service = env.app.state.connection_service
    with env.db.unit_of_work() as uow:
        key = uow.devices.active_key(uuid.UUID(target.id))
    caller = DevicePrincipal(uuid.UUID(target.id), key.id)
    ids = iter([uuid.UUID(r["id"]) for r in requests])
    results = race(lambda: service.approve(caller, next(ids), None, RequestContext()))
    successes = [r for r in results if r[0] == "ok"]
    assert len(successes) == 1
    assert all(isinstance(r[1], ConflictError) and r[1].code == "target_busy" for r in results if r[0] == "error")


def test_audit_trail_records_the_flow_without_secrets(env):
    helper, target = Helper(env), Computer(env)
    request = pending(env, helper, target)
    session = env.client.post(f"{R}/{request['id']}/approve", headers=target.headers).json()
    env.client.post(f"{S}/{session['id']}/terminate", headers=helper.bearer)
    with env.db.unit_of_work() as uow:
        events = uow._session.query(AuditEvent).filter(
            AuditEvent.subject_id.in_([request["id"], session["id"]])).all()
        types = {e.event_type for e in events}
        details = " ".join(e.details or "" for e in events)
    assert {"connection.requested", "connection.approved", "session.created", "session.ended"} <= types
    for secret in (target.token, helper.computer.token, helper.bearer["Authorization"][7:]):
        assert secret not in details
    assert all(json.loads(e.details or "{}") is not None for e in events)
