"""Connection requests on both sides: consent dialog, incoming and outgoing controllers, banner.

Every state shown must come from a (fake) server response; nothing is assumed."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from fabremote.api_client import ApiError
from fabremote.connection import (NOT_AVAILABLE, ConnectionFailure, IncomingController, IncomingRequest,
                                  OutgoingController, OutgoingStatus, RequestStatus, SessionInfo, parse_incoming,
                                  parse_session)
from fabremote.device import DeviceState, DeviceStatus
from fabremote.ui.consent_dialog import ConsentDialog
from fabremote.ui.main_window import MainWindow

USER = {"id": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "email": "alex@example.com", "display_name": "Alex Doe",
        "roles": ["user"]}


def sync_runner(fn, ok, fail):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - delivered like the real worker does
        fail(exc)
    else:
        ok(result)


def request(**changes) -> IncomingRequest:
    values = dict(id=str(uuid.uuid4()), requester_name="Alex Doe", requester_email="alex@example.com",
                  device_name="HELPER-PC", device_remote_id="222333444",
                  expires_at=datetime.now(UTC) + timedelta(seconds=45))
    return IncomingRequest(**{**values, **changes})


def session(active=True, end_reason=None, sid="11111111-1111-1111-1111-111111111111") -> SessionInfo:
    return SessionInfo(sid, active, end_reason, "Alex Doe", "222333444", "105280964")


class FakeGateway:
    def __init__(self):
        self.pending: list[IncomingRequest] = []
        self.live: str | None = None
        self.sessions: dict[str, SessionInfo] = {}
        self.calls: list[tuple] = []
        self.status = RequestStatus("pending", None, None)
        self.fail: dict[str, Exception] = {}
        self.signed_in = True

    def _call(self, name, *args):
        self.calls.append((name, *args))
        if name in self.fail:
            raise self.fail[name]

    # target
    def incoming(self):
        self._call("incoming")
        return list(self.pending), self.live

    def approve(self, request_id):
        self._call("approve", request_id)
        info = session()
        self.sessions[info.id], self.live = info, info.id
        self.pending = [r for r in self.pending if r.id != request_id]
        return info

    def reject(self, request_id, block):
        self._call("reject", request_id, block)
        self.pending = [r for r in self.pending if r.id != request_id]

    def target_session(self, session_id):
        self._call("target_session", session_id)
        return self.sessions[session_id]

    def end_target_session(self, session_id):
        self._call("end_target_session", session_id)
        self.sessions[session_id] = session(False, "target_disconnect", session_id)
        self.live = None
        return self.sessions[session_id]

    # helper
    def request(self, remote_id):
        self._call("request", remote_id)
        return "22222222-2222-2222-2222-222222222222"

    def request_status(self, request_id):
        self._call("request_status", request_id)
        return self.status

    def cancel(self, request_id):
        self._call("cancel", request_id)

    def controller_session(self, session_id):
        self._call("controller_session", session_id)
        return self.sessions[session_id]

    def end_controller_session(self, session_id):
        self._call("end_controller_session", session_id)
        self.sessions[session_id] = session(False, "controller_disconnect", session_id)
        return self.sessions[session_id]


@pytest.fixture
def gw():
    return FakeGateway()


# ------------------------------------------------------------------ parsing server responses


def test_incoming_response_is_validated():
    good = {"items": [{"id": str(uuid.uuid4()), "status": "pending", "expires_at": "2026-10-18T10:00:00Z",
                       "requester": {"display_name": "A", "email": "a@example.com"},
                       "requester_device": {"display_name": "PC", "remote_id": "222333444"}}],
            "live_session_id": None}
    requests, live = parse_incoming(good)
    assert requests[0].device_remote_id == "222333444" and live is None
    for bad in ({"items": "x"}, {"items": [{**good["items"][0], "status": "approved"}]},
                {"items": [{**good["items"][0], "requester_device": {"display_name": "PC", "remote_id": "0123"}}]}):
        with pytest.raises(ConnectionFailure):
            parse_incoming(bad)


def test_session_response_is_validated():
    body = {"id": str(uuid.uuid4()), "state": "authorizing", "end_reason": None,
            "controller": {"display_name": "A", "device_remote_id": "222333444"},
            "target": {"remote_id": "105280964", "display_name": None}}
    assert parse_session(body).active is True
    assert parse_session({**body, "state": "ended", "end_reason": "timeout"}).active is False
    with pytest.raises(ConnectionFailure):
        parse_session({**body, "state": "streaming"})


# ------------------------------------------------------------------ consent dialog


def test_consent_dialog_shows_who_is_asking_and_defaults_to_reject(qapp):
    r = request(requester_name="Mallory <b>", requester_email="m@example.com")
    dialog = ConsentDialog(r)
    texts = " ".join(label.text() for label in dialog.findChildren(type(dialog.countdown)))
    assert "Mallory &lt;b&gt;" in texts and "m@example.com" in texts and "222 333 444" in texts
    assert "support" in texts and "not available in this preview" in texts
    assert dialog.reject_button.isDefault() and not dialog.accept_button.isDefault()
    assert dialog.focusWidget() in (None, dialog.reject_button)
    dialog.close()


def test_consent_dialog_answers_once(qapp):
    r = request()
    dialog = ConsentDialog(r)
    answers = []
    dialog.accepted_request.connect(lambda rid: answers.append(("accept", rid)))
    dialog.rejected_request.connect(lambda rid, block: answers.append(("reject", rid, block)))
    dialog.block.setChecked(True)
    dialog.reject_button.click()
    dialog.accept_button.click()
    assert answers == [("reject", r.id, True)]


def test_closing_the_consent_dialog_rejects(qapp):
    r = request()
    dialog = ConsentDialog(r)
    answers = []
    dialog.rejected_request.connect(lambda rid, block: answers.append(rid))
    dialog.reject()            # Esc / window close
    assert answers == [r.id]


def test_consent_dialog_closes_by_itself_when_the_request_expires(qapp):
    r = request(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    dialog = ConsentDialog(r)
    answers = []
    dialog.accepted_request.connect(answers.append)
    dialog.accept_button.click()
    assert answers == [] and dialog.result() == 0


# ------------------------------------------------------------------ target side


def test_new_requests_are_shown_once_and_closed_when_gone(qapp, gw):
    controller = IncomingController(gw, runner=sync_runner, poll_ms=0)
    shown, closed = [], []
    controller.request_received.connect(shown.append)
    controller.request_closed.connect(closed.append)
    r = request()
    gw.pending = [r]
    controller.poll()
    controller.poll()
    assert shown == [r]
    gw.pending = []                       # expired or withdrawn on the server
    controller.poll()
    assert closed == [r.id]


def test_accept_creates_a_session_only_from_the_server_answer(qapp, gw):
    controller = IncomingController(gw, runner=sync_runner, poll_ms=0)
    changes = []
    controller.session_changed.connect(changes.append)
    r = request()
    gw.pending = [r]
    controller.poll()
    controller.accept(r.id)
    assert ("approve", r.id) in gw.calls and changes[-1].active and controller.session is not None
    controller.poll()                     # follows the live session (its presence signal)
    assert gw.calls[-1][0] == "target_session"
    controller.end_session()
    assert changes[-1].active is False and changes[-1].end_reason == "target_disconnect"
    assert controller.session is None


def test_session_ended_by_the_other_side_is_reported(qapp, gw):
    controller = IncomingController(gw, runner=sync_runner, poll_ms=0)
    changes = []
    controller.session_changed.connect(changes.append)
    r = request()
    gw.pending = [r]
    controller.poll()
    controller.accept(r.id)
    sid = controller.session.id
    gw.sessions[sid], gw.live = session(False, "controller_disconnect", sid), None
    controller.poll()
    assert changes[-1].end_reason == "controller_disconnect" and controller.session is None


def test_reject_and_block_are_sent(qapp, gw):
    controller = IncomingController(gw, runner=sync_runner, poll_ms=0)
    r = request()
    controller.reject(r.id, True)
    assert gw.calls[-1] == ("reject", r.id, True)


def test_failed_accept_shows_a_safe_message(qapp, gw):
    controller = IncomingController(gw, runner=sync_runner, poll_ms=0)
    errors = []
    controller.error.connect(errors.append)
    gw.fail["approve"] = ApiError(410, "request_expired", "internal detail")
    controller.accept(str(uuid.uuid4()))
    assert errors == ["The request expired before you answered."] and controller.session is None


# ------------------------------------------------------------------ helper side


def test_outgoing_waits_then_connects_after_acceptance(qapp, gw):
    controller = OutgoingController(gw, runner=sync_runner, poll_ms=0)
    states = []
    controller.state_changed.connect(states.append)
    controller.connect_to("105 280 964")
    assert gw.calls[0] == ("request", "105280964") and controller.state.status is OutgoingStatus.WAITING
    controller.poll()
    assert controller.state.status is OutgoingStatus.WAITING           # still pending
    info = session()
    gw.sessions[info.id] = info
    gw.status = RequestStatus("approved", "target_approved", info.id)
    controller.poll()
    assert controller.state.status is OutgoingStatus.CONNECTED and controller.state.session == info
    controller.disconnect()
    assert controller.state.status is OutgoingStatus.FINISHED and controller.state.message == "You ended the session."


@pytest.mark.parametrize("status, message", [
    ("rejected", "declined"), ("expired", "No answer"), ("cancelled", "cancelled"),
])
def test_outgoing_outcomes(qapp, gw, status, message):
    controller = OutgoingController(gw, runner=sync_runner, poll_ms=0)
    controller.connect_to("105280964")
    gw.status = RequestStatus(status, None, None)
    controller.poll()
    assert controller.state.status is OutgoingStatus.FINISHED and message in controller.state.message


@pytest.mark.parametrize("error, message", [
    (ApiError(404, "target_unavailable", "x"), NOT_AVAILABLE),
    (ApiError(422, "cannot_connect_to_self", "x"), "own Remote ID"),
    (ApiError(0, "network_error", "x"), "Cannot reach the server"),
    (ApiError(500, "internal", "stack trace PWD=secret"), "could not be sent"),
])
def test_outgoing_failures_show_safe_messages(qapp, gw, error, message):
    controller = OutgoingController(gw, runner=sync_runner, poll_ms=0)
    gw.fail["request"] = error
    controller.connect_to("105280964")
    assert controller.state.status is OutgoingStatus.FINISHED
    assert message in controller.state.message and "secret" not in controller.state.message


def test_session_lost_on_the_other_side_ends_the_helper_view(qapp, gw):
    controller = OutgoingController(gw, runner=sync_runner, poll_ms=0)
    controller.connect_to("105280964")
    info = session()
    gw.sessions[info.id] = info
    gw.status = RequestStatus("approved", "target_approved", info.id)
    controller.poll()
    gw.sessions[info.id] = session(False, "timeout", info.id)
    controller.poll()
    assert controller.state.status is OutgoingStatus.FINISHED and "lost" in controller.state.message


def test_invalid_remote_id_is_never_sent(qapp, gw):
    controller = OutgoingController(gw, runner=sync_runner, poll_ms=0)
    controller.connect_to("012345678")
    assert gw.calls == [] and controller.state.status is OutgoingStatus.IDLE


# ------------------------------------------------------------------ window


class FakeClient:
    base_url = "http://127.0.0.1:8765"
    signed_in = True
    has_device_token = True

    def health(self):
        return True

    def logout(self):
        pass


@pytest.fixture
def window(qapp, gw):
    w = MainWindow(FakeClient(), USER, connection_gateway=gw)
    w.incoming._runner = w.outgoing._runner = sync_runner
    w.incoming._poll_ms = w.outgoing._poll_ms = 0
    w.device._set(DeviceState(DeviceStatus.ONLINE, remote_id="105280964", device_name="PC", identity_verified=True))
    yield w
    w.shutdown()
    w.close()


def test_helper_banner_appears_only_after_the_other_person_accepts(window, gw):
    window.remote_input.setText("222 333 444")
    window._remote_id_edited("222 333 444")
    window.connect_button.click()
    assert window.session_banner.isHidden() and "Waiting" in window.connection_status.text()
    assert window.cancel_button.isVisible() or not window.isVisible()
    info = session()
    gw.sessions[info.id] = info
    gw.status = RequestStatus("approved", "target_approved", info.id)
    window.outgoing.poll()
    assert not window.session_banner.isHidden()
    assert "accepted" in window.session_text.text() and "not available" in window.session_text.text()
    assert not window.connect_button.isEnabled()                         # one session at a time
    window.disconnect_button.click()
    assert window.session_banner.isHidden() and window.connection_status.text() == "You ended the session."


def test_target_sees_consent_dialog_then_banner(window, gw):
    r = request()
    gw.pending = [r]
    window.incoming.poll()
    dialog = window._consent_dialogs[r.id]
    dialog.accept_button.click()
    assert not window.session_banner.isHidden() and "Alex Doe" in window.session_text.text()
    assert "not available" in window.session_text.text()
    window.disconnect_button.click()
    assert window.session_banner.isHidden() and window.connection_status.text() == "You ended the session."
