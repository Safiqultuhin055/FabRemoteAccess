"""Connection requests and sessions (Phase 3e): asking, consent and ending.

- IncomingController (the computer being helped, no account needed): polls the server for
  requests with this computer's device token, hands each new one to the UI for an explicit
  Accept or Reject, and follows the resulting session.
- OutgoingController (the helper, signed in): sends a request for a Remote ID, waits for the
  answer and follows the session.

Honesty: a session only means the other person gave consent. There is no screen or input
yet (Phase 6/7), and every state shown comes from a server response. Polling a session is
also that side's presence signal, so the server ends it when either side disappears.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from PySide6.QtCore import QObject, QTimer, Signal

from fabremote import remote_id as rid
from fabremote.api_client import ApiClient, ApiError
from fabremote.device import ApiDeviceGateway
from fabremote.workers import run_async

Runner = Callable[[Callable[[], object], Callable[[object], None], Callable[[Exception], None]], None]

UNREACHABLE = "Cannot reach the server. Check your connection and try again."
UNEXPECTED = "The server sent an unexpected response. Try again later."
NOT_AVAILABLE = ("That computer is not available. Check the Remote ID and make sure Fabulous Remote is open "
                 "on it.")
_UUID = re.compile(r"^[0-9a-fA-F-]{36}$")


class ConnectionFailure(Exception):
    """A failure with a message that is safe to show to the user."""

    def __init__(self, user_message: str):
        super().__init__(user_message)
        self.user_message = user_message


def _message(error: Exception, fallback: str) -> str:
    if isinstance(error, ConnectionFailure):
        return error.user_message
    if isinstance(error, ApiError):
        if error.status == 0:
            return UNREACHABLE
        if error.code == "target_unavailable":
            return NOT_AVAILABLE
        if error.code == "cannot_connect_to_self":
            return "That is this computer's own Remote ID."
        if error.code == "account_not_verified":
            return "Your account is not allowed to connect yet. Ask your administrator."
        if error.code == "target_busy":
            return "This computer is already in a session."
        if error.code == "request_expired":
            return "The request expired before you answered."
        if error.status == 429:
            return "Too many attempts. Wait a minute and try again."
        if error.status == 401:
            return "Your session has ended. Please sign in again."
    return fallback


# ------------------------------------------------------------------ data


@dataclass(frozen=True)
class IncomingRequest:
    id: str
    requester_name: str
    requester_email: str
    device_name: str
    device_remote_id: str
    expires_at: datetime


@dataclass(frozen=True)
class SessionInfo:
    id: str
    active: bool
    end_reason: str | None
    controller_name: str
    controller_remote_id: str
    target_remote_id: str


@dataclass(frozen=True)
class RequestStatus:
    status: str                    # pending | approved | rejected | expired | cancelled
    decision_reason: str | None
    session_id: str | None


def _uuid(value: object) -> str:
    if not isinstance(value, str) or not _UUID.fullmatch(value):
        raise ConnectionFailure(UNEXPECTED)
    return value


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise ConnectionFailure(UNEXPECTED)
    return value


def _remote_id(value: object) -> str:
    if not isinstance(value, str) or not rid.is_valid(value):
        raise ConnectionFailure(UNEXPECTED)
    return value


def _datetime(value: object) -> datetime:
    try:
        return datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        raise ConnectionFailure(UNEXPECTED) from None


def parse_session(body: object) -> SessionInfo:
    if not isinstance(body, dict) or body.get("state") not in ("authorizing", "active", "ended"):
        raise ConnectionFailure(UNEXPECTED)
    controller, target = body.get("controller"), body.get("target")
    if not isinstance(controller, dict) or not isinstance(target, dict):
        raise ConnectionFailure(UNEXPECTED)
    return SessionInfo(id=_uuid(body.get("id")), active=body["state"] != "ended", end_reason=body.get("end_reason"),
                       controller_name=_text(controller.get("display_name")),
                       controller_remote_id=_remote_id(controller.get("device_remote_id")),
                       target_remote_id=_remote_id(target.get("remote_id")))


def parse_incoming(body: object) -> tuple[list[IncomingRequest], str | None]:
    if not isinstance(body, dict) or not isinstance(body.get("items"), list):
        raise ConnectionFailure(UNEXPECTED)
    requests = []
    for item in body["items"]:
        if not isinstance(item, dict) or item.get("status") != "pending":
            raise ConnectionFailure(UNEXPECTED)
        requester, device = item.get("requester"), item.get("requester_device")
        if not isinstance(requester, dict) or not isinstance(device, dict):
            raise ConnectionFailure(UNEXPECTED)
        requests.append(IncomingRequest(
            id=_uuid(item.get("id")), requester_name=_text(requester.get("display_name")),
            requester_email=_text(requester.get("email")), device_name=_text(device.get("display_name")),
            device_remote_id=_remote_id(device.get("remote_id")), expires_at=_datetime(item.get("expires_at"))))
    live = body.get("live_session_id")
    return requests, (_uuid(live) if live is not None else None)


def parse_status(body: object) -> RequestStatus:
    if not isinstance(body, dict) or body.get("status") not in ("pending", "approved", "rejected", "expired",
                                                                "cancelled"):
        raise ConnectionFailure(UNEXPECTED)
    session = body.get("session_id")
    return RequestStatus(body["status"], body.get("decision_reason"), _uuid(session) if session else None)


# ------------------------------------------------------------------ gateway


class ApiConnectionGateway:
    """Server calls for both sides. Target calls use the device token only."""

    def __init__(self, client: ApiClient, device: ApiDeviceGateway):
        self._client = client
        self._device = device

    @property
    def signed_in(self) -> bool:
        return self._client.signed_in

    # target (no account)
    def incoming(self) -> tuple[list[IncomingRequest], str | None]:
        return parse_incoming(self._device.with_device_token(self._client.incoming_requests))

    def approve(self, request_id: str) -> SessionInfo:
        return parse_session(self._device.with_device_token(lambda: self._client.approve_request(request_id)))

    def reject(self, request_id: str, block: bool) -> None:
        self._device.with_device_token(lambda: self._client.reject_request(request_id, block))

    def target_session(self, session_id: str) -> SessionInfo:
        return parse_session(self._device.with_device_token(lambda: self._client.target_session(session_id)))

    def end_target_session(self, session_id: str) -> SessionInfo:
        return parse_session(self._device.with_device_token(lambda: self._client.end_target_session(session_id)))

    # helper (signed in)
    def request(self, remote_id: str) -> str:
        body = self._device.with_device_token(lambda: self._client.create_request(remote_id))
        return _uuid(body.get("id") if isinstance(body, dict) else None)

    def request_status(self, request_id: str) -> RequestStatus:
        return parse_status(self._client.request_status(request_id))

    def cancel(self, request_id: str) -> None:
        self._client.cancel_request(request_id)

    def controller_session(self, session_id: str) -> SessionInfo:
        return parse_session(self._client.controller_session(session_id))

    def end_controller_session(self, session_id: str) -> SessionInfo:
        return parse_session(self._client.end_controller_session(session_id))


# ------------------------------------------------------------------ target side


class IncomingController(QObject):
    request_received = Signal(object)    # IncomingRequest: ask the user
    request_closed = Signal(str)         # no longer pending (expired, withdrawn): close its dialog
    session_changed = Signal(object)     # SessionInfo (active or ended)
    error = Signal(str)

    def __init__(self, gateway, *, runner: Runner = run_async, poll_ms: int = 2000, parent=None):
        super().__init__(parent)
        self._gateway = gateway
        self._runner = runner
        self._busy = False
        self._seen: set[str] = set()
        self._open: set[str] = set()
        self.session: SessionInfo | None = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.poll)
        self._poll_ms = poll_ms

    @property
    def running(self) -> bool:
        return self._timer.isActive()

    def start(self) -> None:
        if not self._timer.isActive() and self._poll_ms:
            self._timer.start(self._poll_ms)
        self.poll()

    def stop(self) -> None:
        self._timer.stop()

    def poll(self) -> None:
        if self._busy:
            return
        self._busy = True
        self._runner(self._gateway.incoming, self._incoming, self._poll_failed)

    def _incoming(self, result: object) -> None:
        self._busy = False
        requests, live_id = result
        if live_id is not None:
            self._runner(lambda: self._gateway.target_session(live_id), self._session, self._poll_failed)
        elif self.session is not None:
            # The server no longer lists a live session: read how it ended.
            ended_id = self.session.id
            self._runner(lambda: self._gateway.target_session(ended_id), self._session, self._poll_failed)
        current = {r.id for r in requests}
        for request in requests:
            if request.id not in self._seen:
                self._seen.add(request.id)
                self._open.add(request.id)
                self.request_received.emit(request)
        for gone in sorted(self._open - current):
            self._open.discard(gone)
            self.request_closed.emit(gone)

    def _poll_failed(self, error: Exception) -> None:
        self._busy = False          # keep polling; the device card shows connectivity problems

    def accept(self, request_id: str) -> None:
        self._open.discard(request_id)
        self._runner(lambda: self._gateway.approve(request_id), self._session,
                     lambda exc: self.error.emit(_message(exc, "The request could not be accepted.")))

    def reject(self, request_id: str, block: bool = False) -> None:
        self._open.discard(request_id)
        self._runner(lambda: self._gateway.reject(request_id, block), lambda _: None,
                     lambda exc: self.error.emit(_message(exc, "The request could not be declined.")))

    def end_session(self) -> None:
        if self.session is None:
            return
        session_id = self.session.id
        self._runner(lambda: self._gateway.end_target_session(session_id), self._session,
                     lambda exc: self.error.emit(_message(exc, "The session could not be ended. Try again.")))

    def _session(self, info: object) -> None:
        if not isinstance(info, SessionInfo):
            return
        if self.session is not None and not self.session.active and not info.active:
            return                   # already reported as ended
        self.session = info if info.active else None
        self.session_changed.emit(info)


# ------------------------------------------------------------------ helper side


class OutgoingStatus(Enum):
    IDLE = "idle"
    SENDING = "sending"
    WAITING = "waiting"
    CONNECTED = "connected"
    FINISHED = "finished"        # declined, no answer, unavailable, ended or failed: see message


@dataclass(frozen=True)
class OutgoingState:
    status: OutgoingStatus
    remote_id: str | None = None
    message: str | None = None
    session: SessionInfo | None = None

    @property
    def busy(self) -> bool:
        return self.status in (OutgoingStatus.SENDING, OutgoingStatus.WAITING, OutgoingStatus.CONNECTED)


END_MESSAGES = {
    "target_disconnect": "The other person ended the session.",
    "controller_disconnect": "You ended the session.",
    "timeout": "The connection to the other computer was lost.",
    "revoked": "The session was ended by the computer's owner or an administrator.",
}


class OutgoingController(QObject):
    state_changed = Signal(object)

    def __init__(self, gateway, *, runner: Runner = run_async, poll_ms: int = 2000, parent=None):
        super().__init__(parent)
        self._gateway = gateway
        self._runner = runner
        self._busy = False
        self._request_id: str | None = None
        self.state = OutgoingState(OutgoingStatus.IDLE)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.poll)
        self._poll_ms = poll_ms

    def _set(self, state: OutgoingState) -> None:
        self.state = state
        if not state.busy:
            self._timer.stop()
        self.state_changed.emit(state)

    def _finish(self, message: str) -> None:
        self._request_id = None
        self._set(OutgoingState(OutgoingStatus.FINISHED, self.state.remote_id, message))

    def connect_to(self, remote_id: str) -> None:
        if self.state.busy or not rid.is_valid(remote_id):
            return
        digits = rid.normalise(remote_id)
        self._set(OutgoingState(OutgoingStatus.SENDING, digits))
        self._runner(lambda: self._gateway.request(digits), self._sent,
                     lambda exc: self._finish(_message(exc, "The request could not be sent. Try again.")))

    def _sent(self, request_id: object) -> None:
        self._request_id = str(request_id)
        self._set(OutgoingState(OutgoingStatus.WAITING, self.state.remote_id,
                                "Waiting for the other person to accept…"))
        if self._poll_ms:
            self._timer.start(self._poll_ms)

    def poll(self) -> None:
        if self._busy:
            return
        if self.state.status is OutgoingStatus.WAITING and self._request_id:
            request_id = self._request_id
            self._busy = True
            self._runner(lambda: self._gateway.request_status(request_id), self._status, self._poll_failed)
        elif self.state.status is OutgoingStatus.CONNECTED and self.state.session:
            session_id = self.state.session.id
            self._busy = True
            self._runner(lambda: self._gateway.controller_session(session_id), self._session, self._poll_failed)

    def _poll_failed(self, error: Exception) -> None:
        self._busy = False
        if isinstance(error, ApiError) and error.status == 401:
            self._finish(_message(error, ""))

    def _status(self, status: object) -> None:
        self._busy = False
        if not isinstance(status, RequestStatus) or self.state.status is not OutgoingStatus.WAITING:
            return
        if status.status == "approved" and status.session_id:
            session_id = status.session_id
            self._busy = True
            self._runner(lambda: self._gateway.controller_session(session_id), self._session, self._poll_failed)
        elif status.status == "rejected":
            self._finish("The other person declined the request.")
        elif status.status == "expired":
            self._finish("No answer: the request expired.")
        elif status.status == "cancelled":
            self._finish("Request cancelled.")

    def _session(self, info: object) -> None:
        self._busy = False
        if not isinstance(info, SessionInfo):
            return
        if info.active:
            self._set(OutgoingState(OutgoingStatus.CONNECTED, self.state.remote_id, None, info))
        else:
            self._finish(END_MESSAGES.get(info.end_reason or "", "The session has ended."))

    def cancel(self) -> None:
        if self.state.status is not OutgoingStatus.WAITING or not self._request_id:
            return
        request_id = self._request_id
        self._runner(lambda: self._gateway.cancel(request_id), lambda _: self._finish("Request cancelled."),
                     lambda exc: None)   # already answered: the next poll shows the outcome

    def disconnect(self) -> None:
        if self.state.status is not OutgoingStatus.CONNECTED or not self.state.session:
            return
        session_id = self.state.session.id
        self._runner(lambda: self._gateway.end_controller_session(session_id), self._session,
                     lambda exc: self._finish(_message(exc, "The session could not be ended cleanly.")))

    def stop(self) -> None:
        self._timer.stop()
