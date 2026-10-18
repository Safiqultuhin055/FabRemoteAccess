"""Drives the This-device state: (resume or) register → verify identity → verified presence.

Each step runs off the UI thread (via `runner`) and the state only advances on a confirmed
server result, so "Verifying", "Verified" and "Online" are never shown early. Retry resumes
an existing local registration instead of registering again, so it cannot create duplicates.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QTimer, Signal

from fabremote.device import AuthRequiredError, DeviceGateway, DeviceState, DeviceStatus, GatewayError, Registration
from fabremote.workers import run_async

Runner = Callable[[Callable[[], object], Callable[[object], None], Callable[[Exception], None]], None]

GENERIC_FAILURE = "Registration failed. Check your connection and try again."
VERIFY_FAILURE = "The server could not verify this computer's identity. Try registering again."
PRESENCE_UNKNOWN = "Could not confirm the connection to the server. This computer cannot receive requests."
CHECKING = "Checking this computer's registration with the server…"


def _message(error: Exception, fallback: str) -> str:
    # Raw exception text can contain internal details; only GatewayError messages are user-safe.
    return error.user_message if isinstance(error, GatewayError) else fallback


class DeviceController(QObject):
    state_changed = Signal(object)
    auth_required = Signal()

    def __init__(self, gateway: DeviceGateway, device_name: str, *, runner: Runner = run_async,
                 presence_interval_ms: int = 15_000, parent=None):
        super().__init__(parent)
        self._gateway = gateway
        self._device_name = device_name
        self._runner = runner
        self._registration: Registration | None = None
        self._busy = False
        self._state = self._initial_state()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh_presence)
        self._interval = presence_interval_ms

    @property
    def state(self) -> DeviceState:
        return self._state

    def _initial_state(self) -> DeviceState:
        if not self._gateway.supported:
            return DeviceState(DeviceStatus.NOT_REGISTERED, can_register=False,
                               message=self._gateway.unsupported_reason, preview=self._gateway.preview)
        return DeviceState(DeviceStatus.NOT_REGISTERED, preview=self._gateway.preview)

    def _set(self, state: DeviceState) -> None:
        self._state = state
        self.state_changed.emit(state)

    def _state_for(self, status: DeviceStatus, **values) -> DeviceState:
        return DeviceState(status, preview=self._gateway.preview, **values)

    # ---------------------------------------------------------------- actions

    def start(self) -> None:
        """Resume a registration stored on this computer, if any (confirmed with the server)."""
        if not self._gateway.supported or self._busy or not self._gateway.has_local_device():
            return
        self._busy = True
        self._set(self._state_for(DeviceStatus.PENDING, message=CHECKING))
        self._runner(self._gateway.existing, self._resumed, self._failed_from)

    def register(self) -> None:
        if (not self._gateway.supported or self._busy
                or self._state.status not in (DeviceStatus.NOT_REGISTERED, DeviceStatus.FAILED)):
            return
        self._busy = True
        self._timer.stop()
        self._set(self._state_for(DeviceStatus.PENDING, device_name=self._device_name))
        self._runner(lambda: self._gateway.register(self._device_name), self._registered, self._failed_from)

    def retry(self) -> None:
        if self._gateway.supported and self._gateway.has_local_device() and self._registration is None:
            self.start()       # resume, never register a second time
        else:
            self.register()

    def refresh_presence(self) -> None:
        if self._registration is None or self._state.status not in (DeviceStatus.ONLINE, DeviceStatus.OFFLINE):
            return
        self._runner(self._gateway.is_online, self._presence, self._presence_unknown)

    def stop(self) -> None:
        self._timer.stop()

    # -------------------------------------------------------------- callbacks

    def _resumed(self, registration: object) -> None:
        if registration is None:
            self._busy = False
            self._set(self._initial_state())
            return
        self._registered(registration)

    def _registered(self, registration: Registration) -> None:
        try:
            self._set(self._state_for(DeviceStatus.VERIFYING, remote_id=registration.remote_id,
                                      device_name=registration.device_name))
        except ValueError:   # the server returned something that is not a valid Remote ID
            self._failed(GENERIC_FAILURE)
            return
        self._registration = registration
        self._runner(self._gateway.verify_identity, self._verified,
                     lambda exc: self._failed_from(exc, VERIFY_FAILURE))

    def _verified(self, verified: object) -> None:
        if not verified:
            self._failed(VERIFY_FAILURE)
            return
        self._runner(self._gateway.is_online, self._presence, self._presence_unknown)
        if self._interval:
            self._timer.start(self._interval)

    def _presence(self, online: object) -> None:
        self._busy = False
        reg = self._registration
        if reg is None:
            return
        status = DeviceStatus.ONLINE if online else DeviceStatus.OFFLINE
        message = None if online else "Not connected to the server. This computer cannot receive requests."
        self._set(self._state_for(status, remote_id=reg.remote_id, device_name=reg.device_name,
                                  identity_verified=True, message=message))

    def _presence_unknown(self, error: Exception) -> None:
        self._busy = False
        if isinstance(error, AuthRequiredError):
            self._auth_lost()
            return
        reg = self._registration
        if reg is None:
            return
        self._set(self._state_for(DeviceStatus.OFFLINE, remote_id=reg.remote_id, device_name=reg.device_name,
                                  identity_verified=True, message=_message(error, PRESENCE_UNKNOWN)))

    def _failed_from(self, error: Exception, fallback: str = GENERIC_FAILURE) -> None:
        if isinstance(error, AuthRequiredError):
            self._auth_lost()
            return
        self._failed(_message(error, fallback))

    def _auth_lost(self) -> None:
        self._failed(AuthRequiredError().user_message)
        self.auth_required.emit()

    def _failed(self, message: str) -> None:
        self._busy = False
        self._registration = None
        self._timer.stop()
        self._set(self._state_for(DeviceStatus.FAILED, device_name=self._device_name, message=message))
