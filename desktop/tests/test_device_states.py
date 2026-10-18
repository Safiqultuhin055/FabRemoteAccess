"""This-device card: every state, transitions, failures, honesty invariants and accessibility."""

from __future__ import annotations

import pytest

from fabremote.device import (ApiDeviceGateway, AuthRequiredError, DeviceState, DeviceStatus, GatewayError,
                              PreviewDeviceGateway, Registration)
from fabremote.device_controller import GENERIC_FAILURE, PRESENCE_UNKNOWN, VERIFY_FAILURE, DeviceController
from fabremote.ui.device_card import REGISTRATION_REQUIRED, DeviceCard
from fabremote.ui.main_window import MainWindow

RID = "105280964"


def sync_runner(fn, on_success, on_error):
    """Runs the step immediately so transitions can be asserted without threads."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        on_error(exc)
    else:
        on_success(result)


class ScriptedGateway:
    """Test fixture gateway: each step returns or raises what the test scripts."""

    supported = True
    unsupported_reason = ""
    preview = False

    def __init__(self, register=Registration(RID, "OFFICE-PC"), verify=True, online=True, existing=None,
                 local=False):
        self.register_result, self.verify_result, self.online_result = register, verify, online
        self.existing_result, self.local = existing, local
        self.calls: list[str] = []

    def has_local_device(self):
        return self.local

    def existing(self):
        self.calls.append("existing")
        return self._give(self.existing_result)

    @staticmethod
    def _give(value):
        if isinstance(value, Exception):
            raise value
        return value

    def register(self, device_name):
        self.calls.append("register")
        return self._give(self.register_result)

    def verify_identity(self):
        self.calls.append("verify")
        return self._give(self.verify_result)

    def is_online(self):
        self.calls.append("presence")
        return self._give(self.online_result)


def controller_for(gateway) -> tuple[DeviceController, list[DeviceState]]:
    controller = DeviceController(gateway, "OFFICE-PC", runner=sync_runner, presence_interval_ms=0)
    seen: list[DeviceState] = []
    controller.state_changed.connect(seen.append)
    return controller, seen


@pytest.fixture
def card(qapp):
    widget = DeviceCard()
    yield widget
    widget.deleteLater()


# --------------------------------------------------------------- state rendering

STATES = {
    "not_registered": DeviceState(DeviceStatus.NOT_REGISTERED),
    "pending": DeviceState(DeviceStatus.PENDING, device_name="OFFICE-PC"),
    "verifying": DeviceState(DeviceStatus.VERIFYING, remote_id=RID, device_name="OFFICE-PC"),
    "online": DeviceState(DeviceStatus.ONLINE, remote_id=RID, device_name="OFFICE-PC", identity_verified=True),
    "offline": DeviceState(DeviceStatus.OFFLINE, remote_id=RID, device_name="OFFICE-PC", identity_verified=True),
    "failed": DeviceState(DeviceStatus.FAILED, message="The server could not be reached."),
}


@pytest.mark.parametrize("name, remote_id_text, identity, presence, busy, register, retry", [
    ("not_registered", "Not registered", "Not registered", None, False, True, None),
    ("pending", "Registering…", "Registration pending", None, True, False, None),
    ("verifying", "105 280 964", "Verifying identity…", None, True, False, None),
    ("online", "105 280 964", "Identity verified", "● Online", False, False, None),
    ("offline", "105 280 964", "Identity verified", "○ Offline", False, False, "Check again"),
    ("failed", "Not registered", "Registration failed", None, False, False, "Try again"),
])
def test_each_state_renders(card, name, remote_id_text, identity, presence, busy, register, retry):
    card.render(STATES[name])
    assert card.remote_id_label.text() == remote_id_text
    assert card.identity_badge.isVisibleTo(card) and card.identity_badge.text() == identity
    assert card.presence_badge.isVisibleTo(card) == bool(presence)
    if presence:
        assert card.presence_badge.text() == presence
    assert card.progress.isVisibleTo(card) is busy
    assert card.register_button.isVisibleTo(card) is bool(register)
    assert card.retry_button.isVisibleTo(card) is bool(retry)
    if retry:
        assert card.retry_button.text() == retry
    assert card.message_label.text()


def test_unregistered_explains_requirement_and_offers_action(card):
    card.render(STATES["not_registered"])
    assert REGISTRATION_REQUIRED in card.message_label.text()
    assert card.register_button.text() == "Register This Device" and card.register_button.isEnabled()


def test_device_name_only_shown_once_registered(card):
    card.render(STATES["pending"])
    assert not card.device_name_label.isVisibleTo(card)
    card.render(STATES["online"])
    assert card.device_name_label.text() == "Device name: OFFICE-PC"


def test_remote_id_selectable_only_when_assigned(card):
    from PySide6.QtCore import Qt
    card.render(STATES["online"])
    assert card.remote_id_label.textInteractionFlags() & Qt.TextInteractionFlag.TextSelectableByKeyboard
    card.render(STATES["not_registered"])
    assert card.remote_id_label.textInteractionFlags() == Qt.TextInteractionFlag.NoTextInteraction


def test_accessibility_names_and_summary(card):
    card.render(STATES["online"])
    description = card.accessibleDescription()
    assert "Identity verified" in description and "Remote ID 105 280 964" in description and "Online" in description
    assert card.accessibleName() == "This device"
    assert card.remote_id_label.accessibleName() == "Your Remote ID"
    assert card.progress.accessibleName() == "Registration in progress"
    card.render(STATES["failed"])
    assert "Registration failed" in card.accessibleDescription()


def test_preview_label_follows_state(card):
    card.render(DeviceState(DeviceStatus.NOT_REGISTERED, preview=True))
    assert card.preview_badge.isVisibleTo(card) and "preview" in card.accessibleDescription().lower()
    card.render(STATES["not_registered"])
    assert not card.preview_badge.isVisibleTo(card)


# ------------------------------------------------------------ honesty invariants


@pytest.mark.parametrize("kwargs", [
    {"status": DeviceStatus.ONLINE, "remote_id": RID},                                   # online, not verified
    {"status": DeviceStatus.OFFLINE, "remote_id": RID},
    {"status": DeviceStatus.ONLINE, "identity_verified": True},                          # verified without ID
    {"status": DeviceStatus.VERIFYING},                                                  # verifying without ID
    {"status": DeviceStatus.NOT_REGISTERED, "remote_id": RID},                           # ID before registration
    {"status": DeviceStatus.PENDING, "remote_id": RID},
    {"status": DeviceStatus.VERIFYING, "remote_id": "012345678"},                        # malformed ID
    {"status": DeviceStatus.VERIFYING, "remote_id": "12345"},
])
def test_states_the_server_never_confirmed_are_impossible(kwargs):
    with pytest.raises(ValueError):
        DeviceState(**kwargs)


# --------------------------------------------------------------- transitions


def test_successful_registration_sequence():
    controller, seen = controller_for(ScriptedGateway())
    assert controller.state.status is DeviceStatus.NOT_REGISTERED
    controller.register()
    assert [s.status for s in seen] == [DeviceStatus.PENDING, DeviceStatus.VERIFYING, DeviceStatus.ONLINE]
    assert seen[1].remote_id == RID and not seen[1].identity_verified
    assert seen[2].identity_verified and seen[2].remote_id == RID


def test_registration_failure_then_retry():
    gateway = ScriptedGateway(register=GatewayError("The server could not be reached."))
    controller, seen = controller_for(gateway)
    controller.register()
    assert seen[-1].status is DeviceStatus.FAILED and seen[-1].message == "The server could not be reached."
    gateway.register_result = Registration(RID, "OFFICE-PC")
    controller.retry()
    assert seen[-1].status is DeviceStatus.ONLINE


def test_unexpected_errors_show_a_generic_message_only():
    gateway = ScriptedGateway(register=RuntimeError("pyodbc PWD=secret stack trace"))
    controller, seen = controller_for(gateway)
    controller.register()
    assert seen[-1].status is DeviceStatus.FAILED and seen[-1].message == GENERIC_FAILURE


def test_invalid_remote_id_from_server_is_a_failure_not_displayed():
    controller, seen = controller_for(ScriptedGateway(register=Registration("000000000", "X")))
    controller.register()
    assert seen[-1].status is DeviceStatus.FAILED and all(s.remote_id is None for s in seen)


@pytest.mark.parametrize("verify", [False, GatewayError("Key mismatch."), RuntimeError("boom")])
def test_identity_verification_failure(verify):
    controller, seen = controller_for(ScriptedGateway(verify=verify))
    controller.register()
    assert seen[-1].status is DeviceStatus.FAILED and seen[-1].remote_id is None
    assert seen[-1].message in (VERIFY_FAILURE, "Key mismatch.")
    assert DeviceStatus.ONLINE not in [s.status for s in seen]


def test_offline_and_presence_errors():
    gateway = ScriptedGateway(online=False)
    controller, seen = controller_for(gateway)
    controller.register()
    assert seen[-1].status is DeviceStatus.OFFLINE
    gateway.online_result = RuntimeError("timeout")
    controller.refresh_presence()
    assert seen[-1].status is DeviceStatus.OFFLINE and seen[-1].message == PRESENCE_UNKNOWN
    gateway.online_result = True
    controller.refresh_presence()
    assert seen[-1].status is DeviceStatus.ONLINE


def test_register_ignored_while_busy_or_registered():
    gateway = ScriptedGateway()
    controller, _ = controller_for(gateway)
    controller.register()
    controller.register()   # already online: no second registration
    assert gateway.calls.count("register") == 1


# --------------------------------------------------------------- resume, auth, unsupported


def test_startup_resumes_a_stored_registration():
    gateway = ScriptedGateway(existing=Registration(RID, "OFFICE-PC"), local=True)
    controller, seen = controller_for(gateway)
    controller.start()
    assert [s.status for s in seen] == [DeviceStatus.PENDING, DeviceStatus.VERIFYING, DeviceStatus.ONLINE]
    assert "register" not in gateway.calls


def test_startup_without_local_registration_does_nothing():
    gateway = ScriptedGateway()
    controller, seen = controller_for(gateway)
    controller.start()
    assert seen == [] and gateway.calls == []


def test_stored_registration_unknown_to_server_returns_to_not_registered():
    controller, seen = controller_for(ScriptedGateway(existing=None, local=True))
    controller.start()
    assert seen[-1].status is DeviceStatus.NOT_REGISTERED and seen[-1].can_register


def test_retry_after_failed_resume_resumes_instead_of_registering_again():
    gateway = ScriptedGateway(existing=GatewayError("Cannot reach the server."), local=True)
    controller, seen = controller_for(gateway)
    controller.start()
    assert seen[-1].status is DeviceStatus.FAILED
    gateway.existing_result = Registration(RID, "OFFICE-PC")
    controller.retry()
    assert seen[-1].status is DeviceStatus.ONLINE and "register" not in gateway.calls


def test_session_end_sends_the_user_to_sign_in():
    controller, seen = controller_for(ScriptedGateway(register=AuthRequiredError()))
    signals = []
    controller.auth_required.connect(lambda: signals.append(1))
    controller.register()
    assert signals == [1] and seen[-1].status is DeviceStatus.FAILED and "sign in" in seen[-1].message.lower()


def test_unsupported_gateway_disables_registration(card):
    class Unsupported(ScriptedGateway):
        supported = False
        unsupported_reason = "This server does not offer device registration yet."
    controller, seen = controller_for(Unsupported())
    controller.register()
    assert seen == [] and not controller.state.can_register
    card.render(controller.state)
    assert card.register_button.isVisibleTo(card) and not card.register_button.isEnabled()


# --------------------------------------------------------------- preview gateway


def test_preview_gateway_is_labelled_and_demonstrates_retry():
    controller, seen = controller_for(PreviewDeviceGateway("failure", latency=0))
    controller.register()
    assert seen[-1].status is DeviceStatus.FAILED and seen[-1].preview
    controller.retry()
    assert seen[-1].status is DeviceStatus.ONLINE and all(s.preview for s in seen)


@pytest.mark.parametrize("mode, final", [("success", DeviceStatus.ONLINE), ("offline", DeviceStatus.OFFLINE),
                                         ("verify-failure", DeviceStatus.FAILED)])
def test_preview_modes(mode, final):
    controller, seen = controller_for(PreviewDeviceGateway(mode, latency=0))
    controller.register()
    assert seen[-1].status is final


def test_unknown_preview_mode_rejected():
    with pytest.raises(ValueError):
        PreviewDeviceGateway("magic")


# --------------------------------------------------------------- window integration


class FakeClient:
    base_url = "http://127.0.0.1:8765"
    signed_in = True

    def health(self):
        return True

    def logout(self):
        pass


USER = {"id": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "email": "alex@example.com", "display_name": "Alex Doe",
        "roles": ["user"]}


def test_window_defaults_to_real_gateway_without_preview(qapp):
    window = MainWindow(FakeClient(), USER)
    try:
        assert isinstance(window.device._gateway, ApiDeviceGateway)    # live mode: never preview fixtures
        assert window.windowTitle() == "Fabulous Remote"
        assert not window.device_card.preview_badge.isVisibleTo(window.device_card)
        assert window.device_card.remote_id_label.text() == "Not registered"
        assert window.device_card.register_button.isEnabled()
        assert not window.connect_button.isEnabled()
    finally:
        window.close()


def test_window_preview_mode_is_marked(qapp):
    window = MainWindow(FakeClient(), USER, device_gateway=PreviewDeviceGateway("success", latency=0))
    try:
        assert window.windowTitle().endswith("PREVIEW DATA")
        assert window.device_card.preview_badge.isVisibleTo(window.device_card)
        assert window.device_card.register_button.isEnabled()
        assert not window.connect_button.isEnabled()   # connecting is never enabled in this phase
    finally:
        window.close()
