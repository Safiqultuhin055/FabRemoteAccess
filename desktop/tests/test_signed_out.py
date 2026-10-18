"""The app opens without signing in; everything that needs an account leads to sign-in."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QDialog

from fabremote import app as app_module
from fabremote.device import SIGN_IN_REQUIRED, DeviceStatus, SignedOutGateway
from fabremote.ui.main_window import MainWindow

USER = {"id": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "email": "alex@example.com", "display_name": "Alex Doe",
        "roles": ["user"]}


class FakeClient:
    base_url = "http://127.0.0.1:8765"
    signed_in = False

    def __init__(self):
        self.device_calls = 0

    def health(self):
        return True

    def logout(self):
        pass

    def __getattr__(self, name):
        if name.startswith("device"):
            self.device_calls += 1
            raise AssertionError("signed-out window must not call the device API")
        raise AttributeError(name)


@pytest.fixture
def signed_out(qapp):
    client = FakeClient()
    window = MainWindow(client, None)
    yield window, client
    window.close()


def test_signed_out_window_offers_sign_in_instead_of_an_account(signed_out):
    window, client = signed_out
    assert window.sign_in_button.text() == "Sign in"
    assert not hasattr(window, "avatar")
    assert window.device.state.status is DeviceStatus.NOT_REGISTERED
    assert window.your_id.text() == "Not registered"         # no Remote ID before sign-in
    assert SIGN_IN_REQUIRED in window.device_card.message_label.text()
    assert not window.connect_button.isEnabled()
    assert client.device_calls == 0


def test_both_sign_in_buttons_request_sign_in(signed_out):
    window, _ = signed_out
    requests = []
    window.sign_in_requested.connect(lambda: requests.append(1))
    window.sign_in_button.click()
    button = window.device_card.register_button
    assert button.text() == "Sign in to register" and button.isEnabled()
    button.click()
    assert len(requests) == 2


def test_signed_out_gateway_never_reports_a_device():
    gateway = SignedOutGateway()
    assert gateway.supported is False and gateway.has_local_device() is False
    for call in (gateway.existing, gateway.verify_identity, gateway.is_online, lambda: gateway.register("PC")):
        with pytest.raises(Exception):
            call()


def test_signed_in_card_still_registers(qapp):
    window = MainWindow(FakeClient(), USER, device_gateway=SignedOutGateway())
    try:
        assert window.device_card.register_button.text() == "Register This Device"
        assert window.avatar.text() == "AD"
    finally:
        window.close()


class FakeDialog:
    accept = True

    def __init__(self, client, parent=None):
        self.user = USER

    def exec(self):
        return QDialog.DialogCode.Accepted if FakeDialog.accept else QDialog.DialogCode.Rejected


def test_controller_opens_signed_out_then_switches_on_sign_in_and_back_on_sign_out(qapp, monkeypatch):
    monkeypatch.setattr(app_module, "LoginDialog", FakeDialog)
    monkeypatch.setattr("fabremote.ui.main_window.ApiDeviceGateway", lambda *a, **k: SignedOutGateway())
    controller = app_module.Controller(qapp, FakeClient())
    assert controller.start() is True
    first = controller.window
    assert first.isVisible() and first._user is None             # no sign-in dialog on start

    FakeDialog.accept = False
    controller.sign_in()
    assert controller.window is first                             # cancelled: stays signed out

    FakeDialog.accept = True
    controller.sign_in()
    signed_in = controller.window
    assert signed_in is not first and signed_in._user == USER and signed_in.isVisible()

    signed_in.signed_out.emit()
    assert controller.window._user is None and controller.window.isVisible()
    controller.window.close()
