"""The app opens without signing in. This computer registers and receives requests without an
account; only asking to connect to another computer needs a signed-in user."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QDialog

from fabremote import app as app_module
from fabremote.device import DeviceState, DeviceStatus, PreviewDeviceGateway
from fabremote.ui.main_window import MainWindow

USER = {"id": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "email": "alex@example.com", "display_name": "Alex Doe",
        "roles": ["user"]}


class FakeClient:
    base_url = "http://127.0.0.1:8765"
    signed_in = False
    has_device_token = False

    def health(self):
        return True

    def logout(self):
        pass


class NoopConnections:
    signed_in = False


def online(window):
    """Put the device card in the server-confirmed Online state (as the controller would)."""
    state = DeviceState(DeviceStatus.ONLINE, remote_id="105280964", device_name="PC", identity_verified=True)
    window.device._set(state)


@pytest.fixture
def signed_out(qapp):
    window = MainWindow(FakeClient(), None, connection_gateway=NoopConnections())
    yield window
    window.shutdown()
    window.close()


def test_signed_out_window_registers_without_an_account(signed_out):
    assert signed_out.sign_in_button.text() == "Sign in"
    assert not hasattr(signed_out, "avatar")
    button = signed_out.device_card.register_button
    assert button.text() == "Register This Device" and button.isEnabled()   # no sign-in needed
    assert signed_out.your_id.text() == "Not registered"                     # nothing before the server says so


def test_connect_asks_a_signed_out_user_to_sign_in(signed_out):
    online(signed_out)
    signed_out.remote_input.setText("123 456 789")
    signed_out._remote_id_edited("123 456 789")
    assert signed_out.connect_button.isEnabled()
    assert "sign in" in signed_out.connect_button.toolTip()
    requests = []
    signed_out.sign_in_requested.connect(lambda: requests.append(1))
    signed_out.connect_button.click()
    assert requests == [1] and signed_out.outgoing.state.status.value == "idle"


def test_top_bar_sign_in_button_requests_sign_in(signed_out):
    requests = []
    signed_out.sign_in_requested.connect(lambda: requests.append(1))
    signed_out.sign_in_button.click()
    assert requests == [1]


def test_preview_data_never_offers_connecting(qapp):
    window = MainWindow(FakeClient(), USER, device_gateway=PreviewDeviceGateway("success", latency=0))
    try:
        assert window.outgoing is None and window.incoming is None
        assert not window.connect_button.isEnabled()
    finally:
        window.shutdown()
        window.close()


class FakeDialog:
    accept = True

    def __init__(self, client, parent=None):
        self.user = USER

    def exec(self):
        return QDialog.DialogCode.Accepted if FakeDialog.accept else QDialog.DialogCode.Rejected


def test_controller_opens_signed_out_then_switches_on_sign_in_and_back_on_sign_out(qapp, monkeypatch):
    monkeypatch.setattr(app_module, "LoginDialog", FakeDialog)
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
    controller.window.shutdown()
    controller.window.close()
