"""Headless UI checks: layout, honest states and input handling."""

from __future__ import annotations

import pytest

from fabremote import remote_id
from fabremote.api_client import ApiError
from fabremote.ui.login_dialog import LoginDialog, message_for
from fabremote.ui.main_window import MainWindow

USER = {"id": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "email": "alex@example.com", "display_name": "Alex Doe", "roles": ["admin", "user"]}


class FakeClient:
    base_url = "http://127.0.0.1:8765"
    signed_in = True

    def health(self):
        return True

    def logout(self):
        pass


@pytest.fixture
def window(qapp):
    w = MainWindow(FakeClient(), USER)
    yield w
    w.close()


@pytest.mark.parametrize("text, valid, shown", [
    ("105280964", True, "105 280 964"), ("105 280 964", True, "105 280 964"), ("012345678", False, "012 345 678"),
    ("12345", False, "123 45"), ("abc123", False, "123"),
])
def test_remote_id_rules(text, valid, shown):
    assert remote_id.is_valid(text) is valid and remote_id.display(text) == shown


def test_home_shows_no_fabricated_device_state(window):
    assert window.your_id.text() == "Not registered"
    assert not window.connect_button.isEnabled()
    assert "Phase 3e" in window.connect_button.toolTip()
    texts = " ".join(label.text() for label in window.findChildren(type(window.your_id)))
    assert "Secure connection" not in texts and "Ready to connect" not in texts


def test_remote_id_input_formats_but_connect_stays_disabled(window):
    window.remote_input.setText("")
    window._remote_id_edited("105280964")
    assert window.remote_input.text() == "105 280 964"
    assert window.remote_hint.text() == "Valid Remote ID format."
    assert not window.connect_button.isEnabled()


def test_navigation_switches_pages(window):
    for index in range(window.pages.count()):
        window.nav.button(index).click()
        assert window.pages.currentIndex() == index


def test_user_identity_in_top_bar(window):
    assert window.avatar.text() == "AD" and window.avatar.toolTip() == USER["email"]


def test_health_indicator_reflects_real_result(window):
    window._health_result(True)
    assert window.status_text.text() == "Server online"
    window._health_result(False)
    assert window.status_text.text() == "Server unreachable"


def test_login_dialog_messages_are_generic(qapp):
    assert message_for(ApiError(401, "invalid_credentials", "x")) == "Email or password is incorrect."
    assert message_for(ApiError(429, "rate_limited", "x")).startswith("Too many attempts")
    assert message_for(RuntimeError("stack trace with secrets")) == "Something went wrong. Please try again."


def test_login_dialog_clears_password_after_failure(qapp):
    dialog = LoginDialog(FakeClient())
    dialog.password.setText("typed-secret")
    dialog._failed(ApiError(401, "invalid_credentials", "x"))
    assert dialog.password.text() == "" and dialog.error.text() == "Email or password is incorrect."
    assert dialog.submit.isEnabled()


def test_login_dialog_requires_both_fields(qapp):
    dialog = LoginDialog(FakeClient())
    dialog.email.setText("alex@example.com")
    dialog._sign_in()
    assert "Enter your email" in dialog.error.text()
