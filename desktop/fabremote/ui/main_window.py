"""Main window (layout from the design mockup).

The window opens signed out (user None). This computer registers and receives requests
without an account; asking to connect to another computer needs a signed-in user, so
Connect then asks the user to sign in.

Honesty rules (docs/PHASE1_AUDIT.md): status indicators show only verified state. The
Remote ID, verified identity and Online status come only from server responses. A session
only means the other person accepted: there is no screen sharing yet (Phase 6), and the
banner says so. Nothing is simulated outside explicit preview mode, where connecting is
disabled.
"""

from __future__ import annotations

import platform

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtWidgets import (QButtonGroup, QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenu,
                               QPushButton, QStackedWidget, QTabWidget, QVBoxLayout, QWidget)

from fabremote import __version__, remote_id
from fabremote.api_client import ApiClient, ApiError
from fabremote.connection import (ApiConnectionGateway, IncomingController, IncomingRequest, OutgoingController,
                                  OutgoingState, OutgoingStatus, SessionInfo)
from fabremote.device import ApiDeviceGateway, DeviceGateway, DeviceStatus
from fabremote.device_identity import DeviceIdentity, DpapiKeyStore
from fabremote.device_controller import DeviceController
from fabremote.ui.consent_dialog import ConsentDialog
from fabremote.ui.device_card import DeviceCard
from fabremote.ui.theme import CORAL, MUTED, NAVY, OK, icon, logo_icon, logo_pixmap
from fabremote.workers import run_async

NOT_YET = "Screen sharing arrives in a later version (Phase 6)."
NO_MEDIA = "Screen sharing is not available in this preview: the session confirms consent only."
TARGET_END = {"target_disconnect": "You ended the session.",
              "controller_disconnect": "The other person ended the session.",
              "timeout": "The connection to the other computer was lost.",
              "revoked": "The session was ended by an administrator."}
NAV = [("home", "Home"), ("clock", "Recent Sessions"), ("star", "Favorites"), ("book", "Address Book"),
       (None, None), ("settings", "Settings"), ("help", "Help")]


def label(text: str, name: str | None = None, wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    if name:
        widget.setObjectName(name)
    widget.setWordWrap(wrap)
    return widget


def card() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(20, 18, 20, 18)
    return frame, layout


def empty_state(title: str, body: str) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(24, 28, 24, 28)
    layout.addWidget(label(title, "section"))
    layout.addWidget(label(body, "muted", wrap=True))
    layout.addStretch()
    return page


class Dot(QLabel):
    COLORS = {"ok": OK, "down": CORAL, "unknown": "#b8c2d4"}

    def __init__(self, state: str = "unknown"):
        super().__init__()
        self.setFixedSize(10, 10)
        self.set_state(state)

    def set_state(self, state: str) -> None:
        self.setStyleSheet(f"background: {self.COLORS[state]}; border-radius: 5px;")


class MainWindow(QMainWindow):
    signed_out = Signal()
    sign_in_requested = Signal()

    def __init__(self, client: ApiClient, user: dict | None, device_gateway: DeviceGateway | None = None,
                 connection_gateway=None):
        super().__init__()
        self._client = client
        self._user = user
        gateway = device_gateway or ApiDeviceGateway(client, DeviceIdentity(DpapiKeyStore.for_server(client.base_url)))
        self.device = DeviceController(gateway, platform.node() or "This computer", parent=self)
        if connection_gateway is None and isinstance(gateway, ApiDeviceGateway):
            connection_gateway = ApiConnectionGateway(client, gateway)
        # Preview data never pretends to connect: no connection features without a real gateway.
        self.connections = connection_gateway
        self.incoming = IncomingController(connection_gateway, parent=self) if connection_gateway else None
        self.outgoing = OutgoingController(connection_gateway, parent=self) if connection_gateway else None
        self._consent_dialogs: dict[str, ConsentDialog] = {}
        self.device.auth_required.connect(self.signed_out.emit)
        self.setWindowTitle("Fabulous Remote" + (" — PREVIEW DATA" if gateway.preview else ""))
        self.setWindowIcon(logo_icon())
        self.resize(1120, 760)

        root = QWidget()
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._sidebar())
        content = QWidget()
        content.setObjectName("content")
        column = QVBoxLayout(content)
        column.setContentsMargins(36, 18, 36, 24)
        column.addLayout(self._top_bar())
        self.pages = QStackedWidget()
        for page in (self._home(), self._recent_page(), self._favorites_page(), self._address_page(),
                     self._settings_page(), self._help_page()):
            self.pages.addWidget(page)
        column.addWidget(self.pages)
        layout.addWidget(content, 1)
        self.setCentralWidget(root)

        self._health_timer = QTimer(self)
        self._health_timer.timeout.connect(self.check_health)
        self._health_timer.start(15_000)
        self.check_health()

        if self.incoming:
            self.incoming.request_received.connect(self._ask_consent)
            self.incoming.request_closed.connect(self._close_consent)
            self.incoming.session_changed.connect(self._incoming_session)
            self.incoming.error.connect(self._show_connection_message)
        if self.outgoing:
            self.outgoing.state_changed.connect(self._outgoing_changed)
        self.device.state_changed.connect(self._device_changed)
        self._device_changed(self.device.state)

    # --------------------------------------------------------------- layout

    def _sidebar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("sidebar")
        bar.setFixedWidth(220)
        layout = QVBoxLayout(bar)
        layout.setContentsMargins(0, 18, 0, 18)
        layout.setSpacing(2)
        brand = QHBoxLayout()
        brand.setContentsMargins(18, 0, 18, 18)
        logo = QLabel()
        logo.setPixmap(logo_pixmap(26))
        brand.addWidget(logo)
        brand.addWidget(label("Fabulous Remote", "brand"))
        brand.addStretch()
        layout.addLayout(brand)

        self.nav = QButtonGroup(self)
        self.nav.setExclusive(True)
        index = 0
        for key, text in NAV:
            if key is None:
                divider = QFrame()
                divider.setObjectName("divider")
                layout.addWidget(divider)
                continue
            button = QPushButton(f"  {text}")
            button.setIcon(icon(key))
            button.setIconSize(QSize(18, 18))
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            self.nav.addButton(button, index)
            layout.addWidget(button)
            index += 1
        self.nav.button(0).setChecked(True)
        self.nav.idClicked.connect(lambda i: self.pages.setCurrentIndex(i))
        layout.addStretch()
        layout.addWidget(label(f"   Preview build {__version__}", "muted"))
        return bar

    def _top_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.addStretch()
        self.status_dot = Dot()
        self.status_text = label("Checking server…", "muted")
        bar.addWidget(self.status_dot)
        bar.addWidget(self.status_text)
        bar.addSpacing(16)
        if self._user is None:
            self.sign_in_button = QPushButton("Sign in")
            self.sign_in_button.setObjectName("primary")
            self.sign_in_button.setCursor(Qt.CursorShape.PointingHandCursor)
            self.sign_in_button.clicked.connect(self.sign_in_requested)
            bar.addWidget(self.sign_in_button)
            return bar
        initials = "".join(part[:1] for part in self._user.get("display_name", "?").split()[:2]).upper() or "?"
        self.avatar = QPushButton(initials)
        self.avatar.setObjectName("avatar")
        self.avatar.setToolTip(self._user.get("email", ""))
        menu = QMenu(self)
        account = menu.addAction(f"Signed in as {self._user.get('email', '')}")
        account.setEnabled(False)
        menu.addSeparator()
        menu.addAction("Sign out", self.sign_out)
        self.avatar.setMenu(menu)
        bar.addWidget(self.avatar)
        return bar

    def _home(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(14)
        layout.addWidget(label("Connect to a device", "title"))
        layout.addWidget(label("Enter the remote ID of the device you want to connect to and start your session.",
                               "subtitle", wrap=True))

        row = QHBoxLayout()
        self.remote_input = QLineEdit()
        self.remote_input.setPlaceholderText("Enter Remote ID")
        self.remote_input.addAction(icon("monitor", NAVY), QLineEdit.ActionPosition.LeadingPosition)
        self.remote_input.setMaxLength(11)
        self.remote_input.textEdited.connect(self._remote_id_edited)
        self.connect_button = QPushButton("  Connect")
        self.connect_button.setObjectName("primary")
        self.connect_button.setIcon(icon("link", "#ffffff"))
        self.connect_button.setEnabled(False)
        self.connect_button.clicked.connect(self._connect_clicked)
        self.remote_input.returnPressed.connect(self._connect_clicked)
        row.addWidget(self.remote_input, 1)
        row.addWidget(self.connect_button)
        layout.addLayout(row)
        self.remote_hint = label("A Remote ID has 9 digits, for example 105 280 964.", "hint")
        layout.addWidget(self.remote_hint)

        status_row = QHBoxLayout()
        self.connection_status = label("", "muted", wrap=True)
        self.connection_status.setAccessibleName("Connection status")
        self.cancel_button = QPushButton("Cancel request")
        self.cancel_button.setObjectName("secondary")
        self.cancel_button.hide()
        self.cancel_button.clicked.connect(lambda: self.outgoing and self.outgoing.cancel())
        status_row.addWidget(self.connection_status, 1)
        status_row.addWidget(self.cancel_button)
        layout.addLayout(status_row)

        self.session_banner = QFrame()
        self.session_banner.setObjectName("sessionBanner")
        banner = QHBoxLayout(self.session_banner)
        banner.setContentsMargins(16, 12, 16, 12)
        self.session_text = label("", wrap=True)
        self.session_text.setAccessibleName("Session")
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.setObjectName("primary")
        self.disconnect_button.clicked.connect(self._disconnect_clicked)
        banner.addWidget(self.session_text, 1)
        banner.addWidget(self.disconnect_button)
        self.session_banner.hide()
        layout.addWidget(self.session_banner)

        layout.addWidget(label("Connecting asks the other person to accept on their screen; they see your name and "
                               f"email. {NOT_YET}", "notice", wrap=True))

        self.device_card = DeviceCard()
        self.device_card.register_requested.connect(self.device.register)
        self.device_card.retry_requested.connect(self.device.retry)
        self.device_card.recheck_requested.connect(self.device.refresh_presence)
        self.device.state_changed.connect(self.device_card.render)
        self.device_card.render(self.device.state)
        self.device.start()   # resume a registration stored on this computer, confirmed by the server
        self.your_id = self.device_card.remote_id_label
        layout.addWidget(self.device_card)

        tabs = QTabWidget()
        tabs.addTab(empty_state("No sessions yet", "Sessions you start or receive will be listed here."),
                    "Recent Sessions")
        tabs.addTab(empty_state("No favorites yet", "Mark devices from your address book as favorites."), "Favorites")
        tabs.addTab(empty_state("Address book is empty", "Saved contacts and their Remote IDs will appear here."),
                    "Address Book")
        layout.addWidget(tabs, 1)
        return page

    def _recent_page(self) -> QWidget:
        return empty_state("Recent Sessions", "Session history will be listed here in a later version.")

    def _favorites_page(self) -> QWidget:
        return empty_state("Favorites", "Favorites will be available with the address book (Phase 4).")

    def _address_page(self) -> QWidget:
        return empty_state("Address Book", "Saving contacts and Remote IDs will be available in Phase 4.")

    def _settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.addWidget(label("Settings", "title"))
        info, info_layout = card()
        info_layout.addWidget(label("Account", "section"))
        if self._user is None:
            info_layout.addWidget(label("Not signed in.", "muted"))
        else:
            info_layout.addWidget(label(f"{self._user.get('display_name', '')} · {self._user.get('email', '')}",
                                        "muted"))
            info_layout.addWidget(label("Roles: " + ", ".join(self._user.get("roles", [])), "muted"))
        info_layout.addSpacing(8)
        info_layout.addWidget(label("Server", "section"))
        info_layout.addWidget(label(self._client.base_url, "muted"))
        info_layout.addSpacing(8)
        info_layout.addWidget(label("Security", "section"))
        info_layout.addWidget(label("Sign-in tokens and this computer's device token are kept in memory only and "
                                    "are discarded when you close the app (sign-in tokens also when you sign out). "
                                    "The device key never leaves this computer.", "muted", wrap=True))
        layout.addWidget(info)
        layout.addStretch()
        return page

    def _help_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(label("Help", "title"))
        layout.addWidget(label("Protect yourself from support scams: only accept a request from someone you know. "
                               "Never accept a request from someone who contacted you unexpectedly claiming to be "
                               "support.", "warning", wrap=True))
        steps, steps_layout = card()
        steps_layout.addWidget(label("How connecting works", "section"))
        for text in ("1. The person being helped opens Fabulous Remote (no account needed), registers their "
                     "computer once, and reads out the Remote ID shown on the Home screen.",
                     "2. You sign in, enter that ID and press Connect.",
                     "3. They see your name and email and choose Accept or Reject.",
                     "4. A banner shows the session on both computers; either side can disconnect at any time.",
                     f"{NOT_YET} Until then a session confirms consent only."):
            steps_layout.addWidget(label(text, "muted", wrap=True))
        layout.addWidget(steps)
        layout.addStretch()
        return page

    # -------------------------------------------------------------- actions

    # ----------------------------------------------------------- connecting

    def _device_changed(self, state) -> None:
        registered = state.status in (DeviceStatus.ONLINE, DeviceStatus.OFFLINE)
        if self.incoming:
            if registered and not self.incoming.running:
                self.incoming.start()
            elif not registered and self.incoming.running:
                self.incoming.stop()
        self._update_connect()

    def _connect_block_reason(self) -> str | None:
        if self.outgoing is None:
            return "Connecting is not available with preview data."
        if self.device.state.status is not DeviceStatus.ONLINE:
            return "Register this computer and wait until it is online first."
        if self.outgoing.state.busy or (self.incoming and self.incoming.session):
            return "Already connecting or in a session."
        if not remote_id.is_valid(self.remote_input.text()):
            return "Enter a 9-digit Remote ID."
        return None

    def _update_connect(self) -> None:
        reason = self._connect_block_reason()
        self.connect_button.setEnabled(reason is None)
        if reason is None and self._user is None:
            reason = "You will be asked to sign in first."
        self.connect_button.setToolTip(reason or "")

    def _connect_clicked(self) -> None:
        if self._connect_block_reason() is not None:
            return
        if self._user is None:
            self.sign_in_requested.emit()
            return
        self.outgoing.connect_to(self.remote_input.text())

    def _disconnect_clicked(self) -> None:
        if self.outgoing and self.outgoing.state.status is OutgoingStatus.CONNECTED:
            self.outgoing.disconnect()
        elif self.incoming and self.incoming.session:
            self.incoming.end_session()

    def _show_connection_message(self, text: str) -> None:
        self.connection_status.setText(text)

    def _show_banner(self, text: str | None) -> None:
        self.session_banner.setVisible(text is not None)
        self.session_text.setText(text or "")

    def _outgoing_changed(self, state: OutgoingState) -> None:
        target = remote_id.display(state.remote_id or "")
        self.cancel_button.setVisible(state.status is OutgoingStatus.WAITING)
        if state.status is OutgoingStatus.SENDING:
            self.connection_status.setText(f"Sending a request to {target}…")
        elif state.status is OutgoingStatus.WAITING:
            self.connection_status.setText(f"Waiting for {target} to accept…")
        elif state.status is OutgoingStatus.CONNECTED:
            self.connection_status.setText("")
            self._show_banner(f"Connected to {target}: the other person accepted. {NO_MEDIA}")
        else:
            self.connection_status.setText(state.message or "")
            if not (self.incoming and self.incoming.session):
                self._show_banner(None)
        self._update_connect()

    def _ask_consent(self, request: IncomingRequest) -> None:
        dialog = ConsentDialog(request, self)
        dialog.accepted_request.connect(self.incoming.accept)
        dialog.rejected_request.connect(self.incoming.reject)
        dialog.finished.connect(lambda _: self._consent_dialogs.pop(request.id, None))
        self._consent_dialogs[request.id] = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _close_consent(self, request_id: str) -> None:
        dialog = self._consent_dialogs.pop(request_id, None)
        if dialog is not None:
            dialog.expire()

    def _incoming_session(self, info: SessionInfo) -> None:
        if info.active:
            for dialog in list(self._consent_dialogs.values()):   # one session at a time
                dialog.expire()
            self.connection_status.setText("")
            self._show_banner(f"Connected: {info.controller_name} (computer {remote_id.display(info.controller_remote_id)}) "
                              f"has your permission. {NO_MEDIA}")
        else:
            self._show_banner(None)
            self.connection_status.setText(TARGET_END.get(info.end_reason or "", "The session has ended."))
        self._update_connect()

    def shutdown(self) -> None:
        """Stop every timer before the window is replaced (sign-in or sign-out)."""
        self._health_timer.stop()
        self.device.stop()
        for controller in (self.incoming, self.outgoing):
            if controller:
                controller.stop()
        for dialog in list(self._consent_dialogs.values()):
            dialog.expire()

    def _remote_id_edited(self, text: str) -> None:
        formatted = remote_id.display(text)
        if formatted != text:
            self.remote_input.setText(formatted)
        if remote_id.is_valid(formatted):
            self.remote_hint.setText("Valid Remote ID format.")
            self.remote_hint.setObjectName("hintOk")
        else:
            self.remote_hint.setText("A Remote ID has 9 digits, for example 105 280 964.")
            self.remote_hint.setObjectName("hint")
        self.remote_hint.style().unpolish(self.remote_hint)
        self.remote_hint.style().polish(self.remote_hint)
        self._update_connect()

    def check_health(self) -> None:
        run_async(self._client.health, self._health_result, lambda _: self._health_result(False))

    def _health_result(self, online: object) -> None:
        if online:
            self.status_dot.set_state("ok")
            self.status_text.setText("Server online")
        else:
            self.status_dot.set_state("down")
            self.status_text.setText("Server unreachable")

    def sign_out(self) -> None:
        if self.outgoing and self.outgoing.state.status is OutgoingStatus.CONNECTED:
            self.outgoing.disconnect()
        elif self.outgoing and self.outgoing.state.status is OutgoingStatus.WAITING:
            self.outgoing.cancel()
        self.shutdown()
        run_async(self._client.logout, lambda _: self.signed_out.emit(), lambda _: self.signed_out.emit())

    def handle_session_error(self, error: Exception) -> None:
        if isinstance(error, ApiError) and error.status == 401:
            self.signed_out.emit()
