"""Main window (layout from the design mockup).

Honesty rules (docs/PHASE1_AUDIT.md): status indicators show only verified state. The
"This device" card is driven by DeviceController against the real device API (Phase 3d):
the Remote ID, verified identity and Online status come only from server responses.
Connection requests and sessions do not exist yet, so Connect stays disabled with the
reason; nothing is simulated outside explicit preview mode.
"""

from __future__ import annotations

import platform

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtWidgets import (QButtonGroup, QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenu,
                               QPushButton, QStackedWidget, QTabWidget, QVBoxLayout, QWidget)

from fabremote import __version__, remote_id
from fabremote.api_client import ApiClient, ApiError
from fabremote.device import ApiDeviceGateway, DeviceGateway
from fabremote.device_identity import DeviceIdentity, DpapiKeyStore
from fabremote.device_controller import DeviceController
from fabremote.ui.device_card import DeviceCard
from fabremote.ui.theme import CORAL, MUTED, NAVY, OK, icon, logo_icon, logo_pixmap
from fabremote.workers import run_async

NOT_YET = "Available after connection requests and target-side consent are implemented (Phase 3e)."
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

    def __init__(self, client: ApiClient, user: dict, device_gateway: DeviceGateway | None = None):
        super().__init__()
        self._client = client
        self._user = user
        gateway = device_gateway or ApiDeviceGateway(
            client, DeviceIdentity(DpapiKeyStore.for_server(client.base_url)), user["id"])
        self.device = DeviceController(gateway, platform.node() or "This computer", parent=self)
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
        self.connect_button.setToolTip(NOT_YET)
        row.addWidget(self.remote_input, 1)
        row.addWidget(self.connect_button)
        layout.addLayout(row)
        self.remote_hint = label("A Remote ID has 9 digits, for example 105 280 964.", "hint")
        layout.addWidget(self.remote_hint)
        layout.addWidget(label(f"Connecting is not available in this preview. {NOT_YET}", "notice", wrap=True))

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
        return empty_state("Recent Sessions", f"No sessions yet. {NOT_YET}")

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
        info_layout.addWidget(label(f"{self._user.get('display_name', '')} · {self._user.get('email', '')}", "muted"))
        info_layout.addWidget(label("Roles: " + ", ".join(self._user.get("roles", [])), "muted"))
        info_layout.addSpacing(8)
        info_layout.addWidget(label("Server", "section"))
        info_layout.addWidget(label(self._client.base_url, "muted"))
        info_layout.addSpacing(8)
        info_layout.addWidget(label("Security", "section"))
        info_layout.addWidget(label("Sign-in tokens are kept in memory only and are discarded when you sign out "
                                    "or close the app.", "muted", wrap=True))
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
        steps_layout.addWidget(label("How a session will work", "section"))
        for text in ("1. Both people sign in to Fabulous Remote.",
                     "2. The person being helped reads out the Remote ID shown on their Home screen.",
                     "3. You enter it and press Connect; they see your name and choose Accept or Reject.",
                     "4. A banner shows the session is active, and either side can disconnect instantly."):
            steps_layout.addWidget(label(text, "muted", wrap=True))
        layout.addWidget(steps)
        layout.addStretch()
        return page

    # -------------------------------------------------------------- actions

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
        self._health_timer.stop()
        self.device.stop()
        run_async(self._client.logout, lambda _: self.signed_out.emit(), lambda _: self.signed_out.emit())

    def handle_session_error(self, error: Exception) -> None:
        if isinstance(error, ApiError) and error.status == 401:
            self.signed_out.emit()
