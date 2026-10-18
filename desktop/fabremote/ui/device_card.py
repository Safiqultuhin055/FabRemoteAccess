"""The "This device" card. Renders a DeviceState; it never invents a state of its own.

Accessibility: every state is described in text (badges are labelled, not colour-only),
the card's accessible description summarises the current state for screen readers, the
Remote ID is keyboard-selectable, and progress has an accessible name.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QProgressBar, QPushButton, QSizePolicy, QVBoxLayout

from fabremote import remote_id as rid
from fabremote.device import DeviceState, DeviceStatus
from fabremote.ui.theme import NAVY, icon

REGISTRATION_REQUIRED = ("Register this computer to get a Remote ID. Registration is required before this "
                         "computer can receive connection requests.")

TEXT = {
    DeviceStatus.NOT_REGISTERED: ("Not registered", None),
    DeviceStatus.PENDING: ("Registering…", "Registering this computer with the server…"),
    DeviceStatus.VERIFYING: (None, "Confirming this computer's identity with the server. It cannot receive "
                                   "requests until verification is complete."),
    DeviceStatus.ONLINE: (None, "Online. Connection requests will appear here once they are available "
                                "(Phase 3e); you will approve every request."),
    DeviceStatus.OFFLINE: (None, "Not connected to the server. This computer cannot receive requests."),
    DeviceStatus.FAILED: ("Not registered", "Registration failed. Check your connection and try again."),
}


def _badge(name: str, text: str = "") -> QLabel:
    badge = QLabel(text)
    badge.setObjectName(name)
    # Pills keep their natural height instead of stretching with the row.
    badge.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
    badge.hide()
    return badge


class DeviceCard(QFrame):
    register_requested = Signal()
    retry_requested = Signal()
    recheck_requested = Signal()
    sign_in_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setAccessibleName("This device")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 18, 20, 18)
        outer.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel("This device")
        title.setObjectName("section")
        header.addWidget(title)
        self.preview_badge = _badge("previewBadge", "PREVIEW · sample data, not from the server")
        self.preview_badge.setAccessibleName("Preview mode: sample data, not from the server")
        header.addWidget(self.preview_badge, alignment=Qt.AlignmentFlag.AlignVCenter)
        header.addStretch()
        outer.addLayout(header)

        body = QHBoxLayout()
        body.setSpacing(14)
        laptop = QLabel()
        laptop.setPixmap(icon("laptop", NAVY, 48).pixmap(48, 48))
        laptop.setAlignment(Qt.AlignmentFlag.AlignTop)
        body.addWidget(laptop)

        details = QVBoxLayout()
        details.setSpacing(4)
        caption = QLabel("Your ID")
        caption.setObjectName("muted")
        details.addWidget(caption)
        self.remote_id_label = QLabel()
        self.remote_id_label.setObjectName("remoteId")
        self.remote_id_label.setAccessibleName("Your Remote ID")
        details.addWidget(self.remote_id_label)
        self.device_name_label = QLabel()
        self.device_name_label.setObjectName("muted")
        details.addWidget(self.device_name_label)

        badges = QHBoxLayout()
        badges.setSpacing(8)
        self.identity_badge = _badge("badgeNeutral")
        self.presence_badge = _badge("badgeNeutral")
        badges.addWidget(self.identity_badge)
        badges.addWidget(self.presence_badge)
        badges.addStretch()
        details.addLayout(badges)

        self.message_label = QLabel()
        self.message_label.setObjectName("muted")
        self.message_label.setWordWrap(True)
        self.message_label.setAccessibleName("Device status")
        details.addWidget(self.message_label)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)          # indeterminate
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        self.progress.setAccessibleName("Registration in progress")
        self.progress.hide()
        details.addWidget(self.progress)

        actions = QHBoxLayout()
        self.register_button = QPushButton("Register This Device")
        self.register_button.setObjectName("primary")
        self.register_button.setAccessibleName("Register this device")
        self.register_button.clicked.connect(self._on_register)
        self.retry_button = QPushButton("Try again")
        self.retry_button.setObjectName("secondary")
        self.retry_button.clicked.connect(self._on_retry)
        actions.addWidget(self.register_button)
        actions.addWidget(self.retry_button)
        actions.addStretch()
        details.addLayout(actions)

        body.addLayout(details, 1)
        outer.addLayout(body)
        self._state: DeviceState | None = None
        self._needs_sign_in = False

    # ------------------------------------------------------------------ render

    def require_sign_in(self) -> None:
        """Signed out: the register button opens sign-in instead (registration needs an account)."""
        self._needs_sign_in = True
        if self._state:
            self.render(self._state)

    def _on_register(self) -> None:
        (self.sign_in_requested if self._needs_sign_in else self.register_requested).emit()

    def _on_retry(self) -> None:
        if self._state and self._state.status is DeviceStatus.OFFLINE:
            self.recheck_requested.emit()
        else:
            self.retry_requested.emit()

    @staticmethod
    def _set_badge(badge: QLabel, text: str | None, kind: str = "badgeNeutral") -> None:
        if not text:
            badge.hide()
            return
        badge.setText(text)
        badge.setAccessibleName(text)
        badge.setObjectName(kind)
        badge.style().unpolish(badge)
        badge.style().polish(badge)
        badge.show()

    def render(self, state: DeviceState) -> None:
        self._state = state
        s = state.status
        default_id, default_message = TEXT[s]
        registered = state.remote_id is not None

        self.remote_id_label.setText(rid.display(state.remote_id) if registered else default_id)
        self.remote_id_label.setObjectName("remoteIdValue" if registered else "remoteId")
        self.remote_id_label.style().unpolish(self.remote_id_label)
        self.remote_id_label.style().polish(self.remote_id_label)
        flags = (Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
                 if registered else Qt.TextInteractionFlag.NoTextInteraction)
        self.remote_id_label.setTextInteractionFlags(flags)
        self.remote_id_label.setAccessibleDescription(
            f"{rid.display(state.remote_id)} (assigned by the server)" if registered else default_id or "")

        self.device_name_label.setText(f"Device name: {state.device_name}" if state.device_name and registered else "")
        self.device_name_label.setVisible(bool(state.device_name and registered))

        identity = {
            DeviceStatus.NOT_REGISTERED: ("Not registered", "badgeNeutral"),
            DeviceStatus.PENDING: ("Registration pending", "badgeWarn"),
            DeviceStatus.VERIFYING: ("Verifying identity…", "badgeWarn"),
            DeviceStatus.FAILED: ("Registration failed", "badgeError"),
        }.get(s, ("Identity verified", "badgeOk") if state.identity_verified else (None, ""))
        self._set_badge(self.identity_badge, *identity)
        presence = {DeviceStatus.ONLINE: ("● Online", "badgeOk"), DeviceStatus.OFFLINE: ("○ Offline", "badgeNeutral")}
        self._set_badge(self.presence_badge, *presence.get(s, (None, "")))

        if s is DeviceStatus.NOT_REGISTERED:
            message = REGISTRATION_REQUIRED + (f"\n\n{state.message}" if state.message else "")
        else:
            message = state.message or default_message
        self.message_label.setText(message)

        busy = s in (DeviceStatus.PENDING, DeviceStatus.VERIFYING)
        self.progress.setVisible(busy)
        self.register_button.setVisible(s is DeviceStatus.NOT_REGISTERED)
        allowed = state.can_register or self._needs_sign_in
        self.register_button.setEnabled(s is DeviceStatus.NOT_REGISTERED and allowed)
        self.register_button.setToolTip("" if allowed else (state.message or ""))
        self.register_button.setText("Sign in to register" if self._needs_sign_in else "Register This Device")
        self.register_button.setAccessibleName(self.register_button.text())
        self.retry_button.setVisible(s in (DeviceStatus.FAILED, DeviceStatus.OFFLINE))
        self.retry_button.setText("Check again" if s is DeviceStatus.OFFLINE else "Try again")
        self.retry_button.setAccessibleName(self.retry_button.text())
        self.preview_badge.setVisible(state.preview)

        summary = [f"Status: {identity[0] or ''}".strip()]
        if registered:
            summary.append(f"Remote ID {rid.display(state.remote_id)}")
        if s in presence:
            summary.append(presence[s][0].lstrip("●○ "))
        if state.preview:
            summary.append("preview sample data")
        self.setAccessibleDescription(". ".join(p for p in summary if p) + ". " + message)
