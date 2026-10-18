"""Consent dialog: someone asks to connect to this computer; only an explicit Accept allows it.

Safety: Reject is the default button and has the focus, so pressing Enter or closing the
window never grants access. The requester's name and email come from the server (their
signed-in account), with a support-scam warning. The dialog closes itself when the request
expires.
"""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import QCheckBox, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from fabremote import remote_id as rid
from fabremote.connection import IncomingRequest
from fabremote.ui.theme import logo_icon


class ConsentDialog(QDialog):
    accepted_request = Signal(str)
    rejected_request = Signal(str, bool)     # request id, block this person

    def __init__(self, request: IncomingRequest, parent=None, *, now=lambda: datetime.now(UTC)):
        super().__init__(parent)
        self.request = request
        self._now = now
        self._answered = False
        self.setWindowTitle("Fabulous Remote — Connection request")
        self.setWindowIcon(logo_icon())
        self.setFixedWidth(460)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)

        title = QLabel("Someone wants to connect")
        title.setObjectName("title")
        who = QLabel(f"<b>{_escape(request.requester_name)}</b> ({_escape(request.requester_email)}) is asking "
                     "to connect to this computer.")
        who.setWordWrap(True)
        who.setTextFormat(Qt.TextFormat.RichText)
        source = QLabel(f"From computer {_escape(request.device_name)} · ID {rid.display(request.device_remote_id)}")
        source.setObjectName("muted")
        source.setWordWrap(True)
        scope = QLabel("If you accept, they will be connected to this computer. Screen sharing is not available "
                       "in this preview, so they cannot see or control anything yet. Either of you can disconnect "
                       "at any time.")
        scope.setObjectName("muted")
        scope.setWordWrap(True)
        warning = QLabel("Only accept if you know this person and expected their request. Never accept someone "
                         "who contacted you unexpectedly claiming to be support.")
        warning.setObjectName("warning")
        warning.setWordWrap(True)

        self.block = QCheckBox("Block this person from asking again")
        self.countdown = QLabel()
        self.countdown.setObjectName("hint")

        self.reject_button = QPushButton("Reject")
        self.reject_button.setObjectName("secondary")
        self.reject_button.setDefault(True)
        self.reject_button.setAutoDefault(True)
        self.reject_button.clicked.connect(self._reject)
        self.accept_button = QPushButton("Accept")
        self.accept_button.setObjectName("primary")
        self.accept_button.setAutoDefault(False)
        self.accept_button.clicked.connect(self._accept)

        buttons = QHBoxLayout()
        buttons.addWidget(self.countdown)
        buttons.addStretch()
        buttons.addWidget(self.reject_button)
        buttons.addWidget(self.accept_button)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)
        for widget in (title, who, source, scope, warning, self.block):
            layout.addWidget(widget)
        layout.addLayout(buttons)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self._tick()
        self.reject_button.setFocus()

    def seconds_left(self) -> int:
        return max(0, int((self.request.expires_at - self._now()).total_seconds()))

    def _tick(self) -> None:
        left = self.seconds_left()
        self.countdown.setText(f"Expires in {left} s")
        if left <= 0:
            self.expire()

    def expire(self) -> None:
        """The request is no longer pending (expired or withdrawn): close without answering."""
        self._answered = True
        self._timer.stop()
        self.done(QDialog.DialogCode.Rejected)

    def _accept(self) -> None:
        if self._answered:
            return
        self._answered = True
        self._timer.stop()
        self.accepted_request.emit(self.request.id)
        self.accept()

    def _reject(self) -> None:
        if self._answered:
            return
        self._answered = True
        self._timer.stop()
        self.rejected_request.emit(self.request.id, self.block.isChecked())
        self.done(QDialog.DialogCode.Rejected)

    def reject(self) -> None:          # Esc or the window's close button
        if not self._answered:
            self._reject()
        else:
            super().reject()


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
