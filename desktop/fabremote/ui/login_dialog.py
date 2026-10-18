"""Sign-in dialog. Shows only generic errors; the password field is cleared after a failure."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout

from fabremote.api_client import ApiClient, ApiError
from fabremote.ui.theme import logo_icon, logo_pixmap
from fabremote.workers import run_async

MESSAGES = {
    "invalid_credentials": "Email or password is incorrect.",
    "rate_limited": "Too many attempts. Wait a minute and try again.",
    "validation_error": "Enter your email address and password.",
}


def message_for(error: Exception) -> str:
    if isinstance(error, ApiError):
        return MESSAGES.get(error.code, error.message)
    return "Something went wrong. Please try again."


class LoginDialog(QDialog):
    def __init__(self, client: ApiClient, parent=None):
        super().__init__(parent)
        self._client = client
        self.user: dict | None = None
        self.setWindowTitle("Fabulous Remote — Sign in")
        self.setWindowIcon(logo_icon())
        self.setFixedWidth(420)
        # Room for a two-line error without the word-wrapped labels being clipped.
        self.setMinimumHeight(430)

        brand = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(logo_pixmap(32))
        name = QLabel("Fabulous Remote")
        name.setObjectName("section")
        brand.addWidget(logo)
        brand.addWidget(name)
        brand.addStretch()

        title = QLabel("Sign in")
        title.setObjectName("title")
        server = QLabel(f"Server: {client.base_url}")
        server.setObjectName("muted")

        self.email = QLineEdit()
        self.email.setPlaceholderText("Email address")
        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.error = QLabel("")
        self.error.setObjectName("error")
        self.error.setWordWrap(True)

        self.submit = QPushButton("Sign in")
        self.submit.setObjectName("primary")
        self.submit.setDefault(True)
        self.submit.clicked.connect(self._sign_in)
        cancel = QPushButton("Cancel")
        cancel.setObjectName("secondary")
        cancel.clicked.connect(self.reject)

        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(cancel)
        buttons.addWidget(self.submit)

        note = QLabel("Accounts are created by invitation from your administrator.")
        note.setObjectName("hint")
        note.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)
        layout.addLayout(brand)
        layout.addSpacing(6)
        layout.addWidget(title)
        layout.addWidget(server)
        layout.addWidget(self.email)
        layout.addWidget(self.password)
        layout.addWidget(self.error)
        layout.addLayout(buttons)
        layout.addWidget(note, alignment=Qt.AlignmentFlag.AlignLeft)

    def _sign_in(self) -> None:
        email, password = self.email.text().strip(), self.password.text()
        if not email or not password:
            self.error.setText(MESSAGES["validation_error"])
            return
        self.submit.setEnabled(False)
        self.submit.setText("Signing in…")
        self.error.setText("")
        run_async(lambda: self._client.login(email, password), self._succeeded, self._failed)

    def _succeeded(self, user: dict) -> None:
        self.user = user
        self.accept()

    def _failed(self, error: Exception) -> None:
        self.password.clear()
        self.password.setFocus()
        self.error.setText(message_for(error))
        self.submit.setEnabled(True)
        self.submit.setText("Sign in")
