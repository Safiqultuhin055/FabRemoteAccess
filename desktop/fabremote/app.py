"""Desktop client entry point.

    python -m fabremote [--api-url http://127.0.0.1:8765] [--preview-device-states MODE]

Server address, in order: --api-url, FR_DESKTOP_API_URL, %APPDATA%\\Fabulous Remote\\config.json
({"api_url": "..."}, written by the installer), then http://127.0.0.1:8765. Only https, or
http to this computer, is accepted.

--preview-device-states shows the "This device" states with SAMPLE data (clearly labelled
PREVIEW) because the server has no device registration API yet. It never contacts the
server for device data and is off by default.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from fabremote.api_client import ApiClient
from fabremote.device import PREVIEW_MODES, PreviewDeviceGateway
from fabremote.ui.login_dialog import LoginDialog
from fabremote.ui.main_window import MainWindow
from fabremote.ui.theme import STYLESHEET, logo_icon

DEFAULT_API_URL = "http://127.0.0.1:8765"


def config_path() -> Path:
    return Path(os.environ.get("APPDATA", Path.home())) / "Fabulous Remote" / "config.json"


def configured_api_url(path: Path | None = None) -> str:
    """Server address: FR_DESKTOP_API_URL, else the per-user config file (written by the installer), else local."""
    if os.environ.get("FR_DESKTOP_API_URL"):
        return os.environ["FR_DESKTOP_API_URL"]
    try:
        value = json.loads((path or config_path()).read_text(encoding="utf-8")).get("api_url")
    except (OSError, ValueError, AttributeError):
        value = None
    return value if isinstance(value, str) and value.strip() else DEFAULT_API_URL


class Controller:
    """Login → main window → (sign out) → login again, until the user cancels."""

    def __init__(self, app: QApplication, client: ApiClient, preview_mode: str | None = None):
        self._app = app
        self._client = client
        self._preview_mode = preview_mode
        self.window: MainWindow | None = None

    def start(self) -> bool:
        dialog = LoginDialog(self._client)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            self._app.quit()
            return False
        gateway = PreviewDeviceGateway(self._preview_mode) if self._preview_mode else None
        self.window = MainWindow(self._client, dialog.user, device_gateway=gateway)
        self.window.signed_out.connect(self._signed_out)
        self.window.show()
        return True

    def _signed_out(self) -> None:
        # Hide (not close) first, so Qt does not quit while the login dialog is opening.
        old, self.window = self.window, None
        if old:
            old.hide()
        self.start()
        if old:
            old.deleteLater()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fabremote")
    parser.add_argument("--api-url", default=None, help="server address (overrides the config file)")
    parser.add_argument("--preview-device-states", choices=PREVIEW_MODES, metavar="{" + ",".join(PREVIEW_MODES) + "}",
                        help="show the This-device states with labelled sample data (no device API yet)")
    args = parser.parse_args(argv)

    app = QApplication(sys.argv[:1])
    app.setApplicationName("Fabulous Remote")
    app.setWindowIcon(logo_icon())
    app.setStyleSheet(STYLESHEET)
    try:
        client = ApiClient(args.api_url or configured_api_url())
    except ValueError as exc:
        QMessageBox.critical(None, "Fabulous Remote", str(exc))
        return 2
    app.setQuitOnLastWindowClosed(True)
    controller = Controller(app, client, args.preview_device_states)
    if not controller.start():
        client.close()
        return 0
    code = app.exec()
    client.logout()
    client.close()
    return code


if __name__ == "__main__":
    sys.exit(main())
