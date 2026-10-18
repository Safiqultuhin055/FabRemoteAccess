"""Desktop tests run headless (Qt offscreen platform) and never contact a real server."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from fabremote.ui.theme import STYLESHEET  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_device_store(tmp_path, monkeypatch):
    """Device keys are written to a temporary folder, never the real %LOCALAPPDATA%."""
    monkeypatch.setenv("FR_DESKTOP_DATA_DIR", str(tmp_path / "fabremote-data"))


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(STYLESHEET)
    return app
