"""Visual theme (brand tokens from the design mockup) and line icons."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

ASSETS = Path(__file__).resolve().parents[1] / "assets"

NAVY = "#13213f"
NAVY_2 = "#1d2d52"
CORAL = "#f0453a"
CORAL_DARK = "#d63429"
INK = "#0f1b33"
MUTED = "#55617a"
LINE = "#dfe5ef"
BG = "#f4f7fc"
OK = "#1f9d55"

STYLESHEET = f"""
* {{ font-family: "Segoe UI", Arial, sans-serif; color: {INK}; }}
QMainWindow, QDialog, #content {{ background: {BG}; }}
#sidebar {{ background: {NAVY}; }}
#sidebar QLabel#brand {{ color: #ffffff; font-size: 15px; font-weight: 700; }}
#sidebar QPushButton {{ color: #c9d3e6; background: transparent; border: none; text-align: left;
    padding: 11px 18px; font-size: 13px; border-left: 4px solid transparent; }}
#sidebar QPushButton:hover {{ background: {NAVY_2}; color: #ffffff; }}
#sidebar QPushButton:checked {{ background: {NAVY_2}; color: #ffffff; font-weight: 600; border-left: 4px solid {CORAL}; }}
#sidebar QFrame#divider {{ background: #2a3a5f; max-height: 1px; margin: 10px 18px; }}
QLabel#title {{ font-size: 26px; font-weight: 800; color: {NAVY}; }}
QLabel#subtitle, QLabel#muted {{ color: {MUTED}; font-size: 13px; }}
QLabel#section {{ font-size: 15px; font-weight: 700; color: {NAVY}; }}
QLabel#remoteId {{ font-size: 24px; font-weight: 700; color: {MUTED}; }}
QLabel#remoteIdValue {{ font-size: 26px; font-weight: 700; color: {NAVY}; letter-spacing: 1px; }}
QLabel#badgeOk, QLabel#badgeWarn, QLabel#badgeError, QLabel#badgeNeutral {{ border-radius: 10px; padding: 2px 10px;
    font-size: 12px; font-weight: 600; }}
QLabel#badgeOk {{ background: #e6f6ed; color: #146c3c; }}
QLabel#badgeWarn {{ background: #fff1e0; color: #8a4b00; }}
QLabel#badgeError {{ background: #fdeaea; color: #b42318; }}
QLabel#badgeNeutral {{ background: #eef1f7; color: #4b587a; }}
QLabel#previewBadge {{ background: {CORAL}; color: #ffffff; border-radius: 10px; padding: 2px 10px; font-size: 11px;
    font-weight: 700; }}
QProgressBar {{ background: #e6ecf6; border: none; border-radius: 2px; }}
QProgressBar::chunk {{ background: {CORAL}; border-radius: 2px; }}
QLabel#hint {{ color: {MUTED}; font-size: 12px; }}
QLabel#hintOk {{ color: {OK}; font-size: 12px; }}
QLabel#error {{ color: {CORAL_DARK}; font-size: 12px; }}
QLabel#notice {{ background: #fff4e5; color: #8a4b00; border: 1px solid #ffd8a8; border-radius: 8px; padding: 10px 12px; }}
QLabel#warning {{ background: #fff4f3; border-left: 4px solid {CORAL}; padding: 12px; color: {INK}; }}
QFrame#card {{ background: #ffffff; border: 1px solid {LINE}; border-radius: 12px; }}
QFrame#sessionBanner {{ background: #e6f6ed; border: 1px solid #9fd8b5; border-radius: 10px; }}
QFrame#sessionBanner QLabel {{ color: #0f5130; }}
QLineEdit {{ background: #ffffff; border: 1px solid #c9d3e3; border-radius: 8px; padding: 10px 12px; font-size: 14px; }}
QLineEdit:focus {{ border: 1px solid #2f6bff; }}
QPushButton#primary {{ background: {CORAL}; color: #ffffff; border: none; border-radius: 8px; padding: 10px 22px;
    font-size: 14px; font-weight: 600; }}
QPushButton#primary:hover {{ background: {CORAL_DARK}; }}
QPushButton#primary:disabled {{ background: #f6b1ab; color: #ffffff; }}
QPushButton#secondary {{ background: #ffffff; color: {NAVY}; border: 1px solid #c9d3e3; border-radius: 8px;
    padding: 9px 18px; font-weight: 600; }}
QPushButton#secondary:hover {{ background: {BG}; }}
QPushButton#avatar {{ background: {NAVY}; color: #ffffff; border-radius: 17px; font-weight: 700; min-width: 34px;
    max-width: 34px; min-height: 34px; max-height: 34px; padding: 0; }}
QPushButton#avatar::menu-indicator {{ image: none; width: 0; }}
QTabWidget::pane {{ border: 1px solid {LINE}; border-radius: 10px; background: #ffffff; top: -1px; }}
QTabBar::tab {{ background: transparent; padding: 8px 16px; color: {MUTED}; font-size: 13px; border: none; }}
QTabBar::tab:selected {{ color: {NAVY}; font-weight: 600; border-bottom: 3px solid {CORAL}; }}
QMenu {{ background: #ffffff; border: 1px solid {LINE}; }}
QMenu::item {{ padding: 6px 18px; }}
QMenu::item:selected {{ background: {BG}; }}
"""

_PATHS = {
    "home": '<path d="M3 11 12 3l9 8"/><path d="M5 10v10h14V10"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "star": '<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1 6.2L12 17.3 6.5 20.2l1-6.2L3 9.6l6.2-.9z"/>',
    "book": '<path d="M5 4h11a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3z"/><path d="M5 17a3 3 0 0 1 3-3h11"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/>',
    "help": '<circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6V14"/><path d="M12 17h.01"/>',
    "monitor": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "laptop": '<rect x="5" y="5" width="14" height="10" rx="1.5"/><path d="M2 19h20l-2-4H4z"/>',
    "link": '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
}


def _render(svg: bytes, size: int) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(svg))
    pixmap = QPixmap(QSize(size, size))
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return pixmap


def icon(name: str, color: str = "#c9d3e6", size: int = 20) -> QIcon:
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" '
           f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{_PATHS[name]}</svg>').encode()
    return QIcon(_render(svg, size * 2))


def logo_pixmap(size: int = 28) -> QPixmap:
    return _render((ASSETS / "logo.svg").read_bytes(), size * 2).scaled(
        size, size, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)


def logo_icon() -> QIcon:
    return QIcon(_render((ASSETS / "logo.svg").read_bytes(), 128))
