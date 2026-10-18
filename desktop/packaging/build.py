"""Build the Windows installer for the desktop client.

    .venv\\Scripts\\python.exe desktop\\packaging\\build.py

Steps: icon (rendered from the logo) -> version resource -> PyInstaller one-folder build
(dist\\desktop\\FabulousRemote\\) -> Inno Setup installer (dist\\installer\\) -> publish to the
landing page (web\\site\\downloads\\ + latest.json; skip with --no-publish). The output is
NOT code-signed; Windows SmartScreen will warn until a signing certificate is used.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

PACKAGING = Path(__file__).resolve().parent
DESKTOP = PACKAGING.parent
ROOT = DESKTOP.parent
BUILD = ROOT / "build" / "desktop"
DIST = ROOT / "dist"
SITE_DOWNLOADS = ROOT / "web" / "site" / "downloads"
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
ISCC_CANDIDATES = (
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
    Path(os.environ.get("ProgramFiles(x86)", "")) / "Inno Setup 6" / "ISCC.exe",
    Path(os.environ.get("ProgramFiles", "")) / "Inno Setup 6" / "ISCC.exe",
)


def app_version() -> str:
    text = (DESKTOP / "fabremote" / "__init__.py").read_text(encoding="utf-8")
    full = re.search(r'__version__ = "([^"]+)"', text).group(1)
    return re.match(r"\d+\.\d+\.\d+", full).group(0)          # 0.4.0.dev0 -> 0.4.0


def build_icon(target: Path) -> None:
    """Render the SVG logo at several sizes and pack the PNGs into one .ico file."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
    from PySide6.QtGui import QGuiApplication, QImage, QPainter
    from PySide6.QtSvg import QSvgRenderer

    app = QGuiApplication.instance() or QGuiApplication([])  # noqa: F841
    renderer = QSvgRenderer(QByteArray((DESKTOP / "fabremote" / "assets" / "logo.svg").read_bytes()))
    images = []
    for size in ICO_SIZES:
        image = QImage(size, size, QImage.Format.Format_ARGB32)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        renderer.render(painter)
        painter.end()
        buffer = QBuffer()
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        image.save(buffer, "PNG")
        images.append((size, bytes(buffer.data())))
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, png in images:
        dim = 0 if size == 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(blobs))
        blobs += png
    target.write_bytes(header + entries + blobs)


def write_version_resource(target: Path, version: str) -> None:
    major, minor, patch = (int(p) for p in version.split("."))
    target.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({major}, {minor}, {patch}, 0), prodvers=({major}, {minor}, {patch}, 0),
                    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Fabulous Remote'),
      StringStruct('FileDescription', 'Fabulous Remote (Preview)'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'FabulousRemote'),
      StringStruct('OriginalFilename', 'FabulousRemote.exe'),
      StringStruct('ProductName', 'Fabulous Remote'),
      StringStruct('ProductVersion', '{version}-preview')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")


def publish_to_site(installer: Path, version: str, downloads: Path = SITE_DOWNLOADS) -> dict:
    """Copy the installer next to the landing page and describe it in latest.json.

    The page enables its Download button only when this manifest is present and valid, so a
    checkout without a published build keeps saying "not yet available". Older installers
    are removed so only one version is offered.
    """
    downloads.mkdir(parents=True, exist_ok=True)
    for old in downloads.glob("FabulousRemote-Setup-*.exe"):
        if old.name != installer.name:
            old.unlink()
    target = downloads / installer.name
    shutil.copyfile(installer, target)
    manifest = {
        "product": "Fabulous Remote", "version": version, "channel": "preview", "file": installer.name,
        "size_bytes": target.stat().st_size, "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "signed": False, "requirements": "Windows 10 or 11, 64-bit",
        "published_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    (downloads / "latest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def option(name: str) -> str | None:
    """Value of `--name value` or `--name=value` from the command line."""
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg == name and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1]
    return None


def valid_server(url: str) -> bool:
    """Same rule as the installer and the app: https, or http only to this computer."""
    lower = url.strip().lower()
    return (lower.startswith("https://") or lower.startswith(("http://127.0.0.1", "http://localhost")))         and '"' not in url and " " not in url.strip()


def run(cmd: list[str]) -> None:
    print(">", " ".join(f'"{c}"' if " " in c else c for c in cmd), flush=True)
    subprocess.run(cmd, check=True)


def main() -> int:
    version = app_version()
    default_server = option("--default-server") or "http://127.0.0.1:8765"
    if not valid_server(default_server):
        print("--default-server must be https:// (http:// only for 127.0.0.1/localhost)", file=sys.stderr)
        return 2
    shutil.rmtree(BUILD, ignore_errors=True)
    shutil.rmtree(DIST / "desktop", ignore_errors=True)
    BUILD.mkdir(parents=True, exist_ok=True)

    build_icon(BUILD / "FabulousRemote.ico")
    write_version_resource(BUILD / "version_info.txt", version)

    run([sys.executable, "-m", "PyInstaller", str(PACKAGING / "fabremote.spec"), "--noconfirm", "--clean",
         "--distpath", str(DIST / "desktop"), "--workpath", str(BUILD / "pyinstaller")])
    exe = DIST / "desktop" / "FabulousRemote" / "FabulousRemote.exe"
    if not exe.is_file():
        print("PyInstaller did not produce FabulousRemote.exe", file=sys.stderr)
        return 1
    # The work folder holds a half-built FabulousRemote.exe that cannot run on its own
    # (no _internal folder). Remove it so only the real outputs in dist\ remain.
    shutil.rmtree(BUILD / "pyinstaller", ignore_errors=True)

    iscc = next((p for p in ISCC_CANDIDATES if p.is_file()), None)
    if iscc is None:
        print("Inno Setup 6 not found: the one-folder build is in dist\\desktop\\FabulousRemote (no installer).")
        return 0
    run([str(iscc), "/Q", f"/DAppVersion={version}", f"/DRepoRoot={ROOT}", f"/DDefaultServer={default_server}",
         str(PACKAGING / "FabulousRemote.iss")])

    installer = DIST / "installer" / f"FabulousRemote-Setup-{version}-preview.exe"
    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    size_mb = installer.stat().st_size / 1_048_576
    print(f"\nInstaller: {installer}\nSize:      {size_mb:.1f} MB\nSHA-256:   {digest}")
    print(f"Portable:  {exe}  (run this one; build\\ only holds temporary files)")
    print("Not code-signed: Windows SmartScreen will show a warning.")
    print(f"Default server in the installer: {default_server}")
    if default_server != "http://127.0.0.1:8765":
        print("Note: this installer contains that address. The repository is public and web/site/downloads is "
              "committed; consider --no-publish for builds with internal addresses.")
    if "--no-publish" not in sys.argv[1:]:
        manifest = publish_to_site(installer, version)
        print(f"Published: {SITE_DOWNLOADS / manifest['file']}  -> landing page Download button "
              f"(http://127.0.0.1:8765/#download while run_server.py is running)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
