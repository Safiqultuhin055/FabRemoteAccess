# PyInstaller spec for the Fabulous Remote desktop client (one-folder build).
# Built by desktop/packaging/build.py, which supplies the icon and version resource.
# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

PACKAGING = Path(SPECPATH)
DESKTOP = PACKAGING.parent
BUILD = Path(DISTPATH).parent.parent / "build" / "desktop"

a = Analysis(
    [str(PACKAGING / "entry.py")],
    pathex=[str(DESKTOP)],
    datas=[(str(DESKTOP / "fabremote" / "assets"), "fabremote/assets")],
    hiddenimports=["PySide6.QtSvg"],
    excludes=["tkinter", "unittest", "pytest", "fastapi", "sqlalchemy", "pyodbc", "uvicorn", "app"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="FabulousRemote",
    console=False,                       # GUI application, no console window
    icon=str(BUILD / "FabulousRemote.ico"),
    version=str(BUILD / "version_info.txt"),
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="FabulousRemote", upx=False)
