"""Build the Windows installer for the desktop client.

    .venv\\Scripts\\python.exe build_installer.py      (or the IDE "Run" button on this file)

Output:
    dist\\installer\\FabulousRemote-Setup-<version>-preview.exe   installer to share
    dist\\desktop\\FabulousRemote\\FabulousRemote.exe              portable app (no install)

Needs PyInstaller (requirements-dev.txt) and Inno Setup 6. See desktop/README.md.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    build_script = Path(__file__).resolve().parent / "desktop" / "packaging" / "build.py"
    sys.argv = [str(build_script), *sys.argv[1:]]
    runpy.run_path(str(build_script), run_name="__main__")
