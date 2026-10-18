"""Start everything for local development: API + landing page, browser, desktop client.

    .venv\\Scripts\\python.exe run_all.py          (or the IDE "Run" button on this file)

1. Starts run_server.py (LocalDB only, never the shared server) unless it is already running.
2. Opens the landing page in the default browser.
3. Opens the desktop client. Closing it stops the server again (if this script started it).
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
URL = "http://127.0.0.1:8765"


def server_ready(timeout: float = 1.0) -> bool:
    try:
        with urllib.request.urlopen(f"{URL}/health/live", timeout=timeout) as response:
            return json.load(response).get("status") == "ok"
    except (urllib.error.URLError, OSError, ValueError):
        return False


def wait_until_ready(process: subprocess.Popen | None, seconds: float = 30) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if server_ready():
            return True
        if process is not None and process.poll() is not None:   # server exited early
            return False
        time.sleep(0.3)
    return False


def main() -> int:
    server = None
    if server_ready():
        print(f"Server already running at {URL}/ (reusing it).")
    else:
        print("Starting server (API + landing page, LocalDB)…")
        server = subprocess.Popen([sys.executable, str(ROOT / "run_server.py")], cwd=ROOT)
        if not wait_until_ready(server):
            print("The server did not start. Check the messages above (is LocalDB running?).")
            if server.poll() is None:
                server.terminate()
            return 1
    print(f"Landing page: {URL}/    API docs: {URL}/docs")
    webbrowser.open(f"{URL}/")

    print("Opening the desktop client… (close it to stop everything)")
    try:
        desktop = subprocess.run([sys.executable, str(ROOT / "run_desktop.py"), *sys.argv[1:]], cwd=ROOT)
        return desktop.returncode
    except KeyboardInterrupt:
        return 0
    finally:
        if server is not None and server.poll() is None:
            print("Stopping server…")
            server.terminate()
            try:
                server.wait(10)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    sys.exit(main())
