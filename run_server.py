"""Development launcher: API + landing page on the private LocalDB database.

    .venv\\Scripts\\python.exe run_server.py        (or the IDE "Run" button on this file)

Safety: every .env file is ignored and the database is fixed to the local LocalDB
instance, so this launcher can never reach the shared server. Development only.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))

import uvicorn  # noqa: E402

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

HOST, PORT = "127.0.0.1", 8765


def dev_settings() -> Settings:
    # Explicit values win over FR_* environment variables, and no .env file is read.
    return Settings(_env_file=None, env="development", db_host=r"(localdb)\FabRemoteTest",
                    db_name="FabRemotesDB_dev", db_user=None, db_password=None, db_encrypt="optional",
                    log_format="text", site_dir=str(ROOT / "web" / "site"))


def port_in_use(host: str = HOST, port: int = PORT) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def main() -> int:
    if port_in_use():
        print(f"Port {PORT} is already in use: the server is probably already running at http://{HOST}:{PORT}/")
        print("Stop the other server (Ctrl+C in its window) or just use the running one.")
        return 1
    print(f"Fabulous Remote API (development, LocalDB) -> http://{HOST}:{PORT}/   Docs: http://{HOST}:{PORT}/docs")
    print("Press Ctrl+C to stop.")
    uvicorn.run(create_app(dev_settings()), host=HOST, port=PORT, access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
