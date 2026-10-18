"""Production launcher: the Fabulous Remote API and landing page over HTTPS.

    python deploy/server/run_production.py --env-file deploy/server/.env --port 300

Configuration comes from FR_* environment variables and the given .env file (see
.env.production.example). Refuses to start without TLS files or in development/test mode,
and applies all of the backend's configuration safety checks (no `sa`, a strong signing
key, verified database TLS for a remote database, ...).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from pydantic import ValidationError  # noqa: E402

from app.config import Environment, Settings  # noqa: E402

CERTS = Path(__file__).resolve().parent / "certs"


def load_settings(env_file: Path | None) -> Settings:
    return Settings(_env_file=env_file) if env_file else Settings()


def check(settings: Settings, cert: Path, key: Path) -> list[str]:
    problems = []
    if settings.env in (Environment.DEVELOPMENT, Environment.TEST):
        problems.append("FR_ENV must be staging or production (use run_server.py for development)")
    for label, path in (("certificate", cert), ("private key", key)):
        if not path.is_file():
            problems.append(f"TLS {label} not found: {path} (create it with make_internal_ca.py)")
    if not settings.db_configured:
        problems.append("FR_DB_HOST is not set")
    if settings.public_base_url and not settings.public_base_url.startswith("https://"):
        problems.append("FR_PUBLIC_BASE_URL must be the https:// address of this server")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env-file", type=Path, default=None)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=300)
    parser.add_argument("--cert", type=Path, default=CERTS / "server.crt")
    parser.add_argument("--key", type=Path, default=CERTS / "server.key")
    args = parser.parse_args(argv)

    try:
        settings = load_settings(args.env_file)
    except ValidationError as exc:
        fields = ", ".join(".".join(str(p) for p in e["loc"]) or e["msg"] for e in exc.errors())
        print(f"Configuration rejected: {fields}", file=sys.stderr)
        return 2
    problems = check(settings, args.cert, args.key)
    if problems:
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 2

    import uvicorn

    from app.main import create_app

    print(f"Fabulous Remote API ({settings.env.value}) on https://{args.host}:{args.port}/ — "
          f"database: {settings.describe_database()}")
    uvicorn.run(create_app(settings), host=args.host, port=args.port, ssl_certfile=str(args.cert),
                ssl_keyfile=str(args.key), access_log=False, server_header=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
