"""Administrative command line.

    python -m app.cli bootstrap-admin --email admin@example.com [--expires-hours 24]

Creates the first administrator invitation. Refuses when an administrator already exists
or another bootstrap invitation is open. The invitation link (or token) is printed once to
stdout and never logged or stored.

Safety: configuration comes from FR_* variables / .env in the current directory, with the
usual validation (`sa` is rejected). A non-local database is refused unless
`--allow-remote-database` is given, and that check happens before any connection is made.
"""

from __future__ import annotations

import argparse
import sys

from pydantic import ValidationError

from app.config import Settings
from app.db.engine import Database
from app.domain.errors import ConflictError, DomainError
from app.security.clock import Clock
from app.security.passwords import PasswordHasher
from app.services.context import RequestContext
from app.services.invitations import InvitationService

EXIT_OK, EXIT_REFUSED, EXIT_CONFIG = 0, 1, 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    boot = sub.add_parser("bootstrap-admin", help="create the first administrator invitation")
    boot.add_argument("--email", required=True)
    boot.add_argument("--expires-hours", type=int, default=24, choices=range(1, 73), metavar="1-72")
    boot.add_argument("--allow-remote-database", action="store_true",
                      help="required to target a non-local database server")
    return parser


def main(argv: list[str] | None = None, *, settings: Settings | None = None, database: Database | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        settings = settings or Settings()
    except ValidationError as exc:
        fields = ", ".join(".".join(str(p) for p in e["loc"]) or e["msg"] for e in exc.errors())
        print(f"Configuration rejected: {fields}", file=sys.stderr)
        return EXIT_CONFIG
    if not settings.db_configured:
        print("Database is not configured (FR_DB_HOST is empty).", file=sys.stderr)
        return EXIT_CONFIG
    if not settings.db_is_local and not args.allow_remote_database:
        print(f"Refusing to use {settings.describe_database()}: pass --allow-remote-database to confirm.",
              file=sys.stderr)
        return EXIT_CONFIG

    email = args.email.strip().lower()
    if "@" not in email or len(email) > 320:
        print("Invalid email address.", file=sys.stderr)
        return EXIT_CONFIG

    database = database or Database(settings)
    try:
        service = InvitationService(database.unit_of_work, PasswordHasher(), Clock())
        issued = service.bootstrap(email, args.expires_hours, RequestContext(request_id="cli-bootstrap"))
    except ConflictError as exc:
        print(f"Refused: {exc.message} ({exc.code})", file=sys.stderr)
        return EXIT_REFUSED
    except DomainError as exc:
        print(f"Failed: {exc.message} ({exc.code})", file=sys.stderr)
        return EXIT_REFUSED
    finally:
        database.dispose()

    print(f"Bootstrap invitation created for {email}; expires {issued.invitation.expires_at.isoformat()}.")
    if settings.public_base_url:
        print(f"Invitation link (shown once): {settings.public_base_url.rstrip('/')}"
              f"/portal/accept-invitation#token={issued.token}")
    else:
        print(f"Invitation token (shown once): {issued.token}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
