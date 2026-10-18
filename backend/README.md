# Fabulous Remote — Backend (Phase 3a/3b)

FastAPI service. Implemented: configuration, structured logging with redaction, health endpoints, error envelope, request middleware, the SQLAlchemy data layer, and **authentication (Phase 3c)**: invitation-only accounts, Argon2id passwords, desktop access/refresh tokens with rotation and reuse detection, browser cookie sessions with CSRF protection, rate limits, admin invitations and a bootstrap CLI, and **device registration (Phase 3d)**: Ed25519 proof of possession, server-assigned never-reused Remote IDs, verified presence heartbeats, key rotation and revocation (`/api/v1/devices`, see `docs/API_CONTRACTS.md` §5.3). Connection requests are not implemented yet.

Contracts: [docs/API_CONTRACTS.md](../docs/API_CONTRACTS.md). Schema: [docs/DATABASE_DESIGN.md](../docs/DATABASE_DESIGN.md) (draft until the shared-database inventory is reviewed).

## Layout

| Path | Purpose |
|---|---|
| `app/main.py` | `create_app()` factory: middleware, error handlers, routers, lifespan |
| `app/config.py` | `Settings` (FR_* variables / `.env`), safety validation |
| `app/log.py` | JSON/text logging, `RedactionFilter`, request-ID context |
| `app/api/` | `health.py`, `errors.py` (envelope), `middleware.py`, `deps.py` (DI), `v1/` (versioned router) |
| `app/db/` | `engine.py` (lazy engine, readiness), `models.py`, `repositories.py`, `unit_of_work.py`, `errors.py`, `column_types.py` |
| `app/domain/` | `constants.py` (shared with DB tests), `errors.py`, `repositories.py` (interfaces) |
| `app/security/` | `passwords.py` (Argon2id, policy), `tokens.py` (JWT + opaque tokens), `csrf.py`, `rate_limit.py`, `clock.py`, `device_proof.py` (Ed25519 messages) |
| `app/services/` | `auth.py` (login, refresh, logout, authentication), `invitations.py`, `devices.py` (registration, Remote IDs, presence, rotation), `context.py` |
| `app/api/auth_deps.py`, `app/api/v1/` | bearer/cookie authentication, CSRF, rate limits; `auth.py`, `admin_invitations.py`, `devices.py`, `schemas.py` |
| `app/cli.py` | `bootstrap-admin` |
| `tests/unit/` | No database |
| `tests/integration/` | Private LocalDB scratch databases only |

## Setup

```powershell
cd "E:\Python Project\FabRemoteAccess"
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
sqllocaldb create FabRemoteTest -s     # once; private test instance
python -m pytest                       # all suites (database, tools, backend)
python -m pytest backend/tests         # backend only
```

Tests never read `.env`. They clear `FR_*` variables and fail immediately if any code tries to connect to a server other than LocalDB or `127.0.0.1`.

## Running locally

Uvicorn reads `.env` from the **current directory**. The repository's `.env` points at the shared server, so for local runs use a separate folder with a LocalDB-only `.env`:

```powershell
mkdir $env:TEMP\fr-local -Force | Out-Null
@"
FR_ENV=development
FR_DB_HOST=(localdb)\FabRemoteTest
FR_DB_NAME=FabRemotesDB_dev
FR_DB_ENCRYPT=optional
FR_LOG_FORMAT=text
FR_SITE_DIR=E:\Python Project\FabRemoteAccess\web\site
"@ | Set-Content -Encoding utf8 $env:TEMP\fr-local\.env

# Optional: a migrated LocalDB development database
sqlcmd -S "(localdb)\FabRemoteTest" -E -b -Q "IF DB_ID('FabRemotesDB_dev') IS NULL CREATE DATABASE FabRemotesDB_dev"
sqlcmd -S "(localdb)\FabRemoteTest" -d FabRemotesDB_dev -E -b -I -i database\permissions\P001_bootstrap_schema_and_roles.sql
Get-ChildItem database\migrations\V*.sql | Sort-Object Name | ForEach-Object {
    sqlcmd -S "(localdb)\FabRemoteTest" -d FabRemotesDB_dev -E -b -I -i $_.FullName }
sqlcmd -S "(localdb)\FabRemoteTest" -d FabRemotesDB_dev -E -b -I -i database\permissions\P002_grant_runtime_permissions.sql

cd $env:TEMP\fr-local
& "E:\Python Project\FabRemoteAccess\.venv\Scripts\python.exe" -m uvicorn --factory app.main:create_app `
    --app-dir "E:\Python Project\FabRemoteAccess\backend" --host 127.0.0.1 --port 8765 --no-access-log
```

Then open `http://127.0.0.1:8765/` (landing page, when `FR_SITE_DIR` is set), `/health/live`, `/health/ready` and `/docs` (development only).

Note: in Windows PowerShell 5.1, `Set-Content -Encoding utf8` writes a byte-order mark that hides the first variable; keep a non-critical line first or save the file as UTF-8 without BOM.

`--no-access-log` matters: uvicorn's own access log includes query strings. The app writes its own access lines (method, path, status, duration, request ID) without them.

## First administrator (bootstrap)

Run against a **local** database only (the CLI refuses a remote server unless `--allow-remote-database` is passed, and `sa` is always rejected):

```powershell
cd $env:TEMP\fr-local        # folder with the LocalDB-only .env shown above
& "E:\Python Project\FabRemoteAccess\.venv\Scripts\python.exe" -m app.cli bootstrap-admin `
    --email admin@example.com
```

Run it from a folder where `backend` is importable (or set `PYTHONPATH` to `E:\Python Project\FabRemoteAccess\backend`). The token or link is printed once. Accept it with `POST /api/v1/auth/invitations/accept`, then sign in with `POST /api/v1/auth/token` (desktop) or `POST /api/v1/auth/web/login` (browser).

## Conventions

- **Configuration:** everything comes from `FR_*` variables; startup fails on unsafe values (`sa`, relaxed TLS for a remote server, `*` CORS, short signing key, missing key outside development).
- **Readiness** is reported only from a live check: `SELECT 1` plus `MAX(version)` from `fr.schema_migrations` must equal 8 (V0008, device registration). Responses never include error text, host names or version numbers.
- **Transactions:** `with database.unit_of_work() as uow: ...; uow.commit()`. Without `commit()`, or on an exception, everything rolls back.
- **Errors:** constraint violation → `ConflictError(constraint=...)` (409); stale `row_version` → `ConcurrencyError` (412); connectivity → `DependencyUnavailableError` (503); anything else → 500 `internal_error` with no details.
- **Secrets:** the ODBC connection string is passed to pyodbc through a `creator` callable (never in an SQLAlchemy URL); statement parameters are hidden from errors; logs pass through `RedactionFilter`.
- **Time:** timezone-aware UTC only; naive datetimes are rejected at bind time.
- **Schema:** the SQL migrations are authoritative; models never create tables. A drift test compares them with a migrated database.
