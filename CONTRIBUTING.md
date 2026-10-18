# Contributing to Fabulous Remote

Thank you for helping. This is remote-access software, so a few rules are stricter than usual. Please read them before opening a pull request.

## Ground rules

1. **Consent and visibility are non-negotiable.** Do not add hidden, unattended or "stealth" access, persistence mechanisms, or anything that bypasses the target user's approval.
2. **Never commit secrets.** No passwords, tokens, keys, connection strings or internal host names in code, tests, docs or commit messages. `.env` is git-ignored; use `.env.example` for new setting names (with empty values for secrets).
3. **Tests never touch shared databases.** Use the private LocalDB instance. The test fixtures refuse any non-LocalDB server; do not weaken that guard.
4. **Do not weaken safety checks to make something pass** (configuration validation, CSRF, rate limits, database permissions, Content-Security-Policy).
5. **Never edit an applied migration.** Add a new `V000N__*.sql` with a matching rollback `R000N__*.sql`, and update `P002` if the runtime role needs access.

## Development setup

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
sqllocaldb create FabRemoteTest -s
python -m pytest
```

See the [README](README.md#getting-started) for running the server and the desktop app.

## Workflow

1. Create a branch from `main`: `feature/<short-name>` or `fix/<short-name>`.
2. Make small, focused changes that follow the existing architecture (routers → services → repository interfaces → SQLAlchemy).
3. Add or update tests with every change. Security-relevant behaviour needs a test that proves it, including the failure case.
4. Run the **complete** suite (`python -m pytest`), not only the new tests.
5. Update the relevant documentation (`docs/`, component READMEs, `CHANGELOG.md`).
6. Open a pull request describing what changed, why, how it was tested, and any security impact.

## Conventions

| Topic | Convention |
|---|---|
| Python | 3.12, type hints, `from __future__ import annotations`, f-strings |
| Time | Timezone-aware UTC only (`datetime.now(UTC)`); naive datetimes are rejected by the data layer |
| Errors | Raise domain errors (`app/domain/errors.py`); the API maps them to the JSON error envelope. Never return exception text to clients |
| Database | SQL migrations are the source of truth; models never create tables. Constraint names follow `PK_/FK_/UQ_/CK_/DF_<table>_…` |
| Shared values | Enums and limits live in `backend/app/domain/constants.py` and are tested against the database |
| Logging | Use `logging` with `extra={...}`; never log passwords, tokens, cookies, keys or signatures |
| Commits | Imperative subject line (≤ 72 characters), body explaining *why* |

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).
