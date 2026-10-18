# Changelog

All notable changes to this project are documented here. The project is in **preview**; versions follow the desktop client (`0.x`) until the first release.

## [Unreleased]

### Added — Phase 3d: device registration
- Device registration with Ed25519 proof of possession: single-use challenges bound to the user, the login session and the proposed public key.
- Server-assigned 9-digit Remote IDs from a cryptographically secure generator, with a permanent registry so an ID is **never reused**, even after revocation.
- Verified presence: signed heartbeats with server-computed expiry; revoked or unverified devices never appear online.
- Key rotation (signed by the old and the new key) and revocation (keys and bound sessions).
- Migration `V0008` (`remote_id_registry`, `device_registration_challenges`) with rollback, and updated runtime grants (`P002`).
- Desktop: real registration in the "This device" card; DPAPI-protected device key; duplicate-free retry after a lost response.

### Added — tooling
- Windows installer (PyInstaller + Inno Setup): per-user, no service or auto-start, asks for the server address; published to the landing page download section with its SHA-256.
- One-file launchers: `run_all.py`, `run_server.py`, `run_desktop.py`, `build_installer.py`.

## [0.4.0-preview] — Desktop preview

### Added
- PySide6 desktop client: sign-in, account, live server status, sign-out, and a "This device" card with six states, accessibility support and a clearly labelled preview mode.
- Landing page with honest "In development" / "Planned" labels and a strict Content-Security-Policy.

## Phase 3c — Authentication

### Added
- Invitation-only accounts, Argon2id hashing, password policy, DB-backed lockout and rate limits.
- Desktop access tokens (10 minutes) and rotating refresh tokens with reuse detection; browser cookie sessions (`__Host-` cookie) with CSRF and login-CSRF protection.
- Admin invitations and a bootstrap CLI that refuses non-local databases unless explicitly confirmed.

## Phases 3a–3b — Backend foundation and data layer

### Added
- FastAPI application factory, environment-validated configuration, structured logging with secret redaction, health and readiness probes, uniform error envelope, security headers.
- SQLAlchemy 2.x models, repositories, unit of work, database error translation and a model-drift test.

## Phase 2 — Database

### Added
- Schema `fr` with migrations `V0001`–`V0007` and rollbacks, least-privilege roles (`fr_migrator`, `fr_app_runtime`, `fr_maintenance`), append-only audit events and a retention procedure.
- Read-only database inventory tool.

### Fixed
- Session/approval invariants, status/reason consistency, case-insensitive check constraints and a nullable foreign-key column found during the safety review.

## Phase 1 — Architecture
- Architecture, security requirements and threat model, feature status, configuration template.
