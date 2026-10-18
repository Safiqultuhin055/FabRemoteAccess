# Feature Status and Known Limitations

Legend: **Done** · **In progress** · **Planned** (phase) · **Out of scope** (first release)

Last updated: 2026-10-18 (Phase 3c, offline)

## Phases

| Phase | Description | Status |
|---|---|---|
| 1 | Repository inspection and architecture documentation | **Done** |
| 2 | Database design and safe migrations | **Done**; applied to a DEV environment up to version 8. Pending there: dedicated least-privilege logins (P003) |
| 3 | FastAPI backend + tests | **In progress**: 3a, 3b, 3c (authentication) and **3d (device registration, Remote IDs, verified presence, key rotation)** done offline on LocalDB; 3e–3f awaiting approval |
| 4 | PySide6 desktop client integration | **Preview** (`desktop/`): sign-in, account, live server status, sign-out; "This device" card with all registration/presence states (live: Not registered, Register disabled until Phase 3d; other states only in labelled preview mode) |
| 5 | Landing page and web portal | **Landing page done** (`web/site`, served by the backend when `FR_SITE_DIR` is set); web portal planned |
| 6 | Screen-sharing-only WebRTC proof of concept | Planned |
| 7 | Consent-controlled remote input (separate review) | Planned |
| 8 | LAN / Internet / NAT / TURN / failure-recovery testing | Planned |
| 9 | Security review and regression testing | Planned |
| 10 | Windows installer and deployment documentation | **Preview installer** for the desktop client (`desktop/packaging/`, per-user, unsigned); deployment documentation planned |

## Features

| Feature | Status |
|---|---|
| User accounts, login/logout | **API done** (3c): invitation-only accounts, desktop tokens, browser sessions, logout, `/auth/me`; no UI yet |
| Device registration and Remote ID | **Done** (3d): API + desktop "Register This Device" with DPAPI-protected key; server-assigned, never-reused IDs |
| Connection request / consent dialog / reject / timeout | Planned (3, 4) |
| Recent sessions, favorites, address book | Planned (3, 4) |
| Web portal: devices, history, revoke sessions, profile | Planned (5) |
| Landing page | **Done** (marketing page; every feature labelled In development / Planned) |
| Screen viewing (WebRTC) | Planned (6) |
| Remote mouse/keyboard | Planned (7) |
| Windows installer | **Preview** (unsigned, per-user; see `desktop/README.md`) |
| MFA | Planned (before public launch) |
| Unattended access | Out of scope |
| File transfer, clipboard sync, chat | Out of scope |
| macOS, Linux, mobile | Out of scope (roadmap) |

## Known limitations

- No prototype code existed; only branding from the design mockup is carried forward.
- `FabRemotesDB` did not exist before 2026-10-17; it was created empty on the shared DEV server and migrated (see `DATABASE_DESIGN.md` §0).
- DEV environment operational follow-ups are tracked outside this repository.
- No application logins are mapped (P003 not run), so the backend cannot yet connect to the shared database as the runtime role; it has never connected to it.
- Authentication API exists but has only been exercised on LocalDB; no portal or desktop UI uses it yet. Known gaps are listed in `SECURITY.md` §4.
- Retention periods (365 days sessions/audit, 90 days requests/IPs) are proposals pending owner/legal approval; the retention job stays disabled (`FR_RETENTION_ENABLED=false`).
- Account deletion/anonymisation is a production prerequisite and is not implemented (`DATABASE_DESIGN.md` §14).
- Remote input will not work on elevated windows or the UAC secure desktop (Windows UIPI); this is intentional until a privileged component is separately reviewed.
- Python WebRTC performance at high resolutions unverified (measured in Phase 6).
- Internet use requires a public HTTPS endpoint and TURN server, not yet decided.
