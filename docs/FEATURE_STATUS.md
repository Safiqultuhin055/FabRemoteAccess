# Feature Status and Known Limitations

Legend: **Done** · **In progress** · **Planned** (phase) · **Out of scope** (first release)

Last updated: 2026-10-18 (Phase 3e, offline on LocalDB)

## Phases

| Phase | Description | Status |
|---|---|---|
| 1 | Repository inspection and architecture documentation | **Done** |
| 2 | Database design and safe migrations | **Done**; V0001–V0009 written. DEV environment at version 8: **V0009 not applied there yet** (needs approval); dedicated least-privilege logins (P003) pending |
| 3 | FastAPI backend + tests | **In progress**: 3a–3d and **3e (computers without an account, device tokens, connection requests, consent, sessions)** done offline on LocalDB; 3f (audit API, security review) planned |
| 4 | PySide6 desktop client integration | **Preview** (`desktop/`): opens without signing in; registers this computer without an account; Connect (signed in) → consent dialog on the other computer → session banner on both sides with Disconnect |
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
| Device registration and Remote ID | **Done** (3d, 3e): with or without an account; DPAPI-protected key; server-assigned, never-reused IDs |
| Connection request / consent dialog / reject / block / timeout | **Done** (3e): helper signs in; the helped computer needs no account and must Accept every request; sessions end on Disconnect or when either side goes silent |
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
- Internet use requires a public HTTPS endpoint (for requests and consent) and, from Phase 6, a TURN server; neither is decided yet.
- A session confirms consent only: there is no screen sharing or input yet (Phase 6/7). Requests and sessions are polled every 2 s; the presence WebSocket is planned.
- Registering a computer without an account is open to anyone who can reach the server (rate-limited per IP); see `SECURITY.md` §4.
