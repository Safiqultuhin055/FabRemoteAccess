# Phase 1 — Repository and Environment Audit

Date: 2026-10-17
Scope: inspection and architecture documentation only. No application code, no database changes, no remote-access functionality.

## 1. Repository findings

| Item | Finding |
|---|---|
| Project directory | `E:\Python Project\FabRemoteAccess` existed but was **empty**. |
| `main.py`, `requirements.txt`, `index.html`, `styles.css`, `app.js` | **Not present.** There is no prototype code to preserve. |
| Version control | Directory is **not a Git repository**. |
| Branding reference | Only the design mockup supplied with the brief (desktop client, landing page, web portal). It is used as the visual reference for later phases. |

Consequence: "preserve the working prototype" currently applies to branding only. If a prototype exists elsewhere (another folder, machine or repository), it should be copied in **before Phase 2** so it can be reviewed rather than replaced.

### Notes on the design mockup

The mockup is the branding source of truth (navy sidebar, coral/red primary action colour, double-chevron logo, 9-digit Remote ID formatted `105 280 964`). Several things in it must **not** be reproduced as static UI:

- "Secure connection" and "Ready to connect" must reflect real state (authenticated WSS presence, verified transport), never be shown by default.
- Device status differs between the desktop and portal mock-ups (e.g. "Factory Computer" is Offline in one and Online in the other). Real UI must take status from server presence only.
- Recent sessions show device IP addresses. IPs are personal data; they are stored with a retention limit and shown only to the device owner (see `SECURITY.md`).
- The footer "Cross-platform roadmap" wording is correct: only Windows is planned for the first release, and the landing page must label macOS/Linux/mobile as planned.

## 2. Development environment

| Component | Finding | Action |
|---|---|---|
| OS | Windows 11 Pro 22631 | — |
| Python | 3.12 (`E:\Python\python.exe`) and 3.14 (user install). `python` is **not on PATH** (Store alias intercepts it). | Use `py -3.12`. 3.12 has the most mature wheel support for PySide6, aiortc/PyAV, pyodbc and PyInstaller. |
| Git | 2.54 | Initialise the repository before Phase 2. |
| Node.js | 24.19 | Only needed for browser tests (Playwright) — no Node build step for the website. |
| ODBC drivers | ODBC Driver 17 and **18** for SQL Server, legacy Native Client 11 | Use **ODBC Driver 18** (encryption on by default). Do not use Native Client 11 (deprecated, no modern TLS). |
| SQL Server reachability | TCP 1433 on the shared SQL Server host **reachable** from this workstation (TCP test only; no login attempted). | — |
| SQL credentials | **Not available** in the workspace (no `.env`). | Developer to create an untracked `.env` from `.env.example`. |

## 3. Database status

The database `FabRemotesDB` has **not** been inspected: no credentials were provided, and none were requested in chat on purpose.

Before Phase 2 designs any table, run the read-only inspection tool:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install pyodbc
copy .env.example .env    # then fill FR_DB_USER / FR_DB_PASSWORD locally
python tools\inspect_db_schema.py --out docs\db_inventory.md
```

The tool only issues `SELECT` statements against catalog views, opens the connection read-only and rolls back, never reads table rows, and never prints the password. It also reports whether the login is `sysadmin`/`db_owner`, so we can confirm a least-privilege account is in use. Review `docs\db_inventory.md` before committing it — table names may themselves be sensitive.

## 4. Risks and decisions needed before Phase 2

| # | Topic | Detail | Proposed default |
|---|---|---|---|
| 1 | Least-privilege DB login | `sa` must not be used. Need two logins: a **migration** login (DDL on schema `fr` only) and an **application** login (DML on schema `fr` only). | Phase 2 delivers a DBA script for both; DBA runs it. |
| 2 | Coexistence with existing objects | `FabRemotesDB` may already hold tables. | All new objects go in a dedicated schema **`fr`**. Nothing outside it is touched. |
| 3 | SQL Server TLS certificate | Likely self-signed. `TrustServerCertificate=yes` is acceptable only for local development. | Install a certificate trusted by app hosts before any non-dev deployment. |
| 4 | Who may request a session | AnyDesk model (any authenticated user, target consents) vs. organisation/address-book-only. | Any **verified, authenticated** user may request; target consent always required; target can restrict to "address book only". |
| 5 | Account creation | Self-registration vs. admin invite. | Admin invite for the pilot; self-registration later. |
| 6 | Hosting | Internet use needs a public HTTPS endpoint for the API/signalling and a public TURN server. The database host stays private. | Decide hosting before Phase 8; Phases 2–7 run on LAN. |
| 7 | Python WebRTC performance | aiortc encodes in software; 1080p frame rate may be limited. | Measure in Phase 6; fallback options listed in `ARCHITECTURE.md` §8. |
| 8 | Code signing | Unsigned installers trigger SmartScreen and are easy to tamper with. | Obtain a code-signing certificate before Phase 10. |

## 5. Deliverables of this phase

- `README.md` — project overview and local setup basics
- `docs/PHASE1_AUDIT.md` — this report
- `docs/ARCHITECTURE.md` — target architecture, flows, API outline, data model outline, repository layout
- `docs/SECURITY.md` — security requirements and initial threat model
- `docs/FEATURE_STATUS.md` — feature status and known limitations
- `.env.example` — configuration template, no secrets
- `.gitignore` — excludes `.env`, virtualenvs, build output, local inventories
- `tools/inspect_db_schema.py` — read-only database inventory tool
