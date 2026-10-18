# Fabulous Remote — Security Requirements and Threat Review

Status: initial version (Phase 1). Reviewed again at the end of every phase; full review in Phase 9.

## 1. Principles

1. **Consent first.** No session starts without a visible approval on the target device. There is no code path that bypasses it in the first release.
2. **Remote ID is not a secret.** It only lets someone *ask*. Every action requires an authenticated identity plus authorisation.
3. **Always visible.** While a session is active the target shows a persistent indicator naming the viewer, and one click disconnects.
4. **Server never sees the screen.** Media is end-to-end DTLS-SRTP between peers; the backend handles signalling text only.
5. **Least privilege everywhere.** Database logins, service accounts, tokens and session permissions are scoped to the minimum.
6. **No fabricated state.** UI shows "secure", "online" or "connected" only when the underlying state has been verified.
7. **Prohibited, permanently:** stealth/hidden access, hidden persistence, credential harvesting, disabling security software, bypassing UAC or consent.

## 2. Requirements

### Authentication and sessions
- Passwords hashed with Argon2id (argon2-cffi defaults or stronger); never logged, never stored reversibly.
- Login rate limited per account and per IP, with progressive delay; generic error messages (no account enumeration).
- Access tokens ≤ 10–15 minutes. Refresh tokens opaque, stored as SHA-256 hashes, rotated on every use, reuse detection revokes the whole family.
- Logout and admin revocation take effect for refresh tokens immediately and for access tokens within their lifetime; WebSocket connections re-validate and are closed on revocation.
- Web portal: `HttpOnly; Secure; SameSite=Lax` session cookie, CSRF token on all state-changing requests, session rotation on login.
- MFA (TOTP) planned before public launch.

### Devices
- Each device holds an Ed25519 private key protected by Windows DPAPI (Credential Manager). Device authentication is a signed server challenge.
- Device owners can rename, revoke and remove devices from the portal; revocation closes presence and active sessions.

### Connection requests and consent
- Requester must be an authenticated user with a verified email.
- Rate limits: requests per user per minute, concurrent pending requests per user, and requests per target device; repeated rejections trigger a cooldown for that requester/target pair.
- Responses to unknown/offline Remote IDs are uniform to slow enumeration.
- Consent dialog shows: requester display name and email, whether verified, requesting device name, requested permissions (view only / view + input), a countdown, and a warning: *"Only accept if you know this person. Never accept a request from someone who contacted you unexpectedly claiming to be support."*
- Default action on timeout is **reject**. The dialog must be focus-safe (no accidental approval from typing — e.g. a short delay before Accept is enabled).
- Target can block a requester and restrict incoming requests to address-book contacts.

### Transport
- All API and signalling traffic over HTTPS/WSS (TLS 1.2+); HSTS on the public site.
- Signalling WebSocket accepts only the two participants of an active session, authenticated by session token.
- Media over WebRTC DTLS-SRTP; DTLS fingerprints exchanged only over the authenticated signalling channel.
- TURN credentials time-limited (≈10 min), bound to the session, issued only to participants.

### Database
- No `sa` or `sysadmin` for the application. Separate migration login (DDL on schema `fr`) and application login (DML on schema `fr`).
- Encrypted connections (`Encrypt=yes`); `TrustServerCertificate=yes` permitted only with `FR_ENV=development`.
- Parameterised queries only (SQLAlchemy); no string-built SQL.
- Port 1433 reachable only from backend hosts.
- No destructive migration without a reviewed plan, a backup and explicit approval.

### Web
- Same-origin portal; CORS disabled or restricted to an explicit allowlist (never `*` with credentials).
- Content-Security-Policy, `X-Content-Type-Options`, `Referrer-Policy`, frame-ancestors `none`.
- Output encoding for all user-supplied data (device names, aliases, notes).

### Logging and privacy
- Structured logs with a redaction filter: no passwords, tokens, cookies, keys, SDP credentials or screen content.
- Audit events for: login success/failure, token revocation, device registration/revocation, every connection request and decision, session start/end/terminate, permission changes, admin actions.
- IP addresses retained 90 days; audit 1 year (configurable; confirm against applicable data-protection obligations).

### Secrets and configuration
- Secrets from environment / untracked `.env` in development, and from an approved secret store in production.
- `.env` is git-ignored; `.env.example` contains no values for secrets.
- JWT signing key and TURN shared secret are rotatable.

### Distribution
- Installer and executables code-signed. Updates (when added) verified by signature before installing.
- Per-user installation by default; no Windows service and no auto-start that accepts sessions without the UI visible.

## 3. Threat model (initial, STRIDE)

| # | Threat | Category | Mitigation |
|---|---|---|---|
| T1 | Tech-support scam: attacker phones victim and talks them into accepting | Spoofing / social engineering | Verified requester identity in dialog, explicit scam warning, view-only default, block/report, cooldowns, persistent session banner, audit trail |
| T2 | Remote ID enumeration or spam requests | Information disclosure / DoS | Rate limits, uniform responses, per-target limits, address-book-only mode |
| T3 | Stolen access/refresh token | Spoofing | Short access TTL, refresh rotation + reuse detection, DPAPI storage, revocation from portal |
| T4 | Joining someone else's signalling channel | Elevation of privilege | Session-scoped tokens, participant check on every WS connect, session-ID unguessable UUID |
| T5 | Media interception (MITM) | Information disclosure | DTLS-SRTP; fingerprints carried only over authenticated TLS signalling |
| T6 | TURN abused as open relay | DoS / cost | Time-limited HMAC credentials, quotas, narrow relay range, `no-multicast-peers`, deny private relay ranges |
| T7 | SQL injection / DB compromise | Tampering | ORM parameterisation, least-privilege logins, DB not reachable from Internet |
| T8 | XSS / CSRF in portal | Tampering | CSP, output encoding, CSRF tokens, SameSite cookies |
| T9 | Session continues after user wants it stopped | Elevation of privilege | Local Disconnect closes peer connection immediately without waiting for server; server revoke also enforced |
| T10 | Malicious or tampered installer | Tampering | Code signing, published hashes, HTTPS download only |
| T11 | Sensitive data in logs | Information disclosure | Redaction filter, log review in Phase 9 tests |
| T12 | Insider/admin misuse | Repudiation / EoP | RBAC, admin actions audited, admins cannot start sessions without target consent |
| T13 | Remote input escaping intended scope | Elevation of privilege | Input only with explicit per-session permission, toggleable by target at any time, no privileged service (UIPI limits accepted) |
| T14 | Signalling / API flooding | DoS | Reverse-proxy limits, per-connection message size/rate caps, idle timeouts |
| T15 | Leakage of DB credentials | Information disclosure | Never in code, docs or logs; untracked `.env`; secret store in production; rotate if exposed |

## 4. Implementation status (Phases 3c–3e, verified offline on LocalDB)

| Control | Implemented in | Verified by |
|---|---|---|
| Argon2id hashing (t=3, m=64 MiB, p=4), rehash on login when parameters change | `app/security/passwords.py` | `test_security_primitives.py` |
| Password policy 12–128 chars, not trivially simple, not containing the email local part | `passwords.py`, invitation acceptance | unit + `test_invitations_api.py` |
| Indistinguishable login failures (unknown, wrong password, locked, inactive) incl. dummy Argon2 verification | `app/services/auth.py` | `test_auth_api.py` |
| DB-backed lockout (10 failures → 15 min) | `users.failed_login_count/locked_until` | `test_lockout_after_repeated_failures_and_recovery` |
| Rate limits: login, refresh, invitation accept/create | `app/security/rate_limit.py` (**single process only**) | `test_login_rate_limit`, `test_invitation_rate_limits` |
| Invitations: 256-bit, SHA-256 stored, single use (conditional update), expiring, revocable, admin-only, exact role | `app/services/invitations.py` | `test_invitations_api.py`, concurrency test |
| Bootstrap: only while no admin and no open bootstrap invitation; serialised; stale bootstrap invite cannot create a second admin; refuses non-local DB without flag | `app/cli.py`, `invitations.py` | `test_bootstrap.py`, `test_cli_and_isolation.py` |
| Access tokens: HS256, 10 min, iss/aud/typ checked, session re-validated on every request (logout/revocation immediate) | `app/security/tokens.py`, `auth.py` | unit + API tests (tampering, wrong key, alg none, wrong typ, foreign session) |
| Refresh tokens: opaque, hashed, rotated, reuse → session revoked; concurrent reuse safe | `auth.py`, `repositories.py` | `test_refresh_rotation_and_reuse_detection`, `test_auth_concurrency.py` |
| Browser sessions: `__Host-` cookie, HttpOnly, Secure, SameSite=Lax; 12 h idle / 7 d absolute | `api/v1/auth.py`, `auth.py` | cookie and expiry tests |
| CSRF: HMAC token on unsafe cookie requests + Origin/Sec-Fetch-Site; login CSRF blocked; bearer exempt; bearer wins over cookie | `api/auth_deps.py`, `security/csrf.py` | CSRF tests |
| No secrets in logs, audit rows or session metadata; only hashes stored | logging redaction, audit allow-list | `test_no_secrets_in_logs_audit_or_storage` |
| Tests and bootstrap tooling cannot reach the shared server | `tests/conftest.py` guard, CLI checks | `test_cli_and_isolation.py` |
| Device registration by Ed25519 proof of possession; challenge bound to user, session and key; single use; 120 s | `services/devices.py`, `security/device_proof.py` | `test_devices_api.py` (forged, replayed, expired, cross-user, cross-session, wrong purpose) |
| Remote IDs: CSPRNG, 9 digits, permanent registry, never reused, never client-supplied | V0008, `services/devices.py` | collision, exhaustion, reuse-after-revocation and concurrency tests |
| Verified presence: signed heartbeat, server-computed expiry (90 s); revoked or unverified devices never online | `services/devices.py` | presence tests |
| Key rotation signed by old and new key; revocation cascades to keys and bound sessions | `services/devices.py` | rotation and revocation tests |
| Desktop private key stays on the device, DPAPI-encrypted per Windows user; only public key and signatures are sent | `desktop/fabremote/device_identity.py` | `test_device_gateway.py` (DPAPI round trip, key never sent) |
| Computers without an account (V0009): registration by key proof alone, own purpose prefix (signed-in messages cannot be replayed), rate-limited per IP | `services/devices.py`, `security/device_proof.py` | `test_connections_api.py` |
| Device tokens: 10 min, separate key and type from access tokens, bound to the active key ID, re-checked on every request; revocation or rotation ends them | `security/tokens.py`, `api/auth_deps.py` | token tests (wrong key, revoked device, not interchangeable with access tokens) |
| Consent: only a signed-in, verified user can ask; only the target device can approve; approval and session creation in one transaction; one live session per target | `services/connections.py`, `UX_sessions_live_target` | flow, stranger, double-approve, expiry (410), cancel and concurrency tests |
| Refusals are indistinguishable (unknown, revoked, offline, blocked, policy, busy → same 404); requester never sees the target's device name | `services/connections.py` | `test_every_refusal_looks_the_same_to_the_requester` |
| Consent dialog: requester's name and email from the server, scam warning, Reject is default, closing rejects, expires by itself; optional block | `desktop/fabremote/ui/consent_dialog.py` | `test_connection.py` |
| Sessions end on Disconnect from either side or when either side is silent for 30 s | `sessions.controller_seen_at/target_seen_at` (V0009) | `test_session_ends_when_one_side_goes_silent` |

### Not yet verified / known gaps

- **Rate limits are per process.** Several backend instances need a shared store; counters reset on restart (lockout survives because it is in the database).
- **Client IP** is the direct peer address. Behind a reverse proxy, a trusted `X-Forwarded-For` configuration is still to be designed; until then per-IP limits would see the proxy's address.
- **Origin check** compares `Origin` with `Host`; a reverse proxy must preserve `Host`.
- Real browser behaviour of `__Host-` cookies over `http://127.0.0.1` (development) has not been tested; production must use HTTPS.
- No MFA, no password change/reset, no email delivery (invitation links are handed over out of band).
- Signing-key rotation (multiple active keys) is not implemented; changing `FR_JWT_SIGNING_KEY` invalidates all access tokens and CSRF tokens.
- Timing equivalence is verified structurally (same code path), not by measurement.
- Nothing has run against the shared DEV database: it has no application login yet (P003), and the backend refuses `sa`.
- Penetration testing and dependency vulnerability scanning have not been done (Phase 9).
- **Computers without an account:** anyone who can reach the server can register a computer (10 per minute per IP) and each permanently uses a Remote ID. Such a computer can only *receive* requests and must approve each one; it cannot ask to connect. Run the server only where its users are expected, and add abuse monitoring before opening it to the internet.
- **No media yet:** a session is a recorded consent with no screen or input. The consent dialog says so; Phase 6/7 add media under the same session.
- **Polling, not push:** requests and sessions are polled every 2 s (rate-limited); the presence WebSocket is still planned.
- **Devices:** signed-in owners still use their session plus the device key for presence; computers without an account use device tokens. The device limit check is serialised per user with an application lock. DPAPI protects the key from other Windows users and offline copies, but not from malware running as the same user. There is no hardware-backed key storage (TPM) yet. A `key_compromised` revocation stops future use but cannot undo past sessions (there are none before 3e).
- **Shared DEV database:** at schema version 8; this backend expects version 9 (V0009 not applied there yet), and no application logins are mapped (P003), so the backend cannot use it yet.

## 5. Open security items

- MFA design (before public launch).
- Data retention periods to confirm with the business / legal owner.
- Production TLS certificate for SQL Server.
- Code-signing certificate procurement.
- Abuse reporting process for T1.
