# Fabulous Remote — Phase 3 API Plan and Contracts

Status: **Draft for review.** Implemented: 3a/3b (health, error envelope, middleware, data layer), **3c (authentication and admin invitations, §5.2 and §5.6)** and **3d (device registration, Remote IDs, verified presence, §5.3)**. Connection-request, session and audit endpoints are not implemented yet. Contracts follow the draft schema in [DATABASE_DESIGN.md](DATABASE_DESIGN.md). Every enum and limit comes from [`backend/app/domain/constants.py`](../backend/app/domain/constants.py), which is tested against the database constraints.

## 1. Scope

| In Phase 3 | Not in Phase 3 |
|---|---|
| Health, authentication (desktop tokens, web cookie + CSRF), admin invitations, devices and device authentication, connection requests with target consent, session records (create, list, terminate, reduce permission), audit queries, presence WebSocket for incoming-request notifications | Screen streaming, the signalling WebSocket, TURN credential issuance, the `authorizing → active` transition (all Phase 6); remote input (Phase 7); address book/favorites endpoints (Phase 4, with the desktop UI); deployment |

A session can't reach `active` in Phase 3, so no API response can claim a working remote connection.

## 2. Conventions

| Topic | Rule |
|---|---|
| Paths | Health at `/health/*` (unversioned, for load balancers); everything else under `/api/v1` |
| Format | JSON, UTF-8, `snake_case` fields; IDs are UUID strings; timestamps RFC 3339 UTC with milliseconds (`2026-10-17T10:42:00.000Z`) |
| Remote ID | 9-digit string matching `REMOTE_ID_PATTERN`. Input may contain spaces (`"105 280 964"`), which are stripped before validation. Output is always unformatted |
| Request ID | `X-Request-ID` is accepted if it matches `^[A-Za-z0-9-]{1,64}$`, otherwise generated. It's echoed in the response and stored in `audit_events.request_id` |
| Pagination | `limit` (1–200, default 50) and an opaque `cursor`. Responses are `{"items": [...], "next_cursor": "…" \| null}` (keyset, newest first) |
| Concurrency | Resources with `row_version` return an `ETag`. `PATCH` requires `If-Match` (428 if missing, 412 if stale) |
| Visibility | A resource the caller may not see returns **404**, never 403, so the API doesn't reveal what exists. 403 means "visible, but this action isn't allowed" |
| Unknown fields | Rejected (`extra = "forbid"`) |
| Caching | `Cache-Control: no-store` on every `/api/v1` response |

### 2.1 Error envelope

```json
{
  "error": {
    "code": "validation_error",
    "message": "Request validation failed.",
    "request_id": "6f1c0e2a-...",
    "details": [{"field": "remote_id", "issue": "pattern"}]
  }
}
```

| HTTP | Typical `code` values |
|---|---|
| 401 | `unauthenticated`, `invalid_credentials`, `invalid_token`, `token_reused`, `invalid_signature` |
| 403 | `forbidden`, `account_not_verified`, `csrf_failed` |
| 404 | `not_found`, `target_unavailable`, `invitation_invalid`, `device_unavailable` |
| 409 | `conflict`, `account_exists`, `invitation_exists`, `device_limit_reached`, `key_already_registered`, `request_not_pending`, `target_busy`, `session_ended` |
| 410 | `request_expired` |
| 412 / 428 | `precondition_failed` / `precondition_required` |
| 422 | `validation_error`, `cannot_connect_to_self`, `permission_exceeds_request` |
| 429 | `rate_limited` (with `Retry-After`) |
| 500 | `internal_error`: no stack traces or SQL text, ever |
| 503 | `not_ready` |

Database constraint violations that slip past validation are mapped to 409 `conflict` and logged with the constraint name. Values are never logged.

## 3. Credentials

| Credential | Issued by | Sent as | Lifetime (config) | Checked on every use |
|---|---|---|---|---|
| User access token: JWT `typ=access`, claims `sub` (user), `sid` (auth session), optional `did` (bound device) | `/auth/token`, `/auth/refresh`, `/auth/session/device` | `Authorization: Bearer` | 10 min (`FR_ACCESS_TOKEN_TTL_SECONDS`) | Signature, `exp`, `aud`; `auth_sessions` row not revoked or expired; user `active`; roles loaded from `user_roles` |
| Refresh token: opaque, 256-bit | `/auth/token`, `/auth/refresh` | JSON body | 30 days (`FR_REFRESH_TOKEN_TTL_DAYS`) | `auth_tokens` hash; rotated on every use; reuse revokes the session |
| Web session: opaque, 256-bit | `/auth/web/login` | Cookie `__Host-fr_session` (`HttpOnly; Secure; SameSite=Lax; Path=/`, no `Domain`) | 12 h idle, 7 days absolute | `auth_tokens` (type `web`) and its `auth_sessions` row |
| CSRF token: HMAC-SHA256 of the auth session ID | `GET /auth/csrf` | `X-CSRF-Token` header on unsafe methods when cookie-authenticated | Same as the web session | Constant-time compare |
| Device token: JWT `typ=device`, claims `sub` (device), `kid` (key fingerprint) | `/devices/token` | `Authorization: Bearer` | 10 min | Device `active`; key still active |

JWTs use HS256 with a key derived from `FR_JWT_SIGNING_KEY` (at least 32 random bytes; the CSRF key is derived separately; development/test without a key uses an ephemeral one), `iss=fabremote`, `aud=fabremote-api`, 30 s clock skew, and a `jti`. Each endpoint declares which `typ` it accepts, and a token of the wrong type is rejected with 401. Tokens, cookies and keys are never logged.

## 4. Rule ownership

Each rule has one owner. Where the API checks a rule early to give a clearer error, it uses the same constants, and the database remains the final guard.

| Rule | Enforced by |
|---|---|
| Enum values, lengths, Remote ID format, Argon2id-only hashes, lower-case emails | **Database** CHECKs; API validation imports `constants.py` (drift test) |
| Remote ID never reused (permanent registry + FK); one active key per device; fingerprint = SHA-256(public key) | **Database** |
| A session exists only for an approved request with the same users, devices and requested permission; granted permission ≤ requested; one live session per target; an approved request referenced by a session can't change | **Database** (composite FK, CHECK, filtered unique index) |
| Status ↔ decision-reason pairs | **Database** CHECK; API maps outcomes using `DECISION_REASONS_BY_STATUS` |
| Audit is append-only | **Database** permissions (DENY UPDATE/DELETE) |
| Authentication, roles, ownership, visibility, rate limits, cooldowns, request TTL, incoming policy, blocking, verified-email requirement | **API services** |
| Cascades on revocation (device → keys, auth sessions, pending requests, live sessions) | **API service**, in one transaction |
| Expiring pending requests and stale `authorizing` sessions | **API background sweeper** (and lazily on read) |
| Data retention | **Database procedure**, called by a scheduled job only when `FR_RETENTION_ENABLED=true` with approved periods |

## 5. Endpoints

Notation: **Auth** = credential required; **Authz** = who may act; **Audit** = events written (`event_type`, outcome).

### 5.1 Health

| | `GET /health/live` | `GET /health/ready` |
|---|---|---|
| Auth | None | None |
| Does | Process is up. No database access | `SELECT 1` and `MAX(version)` from `fr.schema_migrations` equals the expected version (7). Bounded by `FR_DB_LOGIN_TIMEOUT_SECONDS` (default 5) and `FR_DB_QUERY_TIMEOUT_SECONDS` |
| 200 | `{"status": "ok"}` | `{"status": "ready", "checks": {"database": "ok", "schema": "ok"}}` |
| 503 | — | `{"status": "not_ready", "checks": {...}}` with `database` ∈ `ok`/`error`/`not_configured` and `schema` ∈ `ok`/`mismatch`/`unknown` |
| Never returns | | Error text, host names, server or schema version numbers |
| Tests | 200 without a database | ok, not configured, database unreachable, schema missing, schema mismatch (implemented: `backend/tests/unit/test_app.py`, `backend/tests/integration/test_readiness.py`) |

### 5.2 Authentication — `/api/v1/auth`

`UserOut` = `{id, email, display_name, status, email_verified_at, roles: [Role], created_at}`

| Endpoint | Auth / Authz | Request | Success | Errors | Rules | Audit |
|---|---|---|---|---|---|---|
| `POST /auth/invitations/accept` | None (rate-limited per IP) | `{token, display_name (1–100, trimmed), password (12–128)}` | 201 `{user: UserOut}` | 404 `invitation_invalid` (unknown, expired, revoked or used: same response for all), 409 `account_exists`, 422 | SHA-256 the token, find an open invitation. Create the user `active` with `email_verified_at = now` (the invite proves email ownership), role `user` plus the invitation's role. Mark the invitation accepted with a conditional update; the whole step is one transaction. The password must not contain the email's local part | `user.invitation_accepted` success / failure |
| `POST /auth/token` | None (rate-limited) | `{email, password}` | 200 `{access_token, token_type: "Bearer", expires_in, refresh_token, refresh_expires_in, user: UserOut}` | 401 `invalid_credentials` (unknown, wrong password, disabled: same response), 429 | Constant-time path for unknown emails (dummy Argon2 verify). After 10 consecutive failures, lock for 15 min (`failed_login_count`, `locked_until`). Success resets the counter and creates `auth_sessions` (`desktop`) plus a refresh `auth_tokens` row | `auth.login` success / failure |
| `POST /auth/refresh` | None | `{refresh_token}` | 200, same shape as `/auth/token` | 401 `invalid_token`, 401 `token_reused` | Conditional update `SET consumed_at = now WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now`. If 0 rows and the token exists but is consumed, it's being reused: revoke the session (`token_reuse`) and all its tokens | `auth.refresh` failure only; `auth.token_reuse` denied |
| `POST /auth/session/device` | Access token | `{device_token}` | 200 new token pair with the `did` claim | 401, 404 `device_unavailable` | The device token must be valid and the device owned by the caller and active. Sets `auth_sessions.device_id` | `auth.device_bound` success |
| `POST /auth/logout` | Access token, or cookie + CSRF | — | 204 | 401 | Revoke the current auth session (`logout`) and its tokens. Idempotent | `auth.logout` success |
| `POST /auth/web/login` | None (rate-limited); refused cross-site (`Origin` / `Sec-Fetch-Site`) to prevent login CSRF | `{email, password}` | 204 + `Set-Cookie: __Host-fr_session` | Same as `/auth/token`, plus 403 `csrf_failed` | Same checks; creates `auth_sessions` (`web`) and an `auth_tokens` row (`web`). Always issues a new token (prevents session fixation) | `auth.login` |
| `POST /auth/web/logout` | Cookie + CSRF | — | 204, cookie cleared | 401, 403 `csrf_failed` | Like logout | `auth.logout` |
| `GET /auth/csrf` | Cookie | — | 200 `{csrf_token}` | 401 | | — |
| `GET /auth/me` | Any user credential | — | 200 `UserOut` | 401 | | — |

**Implementation notes (3c):**
- A locked account returns the same 401 `invalid_credentials` as a wrong password (no lockout oracle); 429 comes only from the rate limiter.
- Two concurrent refreshes with the same token are treated as reuse: at most one succeeds and the session is revoked. Clients must serialise refresh calls.
- Desktop sessions have an absolute lifetime of `FR_REFRESH_TOKEN_TTL_DAYS`; rotated refresh tokens never outlive their session.
- `POST /auth/session/device` (device binding, `did` claim) is deferred to Phase 3d with device registration.
- Unknown fields are rejected, passwords are capped at 1024 characters on input (Argon2 DoS guard); the 12–128 policy applies when a password is set.
- Failed logins never record the attempted email address.

Tests (implemented in `backend/tests/integration/test_auth_api.py`, `test_invitations_api.py`, `test_auth_concurrency.py`): invitation happy path; reused, expired and revoked tokens give the same 404; race on double accept; password policy; login lockout and reset; timing path for unknown emails (structure, not wall clock); refresh rotation; refresh reuse revokes the session and blocks the old access token on its next use; logout invalidates the session; cookie flags; CSRF required for cookie-auth unsafe methods but not for bearer; disabled user rejected even with a valid token.

### 5.3 Devices — `/api/v1/devices` (implemented, Phase 3d)

Every endpoint requires a signed-in user (bearer, or cookie + CSRF). Proof of possession uses **Ed25519**: the client signs a server nonce inside a versioned, purpose-specific message (`backend/app/security/device_proof.py`, mirrored byte for byte in `desktop/fabremote/device_identity.py`):

| Purpose | Signed message |
|---|---|
| Registration | `"fabremote-device-register-v1\0" ‖ challenge_id (16 B) ‖ nonce (32 B) ‖ user_id (16 B) ‖ SHA-256(public_key)` |
| Presence | `"fabremote-device-presence-v1\0" ‖ challenge_id ‖ nonce ‖ device_id` |
| Key rotation | `"fabremote-device-rotate-v1\0" ‖ challenge_id ‖ nonce ‖ device_id ‖ SHA-256(new_public_key)`, signed by **both** keys |

`DeviceOut` = `{id, remote_id, display_name, os_name, os_version, client_version, incoming_policy, status, identity_verified, online, last_seen_at, key_fingerprint (hex SHA-256 of the active key), created_at, updated_at, revoked_at, revoked_reason}`. `identity_verified` = active device with an active key; `online` = verified **and** a signed heartbeat younger than `FR_PRESENCE_TTL_SECONDS` (default 90 s), computed by the server. `last_ip` is stored (90-day retention) but not returned.

| Endpoint | Who | Request | Success | Errors | Rules / audit |
|---|---|---|---|---|---|
| `POST /devices/registration-challenge` | User | `{public_key (base64, 32 B), key_algorithm: "ed25519", device_name, os_name?, os_version?, client_version?}` | 201 `{challenge_id, nonce, expires_at, message_format}` | 409 `key_already_registered`, 409 `device_limit_reached` (`FR_MAX_DEVICES_PER_USER`, default 10), 422 (invalid key) | Challenge bound to user, auth session and key; single use; `FR_DEVICE_CHALLENGE_TTL_SECONDS` (default 120). Old challenges of the user are purged |
| `POST /devices/register` | User | `{challenge_id, signature}` | 201 `DeviceOut` + `Location`, `ETag` | 400 `invalid_challenge` (unknown, expired, used, other user or session), 400 `invalid_signature`, 409, 503 | Challenge consumed atomically **before** the signature check (one guess per challenge). Only then is a Remote ID allocated. Binds the auth session to the device. `device.registered` / `device.register` (failure) |
| `GET /devices/me` | User | — | 200 `DeviceOut` | 404 `device_not_registered` | Device bound to the current session (by registration or a successful heartbeat) |
| `GET /devices` | User; admin may pass `owner_user_id` | `?status&limit` | 200 `{items}` | 403 (other owner, non-admin) | — |
| `GET /devices/{id}` | Owner or admin | — | 200 `DeviceOut` + `ETag` | 404 | — |
| `PATCH /devices/{id}` | Owner | `{display_name?, incoming_policy?}` + `If-Match` | 200 + new `ETag` | 404, 409 `device_revoked`, 412, 428 | Ownership is checked before the ETag, so strangers always get 404. `device.updated` |
| `POST /devices/{id}/revoke` | Owner (`owner_removed`) or admin (`admin_revoked`, `key_compromised`) | `{reason?}` | 200 `DeviceOut` (idempotent) | 403 (reason not allowed), 404 | Device revoked, keys revoked, auth sessions bound to the device revoked. The Remote ID stays allocated forever. `device.revoked` |
| `POST /devices/{id}/challenge` | Owner | — | 201 `{challenge_id, nonce, expires_at}` | 404, 409 `device_revoked` | Single-use nonce (`device_auth_challenges`) for presence or rotation |
| `POST /devices/{id}/presence` | Owner + device key | `{challenge_id, signature}` | 200 `DeviceOut` (`online: true`) | 400 `invalid_challenge` / `invalid_signature` | Sets `last_seen_at` (server UTC) and binds the session. Failures audited as `device.presence` |
| `POST /devices/{id}/keys/rotate` | Owner + current key + new key | `{challenge_id, new_public_key, signature_current, signature_new}` | 200 `DeviceOut` (same Remote ID, new fingerprint) | 400, 409 `key_already_registered`, 422 | Old key revoked (`rotated`). `device.key_rotated` |

**Remote IDs:** `secrets.randbelow` in 100000000–999999999. Each candidate is inserted into the permanent `fr.remote_id_registry` inside a savepoint; a collision retries with a new candidate, up to 10 times, after which the response is a generic 503. Devices must reference the registry (`FK_devices_remote_id`), and the application role can only INSERT/SELECT the registry, so **an ID is never issued twice, even after revocation or removal**. A client-supplied `remote_id`, `online` or `identity_verified` field is rejected (422, unknown field).

**Without an account (Phase 3e, V0009, implemented).** The computer being helped needs no user account:

| Signed message | Format |
|---|---|
| Anonymous registration | `"fabremote-device-register-anonymous-v1\0" ‖ challenge_id ‖ nonce ‖ SHA-256(public_key)` |
| Device token | `"fabremote-device-token-v1\0" ‖ challenge_id ‖ nonce ‖ device_id` |

| Endpoint | Auth | Request | Success | Errors | Rules |
|---|---|---|---|---|---|
| `POST /devices/anonymous/registration-challenge` | None | as the signed-in variant | 201 `ChallengeOut` | 409 `key_already_registered`, 422, 429 (10/min per IP) | Challenge bound to the key only; single use |
| `POST /devices/anonymous/register` | None | `{challenge_id, signature}` | 201 `DeviceOut` | 400 `invalid_challenge` / `invalid_signature`, 409, 429 | One guess per challenge; `owner_user_id` NULL; `device.registered` (`anonymous: true`) |
| `POST /devices/token-challenge` | None | `{device_id}` | 201 `ChallengeOut` | 404 (unknown or revoked), 429 | Nonce in `device_auth_challenges` |
| `POST /devices/token` | None | `{device_id, challenge_id, signature}` | 200 `{device_token, token_type: "device", expires_in, device}` | 400, 429 | Counts as a heartbeat. `device.auth` |
| `GET /devices/self`, `POST /devices/self/heartbeat` | `X-Device-Token` | — | 200 `DeviceOut` | 401 `invalid_device_token` | Heartbeat sets `last_seen_at` |

Device tokens are HS256 JWTs (`typ: "device"`, `sub` = device, `kid` = active key ID), 10 minutes (`FR_DEVICE_TOKEN_TTL_SECONDS`), signed with a key derived separately from the access-token key. Every request re-checks that the device is active and the key ID is still its active key. Access tokens are not accepted as device tokens and vice versa. The presence WebSocket (§5.8) is still planned; clients poll.

### 5.4 Connection requests — `/api/v1/connection-requests` (implemented, Phase 3e)

**As implemented:** the requester authenticates as a user (bearer or cookie + CSRF) **and** sends its own computer's `X-Device-Token` (instead of a `did` claim). Target endpoints take `X-Device-Token` only, so the computer being helped needs no account. `GET /connection-requests/incoming` also returns `live_session_id` and counts as the target's heartbeat. A repeated `POST` while a request to the same target is pending returns that request. Expiry is applied lazily on every read and write (no sweeper). `FR_CONNECTION_REQUEST_TTL_SECONDS` defaults to 45.

`RequestOut` = `{id, status, requested_permission, created_at, expires_at, decided_at, decision_reason, target_remote_id, session_id?}`. For the **target**, it also includes `requester: {display_name, email, email_verified}` and `requester_device: {display_name, remote_id}`. The requester never sees the target's device name or owner.

| Endpoint | Auth / Authz | Request | Success | Errors | Rules | Audit |
|---|---|---|---|---|---|---|
| `POST /connection-requests` | Access token **with `did`**; verified, active user | `{remote_id, requested_permission: "view" \| "view_input" (default "view")}` | 201 `RequestOut` (`pending`) | 403 `account_not_verified`, 404 `target_unavailable`, 422 `cannot_connect_to_self`, 429 | See the evaluation order below | `connection.requested` success / denied (with reason) |
| `GET /connection-requests/{id}` | Requester user, target device token, admin, auditor | — | 200 `RequestOut` | 404 | A pending request past `expires_at` is moved to `expired/timeout` first | — |
| `GET /connection-requests/incoming` | Device token | — | 200 `{items: [RequestOut]}` | 401 | Pending, unexpired requests for this device | — |
| `POST /connection-requests/{id}/approve` | Device token of the **target** | `{permission_granted: Permission}` | 201 `SessionOut` (`authorizing`) | 404, 409 `request_not_pending`, 409 `target_busy`, 410 `request_expired`, 422 `permission_exceeds_request` | One transaction: conditional update `pending → approved/target_approved WHERE target_device_id = did AND expires_at > now`, then insert the session with the copied `requested_permission`. If the live-session index rejects the insert, the transaction rolls back (`target_busy`) and the request stays pending | `connection.approved`, `session.created` |
| `POST /connection-requests/{id}/reject` | Device token of the target | `{block_requester: bool = false}` | 200 `RequestOut` | 404, 409, 410 | `rejected/target_rejected`. Optionally inserts `blocked_requesters` (idempotent) | `connection.rejected`, `device.requester_blocked` |
| `POST /connection-requests/{id}/cancel` | Requester user | — | 200 `RequestOut` | 404, 409 | `cancelled/requester_cancelled` | `connection.cancelled` |

**`POST` evaluation order:**
1. Validate the payload.
2. User active and email verified, otherwise 403.
3. The `did` device is active, otherwise 401.
4. Rate limits (§6), otherwise 429.
5. Target is the requester's own device: 422.
6. Target unknown, revoked, `incoming_policy = disabled`, requester blocked, `address_book_only` not satisfied (the requester device's Remote ID must be in the target owner's address book), target offline (presence), or target already has a live session: **404 `target_unavailable`** in every case. For an existing target the API records a decided row (`rejected/blocked`, `rejected/policy_denied`, `expired/target_offline`) so cooldowns and audit stay accurate. Unknown Remote IDs produce no row, only an audit event.
7. Insert `pending` with `expires_at = now + FR_CONNECTION_REQUEST_TTL_SECONDS` (default 45, allowed 15–120).
8. Push `incoming_request` to the target's presence connection.

Tests: each branch of step 6 returns the same status, body shape and code; rate limits and cooldown; self-request; approve only by the target device (the requester's device gets 404); approve after expiry gives 410 and marks the request expired; double approve gives 409; concurrent approvals for the same target produce exactly one session; permission escalation 422 (and the database rejects it if the API check is bypassed); reject with block prevents the next request; cancel after approval gives 409; the requester never sees the target's device name.

### 5.5 Sessions — `/api/v1/sessions` (partly implemented, Phase 3e)

**As implemented:** `GET /sessions/{id}` and `POST /sessions/{id}/terminate` for the controller user, the target device (`X-Device-Token`), the target owner and admins (auditors read only). Reading a session is that side's presence signal (`controller_seen_at` / `target_seen_at`, V0009); a session in which either side has been silent for `FR_SESSION_PRESENCE_TIMEOUT_SECONDS` (30) ends with `timeout`. Sessions stay `authorizing` until media exists (Phase 6); `SessionOut.media_available` is `false`, and `target.display_name` is hidden from the controller. `GET /sessions` (list) and `PATCH /sessions/{id}/permission` are not implemented yet.

`SessionOut` = `{id, connection_request_id, state, requested_permission, permission_granted, created_at, started_at, ended_at, end_reason, controller: {user_id, display_name, device_remote_id}, target: {device_id, remote_id, display_name}}`

Who can see a session: the controller user, the target device (device token), the target device's owner, and admins/auditors (read-only).

| Endpoint | Auth / Authz | Request | Success | Errors | Rules | Audit |
|---|---|---|---|---|---|---|
| `GET /sessions` | User (own as controller or target owner); admin/auditor all | `?state&role=controller\|target&from&to&limit&cursor` | 200 page of `SessionOut` | 401, 422 | Newest first | — |
| `GET /sessions/{id}` | As above, or target device token | — | 200 `SessionOut` | 404 | | — |
| `POST /sessions/{id}/terminate` | Controller user → `controller_disconnect`; target device → `target_disconnect`; target owner or admin → `revoked` | `{}` | 200 `SessionOut` (idempotent: already ended returns the current record) | 404 | Conditional update `WHERE state <> 'ended'`; sets `ended_by_*`. Pushes `session_updated` to both sides. Clients must close the peer connection locally **without** waiting for this call | `session.ended` |
| `PATCH /sessions/{id}/permission` | Target device token only | `{permission_granted}` | 200 `SessionOut` | 404, 409 `session_ended`, 422 `permission_exceeds_request` | Can lower to `view` or restore up to `requested_permission` (the database enforces the ceiling) | `session.permission_changed` |
| `POST /sessions/{id}/turn-credentials` | — | — | **Not implemented in Phase 3** (route absent) | | Phase 6 | |

The sweeper ends `authorizing` sessions older than `FR_SESSION_AUTHORIZING_TIMEOUT_SECONDS` (default 60) with `timeout`, so a stale session can't block a target.

Tests: visibility matrix (controller, target device, target owner, stranger, admin, auditor); terminate reasons per actor; idempotent terminate; the auditor can't terminate; permission lowering and restoring; escalation rejected; the sweeper times out stale sessions and the target can then accept a new request.

### 5.6 Admin invitations — `/api/v1/admin/invitations`

Requires role `admin` (bearer, or cookie + CSRF). `InvitationOut` = `{id, email, role, status (open | accepted | revoked | expired, derived), created_at, expires_at, accepted_at, revoked_at, invited_by_user_id}`

| Endpoint | Request | Success | Errors | Rules | Audit |
|---|---|---|---|---|---|
| `POST /admin/invitations` | `{email, role: Role = "user", expires_in_hours: 1–168 = 72}` | 201 `{invitation: InvitationOut, token, accept_url}`. **The token is returned only once** | 409 `account_exists`, 409 `invitation_exists`, 422 | `token = secrets.token_urlsafe(32)`; only the SHA-256 is stored. `accept_url = FR_PUBLIC_BASE_URL + "/portal/accept-invitation#token=…"` (a fragment, so the token stays out of server logs). Email delivery is out of scope; the admin passes the link on out of band | `admin.invitation_created` (role only, never the token) |
| `GET /admin/invitations` | `?status&email&limit&cursor` | 200 page | 403 | | — |
| `POST /admin/invitations/{id}/revoke` | — | 200 `InvitationOut` | 404, 409 if not open | | `admin.invitation_revoked` |

Bootstrap: `python -m app.cli bootstrap-admin --email <address>` runs only while **no** user holds `admin` and no other bootstrap invitation is open (serialised with `sp_getapplock`). It refuses a non-local database unless `--allow-remote-database` is passed, before any connection is made. It creates an invitation with `invited_by_user_id = NULL` and role `admin`, and prints the link once to the console. Audit: `admin.bootstrap_invitation`.

Tests: non-admin gets 403; token returned once and only its hash stored; duplicate open invitation 409; revoke then re-invite; bootstrap refuses once an admin exists.

### 5.7 Audit events — `/api/v1/audit-events`

Requires role `admin` or `auditor`. Read-only: no create, update or delete routes exist.

| Endpoint | Request | Success | Errors | Rules | Audit |
|---|---|---|---|---|---|
| `GET /audit-events` | `?from&to` (**required**, range ≤ 31 days), `event_type` (exact, or prefix such as `session.`), `outcome`, `actor_user_id`, `subject_type`, `subject_id`, `limit`, `cursor` | 200 page of `{id, occurred_at, event_type, outcome, actor_user_id, actor_device_id, subject_type, subject_id, ip_address, request_id, details}` | 403, 422 | Keyset on `id` descending; uses `IX_audit_events_occurred_at` and `_actor_user_id` / `_subject` | `audit.viewed` (filter summary) |

Initial event catalogue: `auth.login`, `auth.logout`, `auth.refresh`, `auth.token_reuse`, `auth.device_bound`, `user.invitation_accepted`, `admin.invitation_created`, `admin.invitation_revoked`, `admin.bootstrap_invitation`, `device.registered`, `device.updated`, `device.revoked`, `device.auth`, `device.requester_blocked`, `connection.requested`, `connection.approved`, `connection.rejected`, `connection.cancelled`, `connection.expired`, `session.created`, `session.ended`, `session.permission_changed`, `audit.viewed`, `retention.purge`.

`details` is a JSON object of at most 2000 characters, built from an allow-list of keys per event type. Passwords, tokens, keys, cookies, SDP and screen data are never included (enforced by a test that scans emitted events).

### 5.8 Presence WebSocket — `/api/v1/ws/device`

Needed so targets receive requests in real time and so "online" is real (it replaces the mockup's static "Ready to connect").

- WSS only. The first client message must be `{"type": "auth", "device_token": "…"}` within 5 s, never in the URL (keeps it out of logs). Otherwise the server closes with code 4401.
- Server → client events: `incoming_request` (`RequestOut` target view), `request_updated`, `session_updated`, `revoked` (then close).
- A device counts as online only while its authenticated socket is open with heartbeats (ping every 20 s, dropped after 45 s).
- Limits: one socket per device (a new one replaces the old), 16 KiB maximum message size, client messages limited to `auth` and `pong`.
- Single-instance registry behind an interface (multi-instance needs a shared bus, deferred).

Tests: auth timeout, bad token, revoked device disconnected, online state flips on disconnect, an event is delivered when a request is created.

## 6. Rate limits (initial values, configurable)

| Action | Limit |
|---|---|
| Login (`/auth/token`, `/auth/web/login`) | 5/min per email + IP; 20/min per IP; lockout after 10 consecutive failures for 15 min |
| `/auth/refresh` | 30/min per auth session |
| `/auth/invitations/accept` | 10/min per IP |
| `/devices/registration-challenge`, `/devices/register` | 10/min per user (each) |
| `/devices/{id}/challenge`, `/devices/{id}/presence` | 30/min per device (each) |
| `/devices/{id}/keys/rotate` | 5/min per device |
| `POST /connection-requests` | 10/min per user; at most 3 pending per user; 20/hour per target; 3 rejections from the same target within 1 h → 15 min cooldown for that pair |
| `/audit-events` | 30/min per user |

Limits are held in process for a single instance and keyed so they can move to a shared store later. Counters that must survive restarts (failed logins, cooldowns) come from the database (`users`, `connection_requests`).

## 7. Backend structure and testability

```
backend/
├─ app/
│  ├─ main.py              app factory: routers, middleware (request ID, security headers, error mapping)
│  ├─ config.py            pydantic-settings, FR_* environment variables
│  ├─ log.py               structured logging, redaction, request-ID context
│  ├─ domain/              constants.py (shared with DB tests), errors.py (domain exceptions → HTTP codes)
│  ├─ api/                 routers per area, dependencies (auth/authz), Pydantic request/response schemas
│  ├─ services/            business rules; depend on repository protocols only
│  ├─ db/                  SQLAlchemy 2.x models of schema fr, repositories, unit of work, engine, error translation
│  ├─ security/            argon2 hashing, JWT, Ed25519 verification, CSRF, token hashing
│  ├─ realtime/            presence registry + WebSocket endpoint
│  └─ cli.py               bootstrap-admin
└─ tests/
   ├─ unit/                services with in-memory fake repositories (no database)
   ├─ api/                 FastAPI TestClient with fakes (no database)
   └─ integration/         repositories against a migrated LocalDB scratch database
```

- Services receive a unit-of-work factory, so the same service code runs against fakes (unit/API tests) or SQL Server (integration).
- Integration tests reuse the LocalDB fixtures from `database/tests` (moved into a shared helper), and refuse any non-LocalDB server, as today.
- A model-drift test compares the SQLAlchemy metadata with the catalog of a migrated database.
- The engine uses `mssql+pyodbc`, ODBC Driver 18, `Encrypt=yes`, the runtime login only, and `pool_pre_ping`. There are no DDL calls (`metadata.create_all` is never used).

## 8. Configuration (environment variables)

Database (`FR_DB_*`) as in `.env.example`, plus:

| Variable | Default | Notes |
|---|---|---|
| `FR_JWT_SIGNING_KEY` | — (required) | At least 32 random bytes; startup fails if missing or short |
| `FR_ACCESS_TOKEN_TTL_SECONDS` | 600 | |
| `FR_REFRESH_TOKEN_TTL_DAYS` | 30 | |
| `FR_WEB_SESSION_IDLE_HOURS` / `FR_WEB_SESSION_ABSOLUTE_DAYS` | 12 / 7 | |
| `FR_CONNECTION_REQUEST_TTL_SECONDS` | 45 | Allowed 15–120 |
| `FR_SESSION_AUTHORIZING_TIMEOUT_SECONDS` | 60 | |
| `FR_MAX_DEVICES_PER_USER` | 10 | |
| `FR_PUBLIC_BASE_URL` | — | Used for invitation links |
| `FR_CORS_ALLOWED_ORIGINS` | empty | Same-origin only by default |
| `FR_RETENTION_ENABLED` + `FR_RETENTION_*_DAYS` | `false` | The scheduler stays off until periods are approved |
| `FR_EXPOSE_OPENAPI` | `true` in development, `false` otherwise | |

## 9. Implementation order (Phase 3 sub-steps)

Each step ends with its tests green before the next starts. All database work runs against LocalDB until the shared-database migrations are approved and applied.

1. **3a** App skeleton, config validation, logging, request ID, error envelope, security headers, `/health/*`. **Done.**
   **3b** Data layer: engine, models, repositories (users, invitations, devices, audit, migrations), unit of work, error translation, model-drift test. **Done.** Remaining repositories (auth sessions/tokens, requests, sessions) are added with their features.
2. **3c** Password hashing, admin invitations, bootstrap CLI, invitation acceptance, desktop and web login, refresh rotation, logout, CSRF, `/auth/me`.
3. **3d** Device registration, challenge/token, session binding, device management and revocation cascade.
4. **3d** Presence WebSocket (with device registration).
5. **3e** Connection requests (policy, rate limits), approve/reject/cancel, sessions (get, terminate), computers without an account, device tokens. **Done** (lazy expiry instead of a sweeper; session list and permission changes still to do).
6. **3f** Audit query endpoint, audit-content scanning test, OpenAPI review, security review of Phase 3.

Dependencies to add then (pinned): `fastapi`, `uvicorn[standard]`, `pydantic-settings`, `sqlalchemy>=2`, `pyodbc`, `argon2-cffi`, `pyjwt`, `cryptography`, `httpx` (tests).
