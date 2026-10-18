"""Domain values shared by the API layer and the database schema.

Every enum and limit here mirrors a CHECK constraint, seed row or column size in
database/migrations. database/tests/test_api_alignment.py compares them with a migrated
database and fails on any drift, so API validation and database constraints cannot
silently disagree.
"""

from __future__ import annotations

from enum import StrEnum


class UserStatus(StrEnum):           # CK_users_status
    INVITED = "invited"
    ACTIVE = "active"
    DISABLED = "disabled"


class Role(StrEnum):                 # seed rows of fr.roles
    USER = "user"
    ADMIN = "admin"
    AUDITOR = "auditor"


class DeviceStatus(StrEnum):         # CK_devices_status
    ACTIVE = "active"
    REVOKED = "revoked"


class IncomingPolicy(StrEnum):       # CK_devices_incoming_policy
    VERIFIED_USERS = "verified_users"
    ADDRESS_BOOK_ONLY = "address_book_only"
    DISABLED = "disabled"


class DeviceRevokedReason(StrEnum):  # CK_devices_revoked_reason
    OWNER_REMOVED = "owner_removed"
    ADMIN_REVOKED = "admin_revoked"
    KEY_COMPROMISED = "key_compromised"
    USER_DISABLED = "user_disabled"


class KeyAlgorithm(StrEnum):         # CK_device_keys_algorithm
    ED25519 = "ed25519"


class KeyRevokedReason(StrEnum):     # CK_device_keys_revoked_reason
    ROTATED = "rotated"
    DEVICE_REVOKED = "device_revoked"
    KEY_COMPROMISED = "key_compromised"


class ClientType(StrEnum):           # CK_auth_sessions_client_type
    WEB = "web"
    DESKTOP = "desktop"


class AuthSessionRevokedReason(StrEnum):  # CK_auth_sessions_revoked_reason
    LOGOUT = "logout"
    ADMIN_REVOKED = "admin_revoked"
    TOKEN_REUSE = "token_reuse"
    PASSWORD_CHANGED = "password_changed"
    USER_DISABLED = "user_disabled"
    DEVICE_REVOKED = "device_revoked"


class TokenType(StrEnum):            # CK_auth_tokens_token_type
    REFRESH = "refresh"
    WEB = "web"


class Permission(StrEnum):           # CK_connection_requests_requested_permission, CK_sessions_permission_granted
    VIEW = "view"
    VIEW_INPUT = "view_input"


class RequestStatus(StrEnum):        # CK_connection_requests_status
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class DecisionReason(StrEnum):       # CK_connection_requests_decision_reason
    TARGET_APPROVED = "target_approved"
    TARGET_REJECTED = "target_rejected"
    TIMEOUT = "timeout"
    REQUESTER_CANCELLED = "requester_cancelled"
    BLOCKED = "blocked"
    POLICY_DENIED = "policy_denied"
    TARGET_OFFLINE = "target_offline"


# CK_connection_requests_status_reason: which reasons each outcome may carry.
DECISION_REASONS_BY_STATUS: dict[RequestStatus, frozenset[DecisionReason]] = {
    RequestStatus.PENDING: frozenset(),
    RequestStatus.APPROVED: frozenset({DecisionReason.TARGET_APPROVED}),
    RequestStatus.REJECTED: frozenset({DecisionReason.TARGET_REJECTED, DecisionReason.BLOCKED,
                                       DecisionReason.POLICY_DENIED}),
    RequestStatus.EXPIRED: frozenset({DecisionReason.TIMEOUT, DecisionReason.TARGET_OFFLINE}),
    RequestStatus.CANCELLED: frozenset({DecisionReason.REQUESTER_CANCELLED}),
}


class SessionState(StrEnum):         # CK_sessions_state
    AUTHORIZING = "authorizing"
    ACTIVE = "active"
    ENDED = "ended"


class SessionEndReason(StrEnum):     # CK_sessions_end_reason
    CONTROLLER_DISCONNECT = "controller_disconnect"
    TARGET_DISCONNECT = "target_disconnect"
    REVOKED = "revoked"
    TIMEOUT = "timeout"
    ERROR = "error"


class AuditOutcome(StrEnum):         # CK_audit_events_outcome
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


# CK_devices_remote_id / CK_address_book_entries_remote_id: 9 digits, no leading zero.
REMOTE_ID_PATTERN = r"^[1-9][0-9]{8}$"
# CK_audit_events_event_type: lower-case dotted names, e.g. "session.ended".
AUDIT_EVENT_TYPE_PATTERN = r"^[a-z0-9_.]+$"
ED25519_PUBLIC_KEY_BYTES = 32        # CK_device_keys_public_key_length

# Column sizes (characters).
EMAIL_MAX_LENGTH = 320               # users.email, user_invitations.email
DISPLAY_NAME_MAX_LENGTH = 100        # users.display_name, devices.display_name
OS_NAME_MAX_LENGTH = 64              # devices.os_name
OS_VERSION_MAX_LENGTH = 64           # devices.os_version
CLIENT_VERSION_MAX_LENGTH = 32       # devices.client_version
ALIAS_MAX_LENGTH = 100               # address_book_entries.alias
NOTES_MAX_LENGTH = 500               # address_book_entries.notes
USER_AGENT_MAX_LENGTH = 256          # auth_sessions.user_agent
EVENT_TYPE_MAX_LENGTH = 64           # audit_events.event_type
AUDIT_DETAILS_MAX_LENGTH = 2000      # audit_events.details
