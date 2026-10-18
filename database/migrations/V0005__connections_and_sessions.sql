/*
    V0005 - Connection requests, consent and remote sessions.

    Run by:   fr_migrator.
    Effects:  creates fr.blocked_requesters, fr.connection_requests, fr.sessions.
    Re-run:   no-op when version 5 is already recorded.
    Rollback: rollback/R0005__connections_and_sessions.sql

    Every remote session is linked 1:1 to a connection request that the target device
    approved. No screen content, SDP or TURN credentials are stored.
*/
SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON;
SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; SET NUMERIC_ROUNDABORT OFF;
GO
SET XACT_ABORT ON;
SET NOCOUNT ON;

IF OBJECT_ID(N'fr.schema_migrations', N'U') IS NULL
    THROW 51001, N'fr.schema_migrations is missing. Apply V0001 first.', 1;

DECLARE @lock INT;
BEGIN TRANSACTION;
EXEC @lock = sp_getapplock @Resource = N'fr.schema_migrations', @LockMode = N'Exclusive',
                           @LockOwner = N'Transaction', @LockTimeout = 30000;
IF @lock < 0
    THROW 51004, N'Could not acquire the migration lock; another migration may be running.', 1;

IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 5)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0005 already applied; nothing to do.';
    RETURN;
END;
IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 4)
    THROW 51002, N'V0004 must be applied before V0005.', 1;
IF EXISTS (SELECT 1 FROM sys.objects WHERE schema_id = SCHEMA_ID(N'fr')
           AND name IN (N'blocked_requesters', N'connection_requests', N'sessions'))
    THROW 51003, N'Conflict: an object planned by V0005 already exists in schema fr. No changes made.', 1;

CREATE TABLE fr.blocked_requesters (
    target_device_id   UNIQUEIDENTIFIER NOT NULL,
    blocked_user_id    UNIQUEIDENTIFIER NOT NULL,
    created_at         DATETIME2(3)     NOT NULL CONSTRAINT DF_blocked_requesters_created_at DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_blocked_requesters PRIMARY KEY CLUSTERED (target_device_id, blocked_user_id),
    CONSTRAINT FK_blocked_requesters_target_device_id FOREIGN KEY (target_device_id) REFERENCES fr.devices (id),
    CONSTRAINT FK_blocked_requesters_blocked_user_id FOREIGN KEY (blocked_user_id) REFERENCES fr.users (id)
);
CREATE INDEX IX_blocked_requesters_blocked_user_id ON fr.blocked_requesters (blocked_user_id);

CREATE TABLE fr.connection_requests (
    id                   UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_connection_requests_id DEFAULT NEWSEQUENTIALID(),
    requester_user_id    UNIQUEIDENTIFIER NOT NULL,
    requester_device_id  UNIQUEIDENTIFIER NOT NULL,
    target_device_id     UNIQUEIDENTIFIER NOT NULL,
    requested_permission VARCHAR(16)      NOT NULL CONSTRAINT DF_connection_requests_requested_permission DEFAULT 'view',
    status               VARCHAR(16)      NOT NULL CONSTRAINT DF_connection_requests_status DEFAULT 'pending',
    created_at           DATETIME2(3)     NOT NULL CONSTRAINT DF_connection_requests_created_at DEFAULT SYSUTCDATETIME(),
    expires_at           DATETIME2(3)     NOT NULL,
    decided_at           DATETIME2(3)     NULL,
    decision_reason      VARCHAR(32)      NULL,
    requester_ip         VARCHAR(45)      NULL,
    -- 1 only for approved requests; lets sessions reference approved requests exclusively.
    approved_flag        AS CAST(CASE WHEN status = 'approved' THEN 1 END AS BIT) PERSISTED,
    row_version          ROWVERSION       NOT NULL,
    CONSTRAINT PK_connection_requests PRIMARY KEY CLUSTERED (id),
    CONSTRAINT UQ_connection_requests_session_link UNIQUE
        (id, requester_user_id, requester_device_id, target_device_id, requested_permission, approved_flag),
    CONSTRAINT FK_connection_requests_requester_user_id FOREIGN KEY (requester_user_id) REFERENCES fr.users (id),
    CONSTRAINT FK_connection_requests_requester_device_id FOREIGN KEY (requester_device_id) REFERENCES fr.devices (id),
    CONSTRAINT FK_connection_requests_target_device_id FOREIGN KEY (target_device_id) REFERENCES fr.devices (id),
    CONSTRAINT CK_connection_requests_requested_permission CHECK (requested_permission IN ('view', 'view_input')),
    CONSTRAINT CK_connection_requests_status CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
    CONSTRAINT CK_connection_requests_not_self CHECK (requester_device_id <> target_device_id),
    CONSTRAINT CK_connection_requests_expiry CHECK (expires_at > created_at),
    CONSTRAINT CK_connection_requests_decision CHECK (
        (status = 'pending' AND decided_at IS NULL AND decision_reason IS NULL)
        OR (status <> 'pending' AND decided_at IS NOT NULL AND decision_reason IS NOT NULL)),
    CONSTRAINT CK_connection_requests_decision_reason CHECK (decision_reason IS NULL OR decision_reason IN
        ('target_approved', 'target_rejected', 'timeout', 'requester_cancelled', 'blocked', 'policy_denied', 'target_offline')),
    -- Each outcome has a fixed set of reasons; only the target device can produce 'approved'.
    CONSTRAINT CK_connection_requests_status_reason CHECK (
        (status = 'pending' AND decision_reason IS NULL)
        OR (status = 'approved' AND decision_reason = 'target_approved')
        OR (status = 'rejected' AND decision_reason IN ('target_rejected', 'blocked', 'policy_denied'))
        OR (status = 'expired' AND decision_reason IN ('timeout', 'target_offline'))
        OR (status = 'cancelled' AND decision_reason = 'requester_cancelled'))
);
CREATE INDEX IX_connection_requests_target_pending ON fr.connection_requests (target_device_id, expires_at)
    WHERE status = 'pending';
-- Supports per-target rate limits and the target's connection history.
CREATE INDEX IX_connection_requests_target_device_id ON fr.connection_requests (target_device_id, created_at);
-- Supports per-user rate limiting and connection history.
CREATE INDEX IX_connection_requests_requester_user_id ON fr.connection_requests (requester_user_id, created_at);
CREATE INDEX IX_connection_requests_created_at ON fr.connection_requests (created_at);

CREATE TABLE fr.sessions (
    id                    UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_sessions_id DEFAULT NEWSEQUENTIALID(),
    connection_request_id UNIQUEIDENTIFIER NOT NULL,
    controller_user_id    UNIQUEIDENTIFIER NOT NULL,
    controller_device_id  UNIQUEIDENTIFIER NOT NULL,
    target_device_id      UNIQUEIDENTIFIER NOT NULL,
    requested_permission  VARCHAR(16)      NOT NULL,   -- copied from the request; checked by FK below
    permission_granted    VARCHAR(16)      NOT NULL,   -- may be reduced by the target at any time
    -- NOT NULL: SQL Server skips FK checks when any referencing column is NULL.
    request_approved      AS CAST(1 AS BIT) PERSISTED NOT NULL,
    state                 VARCHAR(16)      NOT NULL CONSTRAINT DF_sessions_state DEFAULT 'authorizing',
    created_at            DATETIME2(3)     NOT NULL CONSTRAINT DF_sessions_created_at DEFAULT SYSUTCDATETIME(),
    started_at            DATETIME2(3)     NULL,
    last_heartbeat_at     DATETIME2(3)     NULL,
    ended_at              DATETIME2(3)     NULL,
    end_reason            VARCHAR(32)      NULL,
    ended_by_user_id      UNIQUEIDENTIFIER NULL,
    ended_by_device_id    UNIQUEIDENTIFIER NULL,
    row_version           ROWVERSION       NOT NULL,
    CONSTRAINT PK_sessions PRIMARY KEY CLUSTERED (id),
    CONSTRAINT UQ_sessions_connection_request_id UNIQUE (connection_request_id),
    -- A session can only exist for an APPROVED request with the same requester, devices and
    -- requested permission. Once referenced, the request can no longer leave 'approved'.
    CONSTRAINT FK_sessions_connection_request FOREIGN KEY
        (connection_request_id, controller_user_id, controller_device_id, target_device_id, requested_permission, request_approved)
        REFERENCES fr.connection_requests
        (id, requester_user_id, requester_device_id, target_device_id, requested_permission, approved_flag),
    CONSTRAINT FK_sessions_controller_user_id FOREIGN KEY (controller_user_id) REFERENCES fr.users (id),
    CONSTRAINT FK_sessions_controller_device_id FOREIGN KEY (controller_device_id) REFERENCES fr.devices (id),
    CONSTRAINT FK_sessions_target_device_id FOREIGN KEY (target_device_id) REFERENCES fr.devices (id),
    CONSTRAINT FK_sessions_ended_by_user_id FOREIGN KEY (ended_by_user_id) REFERENCES fr.users (id),
    CONSTRAINT FK_sessions_ended_by_device_id FOREIGN KEY (ended_by_device_id) REFERENCES fr.devices (id),
    CONSTRAINT CK_sessions_permission_granted CHECK (permission_granted IN ('view', 'view_input')),
    -- Never more than was requested: input control requires a view_input request.
    CONSTRAINT CK_sessions_permission_within_request CHECK (permission_granted = 'view' OR requested_permission = 'view_input'),
    CONSTRAINT CK_sessions_state CHECK (state IN ('authorizing', 'active', 'ended')),
    CONSTRAINT CK_sessions_not_self CHECK (controller_device_id <> target_device_id),
    CONSTRAINT CK_sessions_started CHECK (state <> 'active' OR started_at IS NOT NULL),
    CONSTRAINT CK_sessions_ended CHECK (
        (state = 'ended' AND ended_at IS NOT NULL AND end_reason IS NOT NULL)
        OR (state <> 'ended' AND ended_at IS NULL AND end_reason IS NULL)),
    CONSTRAINT CK_sessions_end_reason CHECK (end_reason IS NULL OR end_reason IN
        ('controller_disconnect', 'target_disconnect', 'revoked', 'timeout', 'error'))
);
-- Pilot rule: at most one live (authorizing or active) session per target device.
CREATE UNIQUE INDEX UX_sessions_live_target ON fr.sessions (target_device_id) WHERE state <> 'ended';
CREATE INDEX IX_sessions_controller_user_id ON fr.sessions (controller_user_id, created_at);
CREATE INDEX IX_sessions_target_device_id ON fr.sessions (target_device_id, created_at);
CREATE INDEX IX_sessions_ended_at ON fr.sessions (ended_at) WHERE ended_at IS NOT NULL;

INSERT INTO fr.schema_migrations (version, description) VALUES (5, N'Connection requests and remote sessions');

COMMIT TRANSACTION;
PRINT N'V0005 applied.';
