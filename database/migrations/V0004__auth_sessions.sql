/*
    V0004 - Authentication sessions and tokens.

    Run by:   fr_migrator.
    Effects:  creates fr.auth_sessions (one row per login / refresh-token family)
              and fr.auth_tokens (refresh and web-session tokens, stored as SHA-256 hashes).
    Re-run:   no-op when version 4 is already recorded.
    Rollback: rollback/R0004__auth_sessions.sql

    Access tokens, device tokens, remote-session tokens and TURN credentials are
    short-lived and derived/signed at runtime; they are never stored.
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

IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 4)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0004 already applied; nothing to do.';
    RETURN;
END;
IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 3)
    THROW 51002, N'V0003 must be applied before V0004.', 1;
IF EXISTS (SELECT 1 FROM sys.objects WHERE schema_id = SCHEMA_ID(N'fr')
           AND name IN (N'auth_sessions', N'auth_tokens'))
    THROW 51003, N'Conflict: an object planned by V0004 already exists in schema fr. No changes made.', 1;

CREATE TABLE fr.auth_sessions (
    id             UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_auth_sessions_id DEFAULT NEWSEQUENTIALID(),
    user_id        UNIQUEIDENTIFIER NOT NULL,
    client_type    VARCHAR(16)      NOT NULL,
    device_id      UNIQUEIDENTIFIER NULL,   -- set once the desktop client registers its device
    created_at     DATETIME2(3)     NOT NULL CONSTRAINT DF_auth_sessions_created_at DEFAULT SYSUTCDATETIME(),
    last_used_at   DATETIME2(3)     NULL,
    expires_at     DATETIME2(3)     NOT NULL,
    revoked_at     DATETIME2(3)     NULL,
    revoked_reason VARCHAR(32)      NULL,
    user_agent     NVARCHAR(256)    NULL,
    created_ip     VARCHAR(45)      NULL,
    row_version    ROWVERSION       NOT NULL,
    CONSTRAINT PK_auth_sessions PRIMARY KEY CLUSTERED (id),
    CONSTRAINT FK_auth_sessions_user_id FOREIGN KEY (user_id) REFERENCES fr.users (id),
    CONSTRAINT FK_auth_sessions_device_id FOREIGN KEY (device_id) REFERENCES fr.devices (id),
    CONSTRAINT CK_auth_sessions_client_type CHECK (client_type IN ('web', 'desktop')),
    CONSTRAINT CK_auth_sessions_expiry CHECK (expires_at > created_at),
    CONSTRAINT CK_auth_sessions_revocation CHECK (
        (revoked_at IS NULL AND revoked_reason IS NULL) OR (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL)),
    CONSTRAINT CK_auth_sessions_revoked_reason CHECK (revoked_reason IS NULL OR revoked_reason IN
        ('logout', 'admin_revoked', 'token_reuse', 'password_changed', 'user_disabled', 'device_revoked'))
);
CREATE INDEX IX_auth_sessions_user_id ON fr.auth_sessions (user_id) INCLUDE (revoked_at, expires_at);
CREATE INDEX IX_auth_sessions_device_id ON fr.auth_sessions (device_id) WHERE device_id IS NOT NULL;
CREATE INDEX IX_auth_sessions_expires_at ON fr.auth_sessions (expires_at);

-- Refresh tokens rotate on every use: the old row gets consumed_at. Presenting a consumed
-- token is treated as theft and revokes the whole auth_session (reuse detection).
CREATE TABLE fr.auth_tokens (
    id              UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_auth_tokens_id DEFAULT NEWSEQUENTIALID(),
    auth_session_id UNIQUEIDENTIFIER NOT NULL,
    token_type      VARCHAR(16)      NOT NULL,
    token_hash      BINARY(32)       NOT NULL,   -- SHA-256 of a 256-bit random token
    issued_at       DATETIME2(3)     NOT NULL CONSTRAINT DF_auth_tokens_issued_at DEFAULT SYSUTCDATETIME(),
    expires_at      DATETIME2(3)     NOT NULL,
    consumed_at     DATETIME2(3)     NULL,
    revoked_at      DATETIME2(3)     NULL,
    CONSTRAINT PK_auth_tokens PRIMARY KEY CLUSTERED (id),
    CONSTRAINT UQ_auth_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT FK_auth_tokens_auth_session_id FOREIGN KEY (auth_session_id) REFERENCES fr.auth_sessions (id),
    CONSTRAINT CK_auth_tokens_token_type CHECK (token_type IN ('refresh', 'web')),
    CONSTRAINT CK_auth_tokens_expiry CHECK (expires_at > issued_at)
);
CREATE INDEX IX_auth_tokens_auth_session_id ON fr.auth_tokens (auth_session_id);
CREATE INDEX IX_auth_tokens_expires_at ON fr.auth_tokens (expires_at);

INSERT INTO fr.schema_migrations (version, description) VALUES (4, N'Authentication sessions and tokens');

COMMIT TRANSACTION;
PRINT N'V0004 applied.';
