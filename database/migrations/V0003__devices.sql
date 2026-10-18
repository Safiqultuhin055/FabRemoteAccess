/*
    V0003 - Devices and device identity.

    Run by:   fr_migrator.
    Effects:  creates fr.devices, fr.device_keys, fr.device_auth_challenges.
    Re-run:   no-op when version 3 is already recorded.
    Rollback: rollback/R0003__devices.sql

    Only PUBLIC keys are stored. Device private keys stay on the device, protected by
    Windows DPAPI (Credential Manager). The Remote ID is an identifier, not a credential.
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

IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 3)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0003 already applied; nothing to do.';
    RETURN;
END;
IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 2)
    THROW 51002, N'V0002 must be applied before V0003.', 1;
IF EXISTS (SELECT 1 FROM sys.objects WHERE schema_id = SCHEMA_ID(N'fr')
           AND name IN (N'devices', N'device_keys', N'device_auth_challenges'))
    THROW 51003, N'Conflict: an object planned by V0003 already exists in schema fr. No changes made.', 1;

CREATE TABLE fr.devices (
    id                 UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_devices_id DEFAULT NEWSEQUENTIALID(),
    owner_user_id      UNIQUEIDENTIFIER NOT NULL,
    remote_id          CHAR(9)          NOT NULL,
    display_name       NVARCHAR(100)    NOT NULL,
    os_name            NVARCHAR(64)     NULL,
    os_version         NVARCHAR(64)     NULL,
    client_version     VARCHAR(32)      NULL,
    incoming_policy    VARCHAR(24)      NOT NULL CONSTRAINT DF_devices_incoming_policy DEFAULT 'verified_users',
    status             VARCHAR(16)      NOT NULL CONSTRAINT DF_devices_status DEFAULT 'active',
    created_at         DATETIME2(3)     NOT NULL CONSTRAINT DF_devices_created_at DEFAULT SYSUTCDATETIME(),
    updated_at         DATETIME2(3)     NOT NULL CONSTRAINT DF_devices_updated_at DEFAULT SYSUTCDATETIME(),
    last_seen_at       DATETIME2(3)     NULL,
    last_ip            VARCHAR(45)      NULL,
    last_ip_at         DATETIME2(3)     NULL,
    revoked_at         DATETIME2(3)     NULL,
    revoked_by_user_id UNIQUEIDENTIFIER NULL,
    revoked_reason     VARCHAR(32)      NULL,
    row_version        ROWVERSION       NOT NULL,
    CONSTRAINT PK_devices PRIMARY KEY CLUSTERED (id),
    -- Unique across all rows, including revoked devices: a Remote ID is never reassigned.
    CONSTRAINT UQ_devices_remote_id UNIQUE (remote_id),
    CONSTRAINT FK_devices_owner_user_id FOREIGN KEY (owner_user_id) REFERENCES fr.users (id),
    CONSTRAINT FK_devices_revoked_by_user_id FOREIGN KEY (revoked_by_user_id) REFERENCES fr.users (id),
    CONSTRAINT CK_devices_remote_id CHECK (remote_id NOT LIKE '%[^0-9]%' AND remote_id NOT LIKE '0%'),
    CONSTRAINT CK_devices_incoming_policy CHECK (incoming_policy IN ('verified_users', 'address_book_only', 'disabled')),
    CONSTRAINT CK_devices_status CHECK (status IN ('active', 'revoked')),
    CONSTRAINT CK_devices_revocation CHECK (
        (status = 'active' AND revoked_at IS NULL AND revoked_reason IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL AND revoked_reason IS NOT NULL)),
    CONSTRAINT CK_devices_revoked_reason CHECK (revoked_reason IS NULL
        OR revoked_reason IN ('owner_removed', 'admin_revoked', 'key_compromised', 'user_disabled')),
    CONSTRAINT CK_devices_last_ip CHECK ((last_ip IS NULL AND last_ip_at IS NULL) OR (last_ip IS NOT NULL AND last_ip_at IS NOT NULL))
);
CREATE INDEX IX_devices_owner_user_id ON fr.devices (owner_user_id) INCLUDE (status, remote_id);
CREATE INDEX IX_devices_last_ip_at ON fr.devices (last_ip_at) WHERE last_ip_at IS NOT NULL;

CREATE TABLE fr.device_keys (
    id             UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_device_keys_id DEFAULT NEWSEQUENTIALID(),
    device_id      UNIQUEIDENTIFIER NOT NULL,
    algorithm      VARCHAR(16)      NOT NULL CONSTRAINT DF_device_keys_algorithm DEFAULT 'ed25519',
    public_key     VARBINARY(64)    NOT NULL,
    -- Derived by the database so it can never disagree with public_key.
    fingerprint    AS CAST(HASHBYTES('SHA2_256', public_key) AS BINARY(32)) PERSISTED NOT NULL,
    created_at     DATETIME2(3)     NOT NULL CONSTRAINT DF_device_keys_created_at DEFAULT SYSUTCDATETIME(),
    revoked_at     DATETIME2(3)     NULL,
    revoked_reason VARCHAR(32)      NULL,
    CONSTRAINT PK_device_keys PRIMARY KEY CLUSTERED (id),
    CONSTRAINT UQ_device_keys_fingerprint UNIQUE (fingerprint),
    CONSTRAINT FK_device_keys_device_id FOREIGN KEY (device_id) REFERENCES fr.devices (id),
    CONSTRAINT CK_device_keys_algorithm CHECK (algorithm IN ('ed25519')),
    CONSTRAINT CK_device_keys_public_key_length CHECK (algorithm <> 'ed25519' OR DATALENGTH(public_key) = 32),
    CONSTRAINT CK_device_keys_revocation CHECK (
        (revoked_at IS NULL AND revoked_reason IS NULL) OR (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL)),
    CONSTRAINT CK_device_keys_revoked_reason CHECK (revoked_reason IS NULL
        OR revoked_reason IN ('rotated', 'device_revoked', 'key_compromised'))
);
-- At most one active key per device.
CREATE UNIQUE INDEX UX_device_keys_active_device ON fr.device_keys (device_id) WHERE revoked_at IS NULL;

-- Single-use nonces signed by the device private key to obtain a short-lived device token.
CREATE TABLE fr.device_auth_challenges (
    id         UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_device_auth_challenges_id DEFAULT NEWSEQUENTIALID(),
    device_id  UNIQUEIDENTIFIER NOT NULL,
    nonce      BINARY(32)       NOT NULL,
    created_at DATETIME2(3)     NOT NULL CONSTRAINT DF_device_auth_challenges_created_at DEFAULT SYSUTCDATETIME(),
    expires_at DATETIME2(3)     NOT NULL,
    used_at    DATETIME2(3)     NULL,
    CONSTRAINT PK_device_auth_challenges PRIMARY KEY CLUSTERED (id),
    CONSTRAINT UQ_device_auth_challenges_nonce UNIQUE (nonce),
    CONSTRAINT FK_device_auth_challenges_device_id FOREIGN KEY (device_id) REFERENCES fr.devices (id),
    CONSTRAINT CK_device_auth_challenges_expiry CHECK (expires_at > created_at)
);
CREATE INDEX IX_device_auth_challenges_device_id ON fr.device_auth_challenges (device_id);
CREATE INDEX IX_device_auth_challenges_expires_at ON fr.device_auth_challenges (expires_at);

INSERT INTO fr.schema_migrations (version, description) VALUES (3, N'Devices and device identity');

COMMIT TRANSACTION;
PRINT N'V0003 applied.';
