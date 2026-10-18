/*
    V0008 - Device registration: permanent Remote ID registry and registration challenges.

    Run by:   fr_migrator, after V0007. Then re-run permissions/P002 (grants for the new tables).
    Effects:  creates fr.remote_id_registry (append-only record of every Remote ID ever
              issued), back-fills it from fr.devices, adds FK_devices_remote_id so every device
              must use a registered ID, and creates fr.device_registration_challenges.
    Re-run:   no-op when version 8 is already recorded.
    Rollback: rollback/R0008__device_registration.sql

    Why a registry: UQ_devices_remote_id only prevents duplicates among rows that still
    exist. The registry has no foreign keys to devices and the application role may only
    INSERT/SELECT it (P002), so an ID stays allocated even if a device row were ever removed.
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

IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 8)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0008 already applied; nothing to do.';
    RETURN;
END;
IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 7)
    THROW 51002, N'V0007 must be applied before V0008.', 1;
IF EXISTS (SELECT 1 FROM sys.objects WHERE schema_id = SCHEMA_ID(N'fr')
           AND name IN (N'remote_id_registry', N'device_registration_challenges', N'FK_devices_remote_id'))
    THROW 51003, N'Conflict: an object planned by V0008 already exists in schema fr. No changes made.', 1;

CREATE TABLE fr.remote_id_registry (
    remote_id    CHAR(9)      NOT NULL,
    allocated_at DATETIME2(3) NOT NULL CONSTRAINT DF_remote_id_registry_allocated_at DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_remote_id_registry PRIMARY KEY CLUSTERED (remote_id),
    CONSTRAINT CK_remote_id_registry_remote_id CHECK (remote_id NOT LIKE '%[^0-9]%' AND remote_id NOT LIKE '0%')
);

-- Existing devices keep their IDs; they become permanent allocations.
INSERT INTO fr.remote_id_registry (remote_id, allocated_at)
SELECT remote_id, created_at FROM fr.devices;

ALTER TABLE fr.devices ADD CONSTRAINT FK_devices_remote_id
    FOREIGN KEY (remote_id) REFERENCES fr.remote_id_registry (remote_id);

-- A registration attempt: bound to the user, their auth session and the proposed public key.
-- The device signs the nonce; only then is a Remote ID allocated. Single use, short-lived.
CREATE TABLE fr.device_registration_challenges (
    id              UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_device_registration_challenges_id DEFAULT NEWSEQUENTIALID(),
    user_id         UNIQUEIDENTIFIER NOT NULL,
    auth_session_id UNIQUEIDENTIFIER NOT NULL,
    algorithm       VARCHAR(16)      NOT NULL CONSTRAINT DF_device_registration_challenges_algorithm DEFAULT 'ed25519',
    public_key      VARBINARY(64)    NOT NULL,
    key_fingerprint AS CAST(HASHBYTES('SHA2_256', public_key) AS BINARY(32)) PERSISTED NOT NULL,
    device_name     NVARCHAR(100)    NOT NULL,
    os_name         NVARCHAR(64)     NULL,
    os_version      NVARCHAR(64)     NULL,
    client_version  VARCHAR(32)      NULL,
    nonce           BINARY(32)       NOT NULL,
    created_at      DATETIME2(3)     NOT NULL CONSTRAINT DF_device_registration_challenges_created_at DEFAULT SYSUTCDATETIME(),
    expires_at      DATETIME2(3)     NOT NULL,
    consumed_at     DATETIME2(3)     NULL,
    CONSTRAINT PK_device_registration_challenges PRIMARY KEY CLUSTERED (id),
    CONSTRAINT UQ_device_registration_challenges_nonce UNIQUE (nonce),
    CONSTRAINT FK_device_registration_challenges_user_id FOREIGN KEY (user_id) REFERENCES fr.users (id),
    CONSTRAINT FK_device_registration_challenges_auth_session_id
        FOREIGN KEY (auth_session_id) REFERENCES fr.auth_sessions (id),
    CONSTRAINT CK_device_registration_challenges_algorithm CHECK (algorithm IN ('ed25519')),
    CONSTRAINT CK_device_registration_challenges_public_key_length
        CHECK (algorithm <> 'ed25519' OR DATALENGTH(public_key) = 32),
    CONSTRAINT CK_device_registration_challenges_expiry CHECK (expires_at > created_at)
);
CREATE INDEX IX_device_registration_challenges_user_id ON fr.device_registration_challenges (user_id, created_at);
CREATE INDEX IX_device_registration_challenges_expires_at ON fr.device_registration_challenges (expires_at);

INSERT INTO fr.schema_migrations (version, description) VALUES (8, N'Device registration: Remote ID registry and challenges');

COMMIT TRANSACTION;
PRINT N'V0008 applied.';
