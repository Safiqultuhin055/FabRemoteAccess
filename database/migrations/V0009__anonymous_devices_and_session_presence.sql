/*
    V0009 - Devices without an account (the helped computer) and per-side session presence.

    Run by:   fr_migrator, after V0008. No new tables, so P002 does not need to be re-run.
    Effects:  - fr.devices.owner_user_id becomes NULLable: a device registered without signing
                in (proof of key possession only). Such a device can only use the
                'verified_users' or 'disabled' incoming policy (no owner, no address book).
              - fr.device_registration_challenges.user_id / auth_session_id become NULLable,
                both or neither (anonymous registration attempts).
              - fr.sessions gets controller_seen_at and target_seen_at, so a session ends
                when either side stops responding (not only when both do).
    Re-run:   no-op when version 9 is already recorded.
    Rollback: rollback/R0009__anonymous_devices_and_session_presence.sql

    Consent is unchanged: a connection request still needs a signed-in requester
    (requester_user_id NOT NULL) and only the target device can approve it.
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

IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 9)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0009 already applied; nothing to do.';
    RETURN;
END;
IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 8)
    THROW 51002, N'V0008 must be applied before V0009.', 1;
IF EXISTS (SELECT 1 FROM sys.objects WHERE schema_id = SCHEMA_ID(N'fr')
           AND name IN (N'CK_devices_anonymous_policy', N'CK_device_registration_challenges_owner'))
   OR COL_LENGTH(N'fr.sessions', N'controller_seen_at') IS NOT NULL
   OR COL_LENGTH(N'fr.sessions', N'target_seen_at') IS NOT NULL
    THROW 51003, N'Conflict: an object planned by V0009 already exists in schema fr. No changes made.', 1;

-- Devices: the owner becomes optional (its index and foreign key stay in place).
ALTER TABLE fr.devices ALTER COLUMN owner_user_id UNIQUEIDENTIFIER NULL;
-- A device without an owner has no address book to check against.
ALTER TABLE fr.devices ADD CONSTRAINT CK_devices_anonymous_policy
    CHECK (owner_user_id IS NOT NULL OR incoming_policy IN ('verified_users', 'disabled'));

-- Registration challenges: anonymous attempts carry neither a user nor an auth session.
ALTER TABLE fr.device_registration_challenges ALTER COLUMN user_id UNIQUEIDENTIFIER NULL;
ALTER TABLE fr.device_registration_challenges ALTER COLUMN auth_session_id UNIQUEIDENTIFIER NULL;
ALTER TABLE fr.device_registration_challenges ADD CONSTRAINT CK_device_registration_challenges_owner
    CHECK ((user_id IS NULL AND auth_session_id IS NULL) OR (user_id IS NOT NULL AND auth_session_id IS NOT NULL));

-- Sessions: when each side was last heard from (server time).
ALTER TABLE fr.sessions ADD controller_seen_at DATETIME2(3) NULL, target_seen_at DATETIME2(3) NULL;

INSERT INTO fr.schema_migrations (version, description) VALUES (9, N'Devices without an account; per-side session presence');

COMMIT TRANSACTION;
PRINT N'V0009 applied.';
