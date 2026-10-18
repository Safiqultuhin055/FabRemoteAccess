/*
    R0009 - Roll back V0009 (devices without an account; per-side session presence).

    Run by:   fr_migrator, only with an approved rollback plan.
    Guards:   no-op if V0009 is not applied; refuses if a later version is applied;
              refuses while any device or registration challenge has no owner, or any
              session has per-side presence recorded (restore from backup instead).
    Effects:  restores NOT NULL owners, drops the V0009 constraints and session columns,
              and removes its history row.
*/
SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON;
SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; SET NUMERIC_ROUNDABORT OFF;
GO
SET XACT_ABORT ON;
SET NOCOUNT ON;

IF OBJECT_ID(N'fr.schema_migrations', N'U') IS NULL
BEGIN
    PRINT N'fr.schema_migrations does not exist; nothing to roll back.';
    RETURN;
END;

DECLARE @lock INT;
BEGIN TRANSACTION;
EXEC @lock = sp_getapplock @Resource = N'fr.schema_migrations', @LockMode = N'Exclusive',
                           @LockOwner = N'Transaction', @LockTimeout = 30000;
IF @lock < 0
    THROW 51004, N'Could not acquire the migration lock; another migration may be running.', 1;

IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 9)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0009 is not applied; nothing to roll back.';
    RETURN;
END;
IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version > 9)
    THROW 51010, N'Later migrations are applied. Roll them back first, newest first. No changes made.', 1;
IF EXISTS (SELECT 1 FROM fr.devices WHERE owner_user_id IS NULL)
   OR EXISTS (SELECT 1 FROM fr.device_registration_challenges WHERE user_id IS NULL)
   OR EXISTS (SELECT 1 FROM fr.sessions WHERE controller_seen_at IS NOT NULL OR target_seen_at IS NOT NULL)
    THROW 51011, N'Data created under this migration exists. Rolling back would destroy it; restore from backup instead. No changes made.', 1;

ALTER TABLE fr.sessions DROP COLUMN controller_seen_at, target_seen_at;

ALTER TABLE fr.device_registration_challenges DROP CONSTRAINT CK_device_registration_challenges_owner;
-- An indexed column cannot become NOT NULL in place: rebuild the index around the change.
DROP INDEX IX_device_registration_challenges_user_id ON fr.device_registration_challenges;
ALTER TABLE fr.device_registration_challenges ALTER COLUMN user_id UNIQUEIDENTIFIER NOT NULL;
ALTER TABLE fr.device_registration_challenges ALTER COLUMN auth_session_id UNIQUEIDENTIFIER NOT NULL;
CREATE INDEX IX_device_registration_challenges_user_id ON fr.device_registration_challenges (user_id, created_at);

ALTER TABLE fr.devices DROP CONSTRAINT CK_devices_anonymous_policy;
DROP INDEX IX_devices_owner_user_id ON fr.devices;
ALTER TABLE fr.devices ALTER COLUMN owner_user_id UNIQUEIDENTIFIER NOT NULL;
CREATE INDEX IX_devices_owner_user_id ON fr.devices (owner_user_id) INCLUDE (status, remote_id);

DELETE FROM fr.schema_migrations WHERE version = 9;
COMMIT TRANSACTION;
PRINT N'V0009 rolled back.';
