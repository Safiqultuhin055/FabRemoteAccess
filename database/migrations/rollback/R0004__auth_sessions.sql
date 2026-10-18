/*
    R0004 - Roll back V0004 (authentication sessions and tokens).

    Run by:   fr_migrator, only with an approved rollback plan.
    Guards:   no-op if V0004 is not applied; refuses if a later version is applied;
              refuses if the affected tables contain data (restore from backup instead).
    Effects:  drops the objects created by V0004 and removes its history row.
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

IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 4)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0004 is not applied; nothing to roll back.';
    RETURN;
END;
IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version > 4)
    THROW 51010, N'Later migrations are applied. Roll them back first, newest first. No changes made.', 1;
IF EXISTS (SELECT 1 FROM fr.auth_tokens)
   OR EXISTS (SELECT 1 FROM fr.auth_sessions)
    THROW 51011, N'Tables created by this migration contain data. Rolling back would destroy it; restore from backup instead. No changes made.', 1;
DROP TABLE fr.auth_tokens;
DROP TABLE fr.auth_sessions;
DELETE FROM fr.schema_migrations WHERE version = 4;
COMMIT TRANSACTION;
PRINT N'V0004 rolled back.';
