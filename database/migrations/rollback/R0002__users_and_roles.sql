/*
    R0002 - Roll back V0002 (users, roles and invitations).

    Run by:   fr_migrator, only with an approved rollback plan.
    Guards:   no-op if V0002 is not applied; refuses if a later version is applied;
              refuses if the affected tables contain data (restore from backup instead).
    Effects:  drops the objects created by V0002 and removes its history row.
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

IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 2)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0002 is not applied; nothing to roll back.';
    RETURN;
END;
IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version > 2)
    THROW 51010, N'Later migrations are applied. Roll them back first, newest first. No changes made.', 1;
-- fr.roles holds only seed data and is not checked.
IF EXISTS (SELECT 1 FROM fr.user_invitations)
   OR EXISTS (SELECT 1 FROM fr.user_roles)
   OR EXISTS (SELECT 1 FROM fr.users)
    THROW 51011, N'Tables created by this migration contain data. Rolling back would destroy it; restore from backup instead. No changes made.', 1;
DROP TABLE fr.user_invitations;
DROP TABLE fr.user_roles;
DROP TABLE fr.users;
DROP TABLE fr.roles;
DELETE FROM fr.schema_migrations WHERE version = 2;
COMMIT TRANSACTION;
PRINT N'V0002 rolled back.';
