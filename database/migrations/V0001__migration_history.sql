/*
    V0001 - Migration history table.

    Run by:   fr_migrator, after permissions/P001.
    Effects:  creates fr.schema_migrations and records version 1.
    Re-run:   no-op when version 1 is already recorded.
    Rollback: rollback/R0001__migration_history.sql
*/
SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON;
SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; SET NUMERIC_ROUNDABORT OFF;
GO
SET XACT_ABORT ON;
SET NOCOUNT ON;

IF SCHEMA_ID(N'fr') IS NULL
    THROW 51000, N'Schema fr does not exist. Run database/permissions/P001 first.', 1;
IF NOT EXISTS (SELECT 1 FROM sys.schemas s
               JOIN sys.database_principals p ON p.principal_id = s.principal_id
               WHERE s.name = N'fr' AND p.name = N'fr_owner')
    THROW 51000, N'Schema fr must be owned by fr_owner (see P001). No changes made.', 1;

DECLARE @lock INT;
BEGIN TRANSACTION;
EXEC @lock = sp_getapplock @Resource = N'fr.schema_migrations', @LockMode = N'Exclusive',
                           @LockOwner = N'Transaction', @LockTimeout = 30000;
IF @lock < 0
    THROW 51004, N'Could not acquire the migration lock; another migration may be running.', 1;

IF OBJECT_ID(N'fr.schema_migrations', N'U') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 1)
    BEGIN
        COMMIT TRANSACTION;
        PRINT N'V0001 already applied; nothing to do.';
        RETURN;
    END;
    THROW 51003, N'Conflict: fr.schema_migrations exists but does not record version 1. No changes made.', 1;
END;

CREATE TABLE fr.schema_migrations (
    version     INT           NOT NULL,
    description NVARCHAR(200) NOT NULL,
    applied_at  DATETIME2(3)  NOT NULL CONSTRAINT DF_schema_migrations_applied_at DEFAULT SYSUTCDATETIME(),
    applied_by  NVARCHAR(128) NOT NULL CONSTRAINT DF_schema_migrations_applied_by DEFAULT ORIGINAL_LOGIN(),
    CONSTRAINT PK_schema_migrations PRIMARY KEY CLUSTERED (version),
    CONSTRAINT CK_schema_migrations_version CHECK (version > 0)
);

INSERT INTO fr.schema_migrations (version, description) VALUES (1, N'Migration history');

COMMIT TRANSACTION;
PRINT N'V0001 applied.';
