/*
    PR001 - Reverse P001-P003 (full decommission of the fr schema and roles).

    Run by:   a DBA (db_owner), only after ALL migrations have been rolled back
              (rollback/R0007 ... R0001) and with an approved plan.
    Guards:   refuses if schema fr still contains any object.
    Effects:  removes all members from fr_migrator / fr_app_runtime / fr_maintenance,
              drops those roles, schema fr and user fr_owner.
              Database users created by P003 for logins are NOT dropped automatically;
              review and drop them with DROP USER if they are no longer needed.
*/
SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON;
SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; SET NUMERIC_ROUNDABORT OFF;
GO
SET XACT_ABORT ON;
SET NOCOUNT ON;

IF IS_MEMBER(N'db_owner') <> 1
    THROW 51200, N'PR001 must be run by a member of db_owner in the target database.', 1;
IF SCHEMA_ID(N'fr') IS NOT NULL AND EXISTS (SELECT 1 FROM sys.objects WHERE schema_id = SCHEMA_ID(N'fr'))
    THROW 51230, N'Schema fr still contains objects. Roll back all migrations first. No changes made.', 1;

DECLARE @role SYSNAME, @member SYSNAME, @sql NVARCHAR(600);

BEGIN TRANSACTION;

DECLARE member_cursor CURSOR LOCAL FAST_FORWARD FOR
    SELECT r.name, m.name
    FROM sys.database_role_members rm
    JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
    JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id
    WHERE r.name IN (N'fr_migrator', N'fr_app_runtime', N'fr_maintenance');
OPEN member_cursor;
FETCH NEXT FROM member_cursor INTO @role, @member;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @sql = N'ALTER ROLE ' + QUOTENAME(@role) + N' DROP MEMBER ' + QUOTENAME(@member) + N';';
    EXEC sys.sp_executesql @sql;
    FETCH NEXT FROM member_cursor INTO @role, @member;
END;
CLOSE member_cursor;
DEALLOCATE member_cursor;

IF DATABASE_PRINCIPAL_ID(N'fr_maintenance') IS NOT NULL DROP ROLE fr_maintenance;
IF DATABASE_PRINCIPAL_ID(N'fr_app_runtime') IS NOT NULL DROP ROLE fr_app_runtime;
IF DATABASE_PRINCIPAL_ID(N'fr_migrator') IS NOT NULL    DROP ROLE fr_migrator;
IF SCHEMA_ID(N'fr') IS NOT NULL                         DROP SCHEMA fr;
IF USER_ID(N'fr_owner') IS NOT NULL                     DROP USER fr_owner;

COMMIT TRANSACTION;
PRINT N'PR001 complete. Review database users created by P003 and drop them if no longer needed.';
