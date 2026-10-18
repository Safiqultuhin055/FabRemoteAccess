/*
    P003 - Map existing server logins to the Fabulous Remote roles.

    Run by:   a DBA (db_owner) after P001. Logins must already exist; this script never
              creates logins and contains no passwords. Pass names as sqlcmd variables:

        sqlcmd -S <server> -d FabRemotesDB -E -N -b -I -i P003_map_logins_to_roles.sql ^
               -v MigratorLogin="<login>" AppLogin="<login>" MaintenanceLogin="<login>"

    Rules enforced (any violation aborts with no changes):
      - each login exists and is not sa / sysadmin;
      - the migrator login differs from the runtime and maintenance logins
        (maintenance MAY equal the runtime login during the pilot);
      - mapped database users are not dbo and belong to no fixed database role
        (db_owner, db_datawriter, db_datareader, ...) and to no other fr_* role.
    Safe to re-run.
*/
SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON;
SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; SET NUMERIC_ROUNDABORT OFF;
GO
SET XACT_ABORT ON;
SET NOCOUNT ON;

DECLARE @migrator_login    SYSNAME = N'$(MigratorLogin)';
DECLARE @app_login         SYSNAME = N'$(AppLogin)';
DECLARE @maintenance_login SYSNAME = N'$(MaintenanceLogin)';

IF IS_MEMBER(N'db_owner') <> 1
    THROW 51200, N'P003 must be run by a member of db_owner in the target database.', 1;
IF DATABASE_PRINCIPAL_ID(N'fr_migrator') IS NULL OR DATABASE_PRINCIPAL_ID(N'fr_app_runtime') IS NULL
   OR DATABASE_PRINCIPAL_ID(N'fr_maintenance') IS NULL
    THROW 51210, N'Roles are missing. Run P001 first.', 1;
IF @migrator_login IN (@app_login, @maintenance_login)
    THROW 51220, N'The migrator login must be different from the runtime and maintenance logins.', 1;

DECLARE @map TABLE (login_name SYSNAME NOT NULL, role_name SYSNAME NOT NULL, user_name SYSNAME NULL);
INSERT INTO @map (login_name, role_name) VALUES
    (@migrator_login, N'fr_migrator'), (@app_login, N'fr_app_runtime'), (@maintenance_login, N'fr_maintenance');

IF EXISTS (SELECT 1 FROM @map m WHERE NOT EXISTS
           (SELECT 1 FROM sys.server_principals sp WHERE sp.name = m.login_name AND sp.type IN ('S', 'U', 'G', 'E', 'X')))
    THROW 51221, N'A login passed to P003 does not exist. Create it first (see docs/DATABASE_DESIGN.md).', 1;
IF EXISTS (SELECT 1 FROM @map m JOIN sys.server_principals sp ON sp.name = m.login_name
           WHERE sp.sid = 0x01 OR IS_SRVROLEMEMBER(N'sysadmin', m.login_name) = 1)
    THROW 51222, N'sa and sysadmin logins must not be used by Fabulous Remote.', 1;

-- Resolve existing database users by SID.
UPDATE m SET user_name = dp.name
FROM @map m
JOIN sys.server_principals sp ON sp.name = m.login_name
JOIN sys.database_principals dp ON dp.sid = sp.sid;

IF EXISTS (SELECT 1 FROM @map WHERE user_name = N'dbo')
    THROW 51223, N'A login maps to dbo (database owner). Use a dedicated login.', 1;
IF EXISTS (SELECT 1 FROM @map m
           JOIN sys.database_role_members rm ON rm.member_principal_id = DATABASE_PRINCIPAL_ID(m.user_name)
           JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
           WHERE r.is_fixed_role = 1)
    THROW 51224, N'A mapped user belongs to a fixed database role (e.g. db_owner, db_datawriter). Remove it first.', 1;
IF EXISTS (SELECT 1 FROM @map m
           JOIN sys.database_role_members rm ON rm.member_principal_id = DATABASE_PRINCIPAL_ID(m.user_name)
           JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
           WHERE r.name LIKE N'fr[_]%'
             AND NOT EXISTS (SELECT 1 FROM @map m2 WHERE m2.login_name = m.login_name AND m2.role_name = r.name))
    THROW 51225, N'A mapped user already belongs to a different fr_* role. Review manually.', 1;

DECLARE @login SYSNAME, @role SYSNAME, @user SYSNAME, @sql NVARCHAR(600);

BEGIN TRANSACTION;

DECLARE map_cursor CURSOR LOCAL FAST_FORWARD FOR SELECT login_name, role_name, user_name FROM @map;
OPEN map_cursor;
FETCH NEXT FROM map_cursor INTO @login, @role, @user;
WHILE @@FETCH_STATUS = 0
BEGIN
    IF @user IS NULL
    BEGIN
        -- A previous iteration may have created the user (maintenance = runtime login).
        SELECT @user = dp.name FROM sys.database_principals dp
        JOIN sys.server_principals sp ON sp.sid = dp.sid WHERE sp.name = @login;
    END;
    IF @user IS NULL
    BEGIN
        SET @sql = N'CREATE USER ' + QUOTENAME(@login) + N' FOR LOGIN ' + QUOTENAME(@login) + N' WITH DEFAULT_SCHEMA = fr;';
        EXEC sys.sp_executesql @sql;
        SET @user = @login;
    END;
    IF IS_ROLEMEMBER(@role, @user) <> 1
    BEGIN
        SET @sql = N'ALTER ROLE ' + QUOTENAME(@role) + N' ADD MEMBER ' + QUOTENAME(@user) + N';';
        EXEC sys.sp_executesql @sql;
    END;
    FETCH NEXT FROM map_cursor INTO @login, @role, @user;
END;
CLOSE map_cursor;
DEALLOCATE map_cursor;

COMMIT TRANSACTION;
PRINT N'P003 complete: logins mapped to fr_migrator, fr_app_runtime and fr_maintenance.';
