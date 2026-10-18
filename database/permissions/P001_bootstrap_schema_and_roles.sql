/*
    P001 - Bootstrap schema fr and database roles.

    Run by:   a DBA (db_owner or equivalent) in FabRemotesDB, BEFORE any migration.
    Effects:  creates user fr_owner (WITHOUT LOGIN), schema fr owned by fr_owner,
              roles fr_migrator / fr_app_runtime / fr_maintenance, and the
              migrator's DDL permissions limited to schema fr.
    Safe to re-run: existing objects are verified, never dropped or altered.
    Touches nothing outside schema fr except the three roles and the fr_owner user.

    Why fr_owner: objects in fr are owned by a principal that owns nothing else, so
    ownership chaining can never be used from fr to read objects in other schemas.
*/
SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON;
SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; SET NUMERIC_ROUNDABORT OFF;
GO
SET XACT_ABORT ON;
SET NOCOUNT ON;

IF IS_MEMBER(N'db_owner') <> 1
    THROW 51200, N'P001 must be run by a member of db_owner in the target database.', 1;

-- Pre-flight: an existing principal with one of our names must have the expected type.
IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'fr_owner' AND type <> 'S')
    THROW 51201, N'A principal named fr_owner exists but is not a user WITHOUT LOGIN. Review manually; no changes made.', 1;
IF EXISTS (SELECT 1 FROM sys.database_principals
           WHERE name IN (N'fr_migrator', N'fr_app_runtime', N'fr_maintenance') AND type <> 'R')
    THROW 51202, N'A non-role principal uses a reserved fr_* role name. Review manually; no changes made.', 1;
IF SCHEMA_ID(N'fr') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sys.schemas s
                   JOIN sys.database_principals p ON p.principal_id = s.principal_id
                   WHERE s.name = N'fr' AND p.name = N'fr_owner')
    THROW 51203, N'Schema fr already exists with a different owner. Review manually; no changes made.', 1;

BEGIN TRANSACTION;

IF USER_ID(N'fr_owner') IS NULL
    CREATE USER fr_owner WITHOUT LOGIN WITH DEFAULT_SCHEMA = fr;

IF SCHEMA_ID(N'fr') IS NULL
    EXEC (N'CREATE SCHEMA fr AUTHORIZATION fr_owner;');

IF DATABASE_PRINCIPAL_ID(N'fr_migrator') IS NULL    CREATE ROLE fr_migrator;
IF DATABASE_PRINCIPAL_ID(N'fr_app_runtime') IS NULL CREATE ROLE fr_app_runtime;
IF DATABASE_PRINCIPAL_ID(N'fr_maintenance') IS NULL CREATE ROLE fr_maintenance;

-- Migrator: create/alter/drop objects in fr only. CREATE <object> is database-scoped,
-- but object creation also needs ALTER on the target schema, which exists only for fr.
GRANT CREATE TABLE, CREATE VIEW, CREATE PROCEDURE, CREATE FUNCTION TO fr_migrator;
GRANT ALTER, SELECT, INSERT, UPDATE, DELETE, REFERENCES, EXECUTE, VIEW DEFINITION
    ON SCHEMA::fr TO fr_migrator;
-- Lets migrations verify that schema fr is owned by fr_owner (metadata visibility only).
GRANT VIEW DEFINITION ON USER::fr_owner TO fr_migrator;

-- Runtime and maintenance permissions are object-level and granted by P002 after migrations.

COMMIT TRANSACTION;
PRINT N'P001 complete: schema fr, user fr_owner and roles fr_migrator, fr_app_runtime, fr_maintenance are in place.';
