/*
    P002 - Object-level permissions for the runtime and maintenance roles.

    Run by:   a DBA (db_owner) after migrations V0001-V0008 are applied.
              Re-run after any future migration that adds objects.
    Effects:  GRANT/DENY on individual objects in schema fr only. No schema-wide grants,
              so new tables are inaccessible to the application until reviewed here.
    Safe to re-run: GRANT and DENY are idempotent.
*/
SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON;
SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; SET NUMERIC_ROUNDABORT OFF;
GO
SET XACT_ABORT ON;
SET NOCOUNT ON;

IF IS_MEMBER(N'db_owner') <> 1
    THROW 51200, N'P002 must be run by a member of db_owner in the target database.', 1;
IF DATABASE_PRINCIPAL_ID(N'fr_app_runtime') IS NULL OR DATABASE_PRINCIPAL_ID(N'fr_maintenance') IS NULL
    THROW 51210, N'Roles are missing. Run P001 first.', 1;
IF OBJECT_ID(N'fr.schema_migrations', N'U') IS NULL
    THROW 51211, N'Migrations have not been applied. Apply V0001-V0008 before P002.', 1;
IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 8)
    THROW 51211, N'Migrations have not been applied. Apply V0001-V0008 before P002.', 1;

BEGIN TRANSACTION;

-- Read-only reference data. Readiness checks read the migration version.
GRANT SELECT ON fr.schema_migrations TO fr_app_runtime;
DENY INSERT, UPDATE, DELETE ON fr.schema_migrations TO fr_app_runtime;
GRANT SELECT ON fr.roles TO fr_app_runtime;

-- Accounts and devices: soft-delete only (status / revoked_at), never DELETE.
GRANT SELECT, INSERT, UPDATE ON fr.users                  TO fr_app_runtime;
GRANT SELECT, INSERT, DELETE ON fr.user_roles             TO fr_app_runtime;
GRANT SELECT, INSERT, UPDATE ON fr.user_invitations       TO fr_app_runtime;
GRANT SELECT, INSERT, UPDATE ON fr.devices                TO fr_app_runtime;
GRANT SELECT, INSERT, UPDATE ON fr.device_keys            TO fr_app_runtime;
GRANT SELECT, INSERT, UPDATE ON fr.device_auth_challenges TO fr_app_runtime;
-- Registration challenges are short-lived; the application deletes expired ones itself.
GRANT SELECT, INSERT, UPDATE, DELETE ON fr.device_registration_challenges TO fr_app_runtime;
-- Remote IDs are allocated forever: insert-only for the application (never reused).
GRANT SELECT, INSERT ON fr.remote_id_registry TO fr_app_runtime;
DENY UPDATE, DELETE ON fr.remote_id_registry TO fr_app_runtime;

-- Authentication: tokens are revoked/consumed by UPDATE; expired rows are purged by the
-- retention procedure, not by the application.
GRANT SELECT, INSERT, UPDATE ON fr.auth_sessions TO fr_app_runtime;
GRANT SELECT, INSERT, UPDATE ON fr.auth_tokens   TO fr_app_runtime;

-- Consent and sessions.
GRANT SELECT, INSERT, DELETE ON fr.blocked_requesters  TO fr_app_runtime;
GRANT SELECT, INSERT, UPDATE ON fr.connection_requests TO fr_app_runtime;
GRANT SELECT, INSERT, UPDATE ON fr.sessions            TO fr_app_runtime;

-- User-owned contact data.
GRANT SELECT, INSERT, UPDATE, DELETE ON fr.address_book_entries TO fr_app_runtime;

-- Audit trail is append-only for the application. DENY also overrides any broader
-- grant (e.g. db_datawriter) that might be added to the login by mistake later.
GRANT SELECT, INSERT ON fr.audit_events TO fr_app_runtime;
DENY UPDATE, DELETE ON fr.audit_events TO fr_app_runtime;

-- Retention job: EXECUTE only; it reaches the tables through ownership chaining inside fr.
GRANT EXECUTE ON fr.usp_purge_expired_data TO fr_maintenance;

COMMIT TRANSACTION;
PRINT N'P002 complete: runtime and maintenance permissions granted.';
