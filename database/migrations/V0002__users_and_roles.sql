/*
    V0002 - Users, roles and admin invitations.

    Run by:   fr_migrator.
    Effects:  creates fr.roles (seeded), fr.users, fr.user_roles, fr.user_invitations.
    Re-run:   no-op when version 2 is already recorded.
    Rollback: rollback/R0002__users_and_roles.sql
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

IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 2)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0002 already applied; nothing to do.';
    RETURN;
END;
IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 1)
    THROW 51002, N'V0001 must be applied before V0002.', 1;
IF EXISTS (SELECT 1 FROM sys.objects WHERE schema_id = SCHEMA_ID(N'fr')
           AND name IN (N'roles', N'users', N'user_roles', N'user_invitations'))
    THROW 51003, N'Conflict: an object planned by V0002 already exists in schema fr. No changes made.', 1;

CREATE TABLE fr.roles (
    code        VARCHAR(32)   NOT NULL,
    description NVARCHAR(200) NOT NULL,
    CONSTRAINT PK_roles PRIMARY KEY CLUSTERED (code),
    CONSTRAINT CK_roles_code CHECK (LEN(code) > 0 AND code COLLATE Latin1_General_100_BIN2 NOT LIKE '%[^a-z_]%')
);

INSERT INTO fr.roles (code, description) VALUES
    ('user',    N'Standard user: own devices, address book and sessions'),
    ('admin',   N'Administrator: invitations, users, devices and session revocation'),
    ('auditor', N'Read-only access to audit events and connection history');

CREATE TABLE fr.users (
    id                  UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_users_id DEFAULT NEWSEQUENTIALID(),
    email               NVARCHAR(320)    NOT NULL,
    display_name        NVARCHAR(100)    NOT NULL,
    password_hash       VARCHAR(255)     NULL,
    password_changed_at DATETIME2(3)     NULL,
    email_verified_at   DATETIME2(3)     NULL,
    status              VARCHAR(16)      NOT NULL CONSTRAINT DF_users_status DEFAULT 'invited',
    failed_login_count  INT              NOT NULL CONSTRAINT DF_users_failed_login_count DEFAULT 0,
    locked_until        DATETIME2(3)     NULL,
    last_login_at       DATETIME2(3)     NULL,
    created_at          DATETIME2(3)     NOT NULL CONSTRAINT DF_users_created_at DEFAULT SYSUTCDATETIME(),
    updated_at          DATETIME2(3)     NOT NULL CONSTRAINT DF_users_updated_at DEFAULT SYSUTCDATETIME(),
    row_version         ROWVERSION       NOT NULL,
    CONSTRAINT PK_users PRIMARY KEY CLUSTERED (id),
    CONSTRAINT UQ_users_email UNIQUE (email),
    CONSTRAINT CK_users_status CHECK (status IN ('invited', 'active', 'disabled')),
    CONSTRAINT CK_users_email_lowercase
        CHECK (email COLLATE Latin1_General_100_BIN2 = LOWER(email) COLLATE Latin1_General_100_BIN2),
    CONSTRAINT CK_users_email_format CHECK (email LIKE '_%@_%._%'),
    -- Only Argon2id PHC strings are accepted; plaintext cannot be stored by mistake.
    CONSTRAINT CK_users_password_hash CHECK (password_hash IS NULL OR password_hash LIKE '$argon2id$%'),
    CONSTRAINT CK_users_active_has_password CHECK (status <> 'active' OR password_hash IS NOT NULL),
    CONSTRAINT CK_users_failed_login_count CHECK (failed_login_count >= 0)
);

CREATE TABLE fr.user_roles (
    user_id            UNIQUEIDENTIFIER NOT NULL,
    role_code          VARCHAR(32)      NOT NULL,
    granted_at         DATETIME2(3)     NOT NULL CONSTRAINT DF_user_roles_granted_at DEFAULT SYSUTCDATETIME(),
    granted_by_user_id UNIQUEIDENTIFIER NULL,
    CONSTRAINT PK_user_roles PRIMARY KEY CLUSTERED (user_id, role_code),
    CONSTRAINT FK_user_roles_user_id FOREIGN KEY (user_id) REFERENCES fr.users (id),
    CONSTRAINT FK_user_roles_role_code FOREIGN KEY (role_code) REFERENCES fr.roles (code),
    CONSTRAINT FK_user_roles_granted_by_user_id FOREIGN KEY (granted_by_user_id) REFERENCES fr.users (id)
);
CREATE INDEX IX_user_roles_role_code ON fr.user_roles (role_code);

-- Pilot accounts are created only through admin invitations. The invite token itself is
-- never stored: only its SHA-256 hash.
CREATE TABLE fr.user_invitations (
    id                 UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_user_invitations_id DEFAULT NEWSEQUENTIALID(),
    email              NVARCHAR(320)    NOT NULL,
    role_code          VARCHAR(32)      NOT NULL CONSTRAINT DF_user_invitations_role_code DEFAULT 'user',
    token_hash         BINARY(32)       NOT NULL,
    invited_by_user_id UNIQUEIDENTIFIER NULL,   -- NULL only for the bootstrap administrator
    created_at         DATETIME2(3)     NOT NULL CONSTRAINT DF_user_invitations_created_at DEFAULT SYSUTCDATETIME(),
    expires_at         DATETIME2(3)     NOT NULL,
    accepted_at        DATETIME2(3)     NULL,
    accepted_user_id   UNIQUEIDENTIFIER NULL,
    revoked_at         DATETIME2(3)     NULL,
    CONSTRAINT PK_user_invitations PRIMARY KEY CLUSTERED (id),
    CONSTRAINT UQ_user_invitations_token_hash UNIQUE (token_hash),
    CONSTRAINT FK_user_invitations_role_code FOREIGN KEY (role_code) REFERENCES fr.roles (code),
    CONSTRAINT FK_user_invitations_invited_by_user_id FOREIGN KEY (invited_by_user_id) REFERENCES fr.users (id),
    CONSTRAINT FK_user_invitations_accepted_user_id FOREIGN KEY (accepted_user_id) REFERENCES fr.users (id),
    CONSTRAINT CK_user_invitations_email_lowercase
        CHECK (email COLLATE Latin1_General_100_BIN2 = LOWER(email) COLLATE Latin1_General_100_BIN2),
    CONSTRAINT CK_user_invitations_expiry CHECK (expires_at > created_at),
    CONSTRAINT CK_user_invitations_accepted CHECK (
        (accepted_at IS NULL AND accepted_user_id IS NULL) OR (accepted_at IS NOT NULL AND accepted_user_id IS NOT NULL)),
    CONSTRAINT CK_user_invitations_accepted_or_revoked CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);
CREATE UNIQUE INDEX UX_user_invitations_open_email ON fr.user_invitations (email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX IX_user_invitations_expires_at ON fr.user_invitations (expires_at);

INSERT INTO fr.schema_migrations (version, description) VALUES (2, N'Users, roles and invitations');

COMMIT TRANSACTION;
PRINT N'V0002 applied.';
