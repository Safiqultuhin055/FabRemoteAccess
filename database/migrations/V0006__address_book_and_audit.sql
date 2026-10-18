/*
    V0006 - Address book (with favorites) and audit events.

    Run by:   fr_migrator.
    Effects:  creates fr.address_book_entries and fr.audit_events.
    Re-run:   no-op when version 6 is already recorded.
    Rollback: rollback/R0006__address_book_and_audit.sql

    audit_events is append-only for the application (UPDATE/DELETE denied in P002).
    It deliberately has no foreign keys so that audit history is independent of the
    lifecycle of the rows it describes. details must never contain passwords, tokens,
    keys or screen content.
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

IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 6)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0006 already applied; nothing to do.';
    RETURN;
END;
IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 5)
    THROW 51002, N'V0005 must be applied before V0006.', 1;
IF EXISTS (SELECT 1 FROM sys.objects WHERE schema_id = SCHEMA_ID(N'fr')
           AND name IN (N'address_book_entries', N'audit_events'))
    THROW 51003, N'Conflict: an object planned by V0006 already exists in schema fr. No changes made.', 1;

-- Entries reference a Remote ID rather than a device row, so a contact can be saved before
-- the device is registered. Favorites are entries with is_favorite = 1.
CREATE TABLE fr.address_book_entries (
    id            UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_address_book_entries_id DEFAULT NEWSEQUENTIALID(),
    owner_user_id UNIQUEIDENTIFIER NOT NULL,
    remote_id     CHAR(9)          NOT NULL,
    alias         NVARCHAR(100)    NULL,
    notes         NVARCHAR(500)    NULL,
    is_favorite   BIT              NOT NULL CONSTRAINT DF_address_book_entries_is_favorite DEFAULT 0,
    created_at    DATETIME2(3)     NOT NULL CONSTRAINT DF_address_book_entries_created_at DEFAULT SYSUTCDATETIME(),
    updated_at    DATETIME2(3)     NOT NULL CONSTRAINT DF_address_book_entries_updated_at DEFAULT SYSUTCDATETIME(),
    row_version   ROWVERSION       NOT NULL,
    CONSTRAINT PK_address_book_entries PRIMARY KEY CLUSTERED (id),
    CONSTRAINT UQ_address_book_entries_owner_remote_id UNIQUE (owner_user_id, remote_id),
    CONSTRAINT FK_address_book_entries_owner_user_id FOREIGN KEY (owner_user_id) REFERENCES fr.users (id),
    CONSTRAINT CK_address_book_entries_remote_id CHECK (remote_id NOT LIKE '%[^0-9]%' AND remote_id NOT LIKE '0%')
);
-- Supports the address_book_only incoming policy check.
CREATE INDEX IX_address_book_entries_remote_id ON fr.address_book_entries (remote_id) INCLUDE (owner_user_id);

CREATE TABLE fr.audit_events (
    id              BIGINT           IDENTITY(1, 1) NOT NULL,
    occurred_at     DATETIME2(3)     NOT NULL CONSTRAINT DF_audit_events_occurred_at DEFAULT SYSUTCDATETIME(),
    event_type      VARCHAR(64)      NOT NULL,
    outcome         VARCHAR(16)      NOT NULL,
    actor_user_id   UNIQUEIDENTIFIER NULL,
    actor_device_id UNIQUEIDENTIFIER NULL,
    subject_type    VARCHAR(32)      NULL,
    subject_id      VARCHAR(64)      NULL,
    ip_address      VARCHAR(45)      NULL,
    request_id      VARCHAR(64)      NULL,
    details         NVARCHAR(2000)   NULL,
    CONSTRAINT PK_audit_events PRIMARY KEY CLUSTERED (id),
    -- Binary collation: under a case-insensitive database collation [a-z] would also match A-Z.
    CONSTRAINT CK_audit_events_event_type
        CHECK (LEN(event_type) > 0 AND event_type COLLATE Latin1_General_100_BIN2 NOT LIKE '%[^a-z0-9_.]%'),
    CONSTRAINT CK_audit_events_outcome CHECK (outcome IN ('success', 'failure', 'denied'))
);
CREATE INDEX IX_audit_events_occurred_at ON fr.audit_events (occurred_at);
CREATE INDEX IX_audit_events_actor_user_id ON fr.audit_events (actor_user_id, occurred_at) WHERE actor_user_id IS NOT NULL;
CREATE INDEX IX_audit_events_subject ON fr.audit_events (subject_type, subject_id, occurred_at) WHERE subject_id IS NOT NULL;

INSERT INTO fr.schema_migrations (version, description) VALUES (6, N'Address book and audit events');

COMMIT TRANSACTION;
PRINT N'V0006 applied.';
