/*
    V0007 - Data-retention procedure.

    Run by:   fr_migrator.
    Effects:  creates fr.usp_purge_expired_data. It deletes expired tokens, challenges,
              invitations, ended sessions, decided requests and old audit events, and
              clears stored IP addresses past their retention period.
    Re-run:   no-op when version 7 is already recorded.
    Rollback: rollback/R0007__retention_procedure.sql

    The procedure is owned by fr_owner (schema owner), so callers need only EXECUTE
    (granted to fr_maintenance in P002); the application role never gets DELETE on
    audit_events. Retention periods have NO defaults: the caller must pass the approved
    values explicitly (proposed values are pending owner/legal approval; see
    docs/DATABASE_DESIGN.md section 6). @dry_run = 1 (default) performs the work inside a transaction, reports
    exact counts and rolls everything back. Deletes run in batches and commit per batch
    when @dry_run = 0, so an interrupted run is safe to repeat.
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

IF EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 7)
BEGIN
    COMMIT TRANSACTION;
    PRINT N'V0007 already applied; nothing to do.';
    RETURN;
END;
IF NOT EXISTS (SELECT 1 FROM fr.schema_migrations WHERE version = 6)
    THROW 51002, N'V0006 must be applied before V0007.', 1;
IF OBJECT_ID(N'fr.usp_purge_expired_data') IS NOT NULL
    THROW 51003, N'Conflict: fr.usp_purge_expired_data already exists. No changes made.', 1;

-- CREATE PROCEDURE must start a batch; EXEC keeps it inside this migration's transaction.
EXEC (N'
CREATE PROCEDURE fr.usp_purge_expired_data
    @session_retention_days INT,
    @request_retention_days INT,
    @audit_retention_days   INT,
    @ip_retention_days      INT,
    @token_grace_days       INT,
    @batch_size             INT = 5000,
    @dry_run                BIT = 1
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF COALESCE(@session_retention_days, 0) < 30 OR COALESCE(@request_retention_days, 0) < 30
       OR COALESCE(@audit_retention_days, 0) < 90 OR COALESCE(@ip_retention_days, 0) < 1
       OR COALESCE(@token_grace_days, -1) < 0 OR COALESCE(@batch_size, 0) NOT BETWEEN 1 AND 50000
       OR @dry_run IS NULL
        THROW 51100, N''Retention parameter out of allowed range.'', 1;

    DECLARE @now            DATETIME2(3) = SYSUTCDATETIME();
    DECLARE @session_cutoff DATETIME2(3) = DATEADD(DAY, -@session_retention_days, @now);
    DECLARE @request_cutoff DATETIME2(3) = DATEADD(DAY, -@request_retention_days, @now);
    DECLARE @audit_cutoff   DATETIME2(3) = DATEADD(DAY, -@audit_retention_days, @now);
    DECLARE @ip_cutoff      DATETIME2(3) = DATEADD(DAY, -@ip_retention_days, @now);
    DECLARE @token_cutoff   DATETIME2(3) = DATEADD(DAY, -@token_grace_days, @now);
    DECLARE @n INT, @total INT;
    DECLARE @counts TABLE (seq INT IDENTITY(1, 1) NOT NULL, item VARCHAR(64) NOT NULL, affected INT NOT NULL);

    IF @dry_run = 1
        BEGIN TRANSACTION;

    -- Tokens and challenges past expiry (or revoked) plus a grace period.
    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        DELETE TOP (@batch_size) FROM fr.auth_tokens
        WHERE expires_at < @token_cutoff OR revoked_at < @token_cutoff;
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''deleted.auth_tokens'', @total);

    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        DELETE TOP (@batch_size) s FROM fr.auth_sessions AS s
        WHERE (s.expires_at < @token_cutoff OR s.revoked_at < @token_cutoff)
          AND NOT EXISTS (SELECT 1 FROM fr.auth_tokens AS t WHERE t.auth_session_id = s.id);
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''deleted.auth_sessions'', @total);

    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        DELETE TOP (@batch_size) FROM fr.device_auth_challenges WHERE expires_at < @token_cutoff;
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''deleted.device_auth_challenges'', @total);

    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        DELETE TOP (@batch_size) FROM fr.user_invitations
        WHERE accepted_at < @request_cutoff OR revoked_at < @request_cutoff
           OR (accepted_at IS NULL AND expires_at < @request_cutoff);
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''deleted.user_invitations'', @total);

    -- Remote sessions first, then the requests they no longer reference.
    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        DELETE TOP (@batch_size) FROM fr.sessions WHERE state = ''ended'' AND ended_at < @session_cutoff;
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''deleted.sessions'', @total);

    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        DELETE TOP (@batch_size) r FROM fr.connection_requests AS r
        WHERE ((r.status <> ''pending'' AND r.decided_at < @request_cutoff)
               OR (r.status = ''pending'' AND r.expires_at < @request_cutoff))
          AND NOT EXISTS (SELECT 1 FROM fr.sessions AS s WHERE s.connection_request_id = r.id);
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''deleted.connection_requests'', @total);

    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        DELETE TOP (@batch_size) FROM fr.audit_events WHERE occurred_at < @audit_cutoff;
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''deleted.audit_events'', @total);

    -- IP addresses are personal data: cleared after @ip_retention_days.
    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        UPDATE TOP (@batch_size) fr.devices SET last_ip = NULL, last_ip_at = NULL WHERE last_ip_at < @ip_cutoff;
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''cleared_ip.devices'', @total);

    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        UPDATE TOP (@batch_size) fr.auth_sessions SET created_ip = NULL
        WHERE created_ip IS NOT NULL AND created_at < @ip_cutoff;
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''cleared_ip.auth_sessions'', @total);

    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        UPDATE TOP (@batch_size) fr.connection_requests SET requester_ip = NULL
        WHERE requester_ip IS NOT NULL AND created_at < @ip_cutoff;
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''cleared_ip.connection_requests'', @total);

    SET @total = 0;
    WHILE 1 = 1
    BEGIN
        UPDATE TOP (@batch_size) fr.audit_events SET ip_address = NULL
        WHERE ip_address IS NOT NULL AND occurred_at < @ip_cutoff;
        SET @n = @@ROWCOUNT; SET @total += @n;
        IF @n < @batch_size BREAK;
    END;
    INSERT @counts (item, affected) VALUES (''cleared_ip.audit_events'', @total);

    IF @dry_run = 1
        ROLLBACK TRANSACTION;   -- @counts is a table variable and survives the rollback
    ELSE
        INSERT INTO fr.audit_events (event_type, outcome, subject_type, details)
        SELECT ''retention.purge'', ''success'', ''retention'',
               N''{"total_affected":'' + CAST(SUM(affected) AS NVARCHAR(20)) + N''}''
        FROM @counts;

    SELECT item, affected FROM @counts ORDER BY seq;
END;
');

INSERT INTO fr.schema_migrations (version, description) VALUES (7, N'Data-retention procedure');

COMMIT TRANSACTION;
PRINT N'V0007 applied.';
