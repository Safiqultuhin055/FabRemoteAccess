"""Read-only inventory of the Fabulous Remote SQL Server database.

Lists schemas, tables (with approximate row counts), columns, keys, indexes,
programmable objects, database settings, the current login's privilege level and
any existing objects that clash with names Fabulous Remote reserves. It confirms
the connected server/database before reading metadata, only runs SELECT
statements against catalog views, opens the connection read-only, rolls back
before closing, never reads table rows and never prints the password.

Usage:
    python tools/inspect_db_schema.py [--env-file .env] [--out docs/db_inventory.md]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REQUIRED = ("FR_DB_HOST", "FR_DB_NAME")

# Names Fabulous Remote plans to create (database/migrations, database/permissions).
# Any match reported below must be reviewed before migrations are approved.
RESERVED_PRINCIPALS = ("fr_owner", "fr_migrator", "fr_app_runtime", "fr_maintenance")
RESERVED_OBJECT_NAMES = (
    "schema_migrations", "roles", "users", "user_roles", "user_invitations",
    "devices", "device_keys", "device_auth_challenges", "auth_sessions", "auth_tokens",
    "blocked_requesters", "connection_requests", "sessions", "address_book_entries",
    "audit_events", "usp_purge_expired_data", "remote_id_registry", "device_registration_challenges",
)


def _sql_list(names: tuple[str, ...]) -> str:
    return ", ".join(f"'{n}'" for n in names)


QUERIES: dict[str, str] = {
    "Schemas": """
        SELECT s.name AS schema_name, p.name AS owner
        FROM sys.schemas s JOIN sys.database_principals p ON p.principal_id = s.principal_id
        WHERE s.schema_id < 16384 AND s.name NOT IN ('sys', 'INFORMATION_SCHEMA', 'guest')
        ORDER BY s.name""",
    "Tables": """
        SELECT SCHEMA_NAME(t.schema_id) AS schema_name, t.name AS table_name,
               SUM(CASE WHEN p.index_id IN (0, 1) THEN p.rows ELSE 0 END) AS approx_rows,
               t.create_date, t.modify_date
        FROM sys.tables t JOIN sys.partitions p ON p.object_id = t.object_id
        GROUP BY t.schema_id, t.name, t.create_date, t.modify_date
        ORDER BY schema_name, table_name""",
    "Columns": """
        SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE,
               CHARACTER_MAXIMUM_LENGTH AS max_len, IS_NULLABLE, COLUMN_DEFAULT
        FROM INFORMATION_SCHEMA.COLUMNS
        ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION""",
    "Indexes and keys": """
        SELECT SCHEMA_NAME(o.schema_id) AS schema_name, o.name AS table_name, i.name AS index_name,
               i.type_desc, i.is_primary_key, i.is_unique, i.is_unique_constraint,
               STRING_AGG(c.name, ', ') WITHIN GROUP (ORDER BY ic.key_ordinal) AS key_columns
        FROM sys.indexes i
        JOIN sys.objects o ON o.object_id = i.object_id AND o.is_ms_shipped = 0
        JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
        JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
        WHERE i.name IS NOT NULL AND ic.is_included_column = 0
        GROUP BY o.schema_id, o.name, i.name, i.type_desc, i.is_primary_key, i.is_unique,
                 i.is_unique_constraint
        ORDER BY schema_name, table_name, index_name""",
    "Foreign keys": """
        SELECT fk.name AS fk_name,
               SCHEMA_NAME(pt.schema_id) + '.' + pt.name AS from_table,
               SCHEMA_NAME(rt.schema_id) + '.' + rt.name AS to_table,
               fk.delete_referential_action_desc AS on_delete
        FROM sys.foreign_keys fk
        JOIN sys.tables pt ON pt.object_id = fk.parent_object_id
        JOIN sys.tables rt ON rt.object_id = fk.referenced_object_id
        ORDER BY from_table, fk_name""",
    "Views, procedures, functions, triggers": """
        SELECT SCHEMA_NAME(schema_id) AS schema_name, name, type_desc, create_date, modify_date
        FROM sys.objects
        WHERE is_ms_shipped = 0 AND type IN ('V', 'P', 'FN', 'IF', 'TF', 'TR')
        ORDER BY type_desc, schema_name, name""",
    "Current login and privileges": """
        SELECT @@VERSION AS server_version, DB_NAME() AS database_name,
               SUSER_SNAME() AS login_name, USER_NAME() AS database_user,
               IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin,
               IS_ROLEMEMBER('db_owner') AS is_db_owner,
               IS_ROLEMEMBER('db_ddladmin') AS is_db_ddladmin,
               IS_ROLEMEMBER('db_datawriter') AS is_db_datawriter,
               IS_ROLEMEMBER('db_datareader') AS is_db_datareader""",
    "Connection encryption": """
        SELECT encrypt_option, auth_scheme, protocol_type
        FROM sys.dm_exec_connections WHERE session_id = @@SPID""",
    "Database settings": """
        SELECT CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)) AS product_version,
               CAST(SERVERPROPERTY('ProductLevel') AS NVARCHAR(128)) AS product_level,
               CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)) AS edition,
               compatibility_level, collation_name, recovery_model_desc,
               is_read_committed_snapshot_on, snapshot_isolation_state_desc
        FROM sys.databases WHERE database_id = DB_ID()""",
    # Who holds broad rights today (fixed roles) and any existing fr_* role members.
    "Role memberships (fixed and fr_* roles)": """
        SELECT r.name AS role_name, m.name AS member_name, m.type_desc AS member_type
        FROM sys.database_role_members rm
        JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
        JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id
        WHERE r.is_fixed_role = 1 OR r.name LIKE 'fr[_]%'
        ORDER BY r.name, m.name""",
    # Visibility of principals depends on the login's permissions; P001 re-checks as DBA.
    "Fabulous Remote reserved names": f"""
        SELECT 'schema' AS kind, name, NULL AS detail FROM sys.schemas WHERE name = 'fr'
        UNION ALL
        SELECT 'principal', name, type_desc FROM sys.database_principals
        WHERE name IN ({_sql_list(RESERVED_PRINCIPALS)})
        UNION ALL
        SELECT 'object', SCHEMA_NAME(schema_id) + '.' + name, type_desc FROM sys.objects
        WHERE is_ms_shipped = 0 AND parent_object_id = 0
          AND (schema_id = SCHEMA_ID('fr') OR name IN ({_sql_list(RESERVED_OBJECT_NAMES)}))""",
}


IDENTITY_QUERY = """
    SELECT DB_NAME() AS database_name, CAST(@@SERVERNAME AS NVARCHAR(128)) AS server_name"""

LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "(localdb)")


def load_env_file(path: Path) -> None:
    """Minimal KEY=VALUE loader; existing environment variables take precedence."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def build_connection_string() -> str:
    missing = [k for k in REQUIRED if not os.environ.get(k)]
    if missing:
        raise SystemExit(f"Missing required settings: {', '.join(missing)}")

    env = os.environ.get("FR_ENV", "development").lower()
    host = os.environ["FR_DB_HOST"]
    trust_cert = os.environ.get("FR_DB_TRUST_SERVER_CERT", "no").lower() == "yes"
    if trust_cert and env != "development":
        raise SystemExit("FR_DB_TRUST_SERVER_CERT=yes is only allowed when FR_ENV=development")
    if trust_cert and not host.lower().startswith(LOCAL_HOSTS):
        raise SystemExit(
            "FR_DB_TRUST_SERVER_CERT=yes disables certificate validation and is only allowed for a "
            "local development server. For a remote server, install a trusted certificate or set "
            "FR_DB_SERVER_CERTIFICATE / FR_DB_HOST_NAME_IN_CERTIFICATE.")

    parts = {
        "DRIVER": "{" + os.environ.get("FR_DB_DRIVER", "ODBC Driver 18 for SQL Server") + "}",
        "SERVER": f"tcp:{host},{os.environ.get('FR_DB_PORT', '1433')}",
        "DATABASE": os.environ["FR_DB_NAME"],
        "Encrypt": os.environ.get("FR_DB_ENCRYPT", "yes"),
        "TrustServerCertificate": "yes" if trust_cert else "no",
        "ApplicationIntent": "ReadOnly",
        "Connection Timeout": "15",
    }
    # Validation stays on: pin the server's exported certificate (ODBC Driver 18.1+) and/or
    # name the host the certificate was issued to when connecting by IP address.
    if os.environ.get("FR_DB_SERVER_CERTIFICATE"):
        parts["ServerCertificate"] = "{" + os.environ["FR_DB_SERVER_CERTIFICATE"] + "}"
    if os.environ.get("FR_DB_HOST_NAME_IN_CERTIFICATE"):
        parts["HostNameInCertificate"] = os.environ["FR_DB_HOST_NAME_IN_CERTIFICATE"]
    user, password = os.environ.get("FR_DB_USER"), os.environ.get("FR_DB_PASSWORD")
    if user:
        if user.lower() == "sa":
            print("WARNING: connecting as 'sa'. Use a least-privilege login.", file=sys.stderr)
        parts["UID"] = user
        parts["PWD"] = "{" + (password or "").replace("}", "}}") + "}"
    else:
        parts["Trusted_Connection"] = "yes"
    return ";".join(f"{k}={v}" for k, v in parts.items())


def to_markdown(title: str, columns: list[str], rows: list[tuple]) -> str:
    out = [f"## {title}", ""]
    if not rows:
        return "\n".join(out + ["_None._", ""])
    out.append("| " + " | ".join(columns) + " |")
    out.append("|" + "---|" * len(columns))
    for row in rows:
        cells = ["" if v is None else str(v).replace("|", "\\|").replace("\n", " ") for v in row]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out + [""])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env-file", default=".env", type=Path)
    parser.add_argument("--out", type=Path, help="Write Markdown here instead of stdout")
    args = parser.parse_args()

    load_env_file(args.env_file)
    conn_str = build_connection_string()

    try:
        import pyodbc
    except ImportError:
        raise SystemExit("pyodbc is not installed: pip install pyodbc")

    try:
        conn = pyodbc.connect(conn_str, autocommit=False, readonly=True)
    except pyodbc.Error as exc:
        # Driver messages do not include the password, but never echo the connection string.
        raise SystemExit(f"Connection failed: {exc.args[-1] if exc.args else exc}")

    sections = [f"# {os.environ['FR_DB_NAME']} inventory", ""]
    try:
        cursor = conn.cursor()
        # Confirm the target before reading any metadata.
        cursor.execute(IDENTITY_QUERY)
        database_name, server_name = cursor.fetchone()
        expected_server = os.environ.get("FR_DB_EXPECTED_SERVER")
        if (database_name or "").lower() != os.environ["FR_DB_NAME"].lower():
            raise SystemExit(f"Connected to database '{database_name}', expected '{os.environ['FR_DB_NAME']}'. Aborted.")
        if expected_server and (server_name or "").lower() != expected_server.lower():
            raise SystemExit(f"Connected to server '{server_name}', expected '{expected_server}'. Aborted.")
        print(f"Connected to server '{server_name}', database '{database_name}'.", file=sys.stderr)
        for title, sql in QUERIES.items():
            try:
                cursor.execute(sql)
                columns = [d[0] for d in cursor.description]
                sections.append(to_markdown(title, columns, [tuple(r) for r in cursor.fetchall()]))
            except pyodbc.Error as exc:
                sections += [f"## {title}", "", f"_Not available: {exc.args[-1]}_", ""]
    finally:
        conn.rollback()
        conn.close()

    report = "\n".join(sections)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"Inventory written to {args.out}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
