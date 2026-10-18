"""Offline checks on the SQL files themselves (no database needed)."""

from __future__ import annotations

import re
from pathlib import Path

from localdb import DATABASE_DIR, MIGRATIONS, PERMISSIONS, ROLLBACKS
from sqlrunner import split_batches

REPO_ROOT = DATABASE_DIR.parent
ALL_SQL = MIGRATIONS + ROLLBACKS + sorted(PERMISSIONS.glob("*.sql"))


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def strip_comments(sql: str) -> str:
    return re.sub(r"--[^\n]*", "", re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL))


def version_of(path: Path) -> int:
    return int(path.name[1:5])


def test_migration_files_are_contiguous_and_named():
    assert MIGRATIONS, "no migrations found"
    for path in MIGRATIONS:
        assert re.fullmatch(r"V\d{4}__[a-z0-9_]+\.sql", path.name), path.name
    assert [version_of(p) for p in MIGRATIONS] == list(range(1, len(MIGRATIONS) + 1))


def test_every_migration_has_a_matching_rollback():
    forward = {p.name[1:] for p in MIGRATIONS}
    backward = {p.name[1:] for p in ROLLBACKS}
    assert forward == backward


def test_migrations_are_guarded_versioned_and_transactional():
    for path in MIGRATIONS:
        sql, v = read(path), version_of(path)
        assert "SET XACT_ABORT ON" in sql, path.name
        assert "BEGIN TRANSACTION" in sql and "COMMIT TRANSACTION" in sql, path.name
        assert "sp_getapplock" in sql, path.name
        assert re.search(rf"INSERT INTO fr\.schema_migrations \(version, description\) VALUES \({v},", sql), path.name
        assert "already applied; nothing to do" in sql, path.name
        if v > 1:
            assert f"WHERE version = {v - 1})" in sql, f"{path.name} does not enforce ordering"
            assert "THROW 51003" in sql, f"{path.name} lacks a conflict check"


def test_forward_migrations_never_drop_or_touch_other_schemas():
    for path in MIGRATIONS:
        code = strip_comments(read(path)).upper()
        assert not re.search(r"\b(DROP|TRUNCATE)\b", code), path.name
        assert not re.search(r"\bDBO\.", code), path.name
        for table in re.findall(r"CREATE TABLE\s+([\w.\[\]]+)", code):
            assert table.startswith("FR."), f"{path.name}: {table} is outside schema fr"


def test_every_script_uses_a_single_transactional_batch_after_the_set_options():
    for path in MIGRATIONS + ROLLBACKS:
        batches = split_batches(read(path))
        assert len(batches) == 2, f"{path.name}: expected SET-options batch + one body batch"
        assert "SET QUOTED_IDENTIFIER ON" in batches[0]


def test_no_credentials_in_sql_files():
    for path in ALL_SQL:
        sql = read(path)
        assert not re.search(r"\bPASSWORD\s*=", sql, re.IGNORECASE), path.name
        assert not re.search(r"\b(PWD|UID)\s*=", sql, re.IGNORECASE), path.name
        assert not re.search(r"CREATE\s+LOGIN", sql, re.IGNORECASE), path.name
        assert "192.168." not in sql, f"{path.name} contains a host address"


def test_env_example_contains_no_secret_values():
    secret_keys = re.compile(r"(PASSWORD|SECRET|SIGNING_KEY|TOKEN)\s*=\s*(.*)$")
    for line in read(REPO_ROOT / ".env.example").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = secret_keys.search(line)
        if match:
            assert match.group(2).strip() == "", f"secret value present: {line.split('=')[0]}"


def test_no_private_host_addresses_in_tracked_text():
    private_ip = re.compile(r"\b(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
    paths = [REPO_ROOT / "README.md", REPO_ROOT / ".env.example", *sorted((REPO_ROOT / "docs").glob("*.md")),
             *ALL_SQL, *sorted((REPO_ROOT / "tools").glob("*.py"))]
    for path in paths:
        if path.name == "db_inventory.md":
            continue  # local, git-ignored
        hits = [m.group(0) for m in private_ip.finditer(read(path))]
        assert not hits, f"{path.name}: {hits}"


def test_gitignore_excludes_sensitive_artifacts():
    ignored = read(REPO_ROOT / ".gitignore").splitlines()
    for pattern in (".env", "docs/db_inventory.md", ".venv/", "*.log", "*.pfx", "*.key"):
        assert pattern in ignored, pattern


def test_secret_like_columns_are_hashes_only():
    for path in MIGRATIONS:
        for column in re.findall(r"^\s+(\w*(?:password|token|secret|private)\w*)\s", read(path), re.MULTILINE | re.IGNORECASE):
            assert column.lower().endswith(("_hash", "_at", "_type", "_count", "_id")), f"{path.name}: {column}"
