"""Run the inventory tool's catalog queries against a real (LocalDB) SQL Server."""

from __future__ import annotations

import importlib.util

from localdb import DATABASE_DIR

spec = importlib.util.spec_from_file_location("inspect_db_schema", DATABASE_DIR.parent / "tools" / "inspect_db_schema.py")
inspect_db_schema = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspect_db_schema)


def test_every_inventory_query_runs(migrated_db):
    for title, sql in inspect_db_schema.QUERIES.items():
        if title == "Connection encryption":
            continue  # needs VIEW SERVER STATE on real servers; the tool reports it as unavailable
        migrated_db.execute(sql)


def test_reserved_names_query_flags_existing_fr_objects(migrated_db, db_factory):
    query = inspect_db_schema.QUERIES["Fabulous Remote reserved names"]
    found = {(kind, name) for kind, name, _ in migrated_db.execute(query)}
    assert ("schema", "fr") in found
    assert ("principal", "fr_app_runtime") in found
    assert ("object", "fr.users") in found
    # On a database with only legacy objects, a same-named table in another schema is reported too.
    legacy = db_factory("legacy")
    assert {(k, n) for k, n, _ in legacy.execute(query)} == {("object", "dbo.users")}
