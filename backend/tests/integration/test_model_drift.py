"""The ORM models must match the migrated `fr` schema (columns, nullability, sizes, computed columns)."""

from __future__ import annotations

from sqlalchemy import String

from app.db.models import Base


def catalog(migrated) -> dict[str, dict[str, tuple]]:
    rows = migrated.execute("""
        SELECT t.name, c.name, c.is_nullable, c.is_computed, ty.name,
               CASE WHEN ty.name IN ('nvarchar', 'nchar') THEN c.max_length / 2 ELSE c.max_length END
        FROM sys.tables t
        JOIN sys.columns c ON c.object_id = t.object_id
        JOIN sys.types ty ON ty.user_type_id = c.user_type_id
        WHERE t.schema_id = SCHEMA_ID('fr')""")
    tables: dict[str, dict[str, tuple]] = {}
    for table, column, nullable, computed, type_name, length in rows:
        tables.setdefault(table, {})[column] = (bool(nullable), bool(computed), type_name, length)
    return tables


def test_every_table_and_column_is_mapped(migrated):
    db = catalog(migrated)
    models = {t.name: t for t in Base.metadata.sorted_tables}
    assert set(models) == set(db)
    for name, table in models.items():
        assert {c.name for c in table.columns} == set(db[name]), name


def test_nullability_computed_columns_and_string_lengths_match(migrated):
    db = catalog(migrated)
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            nullable, computed, type_name, length = db[table.name][column.name]
            where = f"{table.name}.{column.name}"
            if not column.primary_key:
                assert column.nullable == nullable, where
            assert (column.computed is not None) == computed, where
            declared = getattr(column.type, "length", None)
            if isinstance(column.type, String) or type_name in ("char", "nchar", "varchar", "nvarchar", "binary",
                                                                "varbinary"):
                assert declared == length, f"{where}: model {declared} != db {length}"
