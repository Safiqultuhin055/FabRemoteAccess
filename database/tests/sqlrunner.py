"""Run sqlcmd-style scripts (GO batch separators, $(Var) substitution) in tests.

Test-only helper: the fixtures in conftest.py only hand it LocalDB connections.
Real environments run the scripts with sqlcmd, as documented in docs/DATABASE_DESIGN.md.
"""

from __future__ import annotations

import re
from pathlib import Path

GO_LINE = re.compile(r"^[ \t]*GO[ \t]*\r?$", re.IGNORECASE | re.MULTILINE)
SQLCMD_VAR = re.compile(r"\$\((\w+)\)")


def split_batches(sql: str) -> list[str]:
    return [batch for batch in GO_LINE.split(sql) if batch.strip()]


def substitute(sql: str, variables: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables:
            # Same behaviour as sqlcmd: an undefined scripting variable is an error.
            raise KeyError(f"scripting variable not defined: {name}")
        return variables[name]

    return SQLCMD_VAR.sub(replace, sql)


def run_script(conn, path: Path, variables: dict[str, str] | None = None) -> list[str]:
    """Execute every batch of a script; return PRINT messages. Errors raise pyodbc.Error."""
    sql = substitute(Path(path).read_text(encoding="utf-8"), variables or {})
    messages: list[str] = []
    cursor = conn.cursor()
    for batch in split_batches(sql):
        cursor.execute(batch)
        while True:
            messages.extend(str(m[1]) for m in cursor.messages)
            if not cursor.nextset():
                break
    return messages
