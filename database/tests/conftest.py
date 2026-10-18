"""Database test fixtures; the implementation lives in localdb.py so other suites can reuse it.

Test modules import helpers from `localdb`, never from `conftest`: several conftest.py files
exist in this repository and a bare `conftest` import would resolve to the wrong one.
"""

from localdb import db_factory, migrated_db, server  # noqa: F401  (re-exported fixtures)
