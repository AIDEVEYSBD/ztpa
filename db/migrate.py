"""Apply db/schema.sql to the database in DATABASE_URL.

Fallback for when `psql` is unavailable. Runs the whole file inside a SINGLE
transaction so `SET search_path TO ztpa` persists across statements even through
a connection pooler (PgBouncer transaction mode pins one backend per
transaction). schema.sql avoids dollar-quoting, so splitting on ';' is safe.

Usage:  python db/migrate.py [schema_file]   # defaults to schema.sql
"""

from __future__ import annotations

import os
import pathlib
import sys

import psycopg

DEFAULT_SCHEMA = pathlib.Path(__file__).with_name("schema.sql")

try:  # load repo-root .env so DATABASE_URL is available when run standalone
    from dotenv import load_dotenv
    load_dotenv(pathlib.Path(__file__).resolve().parents[1] / ".env")
except Exception:
    pass


def _strip_line_comments(sql: str) -> str:
    """Remove every `-- ... ` line comment (to end of line) BEFORE we split on ';'.

    A ';' inside a comment (e.g. "-- snapshot; data here") would otherwise split a
    statement in half. schema.sql uses no '--' inside string literals, so cutting
    at the first '--' on each line is safe and makes re-runs reliable.
    """
    out = []
    for line in sql.splitlines():
        idx = line.find("--")
        out.append(line if idx == -1 else line[:idx])
    return "\n".join(out)


def main() -> int:
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("ERROR: DATABASE_URL is not set (load it from .env).", file=sys.stderr)
        return 2

    schema_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SCHEMA
    sql = _strip_line_comments(schema_path.read_text())
    statements = [c for c in sql.split(";") if c.strip()]

    # autocommit=False -> one transaction for the whole file (search_path persists).
    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            for chunk in statements:
                cur.execute(chunk)        # leading comments are ignored by Postgres
        conn.commit()

    print(f"applied {len(statements)} statements from {schema_path.name} to schema ztpa")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
