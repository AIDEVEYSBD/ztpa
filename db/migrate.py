"""Apply db/schema.sql to the database in DATABASE_URL.

Fallback for when `psql` is unavailable. Runs the whole file inside a SINGLE
transaction so `SET search_path TO ztpa` persists across statements even through
a connection pooler (PgBouncer transaction mode pins one backend per
transaction). schema.sql avoids dollar-quoting, so splitting on ';' is safe.

Usage:  python db/migrate.py
"""

from __future__ import annotations

import os
import pathlib
import sys

import psycopg

SCHEMA_PATH = pathlib.Path(__file__).with_name("schema.sql")

try:  # load repo-root .env so DATABASE_URL is available when run standalone
    from dotenv import load_dotenv
    load_dotenv(pathlib.Path(__file__).resolve().parents[1] / ".env")
except Exception:
    pass


def _strip_comments(chunk: str) -> str:
    """Drop comment-only / blank lines so we can tell whether a chunk is real."""
    return "\n".join(
        line for line in chunk.splitlines() if not line.strip().startswith("--")
    ).strip()


def main() -> int:
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("ERROR: DATABASE_URL is not set (load it from .env).", file=sys.stderr)
        return 2

    sql = SCHEMA_PATH.read_text()
    statements = [c for c in sql.split(";") if _strip_comments(c)]

    # autocommit=False -> one transaction for the whole file (search_path persists).
    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            for chunk in statements:
                cur.execute(chunk)        # leading comments are ignored by Postgres
        conn.commit()

    print(f"applied {len(statements)} statements to schema ztpa")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
