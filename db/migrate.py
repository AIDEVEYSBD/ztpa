"""Apply the schema and every pending migration to the database in DATABASE_URL.

Two things live here, in this order:

1. **The baseline** -- `db/schema.sql`, the fresh-install DDL. Every statement in
   it is `CREATE ... IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`, so applying it
   to an existing database can only ADD; it can never converge a definition that
   CHANGED (a foreign key that must stop cascading, a CHECK that must widen).
2. **The migrations** -- the numbered, forward-only files in `db/migrations/`,
   each applied exactly once, in its own transaction, and recorded in
   `ztpa.schema_migrations`. This is where a *changed* definition goes.

Re-running is safe and is the normal deploy step: the baseline is idempotent and
an already-recorded migration is skipped.

Each file is executed in a SINGLE `execute()` call rather than split on ';'.
psycopg uses the simple query protocol when a query carries no parameters
(_cursor_base.py:458), which runs every statement in the string in order, in one
transaction -- so `SET search_path TO ztpa` at the top of a file holds for the
rest of it even through a connection pooler, and a future migration may contain
a dollar-quoted DO block, which the old split-on-';' parser would have shredded.
The trade-off is that a syntax error reports a character offset into the file
rather than a statement index; the offset is in the error, and the file name is
printed with it.

THIS IS THE ONLY WAY SCHEMA CHANGES APPLY. Until Phase 2 it was one of three:
`db/schema.sql`, this runner, and four `ensure_*` helpers in
`backend/src/persist.py` that executed ALTER/CREATE from the REQUEST path behind
module-level latches -- so the live schema depended on which endpoints had been
hit since the last restart, and one table (`asset_merges`) existed in no .sql
file at all. Those helpers are deleted. The corollary is that this step is no
longer optional on a deploy: a missing column now fails the write that needs it,
loudly, instead of being silently created by the next request. `render.yaml`
runs it in `buildCommand`; see docs/DEPLOY.md.

Usage:
    python db/migrate.py                    # baseline schema.sql, then pending migrations
    python db/migrate.py db/auth_schema.sql # that file as the baseline, then pending migrations
    python db/migrate.py --migrations-only  # skip the baseline (deploy/preDeploy step)
    python db/migrate.py --bootstrap        # every baseline in dependency order, then
                                            # migrations: the one command a deploy runs
    python db/migrate.py --status           # report applied vs pending, change nothing
    python db/migrate.py --check            # exit 1 if anything is pending (CI / pre-deploy gate)

Exit codes: 0 applied (or nothing to do), 1 --check found pending migrations,
2 DATABASE_URL missing / file missing, 3 the repo and the database disagree about
an already-applied migration.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import sys

import psycopg

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_SCHEMA = HERE / "schema.sql"
MIGRATIONS_DIR = HERE / "migrations"

# Hardcoded, like schema.sql's own `CREATE SCHEMA IF NOT EXISTS ztpa`: the DDL
# names the schema literally, so there is nothing to configure here (it mirrors
# src.settings.DB_SCHEMA, which is likewise a constant).
SCHEMA = "ztpa"

try:  # load repo-root .env so DATABASE_URL is available when run standalone
    from dotenv import load_dotenv
    load_dotenv(HERE.parent / ".env")
except Exception:
    pass


def version_of(path: pathlib.Path) -> str:
    """The ordering key for a migration: the leading digits of its filename.

    `0001_governance_fk.sql` -> `0001`. Numeric prefixes are what make the order
    an explicit decision in the repo rather than an accident of mtime or of
    however the filesystem happens to sort. Anything else is a mistake worth
    stopping for -- a file the runner cannot order is a file it cannot promise to
    have applied.
    """
    stem = path.name.split("_", 1)[0]
    if not stem.isdigit():
        raise ValueError(
            f"migration {path.name!r} does not start with digits + '_' "
            f"(expected e.g. 0002_add_thing.sql) -- refusing to guess its order"
        )
    return stem


def migration_files(directory: pathlib.Path = MIGRATIONS_DIR) -> list[pathlib.Path]:
    """Every migration, ordered by version. Missing directory = no migrations.

    Sorted NUMERICALLY, not lexicographically: the repo pads to four digits, so
    the two agree today, but the day someone adds `10_...` next to `0009_...` a
    filename sort would run them out of order -- silently, once, on a production
    database. `int()` is safe because `version_of` has already rejected any name
    whose prefix is not digits.
    """
    if not directory.is_dir():
        return []
    files = sorted(directory.glob("*.sql"), key=lambda p: (int(version_of(p)), p.name))
    versions = [version_of(f) for f in files]           # validates every name
    dupes = {v for v in versions if versions.count(v) > 1}
    if dupes:
        raise ValueError(f"duplicate migration version(s) {sorted(dupes)} in {directory}")
    return files


def checksum(path: pathlib.Path) -> str:
    """sha256 of the file exactly as it will be sent to the server."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ensure_ledger(conn: psycopg.Connection) -> None:
    """Create the ledger if absent. Runs before anything else, so a
    --migrations-only run works against a database that predates it."""
    conn.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")
    conn.execute(f"""CREATE TABLE IF NOT EXISTS {SCHEMA}.schema_migrations (
        version     text PRIMARY KEY,
        filename    text NOT NULL,
        checksum    text NOT NULL,
        applied_at  timestamptz NOT NULL DEFAULT now()
    )""")
    conn.commit()


def _applied(conn: psycopg.Connection) -> dict[str, tuple[str, str]]:
    """version -> (filename, checksum) for everything already applied."""
    rows = conn.execute(
        f"SELECT version, filename, checksum FROM {SCHEMA}.schema_migrations"
    ).fetchall()
    return {r[0]: (r[1], r[2]) for r in rows}


def _apply_file(conn: psycopg.Connection, path: pathlib.Path) -> None:
    """Execute a whole .sql file in one statement, so the caller's transaction
    covers all of it. The corollary is that a migration may not contain DDL that
    Postgres refuses inside a transaction block (CREATE INDEX CONCURRENTLY,
    ALTER TYPE ... ADD VALUE); nothing needs one yet, and an all-or-nothing
    migration is worth more than a concurrent index build."""
    with conn.cursor() as cur:
        cur.execute(path.read_text())       # no params -> simple query protocol


def _drifted(files: list[pathlib.Path], applied: dict[str, tuple[str, str]]) -> list[str]:
    """Migrations whose file changed after they were applied.

    Forward-only means an applied migration is history: editing one makes the
    repo describe a database state that was never produced. We refuse rather
    than 'helpfully' re-running it, because re-running is exactly what a
    forward-only system must not decide to do on its own.
    """
    out = []
    for f in files:
        v = version_of(f)
        if v in applied and applied[v][1] != checksum(f):
            out.append(f"{f.name} (applied as {applied[v][0]}, checksum differs)")
    return out


# The baselines a complete database needs, in dependency order: auth_schema
# creates ztpa.app_users, which sso_schema extends and migration 0005 alters.
# Applying them by hand in the wrong order (or forgetting one) is how a fresh
# database ended up without the SSO columns the frontend writes.
BOOTSTRAP_BASELINES = (HERE / "schema.sql", HERE / "auth_schema.sql", HERE / "sso_schema.sql")

# Serialises concurrent runs (two deploys, a deploy and an operator): the second
# waits instead of racing the first through the same migrations.
_LOCK_ID = 0x6E70726D  # "nprm"


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    bootstrap = "--bootstrap" in args
    check_only = "--check" in args
    status_only = "--status" in args or check_only
    skip_baseline = "--migrations-only" in args
    positional = [a for a in args if not a.startswith("-")]

    url = os.environ.get("DATABASE_URL")
    if not url:
        print("ERROR: DATABASE_URL is not set (load it from .env).", file=sys.stderr)
        return 2

    if bootstrap:
        baselines = list(BOOTSTRAP_BASELINES)
    elif skip_baseline:
        baselines = []
    else:
        baselines = [pathlib.Path(positional[0]) if positional else DEFAULT_SCHEMA]
    for baseline in baselines:
        if not baseline.is_file():
            print(f"ERROR: {baseline} does not exist.", file=sys.stderr)
            return 2

    try:
        files = migration_files()
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    # autocommit=False: each apply below is its own transaction, committed only
    # once its ledger row is written, so a migration and the record of it can
    # never disagree.
    with psycopg.connect(url) as conn:
        if not status_only:
            conn.execute("SELECT pg_advisory_lock(%s)", [_LOCK_ID])
            conn.commit()
        _ensure_ledger(conn)
        applied = _applied(conn)

        drift = _drifted(files, applied)
        if drift:
            print("ERROR: already-applied migration(s) changed on disk:", file=sys.stderr)
            for d in drift:
                print(f"  - {d}", file=sys.stderr)
            print("Migrations are forward-only: add a new numbered file instead of "
                  "editing an applied one.", file=sys.stderr)
            return 3

        pending = [f for f in files if version_of(f) not in applied]

        if status_only:
            print(f"schema {SCHEMA}: {len(applied)} applied, {len(pending)} pending")
            for f in files:
                print(f"  [{'applied' if version_of(f) in applied else 'pending'}] {f.name}")
            if check_only and pending:
                # A gate, not a report: "the database this is about to serve is
                # behind the code about to be deployed" has to be able to fail a
                # pipeline, which needs a non-zero exit.
                print(f"ERROR: {len(pending)} migration(s) pending; run `python db/migrate.py`.",
                      file=sys.stderr)
                return 1
            return 0

        for baseline in baselines:
            _apply_file(conn, baseline)
            conn.commit()
            print(f"applied baseline {baseline.name} to schema {SCHEMA}")

        for f in pending:
            _apply_file(conn, f)
            conn.execute(
                f"INSERT INTO {SCHEMA}.schema_migrations (version, filename, checksum) "
                f"VALUES (%s, %s, %s)",
                [version_of(f), f.name, checksum(f)],
            )
            conn.commit()
            print(f"applied migration {f.name}")

    if not pending:
        print("no pending migrations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
