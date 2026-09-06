"""SSO-only authentication: what was removed, and what had to survive it.

Password sign-in, magic links, invites, password reset, the Manage-users screen
and the two bootstrap scripts are gone. AutoX SSO is the only door, with one
off-by-default emergency credential behind it (docs/BREAKGLASS.md).

Three things make that a change worth pinning with tests rather than trusting:

1. **A deletion is easy to do halfway.** Hiding a tab is not removing a route,
   and a `Credentials` provider that is merely unregistered on the deployment you
   looked at is still an SSO bypass on the one you did not. So this file asserts
   the ABSENCE of the files, the routes, the providers and the columns -- and it
   asserts the absence structurally, not by grepping for a comment that says they
   are gone.

2. **`ztpa.app_users` is NOT obsolete and must not go with them.** It stopped
   being a user directory long before this change -- authorization reads
   `autox:app_roles` off the current token and nothing else -- but
   `db/migrations/0002_audit_identity.sql` added `audit_log.actor_email`,
   `actor_sub` and `actor_role` as plain text so the trail outlives the account,
   and this table is the projection that resolves a historical `actor_sub` back
   to a person. `frontend/lib/users.ts:provisionSsoUser` writes it on every
   authentication. Dropping it breaks sign-in AND destroys the compliance record,
   which is exactly the kind of thing a "clean up the dead auth tables" commit
   does. Half this file exists to make that commit fail.

3. **The way back in has to work.** SSO-only means a broken SSO configuration
   locks everyone out, so the break-glass path is a product feature, not a
   footnote: it must be off by default, must not depend on the database, must be
   attributable in the audit trail, and must expire. The transcript of it being
   executed end to end -- against the app and against the live Azure Container
   App -- is in docs/BREAKGLASS.md §7; what is checkable in CI is here.

WHAT RUNS WHERE.  The source-level assertions need no database, no network and no
Node, so they always run. The rest execute the application's OWN SQL, lifted out
of `frontend/lib/users.ts`, against a real Postgres:

    NPR_TEST_DATABASE_URL=postgresql://npr:nprdev@localhost:55433/npr pytest

Without that variable they skip; set to something unreachable they FAIL at
collection rather than skipping silently (tests/dbharness.py explains why).
Nothing commits -- every test runs in a transaction that is rolled back.
"""

from __future__ import annotations

import os
import pathlib
import re
import uuid
from typing import Any, Iterator

import pytest

from tests.dbharness import FAIL, SKIP, TEST_DB_ENV, collection_decision

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FRONTEND = REPO_ROOT / "frontend"
DB_DIR = REPO_ROOT / "db"
MIGRATION = DB_DIR / "migrations" / "0005_drop_local_auth.sql"


# ---------------------------------------------------------------------------
# the tree scan the "nothing still references it" assertions share
# ---------------------------------------------------------------------------

# Everything a developer would actually change. `docs/` is deliberately excluded
# from the reference scans below and asserted separately: the docs are SUPPOSED
# to name what was removed and why, and a guard that forbids the explanation is
# a guard that deletes the reason.
_SCANNED_ROOTS = ("frontend", "backend", "db", "scripts")
_SCANNED_SUFFIXES = {".ts", ".tsx", ".mjs", ".js", ".py", ".sql", ".sh", ".json", ".yaml", ".yml"}
_SKIP_DIRS = {"node_modules", ".next", "__pycache__", ".venv", ".git", "dist", "build"}


def _iter_sources() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for root in _SCANNED_ROOTS:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p.suffix not in _SCANNED_SUFFIXES:
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.name == "package-lock.json":
                continue
            # ...and not this file. A guard that names what it forbids would
            # otherwise fail on its own error message -- which is the same
            # reason `docs/` is out of scope: explaining a removal is not
            # performing one.
            if p.resolve() == pathlib.Path(__file__).resolve():
                continue
            out.append((p.relative_to(REPO_ROOT).as_posix(), p.read_text(encoding="utf-8", errors="replace")))
    return out


_SOURCES = _iter_sources()

# A whole-line comment in any of the scanned languages. The migration and the
# schema files explain what they dropped, in prose, and must be allowed to.
_COMMENT_LINE = re.compile(r"\s*(?://|/\*|\*|#|--)")


def _code(src: str) -> str:
    """`src` with whole-line comments dropped.

    Every file this module inspects documents, at length, the thing it used to
    do -- that is the house style and it is worth keeping. So the assertions
    read the CODE, and a prose explanation of a deleted provider never reads as
    the provider still being registered.
    """
    return "\n".join(l for l in src.splitlines() if not _COMMENT_LINE.match(l))


def _references(needle: str, *, allow: frozenset[str] = frozenset()) -> list[str]:
    """`path:line: text` for every non-comment line naming `needle`."""
    return [
        f"{path}:{i}: {line.strip()}"
        for path, text in _SOURCES
        if path not in allow
        for i, line in enumerate(text.splitlines(), 1)
        if needle in line and not _COMMENT_LINE.match(line)
    ]


# ---------------------------------------------------------------------------
# 1. the local-auth surface is gone -- structurally, not cosmetically
# ---------------------------------------------------------------------------

# (path, what it was). Every one of these is a way in, a way to mint a
# credential, or a way to manage accounts locally.
DELETED = (
    ("app/forgot/page.tsx", "the password-reset request page"),
    ("app/reset/page.tsx", "the set-a-new-password page"),
    ("app/login/magic/page.tsx", "the magic-link redemption page"),
    ("app/actions.ts", "requestMagic / requestReset / doReset / adminCreateUser / adminListUsers"),
    ("components/auth/ForgotForm.tsx", "the reset-request form"),
    ("components/auth/ResetForm.tsx", "the new-password form"),
    ("components/auth/MagicSignIn.tsx", "the magic-link sign-in component"),
    ("components/admin/UsersAdmin.tsx", "the Manage users admin screen"),
    ("lib/tokens.ts", "createToken / consumeToken against ztpa.auth_tokens"),
    ("lib/email.ts", "the Resend sender for magic / reset / invite links"),
    ("scripts/create-admin.mjs", "the local first-admin bootstrap"),
    ("scripts/send-reset.mjs", "the reset-link mailer"),
)


@pytest.mark.parametrize("rel,what", DELETED, ids=[d[0] for d in DELETED])
def test_the_local_auth_files_are_gone(rel: str, what: str) -> None:
    """These are not hidden behind a flag; they do not exist.

    This replaces, for the two files it covers, the entries
    `components/admin/UsersAdmin.tsx` and `app/actions.ts` carried in
    `test_frontend_error_surfacing.py`'s SURFACING_CONTRACT: that contract asserts
    a deleted screen still renders its failure honestly, which a deleted screen
    cannot do and does not need to. The invariant is not weakened, it is replaced
    by a stronger one -- the panel that could lie is not there to lie.
    """
    assert not (FRONTEND / rel).exists(), (
        f"frontend/{rel} is back. It was removed with local login ({what}). "
        "If it is genuinely needed again, that is an authentication design "
        "decision, not a file restore -- see docs/SSO.md and docs/BREAKGLASS.md."
    )


def test_no_credential_provider_survives_except_break_glass() -> None:
    """The password and magic-link providers are deleted, not disabled.

    `auth.ts` used to register both whenever `localLoginEnabled()` was true --
    which it was by DEFAULT, because it returned `AUTH_LOCAL_LOGIN === "true" ||
    !ssoEnabled()`. A deployment with no SSO_* variables (which the live one is)
    therefore had password login on. Registering them behind any condition is the
    failure mode this guards, so it checks the provider ids, not the flag.
    """
    src = _code((FRONTEND / "auth.ts").read_text(encoding="utf-8"))
    ids = set(re.findall(r'Credentials\(\{\s*\n?\s*id:\s*"([^"]+)"', src))
    assert ids == {"breakglass"}, (
        f"auth.ts registers credential provider ids {sorted(ids)}. The only one allowed "
        "is `breakglass` (docs/BREAKGLASS.md); `password` and `magic` were an SSO bypass."
    )
    assert "localLoginEnabled" not in src, "auth.ts still calls localLoginEnabled()"
    # Registering NOTHING is a legitimate state (no SSO, no break-glass) and must
    # stay a loud one -- otherwise /login is an empty box on a broken deployment.
    assert "NO SIGN-IN METHOD IS CONFIGURED" in (FRONTEND / "auth.ts").read_text(encoding="utf-8"), (
        "auth.ts no longer says anything when it registers no provider at all"
    )


def test_break_glass_is_off_unless_explicitly_armed() -> None:
    """`AUTH_LOCAL_LOGIN` must be exactly "true", with no fallback.

    The old predicate had an `|| !ssoEnabled()` arm, so the emergency door would
    have stood open on every deployment that had not configured SSO yet -- i.e.
    on a fresh clone and on the live app today. That single `||` is the whole
    difference between "off by default" and "on by default", so it is pinned.
    """
    code = _code((FRONTEND / "lib/sso.ts").read_text(encoding="utf-8"))
    assert 'process.env.AUTH_LOCAL_LOGIN !== "true"' in code, (
        "lib/sso.ts no longer gates break-glass on AUTH_LOCAL_LOGIN being exactly 'true'"
    )
    assert "localLoginEnabled" not in code, (
        "localLoginEnabled() is back in lib/sso.ts. It defaulted to ON whenever SSO "
        "was unconfigured; that is the default this change exists to invert."
    )
    # ...and the door must not be usable without a credential, or arming the flag
    # alone would mint an admin session for anyone who guessed a blank password.
    assert "BREAKGLASS_PASSWORD_HASH && !BREAKGLASS_PASSWORD" in code, (
        "breakGlassState() no longer requires a configured credential"
    )


def test_the_dead_auth_routes_are_not_public_paths() -> None:
    """/forgot and /reset are gone from the unauthenticated allowlist.

    A public path is an entry point that needs no session. One that maps to no
    page is surface for nothing. (Runtime behaviour, verified separately and
    recorded in docs/BREAKGLASS.md §7.1: anonymous requests to /forgot, /reset
    and a path that never existed all get the SAME 307 to /login, and an
    AUTHENTICATED request to /forgot or /reset gets a real 404.)
    """
    src = _code((FRONTEND / "auth.config.ts").read_text(encoding="utf-8"))
    public = re.search(r"const PUBLIC = \[([^\]]*)\]", src)
    assert public, "auth.config.ts no longer declares a PUBLIC list"
    entries = set(re.findall(r'"([^"]+)"', public.group(1)))
    assert entries == {"/login", "/sso"}, (
        f"the unauthenticated allowlist is {sorted(entries)}; /forgot and /reset are "
        "deleted routes and must not be in it"
    )


def test_the_manage_users_screen_is_unreachable_from_the_console() -> None:
    """The screen id itself is gone, so nothing can navigate to it."""
    sidebar = _code((FRONTEND / "components/Sidebar.tsx").read_text(encoding="utf-8"))
    console = _code((FRONTEND / "app/console/page.tsx").read_text(encoding="utf-8"))
    assert '| "users"' not in sidebar, "ScreenId still has a `users` member"
    assert '{ id: "users"' not in sidebar, "the Manage users nav entry is back"
    assert "UsersAdmin" not in console, "the console still renders UsersAdmin"
    # The audit trail is what replaced it as the admin's view of who did what.
    assert '{ id: "audit"' in sidebar, "the Audit trail entry vanished with Manage users"


# ---------------------------------------------------------------------------
# 2. ztpa.auth_tokens is dropped, and nothing still reaches for it
# ---------------------------------------------------------------------------

def test_the_migration_drops_auth_tokens_and_the_password_column() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "DROP TABLE IF EXISTS ztpa.auth_tokens" in sql
    assert "ALTER TABLE ztpa.app_users DROP COLUMN IF EXISTS password_hash" in sql


def test_the_migration_does_not_drop_app_users() -> None:
    """THE ONE THING THIS MIGRATION MUST NOT DO.

    Scanned as a statement, not as a substring of the prose: the file talks about
    app_users at length precisely to explain why it is kept.
    """
    code = _code(MIGRATION.read_text(encoding="utf-8"))
    forbidden = re.findall(r"DROP\s+TABLE[^;]*app_users", code, re.IGNORECASE)
    assert not forbidden, (
        f"0005 drops ztpa.app_users: {forbidden}. It is the mirror that "
        "audit_log.actor_sub / actor_email resolve against and that "
        "provisionSsoUser writes on every sign-in -- dropping it breaks SSO "
        "sign-in and destroys the audit trail's identity columns."
    )


def test_nothing_in_the_tree_still_references_auth_tokens() -> None:
    """The table is gone, so a live reader of it is a broken code path.

    The migration itself is the one file allowed to name it in SQL, because
    naming it is how it drops it.
    """
    hits = _references("auth_tokens", allow=frozenset({"db/migrations/0005_drop_local_auth.sql"}))
    assert not hits, (
        "ztpa.auth_tokens is dropped by 0005 but is still referenced:\n  " + "\n  ".join(hits)
    )


def test_nothing_in_the_tree_still_reads_a_password_hash() -> None:
    hits = _references("password_hash", allow=frozenset({"db/migrations/0005_drop_local_auth.sql"}))
    assert not hits, (
        "app_users.password_hash is dropped by 0005 but is still referenced:\n  " + "\n  ".join(hits)
    )


def test_the_baseline_schema_cannot_recreate_what_the_migration_dropped() -> None:
    """`db/migrate.py db/auth_schema.sql` is re-run on every deploy.

    It is a baseline of `CREATE ... IF NOT EXISTS`, so if it still declared
    auth_tokens or password_hash it would put them back on the next deploy and
    the migration would have achieved nothing durable.
    """
    code = _code((DB_DIR / "auth_schema.sql").read_text(encoding="utf-8"))
    assert "auth_tokens" not in code, "db/auth_schema.sql still creates ztpa.auth_tokens"
    assert "password_hash" not in code, "db/auth_schema.sql still declares password_hash"
    assert "CREATE TABLE IF NOT EXISTS ztpa.app_users" in code, (
        "db/auth_schema.sql no longer creates ztpa.app_users -- SSO sign-in provisioning "
        "and the audit trail's identity projection both need it"
    )


def test_the_docs_say_what_the_recovery_is() -> None:
    """A lockout with no documented way back is the failure this change risks.

    Asserted on content, not existence: an empty BREAKGLASS.md would pass a file
    check and help nobody at 3am.
    """
    doc = (REPO_ROOT / "docs" / "BREAKGLASS.md").read_text(encoding="utf-8")
    for needed in (
        "AUTH_LOCAL_LOGIN=true",          # what arms it
        "BREAKGLASS_PASSWORD_HASH",       # ...and with what
        "az containerapp update",         # how, on this deployment
        "--remove-env-vars",              # and how to CLOSE it again
        "actor_sub LIKE 'breakglass:%'",  # how to review what was done through it
    ):
        assert needed in doc, f"docs/BREAKGLASS.md does not say: {needed}"
    sso = (REPO_ROOT / "docs" / "SSO.md").read_text(encoding="utf-8")
    assert "BREAKGLASS.md" in sso, "docs/SSO.md does not point at the recovery path"
    assert "must not be dropped" in sso.lower() or "must not go" in sso.lower(), (
        "docs/SSO.md no longer says app_users survives"
    )


# ---------------------------------------------------------------------------
# 3. the real-database half
# ---------------------------------------------------------------------------

def _probe(url: str) -> str | None:
    try:
        import psycopg
        with psycopg.connect(url, connect_timeout=2) as conn:
            conn.execute("SELECT 1")
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


_URL = os.environ.get(TEST_DB_ENV, "").strip()
_DECISION, _REASON = collection_decision(_URL, _probe(_URL) if _URL else None)

if _DECISION == FAIL:
    raise RuntimeError(_REASON)

needs_db = pytest.mark.skipif(_DECISION == SKIP, reason=_REASON)


@pytest.fixture()
def conn() -> Iterator[Any]:
    """One connection, one transaction, always rolled back."""
    import psycopg
    from psycopg.rows import dict_row

    connection = psycopg.connect(_URL, row_factory=dict_row, autocommit=False)
    try:
        connection.execute("SET search_path TO ztpa, public")
        yield connection
    finally:
        connection.rollback()
        connection.close()


# --- the application's own SQL, lifted out of frontend/lib/users.ts ---------
#
# WHY EXTRACT IT RATHER THAN RETYPE IT. The risk this file is guarding is that a
# column named in provisionSsoUser stops existing -- which is exactly what
# migration 0005 does to `password_hash`, and what a future cleanup could do to
# `status` or `email_verified`. A copy of the SQL in the test would keep passing
# while the application's copy broke. So the statements are read from the file
# and executed as written; the parameters are supplied here, keyed by a phrase
# that identifies each statement, and an unrecognised statement FAILS rather than
# being skipped -- a new query nobody exercised is the case this must not miss.

_Q_LITERAL = re.compile(r"\bq(?:<[^>]*>)?\(\s*(`[^`]*`|\"[^\"]*\")", re.DOTALL)


def _users_ts_statements() -> list[str]:
    src = (FRONTEND / "lib/users.ts").read_text(encoding="utf-8")
    return [m.group(1)[1:-1].strip() for m in _Q_LITERAL.finditer(src)]


def _pg(sql: str, params: list[Any]) -> tuple[str, list[Any]]:
    """Translate a node-postgres statement into a psycopg one.

    `$1 .. $n` are NUMBERED and may appear in any order; `%s` is POSITIONAL. Two
    of the statements in users.ts put `$1` last (`... WHERE id = $1`), so a naive
    a naive substitution with the caller's list in numeric order binds
    the arguments to the wrong columns -- which Postgres reports as a type error
    several columns away from the mistake, if it reports one at all. `params` is
    supplied in NUMERIC order ($1 first) and reordered here to the order the
    placeholders actually appear in; a placeholder used twice takes its value
    twice, which is what a numbered parameter means and what `%s` cannot express.
    """
    order = [int(n) for n in re.findall(r"\$(\d+)", sql)]
    highest = max(order, default=0)
    assert highest <= len(params), (
        f"statement uses ${highest} but only {len(params)} parameters were supplied"
    )
    return re.sub(r"\$\d+", "%s", sql), [params[i - 1] for i in order]


@needs_db
def test_provision_sso_user_writes_the_mirror_row(conn: Any) -> None:
    """The exact statements provisionSsoUser runs, against the real table.

    Asserts the three things the audit trail needs to be able to resolve an
    actor: the AutoX `sub`, the email, and the role that was on the token.
    """
    statements = _users_ts_statements()
    insert = next((s for s in statements if s.upper().startswith("INSERT INTO ZTPA.APP_USERS")
                   and "autox-sso" in s), None)
    assert insert, f"no INSERT ... 'autox-sso' found in lib/users.ts; statements: {len(statements)}"
    select = next((s for s in statements if "WHERE sso_sub = $1" in s), None)
    assert select, "provisionSsoUser no longer looks a user up by sso_sub"

    sub = f"autox-{uuid.uuid4().hex[:12]}"
    email = f"sso-{uuid.uuid4().hex[:8]}@example.com"
    with conn.cursor() as cur:
        # $1 email, $2 name, $3 role, $4 sub, $5 appRoles, $6 isEy, $7 orgType, $8 verifiedAt
        cur.execute(*_pg(insert, [email, "Ada Lovelace", "admin", sub,
                                  ["npr_admin"], True, "EY", None]))
        cur.execute(*_pg(select, [sub]))
        assert cur.fetchone(), "the row provisionSsoUser just inserted cannot be found by sso_sub"

        cur.execute("SELECT email, name, role, status, sso_sub, sso_app_roles, created_by, "
                    "last_login_at FROM ztpa.app_users WHERE sso_sub = %s", [sub])
        row = cur.fetchone()

    assert row["sso_sub"] == sub                      # the audit trail's join key
    assert row["email"] == email
    assert row["role"] == "admin"                     # resolved from autox:app_roles
    assert row["sso_app_roles"] == ["npr_admin"]
    assert row["status"] == "active"
    assert row["created_by"] == "autox-sso"
    assert row["last_login_at"] is not None


@needs_db
def test_every_statement_in_users_ts_still_runs_against_this_schema(conn: Any) -> None:
    """No query in the file may name a column the migration removed.

    The UPDATE branches (already-linked, email adoption) and the break-glass
    insert are just as able to reference a dead column as the main INSERT, and
    they run on paths a happy-path test never takes.
    """
    statements = _users_ts_statements()
    assert len(statements) >= 5, (
        f"expected at least 5 SQL statements in lib/users.ts, found {len(statements)} -- "
        "the extractor has drifted from the file"
    )
    sub = f"autox-{uuid.uuid4().hex[:12]}"
    email = f"drift-{uuid.uuid4().hex[:8]}@example.com"
    # One parameter tuple per statement, matched by a phrase unique to it.
    params: dict[str, list[Any]] = {
        "WHERE sso_sub = $1": [sub],
        "SET email = COALESCE($2, email)": ["dummy-id", email, "N", "viewer", ["npr_viewer"], None, None, None],
        "WHERE lower(email) = $2 AND sso_sub IS NULL": [sub, email, "N", "viewer", ["npr_viewer"], None, None],
        "'autox-sso')": [email, "N", "viewer", sub, ["npr_viewer"], None, None, None],
        "'{breakglass}'": [email, f"breakglass:{email}"],
    }
    unmatched = [s for s in statements if not any(k in s for k in params)]
    assert not unmatched, (
        "lib/users.ts has SQL this test does not exercise. Add a parameter tuple for it "
        "-- an unexercised query is how a dead column survives:\n  "
        + "\n  ".join(s.split("\n")[0][:110] for s in unmatched)
    )
    with conn.cursor() as cur:
        for stmt in statements:
            key = next(k for k in params if k in stmt)
            # A syntax or unknown-column error raises here and names the statement.
            cur.execute(*_pg(stmt, params[key]))


@needs_db
def test_break_glass_sign_in_is_mirrored_and_distinguishable(conn: Any) -> None:
    """The emergency door leaves a row that says it was the emergency door.

    `sso_sub = breakglass:<email>` is the property the whole recovery review
    depends on: it is what makes `SELECT ... WHERE actor_sub LIKE 'breakglass:%'`
    in docs/BREAKGLASS.md §4 a complete answer.
    """
    stmt = next(s for s in _users_ts_statements() if "'{breakglass}'" in s)
    email = f"oncall-{uuid.uuid4().hex[:8]}@example.com"
    with conn.cursor() as cur:
        cur.execute(*_pg(stmt, [email, f"breakglass:{email}"]))
        cur.execute("SELECT role, status, sso_sub, sso_app_roles, created_by "
                    "FROM ztpa.app_users WHERE email = %s", [email])
        row = cur.fetchone()
    assert row["sso_sub"] == f"breakglass:{email}"
    assert row["sso_app_roles"] == ["breakglass"]
    assert row["created_by"] == "breakglass"
    assert row["role"] == "admin"


@needs_db
def test_audit_still_names_the_actor_after_an_sso_sign_in(conn: Any) -> None:
    """The reason app_users survives, proved on a real row.

    `db.audit()` reads `request_ctx` -- which `_ActorMiddleware` fills from the
    `x-npr-*` headers `frontend/middleware.ts` derives from the session -- so
    this is the backend half of the chain that starts at an AutoX sign-in. The
    front half (session -> headers -> these columns) was exercised against a
    running frontend and backend; the transcript is in docs/BREAKGLASS.md §7.2.
    """
    from src import request_ctx
    from src.db import audit

    sub = f"autox-{uuid.uuid4().hex[:12]}"
    email = f"grace-{uuid.uuid4().hex[:8]}@example.com"
    action = f"sso_only_probe_{uuid.uuid4().hex[:8]}"

    request_ctx.set_actor("admin", email, sub)
    try:
        with conn.cursor() as cur:
            audit(cur, action, subject="probe", detail={})
            cur.execute("SELECT actor, actor_email, actor_sub, actor_role "
                        "FROM ztpa.audit_log WHERE action = %s", [action])
            row = cur.fetchone()
    finally:
        request_ctx.set_actor(None, None, None)

    assert row is not None, "audit() wrote no row"
    assert row["actor_email"] == email
    assert row["actor_sub"] == sub, (
        "actor_sub is empty. It is the AutoX subject, and the only key that still "
        "resolves against ztpa.app_users once an email has been reused."
    )
    assert row["actor_role"] == "admin"
    assert row["actor"] == "user"


@needs_db
def test_break_glass_actions_are_attributable_in_the_audit_trail(conn: Any) -> None:
    """...and the review query in docs/BREAKGLASS.md §4 actually finds them."""
    from src import request_ctx
    from src.db import audit

    email = f"oncall-{uuid.uuid4().hex[:8]}@example.com"
    action = f"breakglass_probe_{uuid.uuid4().hex[:8]}"

    request_ctx.set_actor("admin", email, f"breakglass:{email}")
    try:
        with conn.cursor() as cur:
            audit(cur, action, subject="probe", detail={})
            cur.execute("SELECT action, actor_email, actor_role FROM ztpa.audit_log "
                        "WHERE actor_sub LIKE 'breakglass:%%' AND action = %s", [action])
            row = cur.fetchone()
    finally:
        request_ctx.set_actor(None, None, None)

    assert row is not None, (
        "an action taken through the break-glass door is not selected by the review "
        "query docs/BREAKGLASS.md tells an operator to run"
    )
    assert row["actor_email"] == email
    assert row["actor_role"] == "admin"


@needs_db
def test_the_connected_database_has_actually_dropped_them(conn: Any) -> None:
    """The migration is applied here, not merely present in the repo."""
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('ztpa.auth_tokens') AS t")
        assert cur.fetchone()["t"] is None, (
            "ztpa.auth_tokens still exists in this database. It stores LIVE sign-in "
            "credentials and nothing expires them any more -- run `python db/migrate.py`."
        )
        cur.execute("SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='ztpa' AND table_name='app_users'")
        cols = {r["column_name"] for r in cur.fetchall()}
    assert "password_hash" not in cols, "app_users.password_hash still exists"
    # ...and the columns the mirror still needs are all there.
    assert {"sso_sub", "sso_app_roles", "email", "role", "last_login_at"} <= cols, (
        f"ztpa.app_users is missing columns provisionSsoUser writes: {sorted(cols)}"
    )
