"""Source-level guard: a failed fetch may never render as a number.

This test exists because a Phase 0 exit criterion ("a backend failure makes the
console render an explicit error panel; no screen renders a zero count while a
dependent fetch is errored") was refuted after it had been declared met. Five
call sites in `frontend/` still swallowed their rejection and painted a
confident empty result:

  * `ToolsAdmin`      -- `.catch(() => setTools([]))`, and a loading guard that
    only tested for `undefined`, so `[]` fell through and the KPI row printed
    "Tools 0 / 0 invocations / 0 tokens / $0" on any 500, 403 or dead backend.
  * `SnapshotsAdmin`  -- `.catch(() => setSnaps([]))` rendered "0 snapshots" and
    "No snapshots found -- run an analysis to create one", making a dead
    database pixel-identical to a tenant that has never run the engine; and
    `catch { /* ignore */ }` made a refused delete look like one that worked.
  * `UsersAdmin`      -- `.catch(() => setLoaded(true))` rendered "Users (0)" and
    "No users yet" out of a failed server action.
  * `RuleRef`         -- `catch { setRule(null) }` printed "Rule X is not in this
    snapshot", a positive claim about the snapshot's contents, from a request
    that never learned anything about its contents.

A SECOND, OPPOSITE FAILURE is pinned here too, because it is the same defect
with the sign flipped. Phase 0 made `/api/health` answer 503 when the backend is
running but degraded (no database, an unpersisted snapshot), and made `api()`
throw on any non-2xx -- so with no database, which is the state this repo ships
in, every screen rendered a red "the API did not respond" panel out of a backend
that was answering fine, and the Topbar residency chip read "AI residency
unknown" while the `ai` payload it needed sat in the 503 body it had just
discarded. Being unable to tell DEGRADED from DEAD is the same class of lie as
being unable to tell EMPTY from FAILED; the contract below pins both.

Why the check lives in pytest rather than only in ESLint: the ESLint config had
`no-empty` with `allowEmptyCatch: false` and it was NON-ENFORCING against both
banned patterns -- ESLint exempts any block containing a comment, so
`catch { /* ignore */ }` passed clean, and an empty arrow body is out of that
rule's scope entirely, so `.catch(() => {})` passed too. `npm run lint` went
green with the pattern live in the tree. The rules are fixed (see
`frontend/.eslintrc.json`, asserted below), but the lint job is a different CI
job on a different runtime; this suite is the one command that always runs, so
the invariant is pinned here too.

No database, no network, no Node: this reads files.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND = REPO_ROOT / "frontend"

# The three trees the exit criterion names, plus lib/ -- the fetch wrapper and
# the server-action helpers live there and can lie just as loudly.
SCANNED_DIRS = ("app", "components", "lib")
SCANNED_SUFFIXES = (".ts", ".tsx")

# The two patterns the criterion greps for, verbatim.
LITERAL_BANNED = (
    ".catch(() => {})",
    "catch { /*",
)

# ESLint's directive, honoured by the scanner below with the same semantics
# ESLint gives it: it exempts the line immediately after it, and nothing else.
# Every occurrence is therefore a discard somebody had to write down and review.
DISABLE_DIRECTIVE = "eslint-disable-next-line no-restricted-syntax"

# The exemptions that exist today, as (path, reason). Pinned as a set so that
# adding a sixth silent discard is a deliberate edit to this list rather than a
# quiet one-line comment in a component. None of these renders anything: they
# are control-flow defaults, not data.
KNOWN_EXEMPT = {
    "app/sso/logout/route.ts",       # no readable session == the same instruction as a valid one
    "components/auth/SsoSignIn.tsx",  # a probe that does not answer IS the "waking" signal
    # lib/baseurl.ts used to be the third: it called next/headers' `headers()`,
    # which throws outside a request scope, and discarded that to reach the
    # APP_URL fallback. It no longer reads the request at all (host-header
    # injection -- see the contract entry below), so there is nothing left to
    # discard and the exemption is gone with the try/except that needed it.
}


def _iter_sources() -> list[tuple[str, str]]:
    """(repo-relative-ish path, text) for every scanned frontend source file."""
    out: list[tuple[str, str]] = []
    for d in SCANNED_DIRS:
        root = FRONTEND / d
        for p in sorted(root.rglob("*")):
            if p.suffix in SCANNED_SUFFIXES and p.is_file():
                out.append((p.relative_to(FRONTEND).as_posix(), p.read_text(encoding="utf-8")))
    return out


def _skip_trivia(src: str, i: int) -> int:
    """Advance past whitespace and comments. A comment is trivia, not a handler
    -- which is precisely the distinction ESLint's `no-empty` gets wrong."""
    n = len(src)
    while i < n:
        if src[i].isspace():
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j == -1 else j + 1
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            break
    return i


# `catch {`, `catch (e) {`, and the two handler forms passed to `.catch(...)`.
# Anchored on the opening brace so `_skip_trivia` can answer "is the body empty".
_OPENERS = (
    re.compile(r"\bcatch\s*(?:\([^)]*\))?\s*\{"),
    re.compile(r"\.catch\(\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{"),
    re.compile(r"\.catch\(\s*function\s*\**\s*\([^)]*\)\s*\{"),
)


# A line that is only a comment: `//`, `/*`, a `*` continuation, or the JSX
# `{/* ... */}` form. Trailing comments on a code line stay, on purpose.
_COMMENT_LINE = re.compile(r"\s*(?:\{\s*)?(?://|/\*|\*)")


def _empty_handlers(src: str) -> list[tuple[int, str]]:
    """(1-indexed line, source line) for every empty catch body in `src`.

    Multi-line and commented-out bodies included -- reformatting a swallowed
    failure onto two lines must not buy it a pass, which a literal grep for the
    criterion's two strings would happily give it.
    """
    # Keyed by the offset of the opening brace: the patterns deliberately
    # overlap (`.catch(function (e) {})` is matched by two of them), and the
    # same swallowed failure must be reported once, not twice.
    hits: dict[int, tuple[int, str]] = {}
    lines = src.splitlines()
    for rx in _OPENERS:
        for m in rx.finditer(src):
            if src[_skip_trivia(src, m.end())] != "}":
                continue                                   # the body does something
            line_no = src.count("\n", 0, m.start()) + 1
            prev = lines[line_no - 2] if line_no >= 2 else ""
            if DISABLE_DIRECTIVE in prev:
                continue                                   # reviewed, on the record
            hits[m.end()] = (line_no, lines[line_no - 1].strip())
    return [hits[k] for k in sorted(hits)]


def test_scanner_actually_detects_the_banned_forms() -> None:
    """Self-check, so the guard below cannot pass by scanning nothing.

    A source-level test that silently stops matching is worse than no test: it
    reports green forever. This asserts the scanner still fires on every shape
    of swallowed failure, and still keeps its hands off a real handler.
    """
    caught = (
        "try { a(); } catch { /* ignore */ }\n"
        "try { b(); } catch { }\n"
        "try { c(); } catch (e) { }\n"
        "p().catch(() => {});\n"
        "p().catch(e => {});\n"
        "p().catch(function (e) {});\n"
        "try {\n  d();\n} catch {\n  // deliberate\n}\n"
    )
    assert len(_empty_handlers(caught)) == 7, _empty_handlers(caught)

    allowed = (
        "try { a(); } catch (e) { setErr(asApiError(e)); }\n"
        "p().catch((e) => { setErr(asApiError(e)); });\n"
        'const text = await r.text().catch(() => "");\n'   # a value, not an empty block
        "// " + DISABLE_DIRECTIVE + "\n} catch {\n}\n"     # the reviewed-exemption form
    )
    assert _empty_handlers(allowed) == []


def test_no_literal_banned_pattern_in_frontend_sources() -> None:
    """The exit criterion's own grep, run as an assertion."""
    hits = [
        f"{path}:{i}: {line.strip()}"
        for path, text in _iter_sources()
        for i, line in enumerate(text.splitlines(), 1)
        for pat in LITERAL_BANNED
        if pat in line
    ]
    assert not hits, (
        "A swallowed rejection is back. A failure that renders as a zero, an "
        "empty list or a green state is a claim about the customer's network "
        "that no failed request is in a position to make:\n  " + "\n  ".join(hits)
    )


def test_no_empty_catch_body_in_frontend_sources() -> None:
    """The same invariant, structurally -- so reformatting cannot evade it."""
    hits = [
        f"{path}:{line_no}: {text}"
        for path, src in _iter_sources()
        for line_no, text in _empty_handlers(src)
    ]
    assert not hits, (
        "Empty catch body. Surface it with ErrorState/InlineError from "
        f"components/ui/Feedback, or put `{DISABLE_DIRECTIVE}` on the line "
        "above and add the file to KNOWN_EXEMPT with the reason:\n  "
        + "\n  ".join(hits)
    )


def test_exemption_list_has_not_quietly_grown() -> None:
    """Every deliberate discard stays a named, reviewed decision."""
    found = {
        path
        for path, src in _iter_sources()
        if DISABLE_DIRECTIVE in src
    }
    assert found == KNOWN_EXEMPT, (
        "The set of files allowed to discard a failure changed. Adding one is a "
        f"decision, not a detail -- update KNOWN_EXEMPT.\n  added: {sorted(found - KNOWN_EXEMPT)}"
        f"\n  gone:  {sorted(KNOWN_EXEMPT - found)}"
    )


# (file, must contain, must NOT contain) for the five refuted call sites. The
# structural scanners above cannot see these: `.catch(() => setTools([]))` is a
# non-empty handler that lies, which is a semantic property of what it sets.
SURFACING_CONTRACT: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "components/admin/ToolsAdmin.tsx",
        ('<ErrorState resource="the tool registry"', "<InlineError resource="),
        ("setTools([])",),
    ),
    (
        # `UnavailableState` is the 200-shaped half of the same lie. /api/snapshots
        # answers 200 with `[]` + `degraded_reason` when the store is unreachable
        # (a history of PERSISTED runs cannot exist without one), and rendering
        # that through EmptyState would print "No snapshots found -- run an
        # analysis to create one" out of a database that was never read.
        "components/admin/SnapshotsAdmin.tsx",
        ('<ErrorState resource="the snapshot history"', "<InlineError resource=",
         "<UnavailableState resource=", "degraded_reason"),
        ("setSnaps([])",),
    ),

    (
        "components/admin/UsersAdmin.tsx",
        ('<ErrorState resource="the user directory"', '{err ? "(unknown)"'),
        (".catch(() => setLoaded(true))",),
    ),
    (
        # Span-based popover: ErrorState renders a <div>, which cannot legally
        # nest inside it, so the panel is hand-rolled -- but it is still a
        # role="alert" carrying the status and the detail.
        # `errorStatusLabel(err)` replaced the hand-rolled `HTTP ${err.status}`
        # here: the popover has to print the machine-readable status, and it must
        # print the SAME one the block panels do -- including the case where the
        # status came from the proxy rather than from the API (see the lib/api.ts
        # entry below). One vocabulary, one place to change it.
        "components/RuleRef.tsx",
        ('role="alert"', "Could not load rule", "errorStatusLabel(err)", "err.detail"),
        ("catch { setRule(null); }",),
    ),
    (
        # The action itself answered `[]` for a caller holding no admin role,
        # so the client-side fix alone would not have closed the hole.
        "app/actions.ts",
        ("AdminUsersResult", "status: 403", "status: 500"),
        (),
    ),
    (
        # /api/health's 503 IS its answer about itself, and the body carries the
        # reasons plus the `ai` block. Routing it through the generic wrapper
        # threw all of that away and turned a degraded backend into a dead one.
        "lib/api.ts",
        ("readHealth", "r.status === 503", "degraded_reasons", "health: readHealth"),
        ('j<Health>("/api/health")',),
    ),
    (
        # ...and the console renders that as a WARNING it can act on, not as the
        # red "could not load" panel every screen used to carry.
        #
        # The forbidden string is the second half of that refutation. The banner
        # opened with an unconditional "It answered, and everything below was
        # computed for real" -- a claim about panels this component had never
        # looked at, and false in precisely the state the banner exists to
        # describe, because with no database every feed under it was a 500. The
        # required strings are the two things it may now read that claim off:
        # `failures` (did the panels load?) and `fromMemory` (did the backend say
        # it recomputed them instead of reading them back?).
        #
        # NOTE: this entry can only see the MARKUP. That is exactly how the
        # criterion was refuted the first time -- these three strings were all
        # present while the five panels below the banner were HTTP 500. The
        # behavioural half lives in tests/test_degraded_console.py, which drives
        # the real API with DATABASE_URL blanked; keep both.
        #
        # ...AND THEN IT WAS REFUTED AGAIN, which is why the required strings
        # changed. `failures` measures the SIX CONSOLE-LEVEL feeds this page
        # fetches. The panels a user is looking at belong to the child screen,
        # which fetches its own data -- so on the Change Gate with no database
        # the banner rendered "Every panel below loaded" directly above two HTTP
        # 500 panels. Conditioning the sentence on `failures` was necessary and
        # not sufficient: the signal has to be SCREEN-AWARE.
        #
        # `useScreenFailures` is that signal (components/PanelHealth.tsx). Every
        # ErrorState/InlineError mounted under the banner registers itself, so
        # rendering a failure IS reporting it and a new screen cannot forget to.
        # `pending` is the other half: "nothing has failed" is not "everything
        # loaded" while a feed is still in flight.
        "app/console/page.tsx",
        ('role="status"', "degraded_reasons", "degraded.map",
         "useScreenFailures", "PanelHealthProvider", "screenFailures.length > 0",
         "pending > 0", "fromMemory"),
        ("everything below was computed for real", "Every panel below loaded"),
    ),
    (
        # THE DEAD BACKEND THAT READ AS AN APPLICATION BUG.
        #
        # The browser never reaches FastAPI directly -- next.config.mjs rewrites
        # /api/* to BACKEND_URL. With nothing listening there, the Next server
        # answers `HTTP 500`, no content-type, body "Internal Server Error".
        # `fetch` RESOLVES, so the transport branch never fired, `isNetwork`
        # stayed false, and Feedback's `status >= 500` hint told the operator
        # "The API logged an error handling this request... the server log has
        # the request id" -- about a process that was not running, whose log
        # therefore has nothing in it. Same class of lie as an empty panel: the
        # failure reported as a different failure.
        #
        # `reachedApi` is the fact that fixes it, and `looksLikeDeadUpstream` is
        # the discriminator: a 5xx with neither a JSON content-type nor a
        # readable `detail` is not FastAPI talking. Both halves are required, so
        # a genuine FastAPI 500 is never relabelled as an outage.
        "lib/api.ts",
        ("looksLikeDeadUpstream", "reachedApi", "apiUnreachable", "deadUpstreamDetail"),
        (),
    ),
    (
        # ...and the panel says it. `apiUnreachable` (not `isNetwork`) gates the
        # headline and the hint, so the proxy's 500 reads as "the API did not
        # respond" and NOT as an error the API logged.
        "components/ui/Feedback.tsx",
        ("e.apiUnreachable", "from the proxy", "useReportedFailure"),
        (),
    ),
    (
        # HOST-HEADER INJECTION. getBaseUrl() built magic-link / reset / invite
        # URLs from `x-forwarded-host` or `host` -- both client-controlled. One
        # curl with a forged Host produced a real single-use sign-in token inside
        # a link pointing at the attacker, in a mail that genuinely came from us:
        # account takeover of any address an attacker can name. The origin is now
        # pinned to configuration and the request is not consulted at all, so the
        # forbidden list is the whole point of the entry.
        "lib/baseurl.ts",
        ("process.env.APP_URL", "process.env.AUTH_URL"),
        ("next/headers", "headers()", "x-forwarded-host", 'h.get("host")'),
    ),
    (
        # The audit screen may not render an empty table out of a failed read:
        # "no actions recorded" is a claim about the governance log, and this is
        # the one screen whose entire purpose is that claim being true.
        "components/admin/AuditAdmin.tsx",
        ('<ErrorState resource="the audit trail"', "isAdmin(role)", "setPage(undefined)",
         "Array.isArray(p.items)"),
        ("setPage({ items: []",),
    ),
    (
        # The chip must not read a missing provider as "not ollama" and print a
        # confident "Hosted" out of a payload the backend could not fill in --
        # and, in the snapshot dropdown, "no snapshots yet" is a claim about the
        # database, so it may only be made when the database was actually read
        # (`snapsUnknown` carries the API's reason when it was not).
        "components/Topbar.tsx",
        ("!ai?.active_provider", "snapsUnknown"),
        ("if (!ai) {",),
    ),
)


def _code_only(src: str) -> str:
    """Drop whole-line comments. Every file below documents the exact pattern it
    used to carry, so a naive substring scan would flag its own explanation."""
    keep = [ln for ln in src.splitlines() if not _COMMENT_LINE.match(ln)]
    return "\n".join(keep)


@pytest.mark.parametrize("rel,required,forbidden", SURFACING_CONTRACT, ids=lambda v: v if isinstance(v, str) else "")
def test_refuted_call_sites_render_their_failure(rel: str, required: tuple[str, ...], forbidden: tuple[str, ...]) -> None:
    src = (FRONTEND / rel).read_text(encoding="utf-8")
    code = _code_only(src)
    for needle in required:
        assert needle in src, f"{rel} no longer surfaces its failure: missing {needle!r}"
    for needle in forbidden:
        assert needle not in code, f"{rel} is swallowing a failure again: {needle!r}"


def test_tools_admin_error_branch_precedes_the_kpi_tiles() -> None:
    """The exact refutation: `[]` fell through a `=== undefined` loading guard.

    Restoring the error state but leaving it below the loading guard would put
    the KPI row back on screen reading 0 / 0 / 0 / $0, so the ORDER is the
    invariant, not merely the presence of a panel.
    """
    src = (FRONTEND / "components/admin/ToolsAdmin.tsx").read_text(encoding="utf-8")
    err_branch = src.index("if (err) return <ErrorState")
    loading_guard = src.index("if (tools === undefined)")
    kpi = src.index('<Kpi label="Tools"')
    assert err_branch < loading_guard < kpi, (
        "The error branch must return before anything that counts the registry."
    )


def test_eslint_config_actually_bans_both_patterns() -> None:
    """`no-empty` alone is non-enforcing; the config may not regress to it.

    Measured, not assumed: ESLint's `no-empty` exempts a block containing a
    comment (so `catch { /* ignore */ }` passes) and does not look at arrow
    bodies at all (so `.catch(() => {})` passes). The selectors below are what
    make `npm run lint` fail on either.
    """
    raw = (FRONTEND / ".eslintrc.json").read_text(encoding="utf-8")
    # ESLint strips // comments from .json configs; json.loads does not.
    stripped = re.sub(r"^\s*//.*$", "", raw, flags=re.MULTILINE)
    rules = json.loads(stripped)["rules"]

    selectors = {entry["selector"] for entry in rules["no-restricted-syntax"] if isinstance(entry, dict)}
    assert "CatchClause[body.body.length=0]" in selectors, (
        "Nothing fails the build on `catch { /* ignore */ }` any more."
    )
    assert any(
        "ArrowFunctionExpression" in s and "body.body.length=0" in s and "catch" in s
        for s in selectors
    ), "Nothing fails the build on `.catch(() => {})` any more."


def test_ci_runs_the_frontend_lint_that_enforces_this() -> None:
    """The rules above are only a guard if a job actually runs them."""
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "npm run lint" in ci, "The frontend lint step is gone from CI."


def test_the_linter_is_a_declared_dependency_not_a_ci_side_install() -> None:
    """...and the job that runs them can install them on a CLEAN CHECKOUT.

    ESLint was in neither package.json nor package-lock.json -- it existed only
    in a developer's gitignored node_modules -- so CI worked around it with
    `npm install --no-save eslint@... eslint-config-next@...` after `npm ci`.
    That is an unpinned, unlocked, unreviewed dependency deciding whether the
    build passes, and it means the gate enforcing the invariant above could not
    be reproduced from the repository alone.
    """
    pkg = json.loads((FRONTEND / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((FRONTEND / "package-lock.json").read_text(encoding="utf-8"))

    for name in ("eslint", "eslint-config-next"):
        assert name in pkg["devDependencies"], f"{name} is not a declared devDependency"
        # The lockfile's root entry is what `npm ci` reads; a package present
        # deeper in the tree but absent here would NOT be installed.
        assert name in lock["packages"][""]["devDependencies"], f"{name} is not in the lockfile root"
        entry = lock["packages"].get(f"node_modules/{name}")
        assert entry and entry.get("version"), f"{name} has no resolved version in the lockfile"

    # Comment lines are dropped: the workflow documents the workaround it used to
    # carry, and the explanation must not be mistaken for the thing itself.
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    steps = "\n".join(ln for ln in ci.splitlines() if not ln.lstrip().startswith("#"))
    assert "--no-save" not in steps, (
        "CI is installing a package outside the lockfile again. Whatever it is "
        "belongs in package.json + package-lock.json, where it is reviewable.")


# ---------------------------------------------------------------------------
# Host-header injection: a link in an email may never be built from the request.
# ---------------------------------------------------------------------------

# The two headers that carry a client-supplied origin. `Host` is a request header
# like any other; `x-forwarded-host` is whatever the last hop chose to pass on.
# Neither is evidence of anything unless a trusted proxy is known to overwrite
# it, and that is not a property this repository can assert about its deploys.
HOST_HEADER_READS = ('"x-forwarded-host"', "'x-forwarded-host'", '.get("host")', ".get('host')")


def test_no_frontend_source_derives_an_origin_from_the_request_host() -> None:
    """Pins the fix for the account-takeover primitive the security review found.

    `lib/baseurl.ts` built magic-link, password-reset and invite URLs from
    `x-forwarded-host` or `host`. Both are attacker-controllable on any request
    the attacker makes:

        curl -H 'Host: attacker.example' https://app/forgot -d email=admin@corp

    mints a real, valid, single-use sign-in token and embeds it in a link to the
    attacker's server, inside a mail that genuinely came from this application.
    The victim clicks, the attacker receives the token, and replays it here.

    The distinction that makes this different from `req.nextUrl.origin` (still
    used, correctly, in app/sso/logout/route.ts to bounce a user back to the
    origin they arrived on): there, the forged value is echoed to the same
    client that forged it, which gains an attacker nothing. Here, the forged
    value is PERSISTED INTO A CREDENTIAL SENT TO SOMEONE ELSE. Only the second
    is a vulnerability, and only the second is banned.

    The whole tree is scanned rather than just baseurl.ts, because the next
    helper that wants "the current origin" is where this comes back.
    """
    hits = [
        f"{path}:{i}: {line.strip()}"
        for path, text in _iter_sources()
        for i, line in enumerate(text.splitlines(), 1)
        if not _COMMENT_LINE.match(line)
        for pat in HOST_HEADER_READS
        if pat in line
    ]
    assert not hits, (
        "A request-supplied host is being read. If this is for a link that "
        "leaves the server (email, redirect target stored anywhere), it is an "
        "account-takeover primitive: pin the origin to APP_URL/AUTH_URL as "
        "lib/baseurl.ts does.\n  " + "\n  ".join(hits)
    )


# ---------------------------------------------------------------------------
# The audit screen exists, is reachable, and is reachable only by an admin.
# ---------------------------------------------------------------------------

def test_the_audit_screen_is_wired_into_the_admin_only_nav() -> None:
    """A screen nobody can navigate to is not a screen.

    Phase 2's exit criterion is "an admin Audit screen exists and is role-gated".
    Three things have to line up for that to be true, and each one is a separate
    edit somebody can forget: the screen id must exist, the console must render
    the component for it, and the nav entry must sit in the ADMIN group -- the
    block Sidebar renders only when `role === "admin"`. The API is the real gate
    (`Depends(require_admin)`); this asserts the door matches the lock.
    """
    sidebar = (FRONTEND / "components/Sidebar.tsx").read_text(encoding="utf-8")
    console = (FRONTEND / "app/console/page.tsx").read_text(encoding="utf-8")
    screen = (FRONTEND / "components/admin/AuditAdmin.tsx").read_text(encoding="utf-8")

    assert '| "audit"' in sidebar, "ScreenId has no `audit` member"

    # The nav entry must be inside the ADMIN array, not CONSOLE or REFERENCE.
    admin_block = sidebar.split("const ADMIN: NavDef[] = [", 1)
    assert len(admin_block) == 2, "the ADMIN nav group has been renamed or removed"
    admin_block = admin_block[1].split("];", 1)[0]
    assert '{ id: "audit"' in admin_block, "the Audit entry is not in the admin-only nav group"
    assert 'role === "admin" && (' in sidebar, "the ADMIN group is no longer gated on the admin role"

    assert 'screen === "audit" && <AuditAdmin />' in console, "the console does not render the audit screen"
    # ...and the component refuses on its own, so reaching it another way answers
    # with the permissions decision rather than firing an admin-only request.
    assert "isAdmin(role)" in screen, "AuditAdmin does not check the session role"

    # It must page. A trail that only ever shows its first N rows, with no way to
    # see the rest and no statement of how many there are, is a demo of a trail.
    assert "api.audit(limit, offset)" in screen, "the audit screen does not paginate"
    assert "of ${total} entries" in screen, "the audit screen does not say how much it is NOT showing"
