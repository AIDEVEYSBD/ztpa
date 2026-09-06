"""Meta-guard: no test in this suite may name a source file that is not there.

WHY THIS EXISTS
---------------
A large part of this suite is SOURCE-LEVEL contracts -- tables of
`(file, must contain, must NOT contain)` that pin previously-refuted defects in
the frontend, in `db/`, in the deployment scripts. They are the cheapest guard
in the repo (no database, no network, no Node) and they have one structural
weakness: every one of them addresses its subject by PATH, and a path is a
reference that another change can invalidate without ever opening this
directory.

That is not hypothetical. When authentication became SSO-only,
`frontend/app/actions.ts` and `frontend/components/admin/UsersAdmin.tsx` were
deleted -- legitimately; the screen and its server actions were the local
account management that SSO replaces. Two entries in
`test_frontend_error_surfacing.py`'s SURFACING_CONTRACT still named them. The
result was not a clear "these entries are stale": it was
`FileNotFoundError: .../frontend/app/actions.ts` raised out of
`test_refuted_call_sites_render_their_failure`, i.e. a guard against
"a failure that reports as a different failure" failing as a different failure.
Worse, it fails at the point of the READ, so the surfacing assertions for that
entry never ran, and any genuine regression landing in the same change would
have been hidden behind the same red line.

The fix in that module (retire the entry, invert the claim to "the panel that
could lie is not there to lie", assert the inversion) closes the instance. This
module closes the CLASS: it walks every test module's literal path references
and demands that each one either resolves on disk or is covered by a declared
ABSENCE contract. A file deletion that leaves a contract dangling now fails
here, by name, before the dangling contract fails as an IOError -- and it fails
whether the stale reference is in a file the deleting change owned or not.

WHAT COUNTS AS A PATH REFERENCE
-------------------------------
An `ast.Constant` string that contains `/`, ends in a source suffix, has no
whitespace and no placeholder syntax. That deliberately excludes prose: every
module here documents its subject at length, and a docstring naming a file it
used to guard must stay legal (docstrings carry spaces, so they never match).
Anything that matches but is not a path gets one line in `NOT_A_PATH` with a
reason -- the same "adding one is a reviewed decision" shape as the exemption
lists elsewhere in this suite.

No database, no network, no Node: this parses files.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.test_frontend_error_surfacing import RETIRED_CALL_SITES, SURFACING_CONTRACT
from tests.test_sso_only import DELETED as SSO_DELETED

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = Path(__file__).resolve().parent
FRONTEND = REPO_ROOT / "frontend"

# The roots a bare relative path in a test may be written against. `frontend/`
# is here because the frontend contracts hold paths relative to it (`FRONTEND /
# rel`), which is what makes them readable -- and what makes them ambiguous to a
# scanner that only knows the repo root.
SEARCH_ROOTS = (REPO_ROOT, FRONTEND, REPO_ROOT / "backend", REPO_ROOT / "db")

SOURCE_SUFFIXES = (
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".sql", ".sh", ".json", ".yml", ".yaml", ".toml", ".md", ".css",
)

# Literals that look like a path and are not one. Empty today, and kept as a
# named list rather than a widened regex so that the day one is needed it is a
# line somebody wrote down with a reason, not a quietly loosened matcher.
NOT_A_PATH: frozenset[str] = frozenset()


# --------------------------------------------------------------------------
# the declared absences
# --------------------------------------------------------------------------
# A test may name a file that does not exist -- but only to assert that it does
# not exist. Both tables below do exactly that, and both are IMPORTED rather
# than restated here: a copy would be a third place to forget, which is the
# defect this module is about.
#
#   * test_sso_only.DELETED          -- the local-auth surface removed with
#                                       password login and magic links
#   * ...RETIRED_CALL_SITES          -- surfacing contracts whose call site went
#                                       with it
ABSENT_BY_DESIGN: dict[str, str] = {
    **{rel: "tests/test_sso_only.py::DELETED" for rel, _what in SSO_DELETED},
    **{rel: "tests/test_frontend_error_surfacing.py::RETIRED_CALL_SITES"
       for rel, _what, _where in RETIRED_CALL_SITES},
}


def _looks_like_a_path(s: str) -> bool:
    if s in NOT_A_PATH:
        return False
    if "/" not in s or not s.endswith(SOURCE_SUFFIXES):
        return False
    # Prose, format strings, globs and URLs are not references to a file.
    if any(c in s for c in " \t\n{}*?") or s.startswith(("/", "http://", "https://", ".")):
        return False
    return True


def _path_literals(module: Path) -> list[tuple[int, str]]:
    """`(lineno, literal)` for every string constant in `module` that names a file."""
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    seen: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _looks_like_a_path(node.value):
                seen.add((node.lineno, node.value))
    return sorted(seen)


def _resolves(rel: str) -> bool:
    return any((root / rel).exists() for root in SEARCH_ROOTS)


TEST_MODULES = sorted(p for p in TESTS_DIR.glob("*.py") if p.name != "__init__.py")


def test_the_scanner_finds_something_to_check() -> None:
    """Guard the guard. A regex that silently stops matching is a green test
    that checks nothing, which is the failure mode this whole suite is about."""
    total = sum(len(_path_literals(m)) for m in TEST_MODULES)
    assert len(TEST_MODULES) > 20, f"only {len(TEST_MODULES)} test modules found"
    assert total > 25, (
        f"the path scanner matched only {total} literals across "
        f"{len(TEST_MODULES)} modules; it has stopped seeing the contracts"
    )
    # ...and it must really see the live frontend contracts, not just any string.
    surfacing = dict(_path_literals(TESTS_DIR / "test_frontend_error_surfacing.py"))
    assert "components/admin/ToolsAdmin.tsx" in surfacing.values()


@pytest.mark.parametrize("module", TEST_MODULES, ids=[m.name for m in TEST_MODULES])
def test_no_test_names_a_source_file_that_is_gone(module: Path) -> None:
    """Every path a test names resolves, or is a declared absence.

    The failure message is the whole point: a deleted file must produce the
    sentence "this contract names a file that no longer exists, decide what to
    do about it" and not an IOError from inside an unrelated assertion.
    """
    dangling = [
        (lineno, rel)
        for lineno, rel in _path_literals(module)
        if not _resolves(rel) and rel not in ABSENT_BY_DESIGN
    ]
    assert not dangling, (
        f"{module.name} names source files that do not exist:\n  "
        + "\n  ".join(f"line {lineno}: {rel}" for lineno, rel in dangling)
        + "\n\nA source-level contract addresses its subject by path, so deleting "
        "the subject leaves the contract asserting nothing -- or, worse, dying on "
        "the read before its assertions run. Either restore the file, or move the "
        "entry into that module's absence contract (see tests/test_sso_only.py's "
        "DELETED and test_frontend_error_surfacing.py's RETIRED_CALL_SITES) so the "
        "claim inverts from 'it surfaces its failure' to 'it is not there to lie'."
    )


def test_a_declared_absence_is_really_absent() -> None:
    """The other direction: an absence contract that quietly came back.

    `test_sso_only.py` asserts this for its own twelve entries one at a time;
    doing it again here is not redundant, it is the invariant stated where the
    two tables meet. A file listed as deleted that is on disk means one of the
    tables is describing a repo that no longer exists.
    """
    back = sorted(rel for rel in ABSENT_BY_DESIGN if _resolves(rel))
    assert not back, (
        "declared-deleted files exist on disk: " + ", ".join(back)
        + ". They are listed in " + ", ".join(sorted({ABSENT_BY_DESIGN[r] for r in back}))
        + " -- restoring one is an authentication/UI design decision, so the table "
        "has to change with it."
    )


def test_the_present_and_absent_contracts_cannot_contradict_each_other() -> None:
    """THE EXACT DEFECT, pinned across module boundaries.

    `test_sso_only.py::DELETED` said `app/actions.ts` and
    `components/admin/UsersAdmin.tsx` must NOT exist. SURFACING_CONTRACT in
    `test_frontend_error_surfacing.py` said they must exist AND contain specific
    strings. Both tables were in the suite at once, both were "passing" in the
    sense that somebody had thought about them, and nothing anywhere compared
    them -- so the contradiction surfaced as a FileNotFoundError rather than as
    the disagreement it was.

    Two tables that can disagree about the same file need a third thing that
    reads both. This is it.
    """
    required_present = {rel for rel, _req, _forb in SURFACING_CONTRACT}
    contradiction = sorted(required_present & set(ABSENT_BY_DESIGN))
    assert not contradiction, (
        "these files are required to exist by SURFACING_CONTRACT and required to "
        "be gone by an absence contract: " + ", ".join(contradiction)
        + ". Whichever is right, the other has to be updated in the same change."
    )
