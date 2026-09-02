"""How the real-database tests decide between running, skipping and FAILING.

Not a test module (the name does not start with `test_`, so pytest does not
collect it) and deliberately free of side effects: it takes the environment as
two arguments and returns a decision, so the decision itself can be unit-tested
offline -- see `backend/tests/test_persist_snapshot.py`.

WHY IT IS A SEPARATE THING AT ALL. `backend/tests/test_db_governance.py` skips
when there is no database, which is what keeps CI green without one. The obvious
implementation -- `skipif(cannot_connect())` -- also skips when the database was
ASKED FOR and could not be reached: a typo in the password, a container that did
not come up, a CI job that sets the variable to the wrong host. That run exits 0
with 32 skips, and 0 is the number a pipeline reads. The whole value of these
tests is that they are the only ones executed against real rows, so "I asked for
them and they silently did not run" is the one outcome that must be red.

So the three cases are separated:

    variable unset          -> SKIP  (offline, the documented default)
    variable set, reachable -> RUN
    variable set, unreachable -> FAIL, loudly, at collection

The third is an operator error, not a property of the environment.
"""

from __future__ import annotations

SKIP = "skip"
RUN = "run"
FAIL = "fail"

# The environment variable the governance tests read. Deliberately NOT
# `DATABASE_URL`: backend/conftest.py blanks that one at import so the unit suite
# can never reach a server, and this must not be the loophole that undoes it.
TEST_DB_ENV = "NPR_TEST_DATABASE_URL"


def collection_decision(url: str, probe_error: str | None) -> tuple[str, str]:
    """`(SKIP | RUN | FAIL, reason)` for a URL and the result of probing it.

    `url` is the raw environment value (empty or whitespace = unset). `probe_error`
    is None when the connection succeeded and a message when it did not; it is
    ignored when there is no URL, so a caller never has to probe an empty string.
    """
    if not url.strip():
        return SKIP, (f"no database for the governance tests ({TEST_DB_ENV} is not set); "
                      f"set {TEST_DB_ENV} to run them")
    if probe_error:
        return FAIL, (
            f"{TEST_DB_ENV} is set but the database is unreachable: {probe_error}. "
            f"These are the only tests that execute against real rows, so this is a hard "
            f"failure rather than a skip -- a run that was asked for a database and did not "
            f"get one has proved nothing, and must not exit 0. Unset {TEST_DB_ENV} to run "
            f"the suite offline, or fix the connection string.")
    return RUN, "the governance tests are running against a real database"
