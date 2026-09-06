"""One place that decides whether tests which touch the real world may run.

WHY THIS IS A MODULE AND NOT A LINE IN EACH TEST
------------------------------------------------
`backend/conftest.py` opens by stating what this suite is: "a *unit* suite ...
it has no business opening a socket", and it closes three seams to keep that
true (a blanked DATABASE_URL, a stubbed metric writer, a stubbed Ollama probe).
For a while one test contradicted that paragraph. The live Azure discovery probe
gated itself OPT-OUT -- it ran unless `NPR_SKIP_AZURE_LIVE` was set -- so the
documented `pytest` command dialled Azure Resource Manager from any machine with
a working `az login`, which is every machine this feature was built on. It then
asserted the ABSENCE of a GPT deployment in `Foundry-RG`, a resource group
nobody in this repo controls. Somebody deployed `gpt-5.1-codex-mini` and the
suite went red: not because this code changed, not because it was wrong, but
because a stranger clicked Create in a portal.

Two things were wrong and they are different things:

  * the DEFAULT. "Does `pytest` pass?" has to be a question about this
    repository. If the answer depends on a third party's uptime, credentials on
    the machine, and what somebody else deployed this morning, the suite has
    stopped being a measurement of the code.
  * the ENFORCEMENT. The rule lived in a docstring, so obeying it was a matter
    of each test author remembering. The next live test would have had exactly
    the same chance of getting it wrong.

So the rule is now mechanical, in two halves that do not depend on each other:

  1. `backend/conftest.py` SKIPS every `@pytest.mark.live` test at collection
     unless one of `OPT_IN_ENVS` is set. Marking a test live makes it opt-in by
     construction -- there is no per-test gate to forget.
  2. `backend/conftest.py` BLOCKS outbound sockets to anything but loopback for
     every test that is NOT marked live. Forgetting the marker does not buy a
     quiet network call; it buys a loud failure naming the address.

Half 1 without half 2 is a convention. Half 2 without half 1 is a wall with no
door. Together, a test either declares that it reaches the internet and is
therefore opt-in, or it does not reach the internet.

Loopback stays open on purpose: the database-backed tests
(`NPR_TEST_DATABASE_URL=postgresql://npr:nprdev@localhost:55433/npr`) are a
local dependency the developer controls, which is the whole difference.
"""

from __future__ import annotations

import os

# The marker. Registered in pyproject.toml because the suite runs with
# `--strict-markers`, so a typo'd marker is a collection error rather than a
# test that silently loses its gate.
LIVE_MARKER = "live"

# Either of these grants the live tests. Two names, because the general switch
# and the Azure-specific one both already existed in scripts and in operators'
# shell history, and breaking those would just teach people to pass `-p no:...`.
OPT_IN_ENVS = ("NPR_RUN_LIVE", "NPR_RUN_AZURE_LIVE")

# Naming a live TARGET is asking for the live tests just as plainly as flipping
# a switch, and one gate here would otherwise break a stronger one elsewhere:
# `test_advisory_azure.py`'s `live_collection_decision` treats "NPR_TEST_AZURE_
# ENDPOINT is set but the test did not run" as a HARD FAILURE, on the grounds
# that a green run containing a skip is what a pipeline reads as proof. If the
# collection hook could skip those tests while their own target variable was
# set, that guarantee would be silently gone. So a non-empty target counts as
# opt-in, and the specific gate keeps deciding SKIP / RUN / FAIL from there.
TARGET_ENVS = ("NPR_TEST_AZURE_ENDPOINT",)

# The explicit veto, honoured for backwards compatibility with any CI job that
# already sets it. It WINS over the opt-in: a switch whose whole purpose is
# "never touch the network here" must not be overridable by a broader one.
VETO_ENV = "NPR_SKIP_AZURE_LIVE"

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def live_enabled() -> bool:
    """True when tests marked `live` may open sockets to the real world."""
    if _truthy(VETO_ENV):
        return False
    if any(_truthy(name) for name in OPT_IN_ENVS):
        return True
    return any(os.environ.get(name, "").strip() for name in TARGET_ENVS)


def skip_reason() -> str | None:
    """The sentence a skipped live test prints, or None when it may run.

    Written for the person reading a `-r s` summary: it says what the test would
    have done, what it needs, and the exact variable that grants it -- so the
    skip is a documented decision rather than an unexplained gap in the run.
    """
    if _truthy(VETO_ENV):
        return f"{VETO_ENV} is set: live tests are vetoed on this machine"
    if not live_enabled():
        return ("live test is opt-in: it opens a socket to a real external "
                "service and needs a working credential for it. Set "
                f"{OPT_IN_ENVS[0]}=1 to run it, or name a target "
                f"({', '.join(TARGET_ENVS)}).")
    return None
