"""Switchable demo datasets ("scenarios"). Each writes the three simulated tool
exports to data/mock/, so the engine + dashboard can demo different cases:

  demo        the planted problems incl. BOTH cross-tool paths (default)
  partial     the same policy with one console onboarded instead of seven
  clean       internal-only policy, no findings (the "all good" / empty state)
  scale       demo + N synthetic assets (stress the graph + engine)

There is no `multi_path` any more. It existed to show two cross-tool paths, and
the flagship now carries both (`seed_demo` planted problems 5 and 6), so the entry
duplicated the default. It had also started appending an ALGO-031 and a GC-002
that `seed_demo` already defines. Its own second path never materialised anyway:
the pivot was a /16 and `_valid_traversal` correctly refuses a range.

Builders reuse seed_demo so the canonical demo stays the single source of truth.

THE THREE FILES ARE ONE DATASET
-------------------------------
`_write` wrote them with three consecutive `write_text` calls, which is a silent
degradation with no exception anywhere: the engine's only input is these three
files, so a process that dies (or a disk that fills) between the first and the
third leaves a *mixed* estate on disk -- AlgoSec from `scale`, Guardicore and Wiz
from `demo`. Nothing in the pipeline can detect that. `normalize_all` reads three
valid JSON documents, the graph builds, findings come out, and the snapshot is
persisted as authoritative over a topology that never existed. Worse, the
truncation case is invisible even to a human: `write_text` on an existing file
truncates FIRST, so an interruption mid-write leaves a short or empty file rather
than the previous good one.

So the three payloads are serialized in full, written to sibling temp files, and
only then moved into place with `os.replace` -- atomic within a filesystem, and
in the loop's own scope the worst case shrinks from "half a JSON document" to
"one of three files is a version behind", which the log line below names.
`_write` is called by `write_scenario`, which the API calls on every cold engine
build and every recompute; the caller (`app/main.py`) already catches and logs a
failure here, and this module now says which scenario it wrote and, on failure,
which files had already moved.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import seed_demo  # noqa: E402
import seed_topology  # noqa: E402

from . import estate  # noqa: E402

MOCK_DIR = seed_demo.MOCK_DIR

#: The three POLICY exports. `normalizers.REQUIRED` raises when one is missing:
#: they are what the engine was built to analyse, so an absent one is a broken
#: deployment rather than a configuration choice. Every scenario writes all three.
POLICY: tuple[str, ...] = ("algosec_export.json", "guardicore_export.json",
                           "wiz_export.json")

#: The seven INFRASTRUCTURE exports, in `normalizers.OPTIONAL` order. Taken from
#: `seed_topology.EXPORTS` rather than re-listed, because the filename is the
#: contract with the normalizer and a second copy of it is a second thing to
#: drift. WHICH OF THESE EXIST IS THE ESTATE'S ONBOARDING STATE, so a scenario
#: that writes fewer of them has to REMOVE the rest (see `_write_dataset`).
INFRA: tuple[str, ...] = tuple(seed_topology.EXPORTS)

# Child of the API logger; see advisory/client.py for the convention.
log = logging.getLogger("npr.api.scenarios")

#: The picker, in the order it is rendered. `label` and `description` are printed
#: VERBATIM by the console's dataset menu, so these strings are product copy and
#: every number in them is measured, not rounded up.
SCENARIOS = [
    {"id": "demo", "label": "Retail estate under review",
     "description": "The flagship: two cross-tool paths to regulated data, "
                    "nine consoles, a 13-device topology with three designed weak points"},
    # `partial` sits next to `demo` because it is only legible BESIDE it: the two
    # differ in exactly one variable, and switching between them is the demo.
    {"id": "partial", "label": "Partial onboarding (AlgoSec only)",
     "description": "The same estate and the same 38 findings with one aggregator "
                    "connected. Two lanes drawn, the rest named dark with the API "
                    "that fills each"},
    {"id": "clean", "label": "Clean estate (target state)",
     "description": "What good looks like: no policy findings, no single point of "
                    "failure, and the one lane it still cannot see"},
    {"id": "scale", "label": "At scale",
     "description": "The same estate grown to N synthetic assets and N/4 branch "
                    "sites. Both paths survive; the ranked list does not grow"},
]


def _swap(payloads: list[tuple[str, dict]], remove: tuple[str, ...] = ()) -> None:
    """Replace `payloads` and delete `remove`, as close to atomically as a
    filesystem allows.

    Serialize everything first (a builder that raises must leave the previous
    dataset untouched, not a third of a new one), write each document to a
    sibling `.tmp` in the SAME directory -- `os.replace` is only atomic within a
    filesystem -- then move them into place. See the module docstring for why a
    partially-written dataset is the dangerous case rather than a loud one.

    REMOVALS GO LAST, after every replace has succeeded, and they are not part of
    the swap. The ordering is deliberate: the worst intermediate state is then
    MORE consoles onboarded than the scenario asked for -- a coherent estate with
    a stale console still in it -- rather than a lane going dark while the
    product states, falsely, that nobody observed it. Either way the failure is
    named, because a removal that fails leaves an onboarded console the new
    scenario does not want, and that is a mixed estate too.
    """
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    serialized = [(name, json.dumps(doc, indent=2) + "\n") for name, doc in payloads]
    staged: list[tuple[Path, Path]] = []
    moved: list[str] = []
    try:
        for name, text in serialized:
            tmp = MOCK_DIR / f".{name}.tmp"
            tmp.write_text(text)
            staged.append((tmp, MOCK_DIR / name))
        for tmp, final in staged:
            os.replace(tmp, final)             # atomic within the filesystem
            moved.append(final.name)
    except OSError:
        # Name what did and did not move: with some files replaced and others
        # not, the exports on disk are no longer one estate, and the engine
        # cannot tell. The caller (app/main.py) logs the exception; this
        # line is the part only this function knows.
        log.error("scenario write failed part-way; data/mock may mix two datasets",
                  exc_info=True,
                  extra={"event": "scenario_write_partial", "replaced": moved,
                         "pending": [f.name for _t, f in staged if f.name not in moved],
                         # Nothing is unlinked until every replace has landed, so
                         # a failure here has de-onboarded no console. Stated
                         # rather than omitted: the reader of this line is trying
                         # to work out what is on disk.
                         "removed": []})
        for tmp, _final in staged:             # never leave temp files behind
            tmp.unlink(missing_ok=True)
        raise

    unlinked: list[str] = []
    try:
        for name in remove:
            (MOCK_DIR / name).unlink(missing_ok=True)
            unlinked.append(name)
    except OSError:
        log.error("scenario de-onboarding failed part-way; a console this scenario "
                  "does not onboard is still on disk",
                  exc_info=True,
                  extra={"event": "scenario_deonboard_failed", "removed": unlinked,
                         "unremoved": [n for n in remove if n not in unlinked]})
        raise
    if unlinked:
        # A SEPARATE event from `scenario_written` on purpose: an absent export
        # means "this console is not onboarded", so removing one changes what the
        # Sources screen says about the engagement, not just what the engine
        # reads. (It is also why this cannot be folded into `scenario_written` --
        # `test_writing_a_scenario_says_which_dataset_the_engine_will_now_read`
        # unpacks that event as a single record.)
        log.info("infrastructure consoles de-onboarded for this scenario",
                 extra={"event": "scenario_deonboarded", "removed": unlinked})


def _write(algo: dict, gc: dict, wiz: dict) -> None:
    """The three-payload writer, kept EXACTLY as it was.

    Deliberately preserved rather than folded into `_write_dataset`: two failure
    tests call it with three positional dicts and assert the precise
    `replaced` / `pending` lists it produces, and those assertions are the proof
    that the atomic swap works. Widening the signature would have re-baselined
    the test that protects the guarantee, which is the wrong direction.
    """
    _swap(list(zip(POLICY, (algo, gc, wiz))))


def _write_dataset(policy: dict[str, dict], infra: dict[str, dict]) -> None:
    """One scenario's WHOLE estate: the three policy exports and the subset of the
    seven infrastructure exports it onboards.

    Any infrastructure export absent from `infra` is DELETED, and that deletion is
    the load-bearing half. `normalizers._load_optional` reads an absent file as
    "this console is not onboarded" and anything unreadable as a failure; a file
    left behind by the previous scenario therefore onboards a console the new one
    never asked for. That is not hypothetical -- it is the defect this function
    exists to close: `_write` covered three of ten exports, so "Clean estate"
    reported zero policy findings beside an Explorer showing thirteen devices and
    six resilience findings, four of them designed single points of failure.

    Every path is resolved from `scenarios.MOCK_DIR` AT CALL TIME, policy and
    infrastructure alike. The test sandbox monkeypatches this module's MOCK_DIR
    and nothing else, so reading `seed_topology.MOCK_DIR` for the infrastructure
    half would write the suite's fixtures into the real `backend/data/mock` --
    the engine's only input, which every other test reads.
    """
    missing = [name for name in POLICY if name not in policy]
    if missing:
        # A dataset missing a REQUIRED export is not a partial onboarding, it is
        # a broken builder; `normalize_all` would raise on the next engine build
        # with no trace back to here.
        raise ValueError(f"policy exports missing from this dataset: {', '.join(missing)}")
    unknown = sorted(set(infra) - set(INFRA))
    if unknown:
        # An infrastructure payload under a filename no normalizer reads is
        # written and then ignored for ever, which looks exactly like a console
        # that reported nothing.
        raise ValueError(f"not an infrastructure export: {', '.join(unknown)}")
    payloads = [(name, policy[name]) for name in POLICY]
    payloads += [(name, infra[name]) for name in INFRA if name in infra]
    _swap(payloads, remove=tuple(name for name in INFRA if name not in infra))


def _policy() -> dict[str, dict]:
    """The three demo policy exports, shared verbatim by `demo` and `partial`.

    `partial` differs from `demo` ONLY in which infrastructure consoles are
    onboarded. That is the entire argument the pair exists to make -- the policy
    answer does not degrade when infrastructure coverage does -- so the two must
    read the same fixture rather than two copies of it.
    """
    algo, gc, wiz = (seed_demo.algosec_export(), seed_demo.guardicore_export(),
                     seed_demo.wiz_export())
    return dict(zip(POLICY, (algo, gc, wiz)))


def _demo():
    _write_dataset(_policy(), seed_topology.build_exports(estate.build()))


#: What `partial` onboards. The aggregator and nothing else -- the engagement the
#: brief describes, where the client hands over AlgoSec and no console access.
_PARTIAL_CONSOLES = ("algosec_topology",)


def _partial():
    """The same estate, seen through one console instead of seven.

    Identical policy to `demo` (see `_policy`), so the only variable between the
    two is infrastructure coverage. Switching between them side by side is the
    demonstration: the policy findings do not move, and the Explorer loses four
    lanes that each name the API that would light them. That is the difference
    between "we found nothing there" and "nobody looked", which is the claim the
    product is built around and the one a slide cannot make.
    """
    est = estate.build()
    _write_dataset(_policy(), seed_topology.build_exports(est, _PARTIAL_CONSOLES))


#: What `clean` onboards: every console, Meraki included. The resilient estate
#: contains no Meraki hardware, so that export is written PRESENT AND EMPTY
#: rather than removed -- and the difference is the whole point of the card.
#: `normalizers._load_optional` reads an absent file as "not onboarded" and a
#: present one as "this console answered", so an empty Meraki export is the
#: product saying *we read the org and it has no devices*, which is a different
#: statement from *we never asked*. `clean` is the one screen where that
#: distinction can be demonstrated instead of asserted.
_CLEAN_CONSOLES = None          # None == all seven


def _clean():
    """The control case: a well-built estate, on BOTH graphs.

    This is the scenario the old writer made incoherent, and it is the defect
    that started this change. `_write` covered three of ten exports, so `clean`
    replaced the policy half and left whatever infrastructure the previous
    scenario had written -- and "Clean estate" reported zero policy findings
    beside an Explorer showing thirteen devices and a resilience analyzer
    reporting six single points of failure, four of them designed in. The screen
    contradicted the name in the picker.

    Both halves are now the same well-built site. `estate.build_resilient()`
    inverts every designed weakness in the flagship (two carriers, protected dual
    handoffs, everything criss-crossed, nothing dangling) and measures clean;
    `seed_demo.clean_*_export` is an internal-only least-privilege policy that
    measures to zero findings from all five analyzers.

    It still names ONE absence -- no onboarded console enumerates a workstation,
    so the endpoint lane reports `unobserved` -- and it still publishes the HA
    pair's suppression. A product that prints an unqualified all-clear is the one
    you cannot trust when it prints red.
    """
    policy = dict(zip(POLICY, (seed_demo.clean_algosec_export(),
                               seed_demo.clean_guardicore_export(),
                               seed_demo.clean_wiz_export())))
    _write_dataset(policy, seed_topology.build_exports(estate.build_resilient(),
                                                       _CLEAN_CONSOLES))


#: Synthetic policy assets per branch site, so ONE number on the picker grows
#: both halves of the estate. `scale` used to grow the rule table beside the
#: stock thirteen-device topology, so "At scale" answered the policy half of
#: "how long would this take on a real network" and left the expensive half --
#: the topology -- at demo size (`bench_topology.py`: the per-device blast radius
#: is O(V*(V+E)), and it is 90% of the wall clock past a few hundred devices).
#:
#: Four is chosen against the measured ladder, not picked. Each branch is four
#: devices, so `n` synthetic assets buys `n` network devices too, and the API's
#: existing bound on `n` (`DatasetBody.n`, le=2000) becomes the bound on BOTH:
#:
#:     n      branches   devices   full pipeline
#:     500         125       513      ~0.3 s      <- the picker default
#:   1,000         250     1,013      ~1.3 s
#:   2,000         500     2,013      ~5.2 s      <- the API ceiling
#:
#: The ceiling is where it is because `POST /api/admin/dataset` rebuilds the
#: engine synchronously on the request path. The next rung (1,000 branches,
#: 4,013 devices) measures 19.6 s end to end, 18.0 s of it resilience -- which is
#: the number the scale screen should SHOW, with `bench_topology.py 1000` beside
#: it, rather than a number the demo quietly never reaches.
_ASSETS_PER_BRANCH = 4


#: Where the synthetic assets live. NOT 10.0.0.0/8, and the move is worth 500
#: findings. The synthetic hosts used to sit at 10.200.x.y with 10.201.x.0/24
#: sources -- both inside ALGO-001's destination (`0.0.0.0/0 -> 10.0.0.0/8`,
#: service any), so every single synthetic rule was shadowed by it. Measured at
#: n=500: 535 findings of which 516 were `shadowed_rule`, all naming ALGO-001,
#: all identical. That is not a scale demonstration, it is 500 copies of one
#: finding nobody will read, and it buries the flagship's 38 under noise the
#: fixture manufactured. In 172.20/172.24 (RFC 1918, outside 10/8) the same
#: dataset produces 38 + a handful: the ranked list does not grow with the
#: estate, which is the actual claim "At scale" is making.
_SCALE_HOST_PREFIX = "172.20"
_SCALE_SOURCE_PREFIX = "172.24"


def _scale(n: int = 500):
    """The flagship estate grown on BOTH axes: N synthetic policy assets and a
    topology of roughly N/4 more devices.

    `scale` used to grow only the rule table, so "At scale" answered the policy
    half of "how long would this take on a real network" and left the topology
    half at demo size -- and the topology half is the expensive one.
    """
    a, g, w = seed_demo.algosec_export(), seed_demo.guardicore_export(), seed_demo.wiz_export()
    for i in range(n):
        host = f"svc-{i:05d}"
        a["objects"][host] = {"type": "host",
                              "value": f"{_SCALE_HOST_PREFIX}.{(i // 254) % 254}.{(i % 254) + 1}",
                              "tags": ["prod"]}
        a["rules"].append({"rule_id": f"SCALE-{i:05d}", "order": 2000 + i,
                           "src": f"{_SCALE_SOURCE_PREFIX}.{(i // 254) % 254}.0/24", "dst": host,
                           "service": "tcp/443", "action": "allow", "comment": "synthetic"})
    branches = n // _ASSETS_PER_BRANCH
    _write_dataset(dict(zip(POLICY, (a, g, w))),
                   seed_topology.build_exports(estate.build(branches=branches)))


_BUILDERS = {"demo": _demo, "partial": _partial, "clean": _clean, "scale": _scale}


def write_scenario(scenario: str, n: int = 500) -> None:
    """Regenerate data/mock for `scenario`. Raises ValueError on an unknown id.

    Logged because this function OVERWRITES the engine's only input. It runs on
    every cold engine build and every recompute, so "the dataset changed under
    me" is a real support question (it is also the mechanism behind the audit's
    finding that a seeded scale dataset does not survive a restart), and the one
    line here is what makes the answer checkable rather than inferred.
    """
    fn = _BUILDERS.get(scenario)
    if fn is None:
        # Not a silent path -- it raises -- but the log is what ties the 4xx the
        # caller returns to the value that produced it.
        log.error("unknown scenario requested; data/mock left as it was",
                  extra={"event": "scenario_unknown", "scenario": scenario,
                         "known": sorted(_BUILDERS)})
        raise ValueError(f"unknown scenario: {scenario}")
    if scenario == "scale":
        fn(n)
    else:
        fn()
    log.info("scenario written to data/mock", extra={
        "event": "scenario_written", "scenario": scenario,
        "synthetic_assets": n if scenario == "scale" else 0})
