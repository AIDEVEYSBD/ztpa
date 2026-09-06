"""Cross-process determinism: the engine's FULL output, byte for byte.

Why a subprocess and not two calls
----------------------------------
`verify_engine.py` used to check determinism as `r1, r2 = run(), run()` and then
compare three fields of each finding. Both calls were in ONE interpreter, so
`PYTHONHASHSEED` was necessarily identical between them -- and hash
randomisation across processes is precisely the failure mode the determinism
claim is about. A `set` iterated into an output list, a `dict` whose insertion
order leaks into a digest, a `frozenset` reduced with `str()`: none of it can
show up in a same-process A/B. The audit's verdict was that "the determinism
check cannot detect the failure modes determinism claims guard against"
(PROD-READINESS-AUDIT, `backend/scripts/verify_engine.py:48`).

So this module launches real interpreters, seeds each one differently, and
compares a sha256 over EVERYTHING the engine returns: the snapshot id, every
field of every canonical record, every field of every finding INCLUDING its
`signals` blob, the assets, the correlation audit rows, the alias map, the
degraded-analyzer markers, and the graph's sorted nodes and edges with their
attributes. Timings are the one thing excluded, and deliberately -- they are
wall-clock measurements, not results.

Determinism is a product claim here, not an implementation detail: governance
rows hang off `snapshot_id`, cached AI artifacts are keyed by
`(snapshot_id, finding_id)`, and the whole "the engine is the judge" story rests
on the same inputs always producing the same verdict. This test exists so that
property cannot be lost silently.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]

# Seeds run in separate interpreters. "random" is the important one -- it makes
# CPython pick a fresh hash seed per process, which is what turns a latent
# set-iteration leak into a reproducible failure instead of a flake somebody
# sees once. The fixed seeds pin the two ends and one arbitrary middle so a
# failure report names a seed you can re-run.
SEEDS = ("0", "1", "random", "424242")

# The dump program. Kept as source text (rather than importing a helper) because
# it has to run in a pristine interpreter with nothing of pytest's in it.
_DUMP = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
from src.analyzers.run_all import run

merges = [tuple(p.split("=", 1)) for p in sys.argv[2:] if "=" in p]

r = run(manual_merges=merges)

def node_attrs(d):
    # Attribute values are lists/strings already; sort every list so a set that
    # leaked into one would show up as a DIFFERENT hash rather than being
    # normalised away here.
    return {k: v for k, v in sorted(d.items())}

dump = {
    "snapshot_id": r.snapshot_id,
    "label": r.label,
    # Every field of every canonical record, in the engine's own order.
    "records": [rec.model_dump(mode="json") for rec in r.records],
    # Every field of every finding, signals included. This is what the old
    # three-field comparison could not see.
    "findings": [f.model_dump(mode="json") for f in r.findings],
    "assets": [a.model_dump(mode="json") for a in r.assets],
    "correlations": [c.model_dump(mode="json") for c in r.correlations],
    "resolved": [
        {"source_tool": o.source_tool, "object_name": o.object_name,
         "object_kind": o.object_kind, "resolved": o.resolved,
         "source_device": o.source_device, "is_dynamic": o.is_dynamic}
        for o in r.resolved
    ],
    "alias_map": r.alias_map,
    "degraded_analyzers": r.degraded_analyzers,
    "nodes": [[n, node_attrs(d)] for n, d in sorted(r.graph.nodes(data=True))],
    "edges": [[u, v, d] for u, v, d in sorted(r.graph.edges(data=True),
                                              key=lambda e: (e[0], e[1]))],
    # Deliberately NOT r.timings: those are measured milliseconds.
}
sys.stdout.write(json.dumps(dump, sort_keys=True, separators=(",", ":"), default=str))
'''


def _dump(seed: str, merges: tuple[tuple[str, str], ...] = ()) -> str:
    """Run the engine in a fresh interpreter under `seed`; return its raw dump."""
    env = {
        **os.environ,
        "PYTHONHASHSEED": seed,
        # The engine needs no database, and the checked-in .env holds
        # placeholders that would otherwise cost a 30s DNS timeout (see
        # backend/conftest.py). Blanked here for the same reason.
        "DATABASE_URL": "",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    args = [sys.executable, "-c", _DUMP, str(BACKEND)] + [f"{a}={b}" for a, b in merges]
    proc = subprocess.run(args, capture_output=True, text=True, env=env,
                          cwd=str(BACKEND), timeout=180)
    assert proc.returncode == 0, (
        f"engine run under PYTHONHASHSEED={seed} failed:\n{proc.stderr}")
    return proc.stdout


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture(scope="module")
def dumps() -> dict[str, str]:
    """One full engine dump per seed, each from its own interpreter."""
    return {seed: _dump(seed) for seed in SEEDS}


def test_the_dump_is_not_degenerate(dumps):
    """Guard the guard.

    Every assertion below compares two digests. If the dump program silently
    produced `{}` -- an import that failed into an empty result, a run() that
    returned nothing -- the comparisons would all pass while proving nothing. So
    first assert the dumps actually contain a snapshot, records and findings.
    """
    import json
    payload = json.loads(dumps[SEEDS[0]])
    assert payload["snapshot_id"].startswith("snap_")
    assert len(payload["records"]) > 10
    assert len(payload["findings"]) > 10
    assert payload["assets"] and payload["nodes"] and payload["edges"]
    assert payload["degraded_analyzers"] == [], "a degraded analyzer truncates the dump"


def test_the_full_engine_dump_is_identical_across_processes_and_seeds(dumps):
    """The property, stated once: same input, same bytes, in any interpreter.

    Covers snapshot_id, every record field, every finding field including
    `signals`, assets, correlations, alias_map, degraded markers, and the sorted
    graph with node/edge attributes.
    """
    digests = {seed: _digest(text) for seed, text in dumps.items()}
    distinct = set(digests.values())
    assert len(distinct) == 1, (
        "the engine produced different output under different hash seeds: "
        + ", ".join(f"{seed}={d[:12]}" for seed, d in sorted(digests.items())))


def test_the_snapshot_id_is_identical_across_processes_and_seeds(dumps):
    """Stated separately because this is the id governance rows hang off.

    The full-dump test above subsumes it, but when that one fails this one says
    immediately whether the SYSTEM OF RECORD moved or only a finding did.
    """
    import json
    ids = {seed: json.loads(text)["snapshot_id"] for seed, text in dumps.items()}
    assert len(set(ids.values())) == 1, ids


def test_a_rerun_in_the_same_process_is_also_identical():
    """The cheap check `verify_engine.py` used to be, kept as a fast tripwire.

    A same-process re-run cannot see hash-seed effects, but it CAN see a module
    holding mutable state between runs (a cached parse, an analyzer appending to
    a module-level list), which the cross-process test cannot distinguish from a
    clean run. The two failure modes are different, so both checks stay.
    """
    from src.analyzers.run_all import run
    a, b = run(), run()
    assert a.snapshot_id == b.snapshot_id
    assert [f.model_dump(mode="json") for f in a.findings] == \
           [f.model_dump(mode="json") for f in b.findings]


def test_the_digest_actually_moves_when_the_engine_state_moves():
    """Guard the guard, part two: prove the digest is SENSITIVE.

    A digest over a dump that happened to omit the interesting fields would be
    stable for the wrong reason. `manual_merges` is the cleanest lever: it is an
    ENGINE INPUT that touches nothing in the source exports, so it changes the
    asset set, the alias map, the graph and (since Phase 1 widened
    `_fingerprint`) the snapshot id, without changing a single record. If the
    digest did not move here, every equality assertion above would be worthless.

    It is also the Phase 1 exit criterion "changing only ... the manual_merges
    list produces a DIFFERENT snapshot_id", checked end to end through a real
    process rather than against the fingerprint function in isolation.

    THE PAIR MOVED, and the reason matters. This used to merge
    `app-server-07`/`appsrv-07`, which the engine now merges BY ITSELF: the demo
    exports declare the shared `vpcId` that `identity.resolve_identities`
    requires, so asking for that merge by hand is a no-op on the asset set and
    the last assertion could never hold again. `db-prod-01`/`rds-prod-customers`
    replaces it and is a better lever anyway -- it is the near-duplicate the
    embedding suggester flags for review (see `scripts/seed_demo.py`), so it is
    exactly the shape of decision `manual_merges` exists to carry: two names the
    guards will never fuse on their own (different addresses, no shared scope)
    that a human confirms are one database.
    """
    import json
    base = _dump("0")
    merged = _dump("0", merges=(("db-prod-01", "rds-prod-customers"),))
    assert _digest(base) != _digest(merged)
    assert json.loads(base)["snapshot_id"] != json.loads(merged)["snapshot_id"]
    # ...and the merge is what moved: two names became one asset.
    assert len(json.loads(merged)["assets"]) == len(json.loads(base)["assets"]) - 1


def test_the_merged_run_is_itself_deterministic_across_seeds():
    """The identity layer's union-find, guards and suppression counters are the
    newest and most set-heavy code in the engine (`identity.resolve_identities`
    groups by IP, by context and by environment class). Determinism has to hold
    on the path where a HUMAN-CONFIRMED merge bypasses the guards, not only on
    the demo's default path (which now performs one scoped merge of its own)."""
    merges = (("db-prod-01", "rds-prod-customers"),)
    digests = {seed: _digest(_dump(seed, merges=merges)) for seed in ("0", "random")}
    assert len(set(digests.values())) == 1, digests
