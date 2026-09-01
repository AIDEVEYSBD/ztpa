"""Demo acceptance check: regression-check the seeded 27-rule demo dataset.

Exit 0 = all pass. Run any time: `python backend/scripts/verify_engine.py`
(or `make verify` / `python tasks.py verify`).

WHAT THIS IS, AND WHAT IT IS NOT
--------------------------------
Every check below is an assertion about ONE authored fixture -- the five planted
problems in `backend/data/mock/*.json`. It is a regression gate on that dataset,
not a correctness proof on arbitrary input, and the moment a client export is
loaded it fails by construction. The universally-quantified properties that DO
hold on any input (0 <= severity <= 100, forced_critical implies the critical
band, every reported hop is a real edge, every raw_ref resolves, every
severity_vector recomputes to its own severity) live in
`backend/tests/test_engine_invariants.py`, and the cross-seed determinism matrix
lives in `backend/tests/test_determinism.py`. `backend/tests/test_demo_golden.py`
runs everything in this file under pytest so CI covers it too.

TWO STRUCTURAL WEAKNESSES THE AUDIT NAMED, AND HOW THEY ARE FIXED HERE
----------------------------------------------------------------------
1. *Determinism was checked in ONE process.* `r1, r2 = run(), run()` shares an
   interpreter, so `PYTHONHASHSEED` is necessarily identical between the two
   calls -- and cross-process hash randomisation is exactly the failure mode the
   determinism claim is about. The re-run check is kept (it catches module-level
   mutable state, which a subprocess cannot distinguish from a clean run) and a
   SECOND interpreter is now launched with a different seed and compared.
2. *Only three fields of each Finding were compared.* `(id, severity,
   severity_band)` left `signals` -- where the severity vector, the resolved
   CIDRs, the port class and the forced reasons all live -- entirely unchecked.
   Both determinism checks now compare the complete model dump.

THE GOLDENS WERE DELIBERATELY RE-BASELINED IN PHASE 1
-----------------------------------------------------
The demo moved from 17 findings / `snap_d065e3248774` to 30 findings /
`snap_e013ae7930ae`. Every difference is attributed in
`backend/tests/test_demo_golden.py`, which is the file that pins the counts. The
one check in here that CHANGED MEANING rather than merely moving is P5, the
cross-tool path -- see `_check_p5` for the full reasoning. Nothing was deleted
to make this file green.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from src.analyzers.run_all import EngineResult, run          # noqa: E402
from src.graph.reachability import _valid_traversal          # noqa: E402

# The chain the demo's cross-tool path used to traverse. Kept as a constant
# because P5 now asserts things ABOUT it -- that its edges still exist, and that
# the traversal rule is what removes it -- rather than asserting it is reported.
LEGACY_CROSS_TOOL_CHAIN = ["0.0.0.0/0", "lb-public-01", "app-server-07",
                           "internal-app", "db-prod-01"]
# ...and the four rules that granted its hops, in hop order. The chain is a
# graph artefact and can legitimately change shape; these four rules are DATA,
# and if one of them disappears that is a regression in the fixture or the
# normalizers, not a scoring decision.
LEGACY_CROSS_TOOL_GRANTS = ["WIZ-001", "WIZ-002", "GC-001", "ALGO-030"]

# A full engine dump, printed by a pristine interpreter for the cross-process
# determinism check. Duplicated (in spirit) by test_determinism.py, which runs
# the wider seed matrix; this script has to stay importable-free and standalone.
_DUMP = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
from src.analyzers.run_all import run
r = run()
sys.stdout.write(json.dumps({
    "snapshot_id": r.snapshot_id,
    "findings": [f.model_dump(mode="json") for f in r.findings],
    "assets": [a.model_dump(mode="json") for a in r.assets],
    "correlations": [c.model_dump(mode="json") for c in r.correlations],
    "alias_map": r.alias_map,
    "nodes": [[n, dict(sorted(d.items()))] for n, d in sorted(r.graph.nodes(data=True))],
    "edges": [[u, v, d] for u, v, d in sorted(r.graph.edges(data=True), key=lambda e: (e[0], e[1]))],
}, sort_keys=True, separators=(",", ":"), default=str))
'''


class Check:
    """One named assertion, with the detail line a failure should print."""

    __slots__ = ("name", "ok", "detail")

    def __init__(self, name: str, ok: object, detail: str = "") -> None:
        self.name = name
        self.ok = bool(ok)
        self.detail = detail

    def __iter__(self):
        """Unpacks as the old `(name, ok)` tuple, so any caller written against
        the previous shape of this file keeps working."""
        return iter((self.name, self.ok))


def _dump_in_a_fresh_interpreter(seed: str) -> str:
    """The full engine dump from a separate process under `PYTHONHASHSEED=seed`."""
    env = {**os.environ, "PYTHONHASHSEED": seed, "DATABASE_URL": "",
           "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run([sys.executable, "-c", _DUMP, str(BACKEND)],
                          capture_output=True, text=True, env=env,
                          cwd=str(BACKEND), timeout=180)
    if proc.returncode != 0:
        return f"FAILED({seed}): {proc.stderr}"
    return proc.stdout


def _model_dumps(result: EngineResult) -> list[dict]:
    """Every field of every finding, `signals` included."""
    return [f.model_dump(mode="json") for f in result.findings]


# --------------------------------------------------------------------------
# P5 -- the cross-tool path, re-baselined
# --------------------------------------------------------------------------

def _check_p5(r: EngineResult, out: list[Check]) -> None:
    """The demo's flagship path is GONE, on purpose. This pins WHY, and pins it
    hard enough that it cannot come back -- or stay away -- by accident.

    Before Phase 1 the demo reported exactly one `cross_tool_path`:
    `0.0.0.0/0 -> lb-public-01 -> app-server-07 -> internal-app -> db-prod-01`,
    severity 100, forced critical. TWO independent Phase 1 changes remove it,
    and both are corrections the audit asked for by name:

    (1) `internal-app` is the AlgoSec object `{"type": "network", "value":
        "10.40.0.0/16"}` -- a SUBNET. It reached the graph as `concrete` only
        because the normalizer left `abstract` at its default for non-host
        object types, so `_valid_traversal` -- whose entire job is to reject
        paths that pivot through a range -- let it through. The audit filed this
        as a BLOCKER (`reachability.py:47`: "the headline cross-tool path pivots
        THROUGH a /16, the exact fallacy `_valid_traversal` claims to reject")
        and offered two fixes: (a) mark range-denoting objects abstract, which
        "will delete the current money-shot until (b) lands", or (b) implement
        CIDR-membership expansion so the path is rebuilt through the concrete
        hosts inside the range. Phase 1 landed (a). (b) is not built.

    (2) Wiz's `appsrv-07` and AlgoSec/Guardicore's `app-server-07` are no longer
        fused. They used to be unioned on a bare shared IP with no namespace on
        either side, which is the collision the Phase 1 exit criterion
        ("`resolve_identities` refuses to union two entities on an unscoped IP
        collision and emits a manual_review correlation instead") exists to
        prevent. The demo data declares no VPC/VRF/account on either entity, so
        the merge is now WITHHELD for review rather than asserted.

    Deleting P5 would have made this file green while quietly retiring the
    product's differentiator from every regression gate. Instead P5 pins the four
    facts that make the absence explainable and reversible:

      * no cross-tool path is reported;
      * every underlying GRANT still exists (so a data regression that deleted
        one of the four rules fails here just as loudly as it used to);
      * cause (2) is recorded as an auditable withheld-merge row, not silence;
      * cause (1) is independent -- forcing the merge back does NOT restore the
        path, because the /16 pivot is still rejected.

    The day CIDR-membership expansion lands, these checks fail and force a
    conscious re-baseline rather than the path silently flipping back.

    Live coverage of `path_trace` / `score_cross_tool_path` / `describe_path` has
    NOT been lost: `test_engine_invariants.py` runs them against a synthetic
    three-tool estate whose pivots are all concrete hosts.
    """
    paths = [f for f in r.findings if f.type == "cross_tool_path"]
    out.append(Check(
        "P5 no cross-tool path is reported (the only chain pivots through a /16)",
        not paths, f"reported {len(paths)}"))

    # The four grants that made up the chain must all still be in the record set.
    # This is the data-regression half of P5: the path is absent because of a
    # traversal/identity decision, NOT because a rule went missing.
    refs = {rec.raw_ref for rec in r.records}
    missing = sorted(set(LEGACY_CROSS_TOOL_GRANTS) - refs)
    out.append(Check(
        "P5 every grant of the 5-hop chain still exists (data regression check)",
        not missing, f"missing rules: {missing}"))

    out.append(Check(
        "P5 internal-app is abstract (a /16 is an endpoint, never a pivot)",
        r.graph.nodes.get("internal-app", {}).get("kind") == "abstract",
        f"kind = {r.graph.nodes.get('internal-app', {}).get('kind')!r}"))

    withheld = [c for c in r.correlations
                if c.match_key == "manual_review"
                and set(c.evidence.get("names", [])) == {"app-server-07", "appsrv-07"}]
    out.append(Check(
        "P5 the withheld app-server-07/appsrv-07 merge is recorded, not silent",
        bool(withheld) and withheld[0].evidence.get("reason") == "unscoped_ip",
        f"correlations = {[c.evidence for c in withheld]}"))

    # Restore the merge by hand and prove the path STILL does not come back:
    # the two causes are independent, and the /16 pivot is the one that would
    # have to be fixed (audit option (b)) for the money shot to return.
    merged = run(manual_merges=[("app-server-07", "appsrv-07")])
    g = merged.graph
    hops_present = all(g.has_edge(a, b) for a, b in
                       zip(LEGACY_CROSS_TOOL_CHAIN, LEGACY_CROSS_TOOL_CHAIN[1:]))
    out.append(Check(
        "P5 with the merge forced, the chain is a real edge sequence",
        hops_present,
        "missing hops: " + ", ".join(
            f"{a}->{b}" for a, b in zip(LEGACY_CROSS_TOOL_CHAIN, LEGACY_CROSS_TOOL_CHAIN[1:])
            if not g.has_edge(a, b))))
    out.append(Check(
        "P5 ...and _valid_traversal still rejects it (the /16 pivot, not the merge)",
        hops_present and not _valid_traversal(g, LEGACY_CROSS_TOOL_CHAIN),
        f"kinds along the chain: "
        f"{[g.nodes[n].get('kind') for n in LEGACY_CROSS_TOOL_CHAIN if n in g]}"))
    out.append(Check(
        "P5 ...so no cross-tool path returns from the merge alone",
        not [f for f in merged.findings if f.type == "cross_tool_path"]))


# --------------------------------------------------------------------------
# The check set
# --------------------------------------------------------------------------

def checks() -> tuple[list[Check], EngineResult]:
    """Run the engine and evaluate every demo golden. Returns (checks, result)."""
    r1 = run()
    r2 = run()
    fs = r1.findings
    out: list[Check] = []

    def find(pred):
        return next((f for f in fs if pred(f)), None)

    def add(name, ok, detail=""):
        out.append(Check(name, ok, detail))

    p1 = find(lambda f: f.type == "over_permissive" and f.signals.get("protocol") == "any"
              and f.signals.get("source") == "0.0.0.0/0")
    p2 = find(lambda f: f.type == "over_permissive" and f.signals.get("exposed_port") == 3389
              and "pci" in f.signals.get("dest_tags", []))
    p3 = find(lambda f: f.type == "cidr_overlap" and f.signals.get("dest") == "app-segment")
    p4 = find(lambda f: f.type == "shadowed_rule" and f.signals.get("shadowed_action") == "deny")
    p6 = find(lambda f: f.type == "transport_exposure" and f.signals.get("subtype") == "quic_blind_spot"
              and f.signals.get("source") == "0.0.0.0/0")
    p7 = find(lambda f: f.type == "transport_exposure"
              and f.signals.get("subtype") == "tls_fallback_not_blocked")
    # NEW in Phase 1: the audit's headline defect, fixed. `internal-app` is a
    # named AlgoSec object; before Phase 1 it scored E_IDENTITY (0.1, the score
    # of a SINGLE HOST) whatever it dereferenced to, so a /16 segment reaching
    # the PCI database produced no finding at all.
    p8 = find(lambda f: f.type == "over_permissive" and f.raw_refs == ["ALGO-030"])

    add("P1 any/any present", p1 is not None)
    add("P1 forced_critical", bool(p1 and p1.forced_critical))
    # Re-baselined: `PORT_CLASS_LABEL` was keyed by the P VALUE and
    # `P_ANY_PORT == P_ADMIN == 1.0`, so the any-port row was overwritten at
    # import time and every any/any finding shipped a port class naming ports
    # the rule does not mention ("admin / lateral-movement").
    add("P1 port_class names the grant, not a port it never mentions",
        bool(p1 and p1.signals.get("port_class") == "any-port"),
        f"port_class = {p1 and p1.signals.get('port_class')!r}")
    add("P2 RDP->PCI present", p2 is not None)
    add("P2 forced_critical", bool(p2 and p2.forced_critical))
    add("P3 overlap present + low", bool(p3 and p3.severity_band == "low"))
    add("P4 shadowed-deny present + low", bool(p4 and p4.severity_band == "low"))
    # Re-baselined: the earliest covering rule is now ALGO-001 (order 1, the
    # "temporary broad allow (TODO remove)"), not ALGO-020. Shadowing compares
    # RESOLVED address space, so it can finally see that a 0.0.0.0/0 -> 10.0.0.0/8
    # allow at the top of the rulebase subsumes a later rule whose destination is
    # written as a named object. ALGO-001 is genuinely the earlier shadower under
    # first-match, so this is more correct, not merely different.
    add("P4 the shadower is the broad rule at the top of the rulebase",
        bool(p4 and p4.signals.get("shadowing_ref") == "ALGO-001"),
        f"shadowing_ref = {p4 and p4.signals.get('shadowing_ref')!r}")
    _check_p5(r1, out)
    add("P6 QUIC blind spot present (internet)", p6 is not None)
    add("P6 QUIC blind spot forced_critical", bool(p6 and p6.forced_critical))
    add("P6 QUIC decoded l7_app", bool(p6 and p6.signals.get("l7_app") == "quic"))
    add("P7 TLS fallback-not-blocked present", p7 is not None)
    add("P8 named object resolving to a /16 reaching the PCI database is reported",
        bool(p8 and p8.severity_band in ("high", "critical")),
        f"finding = {p8 and (p8.severity, p8.severity_band)}")
    add("P8 the resolved address space is what was scored, not the label",
        bool(p8 and p8.signals.get("source_cidrs") == ["10.40.0.0/16"]
             and p8.signals.get("severity_vector", {}).get("E") == 0.7),
        f"source_cidrs = {p8 and p8.signals.get('source_cidrs')}, "
        f"E = {p8 and p8.signals.get('severity_vector', {}).get('E')}")
    add("L7 decode: declared App-ID resolved to QUIC transport",
        any(f.signals.get("l7_source") == "declared"
            for f in fs if f.type == "transport_exposure"))
    add("every finding has a severity_vector", all("severity_vector" in f.signals for f in fs))
    add("no analyzer degraded (a degraded run is missing a whole finding class)",
        r1.degraded_analyzers == [], f"degraded: {r1.degraded_analyzers}")

    # --- determinism, both ways -------------------------------------------
    # Same process, FULL model dump (was three fields): catches module-level
    # mutable state carried between runs.
    add("determinism (byte-identical re-run, all fields)",
        _model_dumps(r1) == _model_dumps(r2))
    # Separate processes with different hash seeds: catches a set or a dict
    # whose iteration order leaked into an output. A same-process A/B cannot.
    a = _dump_in_a_fresh_interpreter("0")
    b = _dump_in_a_fresh_interpreter("random")
    add("determinism (cross-process, PYTHONHASHSEED 0 vs random)",
        a == b and a.startswith("{"),
        f"sha256 {hashlib.sha256(a.encode()).hexdigest()[:12]} vs "
        f"{hashlib.sha256(b.encode()).hexdigest()[:12]}")
    add("cross-process dump agrees with the in-process snapshot id",
        a.startswith("{") and json.loads(a).get("snapshot_id") == r1.snapshot_id)

    return out, r1


def main() -> int:
    results, r1 = checks()
    print(f"snapshot {r1.snapshot_id} · {len(r1.findings)} findings\n")
    ok_all = True
    for c in results:
        print(f"  [{'PASS' if c.ok else 'FAIL'}] {c.name}"
              + (f"\n         -> {c.detail}" if not c.ok and c.detail else ""))
        ok_all = ok_all and c.ok
    print("\n" + ("ALL CHECKS PASSED" if ok_all else "SOME CHECKS FAILED"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
