"""Demo acceptance check: regression-check the seeded demo dataset.

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

THE GOLDENS HAVE BEEN DELIBERATELY RE-BASELINED TWICE
-----------------------------------------------------
Phase 1 moved the demo from 17 findings / `snap_d065e3248774` to 30 /
`snap_e013ae7930ae` (then 31 on a round-2 analyzer fix). The cross-tool path
re-baseline moved it to 35 / `snap_7aa6db6c2ddb`. Every difference of both is
attributed in `backend/tests/test_demo_golden.py`, which is the file that pins
the counts.

P5 is the check that has changed MEANING rather than merely moving, and it has
now changed twice: Phase 1 turned it into a pin on the flagship path's ABSENCE
(the chain pivoted through a /16 and rested on an unscoped IP merge, so it was
not true); it is now a pin on a path that IS true, walked hop by hop. Crucially,
the two rules that deleted the old one are unchanged and are still asserted here
in the negative -- see `_check_p5`. Nothing was ever deleted to make this file
green.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from src.analyzers.run_all import EngineResult, normalize_all, run   # noqa: E402
from src.config import SENSITIVE_TAGS                        # noqa: E402
from src.graph.build import build_graph                      # noqa: E402
from src.graph.reachability import _valid_traversal, cross_tool_paths   # noqa: E402
from src.identity import CONTEXT_IDENTIFIER_KEYS, resolve_identities    # noqa: E402

# THE cross-tool path: the exposure no single console can see. Every pivot on it
# is a concrete host and every hop is a grant from a different tool's export.
CROSS_TOOL_CHAIN = ["0.0.0.0/0", "lb-public-01", "app-server-07",
                    "internal-app-01", "db-prod-01"]
# ...and the rule that grants each hop, in hop order, with the tool that saw it.
CROSS_TOOL_HOPS = [("0.0.0.0/0", "lb-public-01", "wiz", "WIZ-001"),
                   ("lb-public-01", "app-server-07", "wiz", "WIZ-002"),
                   ("app-server-07", "internal-app-01", "guardicore", "GC-002"),
                   ("internal-app-01", "db-prod-01", "algosec", "ALGO-029")]

# The chain the demo's cross-tool path used to traverse, through the /16
# `internal-app`. Kept as a constant because P5 still asserts things ABOUT it --
# that its edges exist and that `_valid_traversal` STILL refuses it. The real
# path above does not rescue this one; the abstract-pivot rule is untouched.
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

def _paths_with_contexts_stripped() -> list[dict]:
    """The cross-tool paths that survive when every declared namespace is removed.

    The counterfactual half of P5. `identity.resolve_identities` fuses two tools'
    names for one address only inside a SHARED declared scope, so deleting the
    scope must delete the merge -- and with it the path. Running it here proves
    the reported path rests on evidence in the export rather than on the merge
    being lax: if this ever returns a path, the fail-safe has stopped failing safe.

    Deliberately re-derived from the normalizers rather than by editing the
    fixture on disk: the check must not be able to leave the demo data mutated.
    """
    nr = normalize_all()
    stripped = []
    for e in nr.entities:
        clone = replace(e, identifiers={k: v for k, v in e.identifiers.items()
                                        if k not in CONTEXT_IDENTIFIER_KEYS})
        stripped.append(clone)
    idr = resolve_identities(stripped)
    g = build_graph(nr.records, idr.assets, idr.alias_map)
    return cross_tool_paths(g, SENSITIVE_TAGS)


def _check_p5(r: EngineResult, out: list[Check]) -> None:
    """The demo's flagship path is BACK, and this time every hop of it is real.

    THE PATH
    --------
        0.0.0.0/0       --wiz WIZ-001--------> lb-public-01
        lb-public-01    --wiz WIZ-002--------> app-server-07     (Wiz: "appsrv-07")
        app-server-07   --guardicore GC-002--> internal-app-01
        internal-app-01 --algosec ALGO-029---> db-prod-01        (pci, customer-data)

    Three tools, four grants, and NO abstract node anywhere but the two
    endpoints. It is the exposure no single console can see: Wiz knows the
    internet reaches the load balancer and the LB reaches the app server, but
    calls that server `appsrv-07`; Guardicore knows the app server reaches the
    internal app host; only AlgoSec knows that host reaches the PCI database.

    WHY THIS IS NOT THE OLD FABRICATION COMING BACK
    -----------------------------------------------
    Phase 1 deleted the previous "money shot" because it was not true, and BOTH
    reasons it was untrue still hold -- nothing in the engine was relaxed:

    (1) It pivoted through `internal-app`, the AlgoSec object `{"type":
        "network", "value": "10.40.0.0/16"}`. A /16 is a RANGE: reaching hosts
        inside it does not let you originate as it. That object is still
        `abstract` and `_valid_traversal` still refuses it -- asserted below on
        the legacy chain, which still exists as edges and is still rejected. The
        fix was to give the app segment a CONCRETE host (`internal-app-01`,
        10.40.0.5) that Guardicore actually observes and AlgoSec actually grants
        from, so the pivot is a machine. That is the audit's option (b) --
        "the path is rebuilt through the concrete hosts inside the range" --
        supplied as DATA rather than by weakening the traversal rule.

    (2) Wiz's `appsrv-07` and AlgoSec/Guardicore's `app-server-07` were unioned
        on a bare shared IP with no namespace on either side. They are unioned
        again -- but now because both exports DECLARE THE SAME `vpcId`, which is
        the evidence `identity.context_of` requires. The union key is still
        `(context, ip)`; the fail-safe is intact and is simply satisfied for the
        first time. `_paths_with_contexts_stripped` proves the dependency by
        deleting the evidence and watching the path vanish.

    So P5 now pins the path AND the rules that constrain it, in both directions.
    """
    paths = [f for f in r.findings if f.type == "cross_tool_path"]
    out.append(Check("P5 exactly one cross-tool path is reported",
                     len(paths) == 1, f"reported {len(paths)}"))
    f = paths[0] if paths else None
    chain = list(f.signals["path"]) if f else []

    out.append(Check("P5 it is the internet -> LB -> app -> internal-app-01 -> PCI-db chain",
                     chain == CROSS_TOOL_CHAIN, f"path = {chain}"))

    # Hop by hop: each is a REAL edge, granted by the expected rule, seen by the
    # expected tool. A path the engine merely PRINTS is not evidence; this walks it.
    g = r.graph
    bad_hops = [f"{a}->{b}" for a, b, _t, _ref in CROSS_TOOL_HOPS if not g.has_edge(a, b)]
    out.append(Check("P5 every hop on it is a real edge in the graph",
                     not bad_hops, f"missing edges: {bad_hops}"))
    hop_facts = [(h["src"], h["dst"], h["tool"], h["ref"]) for h in f.signals["hops"]] if f else []
    out.append(Check("P5 each hop is granted by the expected rule from the expected tool",
                     hop_facts == CROSS_TOOL_HOPS, f"hops = {hop_facts}"))

    # The rule the whole re-baseline turns on: no range may be a PIVOT.
    kinds = [(n, g.nodes[n].get("kind")) for n in chain if n in g]
    interior_abstract = [n for n in chain[1:-1] if g.nodes.get(n, {}).get("kind") != "concrete"]
    out.append(Check("P5 no node on it is abstract -- every pivot is a concrete host",
                     bool(chain) and not interior_abstract,
                     f"abstract pivots: {interior_abstract}; kinds = {kinds}"))
    out.append(Check("P5 _valid_traversal accepts it",
                     bool(chain) and _valid_traversal(g, chain), f"kinds = {kinds}"))

    tools = sorted(f.signals["tools"]) if f else []
    out.append(Check("P5 it traverses at least 3 distinct source tools",
                     len(tools) >= 3, f"tools = {tools}"))
    out.append(Check("P5 it reaches a regulated asset and is scored critical",
                     bool(f and f.signals.get("reaches_sensitive") and f.forced_critical
                          and f.severity_band == "critical"),
                     f"severity = {f and (f.severity, f.severity_band, f.forced_critical)}"))

    # --- the identity half: the merge happened, and for the RIGHT reason -------
    merged = [c for c in r.correlations
              if c.match_key == "context_ip"
              and set(c.evidence.get("names", [])) == {"app-server-07", "appsrv-07"}]
    out.append(Check("P5 the app-server-07/appsrv-07 merge happened on a SHARED DECLARED scope",
                     bool(merged) and bool(merged[0].evidence.get("context")),
                     f"context_ip rows = {[c.evidence for c in merged]}"))
    withheld = [c for c in r.correlations if c.match_key == "manual_review"]
    out.append(Check("P5 ...so nothing is withheld for review any more",
                     not withheld, f"withheld = {[c.evidence for c in withheld]}"))

    # --- the counterfactuals: both constraints still bite ---------------------
    out.append(Check("P5 strip the declared scopes and the path DISAPPEARS (it needs the merge)",
                     not _paths_with_contexts_stripped(),
                     "a path survived with no scope declared anywhere"))

    # The legacy /16 chain is still edges, and `_valid_traversal` still says no.
    # This is the guard against "fixing" a future regression by relaxing the rule.
    legacy_present = all(g.has_edge(a, b) for a, b in
                         zip(LEGACY_CROSS_TOOL_CHAIN, LEGACY_CROSS_TOOL_CHAIN[1:]))
    out.append(Check("P5 the legacy chain through the /16 is still a real edge sequence",
                     legacy_present,
                     "missing hops: " + ", ".join(
                         f"{a}->{b}" for a, b in
                         zip(LEGACY_CROSS_TOOL_CHAIN, LEGACY_CROSS_TOOL_CHAIN[1:])
                         if not g.has_edge(a, b))))
    out.append(Check("P5 ...and _valid_traversal STILL rejects it (a /16 is never a pivot)",
                     legacy_present and not _valid_traversal(g, LEGACY_CROSS_TOOL_CHAIN),
                     f"kinds along the legacy chain: "
                     f"{[g.nodes[n].get('kind') for n in LEGACY_CROSS_TOOL_CHAIN if n in g]}"))
    out.append(Check("P5 internal-app is still abstract (a /16 is an endpoint, never a pivot)",
                     g.nodes.get("internal-app", {}).get("kind") == "abstract",
                     f"kind = {g.nodes.get('internal-app', {}).get('kind')!r}"))

    # Data-regression check: every grant of BOTH chains must still be in the
    # record set. A path is absent-or-present because of a traversal/identity
    # decision, never because a rule silently went missing from the fixture.
    refs = {rec.raw_ref for rec in r.records}
    missing = sorted((set(LEGACY_CROSS_TOOL_GRANTS) | {ref for *_x, ref in CROSS_TOOL_HOPS}) - refs)
    out.append(Check("P5 every grant of both chains still exists (data regression check)",
                     not missing, f"missing rules: {missing}"))


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
