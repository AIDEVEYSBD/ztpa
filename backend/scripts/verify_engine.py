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

# THE TWO cross-tool paths: the exposures no single console can see. Every pivot
# on both is a concrete host and every hop is a grant from a different tool's
# export. They share NO hop and NO endpoint, so cutting one leaves the other --
# which is what makes the demo's remediation queue an honest one rather than a
# single-shot trick, and why the retired `multi_path` scenario was folded in here
# (it reported ONE path; its pivot was a /16 and `_valid_traversal` refused it).
CROSS_TOOL_PATHS = [
    {
        "name": "A (db-prod-01)",
        "chain": ["0.0.0.0/0", "lb-public-01", "app-server-07",
                  "internal-app-01", "db-prod-01"],
        # (src, dst, tool, rule) in hop order.
        "hops": [("0.0.0.0/0", "lb-public-01", "wiz", "WIZ-001"),
                 ("lb-public-01", "app-server-07", "wiz", "WIZ-002"),
                 ("app-server-07", "internal-app-01", "guardicore", "GC-002"),
                 ("internal-app-01", "db-prod-01", "algosec", "ALGO-029")],
        # The hops a remediation would actually target, and the two that used to
        # carry a COVERING TWIN: GC-001 granted the same service to the /16 that
        # GC-002 grants to one host in it, and ALGO-030 granted the same service
        # from the /16 that ALGO-029 grants from one host in it. The engine does
        # not model CIDR-membership expansion (docs/ENGINE.md 10.2), so cutting
        # either rule deleted the FINDING and left the ACCESS. Pinned below by
        # actually cutting them and re-deriving the graph.
        "sole_grants": [("app-server-07", "internal-app-01", "GC-002"),
                        ("internal-app-01", "db-prod-01", "ALGO-029")],
        # This path needs the SCOPED merge (Wiz calls the host `appsrv-07`), so
        # stripping every declared namespace must delete it.
        "needs_declared_scope": True,
    },
    {
        "name": "B (db-prod-02)",
        "chain": ["0.0.0.0/0", "lb-public-02", "app-server-08",
                  "data-node-01", "db-prod-02"],
        "hops": [("0.0.0.0/0", "lb-public-02", "wiz", "WIZ-010"),
                 ("lb-public-02", "app-server-08", "wiz", "WIZ-011"),
                 ("app-server-08", "data-node-01", "guardicore", "GC-030"),
                 ("data-node-01", "db-prod-02", "algosec", "ALGO-031")],
        "sole_grants": [("app-server-08", "data-node-01", "GC-030"),
                        ("data-node-01", "db-prod-02", "ALGO-031")],
        # Built with the trap designed out: every tool names both pivots
        # IDENTICALLY, so the merges are plain hostname merges and no declared
        # namespace is load-bearing. That asymmetry with path A is itself the
        # assertion -- two paths resting on two different kinds of evidence.
        "needs_declared_scope": False,
    },
]

# The chain the demo's cross-tool path used to traverse, through a /16. Kept as a
# constant because P5 still asserts things ABOUT it -- that its edges exist and
# that `_valid_traversal` STILL refuses it. The real paths above do not rescue
# it; the abstract-pivot rule is untouched.
#
# RE-POINTED when ALGO-030 was re-sourced from `internal-app` to `app-segment`
# (the anti-cheat in `scripts/seed_demo.py`), which deleted the old last hop
# `internal-app -> db-prod-01`. The replacement is a STRONGER statement of the
# same rule, not a weaker one: it is a complete internet-to-PCI-database chain in
# which EVERY pivot is an address range, and the engine refuses all of it.
LEGACY_CROSS_TOOL_CHAIN = ["0.0.0.0/0", "10.0.0.0/8", "app-segment", "db-prod-01"]
# ...and the rules that grant its hops, in hop order. The chain is a graph
# artefact and can legitimately change shape; these rules are DATA, and if one of
# them disappears that is a regression in the fixture or the normalizers, not a
# scoring decision. GC-001 is in the set because it is the rule whose PORT is the
# anti-cheat on path A: if it silently went back to 8443 it would cover GC-002
# again, and `P5 ...the ACCESS goes with it` below would be the check that says so.
LEGACY_CROSS_TOOL_GRANTS = ["ALGO-001", "ALGO-011", "ALGO-030", "GC-001"]

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


def _grant_is_sole(r: EngineResult, src: str, dst: str, ref: str) -> bool:
    """Would removing rule `ref` actually close the flow `src -> dst`?

    The counterfactual behind the demo's remediation beat. `advisory/remediation`
    proposes "remove <rule>" and the gate re-simulates the analyzers -- but the
    analyzers work on the graph, and the graph has no notion that a rule granting
    `10.40.0.0/16 -> db-prod-01` already covers `10.40.0.5 -> db-prod-01`
    (docs/ENGINE.md 10.2). So a finding can resolve while the access it named
    stays open, and nothing in the pipeline notices.

    Cutting the record and re-deriving the graph is the only honest test of that,
    and it is cheap (the graph build is single-digit milliseconds). The assets and
    alias map are reused deliberately: identity is not what is under test here,
    and re-resolving would let an identity change mask a policy one.
    """
    kept = [rec for rec in r.records if rec.raw_ref != ref]
    return not build_graph(kept, r.assets, r.alias_map).has_edge(src, dst)


def _check_p5(r: EngineResult, out: list[Check]) -> None:
    """The demo's TWO cross-tool paths, and the four rules that constrain them.

    THE PATHS
    ---------
    A   0.0.0.0/0       --wiz WIZ-001--------> lb-public-01
        lb-public-01    --wiz WIZ-002--------> app-server-07     (Wiz: "appsrv-07")
        app-server-07   --guardicore GC-002--> internal-app-01
        internal-app-01 --algosec ALGO-029---> db-prod-01        (pci, customer-data)

    B   0.0.0.0/0       --wiz WIZ-010--------> lb-public-02
        lb-public-02    --wiz WIZ-011--------> app-server-08
        app-server-08   --guardicore GC-030--> data-node-01
        data-node-01    --algosec ALGO-031---> db-prod-02        (pci, customer-data)

    Three tools and four grants each, no abstract node anywhere but the internet
    endpoint, and no shared hop -- so cutting one leaves the other standing. They
    are the exposures no single console can see: Wiz knows the internet reaches a
    load balancer and the LB reaches an app server; Guardicore is the only thing
    that saw the east-west hop; only AlgoSec knows the far host reaches a
    regulated database.

    WHY THIS IS NOT THE OLD FABRICATION COMING BACK
    -----------------------------------------------
    Phase 1 deleted the previous "money shot" because it was not true, and BOTH
    reasons it was untrue still hold -- nothing in the engine was relaxed:

    (1) It pivoted through `internal-app`, the AlgoSec object `{"type":
        "network", "value": "10.40.0.0/16"}`. A /16 is a RANGE: reaching hosts
        inside it does not let you originate as it. Ranges are still `abstract`
        and `_valid_traversal` still refuses them -- asserted below on the legacy
        chain, which still exists as edges and is still rejected. The fix was to
        give each segment a CONCRETE host that a second tool independently
        observes, so the pivot is a machine. That is the audit's option (b) --
        "the path is rebuilt through the concrete hosts inside the range" --
        supplied as DATA rather than by weakening the traversal rule.

    (2) Wiz's `appsrv-07` and AlgoSec/Guardicore's `app-server-07` were unioned
        on a bare shared IP with no namespace on either side. They are unioned
        again -- but now because both exports DECLARE THE SAME `vpcId`, which is
        the evidence `identity.context_of` requires. The union key is still
        `(context, ip)`; the fail-safe is intact and is simply satisfied for the
        first time. `_paths_with_contexts_stripped` proves the dependency by
        deleting the evidence and watching path A vanish -- while path B
        survives, because every tool names ITS pivots identically and no
        namespace was ever load-bearing for it.

    THE THIRD CONSTRAINT, NEW AND THE SHARPEST OF THE THREE
    ------------------------------------------------------
    A path the engine reports is only useful if the fix it leads to REMOVES THE
    ACCESS. Both middle and terminal hops of path A used to have a broader twin
    in the same service (GC-001 to the /16 on 8443, ALGO-030 from the /16 on
    5432), and because the engine does not model CIDR-membership expansion
    (docs/ENGINE.md 10.2) deleting the cited rule would have deleted the finding
    and left the flow. That is the demo lying about its own limitation on the one
    screen whose pitch is that it does not. `_grant_is_sole` cuts each of those
    four grants out of the record set, rebuilds the graph, and asserts the hop's
    edge goes with it.
    """
    paths = [f for f in r.findings if f.type == "cross_tool_path"]
    out.append(Check("P5 exactly two cross-tool paths are reported",
                     len(paths) == len(CROSS_TOOL_PATHS),
                     f"reported {len(paths)}: {[f.signals.get('path') for f in paths]}"))

    g = r.graph
    by_chain = {tuple(f.signals["path"]): f for f in paths}
    found = []
    for spec in CROSS_TOOL_PATHS:
        f = by_chain.get(tuple(spec["chain"]))
        found.append(f)
        out.append(Check(f"P5 path {spec['name']} is the expected internet -> LB -> app "
                         f"-> pivot -> PCI-db chain",
                         f is not None,
                         f"chains reported = {sorted(by_chain)}"))

    # Hop by hop: each is a REAL edge, granted by the expected rule, seen by the
    # expected tool. A path the engine merely PRINTS is not evidence; this walks it.
    bad_hops = [f"{spec['name']}: {a}->{b}"
                for spec in CROSS_TOOL_PATHS
                for a, b, _t, _ref in spec["hops"] if not g.has_edge(a, b)]
    out.append(Check("P5 every hop on both is a real edge in the graph",
                     not bad_hops, f"missing edges: {bad_hops}"))
    bad_grants = [f"{spec['name']}: {hops}"
                  for spec, f in zip(CROSS_TOOL_PATHS, found)
                  if (hops := [(h["src"], h["dst"], h["tool"], h["ref"])
                               for h in f.signals["hops"]] if f else []) != spec["hops"]]
    out.append(Check("P5 each hop is granted by the expected rule from the expected tool",
                     not bad_grants, f"hops = {bad_grants}"))

    # The rule the whole re-baseline turns on: no range may be a PIVOT.
    interior_abstract = [(spec["name"], n)
                         for spec in CROSS_TOOL_PATHS for n in spec["chain"][1:-1]
                         if g.nodes.get(n, {}).get("kind") != "concrete"]
    out.append(Check("P5 no node on either is abstract -- every pivot is a concrete host",
                     not interior_abstract, f"abstract pivots: {interior_abstract}"))
    rejected = [spec["name"] for spec in CROSS_TOOL_PATHS
                if not _valid_traversal(g, spec["chain"])]
    out.append(Check("P5 _valid_traversal accepts both",
                     not rejected, f"rejected: {rejected}"))

    thin = [(spec["name"], sorted(f.signals["tools"]))
            for spec, f in zip(CROSS_TOOL_PATHS, found)
            if not f or len(set(f.signals["tools"])) < 3]
    out.append(Check("P5 each traverses at least 3 distinct source tools",
                     not thin, f"tools = {thin}"))
    unscored = [(spec["name"], f and (f.severity, f.severity_band, f.forced_critical))
                for spec, f in zip(CROSS_TOOL_PATHS, found)
                if not (f and f.signals.get("reaches_sensitive") and f.forced_critical
                        and f.severity_band == "critical")]
    out.append(Check("P5 each reaches a regulated asset and is scored critical",
                     not unscored, f"severities = {unscored}"))

    # Two paths are only worth two entries if they are genuinely separate. If a
    # future edit let them share a hop, "cut the first and the second is still
    # there" -- the beat this pair exists for -- would be false.
    hop_sets = [{ref for *_x, ref in spec["hops"]} for spec in CROSS_TOOL_PATHS]
    shared = sorted(hop_sets[0] & hop_sets[1])
    out.append(Check("P5 the two paths share no grant, so cutting one leaves the other",
                     not shared, f"shared grants: {shared}"))

    # --- the anti-cheat: the fix removes the ACCESS, not just the finding ------
    cosmetic = [f"{spec['name']}: {ref} ({src}->{dst})"
                for spec in CROSS_TOOL_PATHS
                for src, dst, ref in spec["sole_grants"]
                if not _grant_is_sole(r, src, dst, ref)]
    out.append(Check("P5 cutting a cited grant cuts the ACCESS, not just the finding",
                     not cosmetic,
                     "these rules have a broader twin, so removing them would resolve "
                     f"the finding and leave the flow: {cosmetic}"))

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
    survivors = {tuple(p["path"]) for p in _paths_with_contexts_stripped()}
    needs_scope = [spec["name"] for spec in CROSS_TOOL_PATHS
                   if spec["needs_declared_scope"] and tuple(spec["chain"]) in survivors]
    out.append(Check("P5 strip the declared scopes and the path that needs the merge DISAPPEARS",
                     not needs_scope,
                     f"survived with no scope declared anywhere: {needs_scope}"))
    # The other half of the same counterfactual, and the reason it is not just an
    # absence: path B is built on hostname agreement across three tools, so it
    # must be UNAFFECTED. A run where both vanish would mean the strip broke the
    # graph rather than the merge, and the check above would pass for the wrong
    # reason.
    lost = [spec["name"] for spec in CROSS_TOOL_PATHS
            if not spec["needs_declared_scope"] and tuple(spec["chain"]) not in survivors]
    out.append(Check("P5 ...while the path built on hostname agreement survives it",
                     not lost, f"also disappeared: {lost}"))

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

    # Data-regression check: every grant of BOTH chains and of the legacy one must
    # still be in the record set. A path is absent-or-present because of a
    # traversal/identity decision, never because a rule silently went missing.
    refs = {rec.raw_ref for rec in r.records}
    wanted = set(LEGACY_CROSS_TOOL_GRANTS)
    for spec in CROSS_TOOL_PATHS:
        wanted |= {ref for *_x, ref in spec["hops"]}
    missing = sorted(wanted - refs)
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
    # 10.30.0.0/16 (`app-segment`), not 10.40.0.0/16 (`internal-app`). ALGO-030
    # was re-sourced in `seed_demo.py` so that it no longer COVERS ALGO-029 --
    # the anti-cheat behind `P5 cutting a cited grant cuts the ACCESS`. The
    # invariant this check exists for is untouched: a named object is still
    # scored on the address space it RESOLVES to (E = 0.7, a /16) rather than on
    # the fact that it has a name. Only which /16 moved.
    add("P8 the resolved address space is what was scored, not the label",
        bool(p8 and p8.signals.get("source_cidrs") == ["10.30.0.0/16"]
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
