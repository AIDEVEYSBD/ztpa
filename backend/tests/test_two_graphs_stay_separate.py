"""A cable is not a grant.

The engine now builds TWO graphs from one ingest. `src.graph` is policy: who may
reach what, traversed by `reachability` to produce the cross-tool paths that are
the product's only genuinely differentiated computation. `src.topology` is
cabling and adjacency.

If a topology link ever became a policy edge, the engine would report
reachability that no rule permits. That is the one error a security tool cannot
ship, and it would be almost invisible: the path would look exactly like a real
one, with real endpoints, and would be wrong.

The separation is defended three ways, because a comment is not a defence:

  1. a grep, so a future import cannot quietly couple them;
  2. an equivalence assertion, so populating the topology cannot change a
     finding even indirectly;
  3. a fingerprint assertion, so the two cannot share an id while differing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from src.analyzers import run_all
from src.estate import build as build_estate
from src.models import Circuit, NetDevice, NetInterface, NetLink, Provenance
from src.normalizers.common import NormalizeResult

REPO = Path(__file__).resolve().parents[2]
GRAPH_DIR = REPO / "backend" / "src" / "graph"


def test_the_policy_graph_never_imports_the_topology_package():
    """The structural guard. Coupling these is a one-line mistake that would not
    fail any other test until it produced a fabricated path in front of a
    client."""
    offenders = []
    for path in sorted(GRAPH_DIR.glob("*.py")):
        text = path.read_text()
        if re.search(r"^\s*from\s+\.\.topology|^\s*import\s+.*\btopology\b", text, re.M):
            offenders.append(path.name)
    assert not offenders, (
        f"{offenders} imports the topology package. A topology link is an "
        f"observation about cabling, not a grant; traversing one would report "
        f"reachability no rule permits."
    )


def test_no_analyzer_reads_the_topology():
    """Same rule one layer out: an analyzer scores policy and must never see a
    cable.

    `run_all.py` is exempt and is the ONLY exemption: it is the orchestrator that
    builds both graphs, so it necessarily names both. What matters is that it
    hands `graph` to the analyzers and `topology` to nobody -- asserted below.
    """
    offenders = []
    for path in sorted((REPO / "backend" / "src" / "analyzers").glob("*.py")):
        if path.name == "run_all.py":
            continue
        if re.search(r"^\s*from\s+\.\.topology|\.topology\b", path.read_text(), re.M):
            offenders.append(path.name)
    assert not offenders, f"{offenders} reads the topology; analyzers score policy only"


def test_the_orchestrator_hands_no_analyzer_the_topology():
    """The exemption above, closed. `_run_analyzers` takes records, the policy
    graph and the alias map — and must never grow a topology parameter."""
    src = (REPO / "backend" / "src" / "analyzers" / "run_all.py").read_text()
    sig = re.search(r"def _run_analyzers\(([^)]*)\)", src, re.S)

    assert sig, "could not find _run_analyzers"
    assert "topology" not in sig.group(1), (
        "an analyzer is being handed the topology; a cable is not a grant"
    )


def _infra_result() -> NormalizeResult:
    """A NormalizeResult carrying ONLY infrastructure — no records, no entities.

    This is the shape every topology normalizer must produce. If one of them ever
    emits a PolicyRecord, the golden snapshot moves and the equivalence below
    breaks, which is the point.
    """
    est = build_estate()
    p = Provenance(source_tool="algosec", source_tier="aggregator", raw_ref="t", simulated=True)
    nr = NormalizeResult()
    nr.devices = [NetDevice(device_key=d.key, name=d.name, vendor=d.vendor,
                            model=d.model, mgmt_ip=d.mgmt_ip, provenance=p)
                  for d in est.devices]
    nr.interfaces = [NetInterface(interface_key=f"{i.device}:{i.name}", device_key=i.device,
                                  name=i.name, addresses=list(i.addresses),
                                  vlan_id=i.vlan_id, provenance=p)
                     for i in est.interfaces]
    nr.links = [NetLink(link_key=f"l{n}", a_device=l.a_device, b_device=l.b_device,
                        evidence="cdp", provenance=p)
                for n, l in enumerate(est.links)]
    nr.circuits = [Circuit(circuit_id=c.circuit_id, provider=c.provider,
                           technology=c.technology, device_key=c.device, provenance=p)
                   for c in est.circuits]
    return nr


def test_populating_the_topology_changes_no_finding():
    """THE EQUIVALENCE. Run the engine with NO infrastructure and again with a
    full one, and assert every finding is identical.

    `cross_tool_paths` in particular: it is the flagship computation, it is the
    one a reviewer is shown, and it is exactly what a leaked topology edge would
    corrupt.

    The policy-only run is produced by stripping the infrastructure off the real
    ingest rather than by deleting the export files, so this test does not depend
    on which consoles happen to be onboarded in the working tree.
    """
    real_normalize = run_all.normalize_all

    def normalize_policy_only():
        nr = real_normalize()
        nr.devices, nr.interfaces, nr.links = [], [], []
        nr.vlans, nr.subnets, nr.circuits = [], [], []
        return nr

    infra = _infra_result()

    def normalize_with_infra():
        nr = normalize_policy_only()
        nr.devices, nr.interfaces = infra.devices, infra.interfaces
        nr.links, nr.circuits = infra.links, infra.circuits
        return nr

    try:
        run_all.normalize_all = normalize_policy_only
        without = run_all.run(label="two-graph-a")
        run_all.normalize_all = normalize_with_infra
        with_infra = run_all.run(label="two-graph-a")
    finally:
        run_all.normalize_all = real_normalize

    # The topology genuinely arrived on one side and not the other...
    assert len(with_infra.topology.devices) == 13
    assert without.topology.devices == []

    # ...and changed nothing about what the policy engine concluded.
    #
    # Compared as a CONTENT-KEYED SET rather than as an ordered list, and the
    # reason is worth stating. Findings are sorted with `f.id` as the final
    # tiebreaker, and `f.id` is `det_id("F", snapshot_id, ...)` — so genuinely
    # tied findings order differently under two different snapshot ids. That is
    # deterministic WITHIN a snapshot, which is what the determinism guarantee
    # actually promises, and these two runs have different ids by construction
    # (the topology is in the fingerprint). Asserting list equality here would
    # be asserting something the engine has never promised and does not need to.
    def by_content(r):
        return sorted(
            json.dumps({k: v for k, v in f.model_dump().items() if k != "id"},
                       sort_keys=True, default=str)
            for f in r.findings
        )

    assert by_content(with_infra) == by_content(without)
    # 38 since the demo gained its second cross-tool path and ALGO-062 (see
    # `test_demo_golden`). The number is pinned here as a tripwire, not as a
    # claim: the assertion that matters is the equality on either side of it.
    # A literal that silently tracked the fixture would let "the topology
    # changes no finding" pass while BOTH sides moved together.
    assert len(with_infra.findings) == len(without.findings) == 38
    assert len(with_infra.graph.nodes) == len(without.graph.nodes)
    assert len(with_infra.graph.edges) == len(without.graph.edges)


def test_two_ingests_differing_only_in_topology_do_not_share_a_snapshot_id():
    """The id keys `devices`, `topology_links`, `vlans` and the rest. If it did
    not cover them, two ingests differing only in topology would share one id and
    the rows a reader got back would depend on which run wrote last."""
    est = run_all.run(label="fp")
    base = run_all._fingerprint(est.records, est.entities if hasattr(est, "entities") else [],
                                est.resolved, [], [])
    with_infra = run_all._fingerprint(est.records,
                                      est.entities if hasattr(est, "entities") else [],
                                      est.resolved, [], [], _infra_result())

    assert base != with_infra


def test_an_estate_with_no_topology_keeps_the_id_it_always_had():
    """The other half: an empty sixth blob must not be appended, or every
    existing snapshot re-baselines for an ingest that read nothing new."""
    est = run_all.run(label="fp")
    ents = est.entities if hasattr(est, "entities") else []

    assert (run_all._fingerprint(est.records, ents, est.resolved, [], [])
            == run_all._fingerprint(est.records, ents, est.resolved, [], [],
                                    NormalizeResult()))
