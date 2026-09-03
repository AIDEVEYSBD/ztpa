"""The graph layer's one job: never give two different answers to one question.

`reachable`, `find_paths` and `who_can_reach` all decide "is there a path?" and
all three are exposed to the assistant, which may call any of them in a single
turn. They used to disagree on the SHIPPED demo with no crafted input --
`effective_policy('app-segment')` said `internet_exposed: true` while
`reachable('0.0.0.0/0', 'app-segment')` said there was no path -- because
`who_can_reach` asked a bare `nx.has_path` and skipped the abstract-pivot rule
the other two enforce.

So the load-bearing tests here are properties over the whole seeded snapshot,
not spot checks: for EVERY node the two answers must match, and every path any
of them returns must be a real, rule-abiding walk through the graph. The
synthetic-graph unit tests below pin the two predicates those properties rest
on (`_valid_traversal`, `_grant_matches`) so a regression names its own cause
instead of showing up as a mystery property failure.

Two shapes the 25-asset demo does not contain are built by hand at the bottom,
because the properties above are vacuous without them:

  * a CYCLE. "No node is listed as reaching itself" used to be asserted on the
    demo behind `assert nx.is_directed_acyclic_graph(g)`, which pinned an
    accident of the fixture rather than the code -- on an acyclic graph the
    statement is true however the traversal is implemented. The property with
    content is that a self-report happens IFF a real allow chain returns to the
    node, and never from a zero-hop path.
  * a graph big enough to trip `_PATH_SCAN_CAP`. The enumeration cap is
    security-relevant (`find_paths` feeds the change gate's force-escalation)
    and no test reached the branch, so the fallback that keeps the three tools
    agreeing under truncation was unexercised in both directions.
  * an estate whose internet source is NOT spelled `0.0.0.0/0`. The demo's is,
    and so was every fixture that ever exercised `cross_tool_paths`, so the
    product's headline analyzer was tested with exactly the one spelling that
    worked while `any` / `ANY-EXTERNAL` / a named group returned zero paths --
    rendered to a buyer as "no internet-to-crown-jewel path exists" (audit B1).
    The last section drives all four spellings through the real normalizers.

Offline by construction: `run()` reads the seeded fixtures, no DB, no model.
"""

from __future__ import annotations

import logging
import types

import networkx as nx
import pytest

from src.agent import tools
from src.analyzers import path_trace
from src.analyzers.run_all import run
from src.analyzers.severity import score_cross_tool_path
from src.config import SENSITIVE_TAGS
from src.graph import reachability
from src.graph.build import build_graph
from src.graph.reachability import (
    _PATH_SCAN_CAP, _grant_matches, _valid_traversal, cross_tool_paths, describe_path,
    find_paths, internet_entries, reachable, who_can_reach,
)
from src.graph.zones import zone_of
from src.identity import resolve_identities
from src.normalizers import algosec, guardicore
from src.normalizers.common import INTERNET_CIDR, NormalizeResult

# The SAME four spellings `test_analyzers.py` scores through `over_permissive`,
# imported rather than restated: the Phase-1 exit criterion and this one are the
# same claim about the same four encodings, and two copies of the matrix would
# eventually disagree about what "the four encodings" are.
from tests.test_analyzers import FOUR_ENCODINGS

# The assets the internet can reach under the documented traversal rule. Pinned so
# a change to the rule (or to how a normalizer labels a node concrete/abstract)
# has to be an explicit edit here rather than a silent shift in the headline claim.
#
# RE-BASELINED for the scoped identity merge (Phase 1). `app-server-07` (AlgoSec,
# Guardicore) and `appsrv-07` (Wiz) are one host on 10.30.7.7, and the demo
# exports declare no VPC / account / VRF for either, so `resolve_identities` now
# REFUSES to fuse them on the shared address and files the collision as a
# `manual_review` row instead — an unscoped IP is not evidence of identity, and
# fusing on one is how the engine used to report reachability that does not
# exist. Split, the two halves of that host hold different edges: Wiz's view
# receives the internet ingress (lb-public-01 -> appsrv-07) and has no outbound
# rule, while AlgoSec's view holds the only edge into `internal-app` and is
# reachable only from the abstract 10.0.0.0/8 (not a legal pivot) and from
# `monitoring`. So `appsrv-07` enters this set and `app-server-07` and
# `internal-app` leave it.
#
# That is a withheld merge, not a lost fact: the engine says so out loud, and
# `test_confirming_the_withheld_merge_restores_the_old_exposure_set` pins the
# OTHER half — the operator confirming the merge reproduces the previous set
# exactly, member for member. Both states are pinned so neither can drift.
INTERNET_EXPOSED = {
    "10.0.0.0/8", "app-server-08", "app-server-09", "appsrv-07",
    "db-prod-01", "lb-public-01", "lb-public-02",
}

# The same set when an operator confirms the merge the identity layer withheld.
INTERNET_EXPOSED_IF_MERGED = {
    "10.0.0.0/8", "app-server-07", "app-server-08", "app-server-09",
    "db-prod-01", "internal-app", "lb-public-01", "lb-public-02",
}


@pytest.fixture(scope="module")
def eng():
    """The demo snapshot, built through the normal entrypoint verify_engine.py uses."""
    return run()


@pytest.fixture(scope="module")
def g(eng):
    return eng.graph


def _graph(kinds: dict[str, str], edges: list[tuple[str, str]],
           ports: dict[tuple[str, str], int] | None = None) -> nx.DiGraph:
    """A hand-built graph in exactly build_graph's node/edge shape.

    Synthetic rather than fixture-derived so the traversal rule can be tested on
    shapes the demo data does not happen to contain (deep chains, abstract
    terminals, cycles, meshes) without teaching the test anything about the seed.

    Edges default to tcp/443; `ports` overrides individual ones, which is what
    lets the last-hop filter be aimed at ONE edge. Insertion order is preserved
    (networkx iterates adjacency in insertion order, and `all_simple_paths` is a
    DFS over that), so a test can decide which branch is enumerated first."""
    g = nx.DiGraph()
    for name, kind in kinds.items():
        g.add_node(name, kind=kind, tags=[], ip_set=[], display=name,
                   zone=zone_of(name, []), tools=["algosec"])
    for u, v in edges:
        port = (ports or {}).get((u, v), 443)
        g.add_edge(u, v, tools=["algosec"], services=[f"tcp/{port}"], apps=[],
                   grants=[{"service": f"tcp/{port}", "port": port, "port_end": None,
                            "protocol": "tcp", "l7_app": None, "l7_source": None,
                            "tool": "algosec", "ref": f"R-{u}>{v}"}])
    return g


# --------------------------------------------------------------------------
# The Phase 0 exit criterion, as a property over every node in the snapshot
# --------------------------------------------------------------------------

def test_internet_exposed_matches_reachable_for_every_asset(g):
    """effective_policy(a).internet_exposed == reachable('0.0.0.0/0', a).reachable."""
    disagreements = [
        (n, who_can_reach(g, n)["internet_exposed"], reachable(g, INTERNET_CIDR, n)["reachable"])
        for n in sorted(g.nodes)
        if who_can_reach(g, n)["internet_exposed"] != reachable(g, INTERNET_CIDR, n)["reachable"]
    ]
    assert disagreements == [], "who_can_reach and reachable disagree about internet exposure"


def test_internet_exposed_matches_reachable_through_the_agent_tools(eng):
    """Same property one layer up, where the assistant actually sees it.

    The engine primitives agreeing is not enough -- the contradiction the audit
    caught was between two TOOLS, so it has to be asserted on the tool payloads
    (which canonicalise names through alias_map and reshape the result)."""
    for n in sorted(eng.graph.nodes):
        policy = tools.effective_policy(eng, n)
        probe = tools.reachable(eng, INTERNET_CIDR, n)
        assert policy["internet_exposed"] == probe["reachable"], n
        # ...and when it says exposed, it hands over the path rather than asserting it.
        assert (policy["internet_path"] is not None) == policy["internet_exposed"], n


def test_internet_exposed_set_is_pinned(g):
    exposed = {n for n in g.nodes if who_can_reach(g, n)["internet_exposed"]}
    assert exposed == INTERNET_EXPOSED


def test_the_withheld_merge_is_reported_not_silent(eng):
    """The reason the set above changed has to be visible in the snapshot.

    A merge the identity layer declines is only defensible if the operator can
    SEE it declined: one `manual_review` row, confidence 0.0, naming the address,
    the missing scope and both names. If this row ever stops being emitted, the
    demo would simply show two unrelated hosts and nobody could tell that the
    engine had made a decision."""
    withheld = [c for c in eng.correlations
                if c.match_key == "manual_review" and c.evidence.get("status") == "withheld"]
    assert [(c.confidence, c.evidence["reason"], c.evidence["ip"], c.evidence["names"])
            for c in withheld] == [(0.0, "unscoped_ip", "10.30.7.7",
                                    ["app-server-07", "appsrv-07"])]


def test_confirming_the_withheld_merge_restores_the_old_exposure_set():
    """The other half of the re-baseline above, and the proof it is a WITHHELD
    merge rather than a lost one: the operator's confirmation is the only thing
    missing, and supplying it reproduces the previous headline set exactly."""
    merged = run(manual_merges=[("app-server-07", "appsrv-07")])
    exposed = {n for n in merged.graph.nodes
               if who_can_reach(merged.graph, n)["internet_exposed"]}

    assert exposed == INTERNET_EXPOSED_IF_MERGED
    # ...and the confirmed merge is itself one asset with both tools' views on it.
    assert merged.alias_map["appsrv-07"] == merged.alias_map["app-server-07"] == "app-server-07"
    # The snapshot id follows the merge set, so the two runs are not confusable.
    assert merged.snapshot_id != run().snapshot_id


def test_app_segment_is_not_internet_exposed(g):
    """The finding that made this workstream exist, pinned in both directions.

    `app-segment` is 10.30.0.0/16 and the internet does hold an any/any allow into
    10.0.0.0/8, which contains it -- but the graph has no CIDR-membership
    expansion, so the only candidate path pivots THROUGH the abstract 10.0.0.0/8
    node, which `_valid_traversal` rejects. Both tools must therefore say NO. The
    exposure itself is not lost: over_permissive still flags the any/any rule
    forced-critical. See the summary note about the false negative this pins."""
    policy = who_can_reach(g, "app-segment")
    assert policy["internet_exposed"] is False
    assert INTERNET_CIDR not in policy["sources"]
    assert reachable(g, INTERNET_CIDR, "app-segment")["reachable"] is False
    # The abstract source is still a legitimate path ENDPOINT, just not a pivot.
    assert "10.0.0.0/8" in policy["sources"]
    assert reachable(g, "10.0.0.0/8", "app-segment")["reachable"] is True


# --------------------------------------------------------------------------
# who_can_reach <-> reachable <-> find_paths, over every pair in the graph
# --------------------------------------------------------------------------

def test_who_can_reach_agrees_with_reachable_for_every_pair(g):
    """s in who_can_reach(t).sources  <=>  reachable(s, t).reachable, for all (s, t)."""
    disagreements = []
    for target in sorted(g.nodes):
        sources = set(who_can_reach(g, target)["sources"])
        for src in sorted(g.nodes):
            if (src in sources) != reachable(g, src, target)["reachable"]:
                disagreements.append((src, target))
    assert disagreements == []


def test_find_paths_agrees_with_reachable_for_every_pair(g):
    """The third tool is on the same primitive too: a non-empty path list iff reachable."""
    disagreements = [
        (s, t) for t in sorted(g.nodes) for s in sorted(g.nodes)
        if bool(find_paths(g, s, t)) != reachable(g, s, t)["reachable"]
    ]
    assert disagreements == []


def test_no_node_reaches_itself_in_the_snapshot(g):
    """On the SEEDED graph, nothing reaches itself.

    Deliberately not asserted via `nx.is_directed_acyclic_graph(g)` any more: that
    made the test pass because of a property of the fixture (no allow chain in the
    demo loops), which is true no matter how the traversal is implemented. It is
    kept as a regression pin on the shipped data -- a self-source appearing here
    would mean either a zero-hop 'path' leaked into an answer or the demo grew a
    policy cycle -- and the real invariant is asserted on a cyclic graph below,
    which is the only place it has content."""
    for n in sorted(g.nodes):
        assert n not in who_can_reach(g, n)["sources"], n
        assert reachable(g, n, n)["reachable"] is False, n


# A 3-node allow cycle with one node hanging off it. Everything is concrete, so
# `_valid_traversal` never intervenes and the only thing under test is whether a
# self-report is backed by a real chain of grants.
_CYCLE_GRAPH = _graph(
    {"a": "concrete", "b": "concrete", "c": "concrete", "leaf": "concrete"},
    [("a", "b"), ("b", "c"), ("c", "a"), ("c", "leaf")],
)


@pytest.mark.parametrize("node", ["a", "b", "c"])
def test_a_node_on_a_cycle_reaches_itself_through_real_grants(node):
    """The zero-hop leak stays banned; a genuine loop is reported as the fact it is.

    `a -> b -> c -> a` IS an effective-policy statement: traffic allowed out of
    `a` can be allowed back into it, across three real grants. What must never
    happen is the degenerate answer -- a node 'reaching itself' over a path that
    traverses no grant at all, which is what an unfiltered `nx.has_path` or a
    len-1 path leaking out of `all_simple_paths` would produce."""
    g = _CYCLE_GRAPH
    policy = who_can_reach(g, node)
    probe = reachable(g, node, node)

    assert node in policy["sources"]
    assert probe["reachable"] is True
    for described in [w for w in policy["witnesses"] if w["entry"] == node] + probe["paths"]:
        path = described["path"]
        assert path[0] == path[-1] == node
        assert described["length"] >= 1, "a self-reach must traverse at least one grant"
        assert len(path) >= 2, path
        for u, v in zip(path, path[1:]):
            assert g.has_edge(u, v), f"{u} -> {v} is not an edge"


def test_a_node_off_the_cycle_still_does_not_reach_itself():
    """The other half: on the SAME cyclic graph, a node with no chain back to it
    is not listed -- so the test above is not passing because everything is."""
    g = _CYCLE_GRAPH
    assert "leaf" not in who_can_reach(g, "leaf")["sources"]
    assert reachable(g, "leaf", "leaf")["reachable"] is False
    assert find_paths(g, "leaf", "leaf") == []


def test_the_three_tools_still_agree_on_a_cyclic_graph():
    """The module's core invariant, re-asserted where cycles can break it: a cycle
    is exactly the shape in which `_bfs_witnesses` can hand back the origin as one
    of its own keys, and in which `all_simple_paths` yields the zero-edge `[n]`."""
    g = _CYCLE_GRAPH
    for target in sorted(g.nodes):
        sources = set(who_can_reach(g, target)["sources"])
        for src in sorted(g.nodes):
            probe = reachable(g, src, target)
            assert (src in sources) == probe["reachable"], (src, target)
            assert bool(find_paths(g, src, target)) == probe["reachable"], (src, target)


# --------------------------------------------------------------------------
# Every witness path is a real path
# --------------------------------------------------------------------------

def test_every_witness_path_is_a_real_valid_path(g):
    """Each consecutive hop is an actual edge, and the whole path passes the rule."""
    for target in sorted(g.nodes):
        policy = who_can_reach(g, target)
        witnesses = policy["witnesses"]
        assert sorted(w["entry"] for w in witnesses) == policy["sources"]
        for w in witnesses:
            path = w["path"]
            assert len(path) >= 2, "a witness must traverse at least one grant"
            assert path[-1] == target and w["terminal"] == target
            for u, v in zip(path, path[1:]):
                assert g.has_edge(u, v), f"{u} -> {v} is not an edge"
            assert _valid_traversal(g, path), path
            # the hop list describe_path built must line up with the path itself
            assert [h["src"] for h in w["hops"]] == path[:-1]
            assert [h["dst"] for h in w["hops"]] == path[1:]


def test_witness_is_one_of_the_paths_reachable_would_return(g):
    """Provable consistency: the path effective_policy cites is a path the other
    tool returns for the same pair, and it is the shortest one."""
    for target in sorted(g.nodes):
        for w in who_can_reach(g, target)["witnesses"]:
            enumerated = reachable(g, w["entry"], target)["paths"]
            assert w["path"] in [p["path"] for p in enumerated]
            assert w["length"] == min(p["length"] for p in enumerated)


def test_internet_path_is_the_witness_from_an_internet_node(g):
    """The path shipped with `internet_exposed` must start at an INTERNET-ZONE
    node -- which is the graph's own classification, not the string 0.0.0.0/0.

    Asserting `entry == INTERNET_CIDR` (as this did) is only true because the
    demo happens to spell its internet source that way; it would have passed
    unchanged on an estate where the whole mechanism was silently dead. The
    property with content is "the entry is one of `internet_entries`, and it is
    the shortest of them".
    """
    entries = set(internet_entries(g))
    for target in sorted(g.nodes):
        policy = who_can_reach(g, target)
        if not policy["internet_exposed"]:
            assert policy["internet_path"] is None
            assert policy["internet_entries"] == []
            continue
        assert set(policy["internet_entries"]) <= entries
        assert policy["internet_path"]["entry"] in policy["internet_entries"]
        assert policy["internet_path"]["terminal"] == target
        assert _valid_traversal(g, policy["internet_path"]["path"])
        # The deterministic pick: the SHORTEST witness among the qualifying
        # entries, ties broken by the entry name (the paths are sorted by
        # `(length, path)` and `path[0]` is the entry). Compared on length +
        # entry rather than on the path itself because `_bfs_witnesses` picks one
        # shortest path where the enumeration may hold several of equal length --
        # `test_witness_is_a_path_the_enumeration_also_returns` pins that half.
        shortest = sorted((min(q["length"] for q in reachable(g, e, target)["paths"]), e)
                          for e in policy["internet_entries"])
        assert (policy["internet_path"]["length"], policy["internet_path"]["entry"]) == shortest[0]


def test_unknown_target_returns_the_empty_shape(g):
    policy = who_can_reach(g, "no-such-asset")
    assert policy == {"target": "no-such-asset", "target_tags": [], "sources": [],
                      "witnesses": [], "internet_entries": [], "internet_exposed": False,
                      "internet_path": None}
    # `truncated` False alongside a False verdict is the claim "this no is proven,
    # nothing was cut short to reach it" -- see the truncation section below.
    assert reachable(g, INTERNET_CIDR, "no-such-asset") == {
        "reachable": False, "paths": [], "truncated": False}
    assert find_paths(g, "no-such-asset", INTERNET_CIDR) == []


# --------------------------------------------------------------------------
# _valid_traversal: the abstract-pivot rule, on synthetic shapes
# --------------------------------------------------------------------------

_PIVOT_GRAPH = _graph(
    {"0.0.0.0/0": "abstract", "10.0.0.0/8": "abstract", "lb": "concrete",
     "host": "concrete", "db": "concrete"},
    [("0.0.0.0/0", "10.0.0.0/8"), ("10.0.0.0/8", "host"), ("0.0.0.0/0", "lb"),
     ("lb", "host"), ("host", "db")],
)


@pytest.mark.parametrize("path,ok,why", [
    (["host"], True, "a single node has no intermediate hops"),
    (["0.0.0.0/0", "lb"], True, "an abstract node may be the path's origin"),
    (["lb", "10.0.0.0/8"], True, "an abstract node may be the path's terminal"),
    (["0.0.0.0/0", "lb", "host"], True, "a concrete intermediate is a real pivot"),
    (["0.0.0.0/0", "10.0.0.0/8", "host"], False, "you cannot originate AS a subnet"),
    (["0.0.0.0/0", "lb", "host", "db"], True, "all intermediates concrete"),
    (["0.0.0.0/0", "10.0.0.0/8", "host", "db"], False, "one abstract pivot is enough to reject"),
])
def test_valid_traversal_abstract_pivot_rule(path, ok, why):
    assert _valid_traversal(_PIVOT_GRAPH, path) is ok, why


def test_abstract_pivot_rule_is_enforced_by_both_tools():
    """The same rule, reached through the two tools instead of the predicate."""
    g = _PIVOT_GRAPH
    # via the abstract /8 only -> rejected; via the concrete lb -> accepted.
    assert reachable(g, "0.0.0.0/0", "host")["reachable"] is True     # 0/0 -> lb -> host
    assert who_can_reach(g, "host")["internet_exposed"] is True
    assert who_can_reach(g, "host")["internet_path"]["path"] == ["0.0.0.0/0", "lb", "host"]

    no_lb = _graph({"0.0.0.0/0": "abstract", "10.0.0.0/8": "abstract", "host": "concrete"},
                   [("0.0.0.0/0", "10.0.0.0/8"), ("10.0.0.0/8", "host")])
    assert reachable(no_lb, "0.0.0.0/0", "host")["reachable"] is False
    assert who_can_reach(no_lb, "host") == {
        "target": "host", "target_tags": [], "sources": ["10.0.0.0/8"],
        "witnesses": [describe_path(no_lb, ["10.0.0.0/8", "host"])],
        # 0.0.0.0/0 IS an internet node here and it still does not reach `host`:
        # `internet_entries` lists the entries that reach the target, not every
        # entry in the graph, so the abstract-pivot rule still decides.
        "internet_entries": [], "internet_exposed": False, "internet_path": None,
    }


def test_cutoff_bounds_path_length_identically_in_both_tools():
    """cutoff counts EDGES, and both tools have to count them the same way."""
    chain = _graph({n: "concrete" for n in "abcde"},
                   [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")])
    for cutoff in range(1, 6):
        expected = cutoff >= 4                       # a -> e is 4 edges
        assert reachable(chain, "a", "e", cutoff=cutoff)["reachable"] is expected
        assert ("a" in who_can_reach(chain, "e", cutoff=cutoff)["sources"]) is expected


# --------------------------------------------------------------------------
# _PATH_SCAN_CAP: what a "no" means when the search ran out of budget
# --------------------------------------------------------------------------

# A graph whose path count exceeds the cap, built so the expensive branch is
# enumerated FIRST. Six layers of four abstract nodes, fully connected layer to
# layer, give 4**6 == 4096 simple src->dst paths of 7 edges each (inside the
# default cutoff of 8) -- every one of them rejected by `_valid_traversal`,
# because pivoting through an abstract node is not a real path. Two concrete
# load balancers carry the only VALID paths, and their edges are added last, so
# `all_simple_paths` (a DFS in adjacency-insertion order) burns the whole
# 4000-candidate budget on the mesh before it ever reaches them.
_MESH_LAYERS, _MESH_WIDTH = 6, 4
assert _MESH_WIDTH ** _MESH_LAYERS > _PATH_SCAN_CAP, "the mesh must actually trip the cap"


def _mesh_graph() -> nx.DiGraph:
    layers = [[f"mesh-{i}-{j}" for j in range(_MESH_WIDTH)] for i in range(_MESH_LAYERS)]
    kinds = {"src": "concrete", "dst": "concrete", "lb1": "concrete", "lb2": "concrete"}
    kinds.update({n: "abstract" for layer in layers for n in layer})
    edges = [("src", n) for n in layers[0]]
    for near, far in zip(layers, layers[1:]):
        edges += [(u, v) for u in near for v in far]
    edges += [(n, "dst") for n in layers[-1]]
    # last, so the DFS reaches them last: these are the only valid paths.
    edges += [("src", "lb1"), ("lb1", "dst"), ("src", "lb2"), ("lb2", "dst")]
    # One distinguishing port per load balancer, for the last-hop filter below.
    return _graph(kinds, edges, ports={("lb1", "dst"): 8443, ("lb2", "dst"): 9443})


_MESH = _mesh_graph()


class _Collector(logging.Handler):
    """Attached straight to the module's logger rather than using `caplog`:
    app.main sets `propagate = False` on the parent 'npr.api' logger, so whether
    a record reaches pytest's root handler depends on whether some other test
    module imported the API first. This does not."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def logged():
    handler = _Collector()
    reachability.log.addHandler(handler)
    try:
        yield handler.records
    finally:
        reachability.log.removeHandler(handler)


def test_the_scan_cap_is_reported_and_the_answer_survives_it(logged):
    """The branch nothing reached: `all_simple_paths` is cut off before any valid
    path is seen, so the enumeration alone would answer "not reachable" for a pair
    `_bfs_witnesses` just proved reachable -- and `who_can_reach`, which never
    enumerates, would keep saying the opposite. The witness fallback is what keeps
    the three tools agreeing, and `truncated` is what stops the smaller answer
    from being mistaken for the whole one."""
    res = reachable(_MESH, "src", "dst")

    assert res["truncated"] is True
    assert res["reachable"] is True
    # TWO valid paths exist (via lb1 and via lb2). Exactly one comes back, and it
    # is the BFS witness -- which is the proof that the fallback fired rather than
    # the enumeration having quietly reached the load balancers after all.
    assert [p["path"] for p in res["paths"]] == [["src", "lb1", "dst"]]

    # ...and the invariant the whole module exists for still holds under truncation.
    assert "src" in who_can_reach(_MESH, "dst")["sources"]
    assert bool(find_paths(_MESH, "src", "dst")) == res["reachable"]

    event = next(r for r in logged if getattr(r, "event", None) == "path_scan_truncated")
    assert event.levelno == logging.WARNING
    assert (event.src, event.dst, event.cap) == ("src", "dst", _PATH_SCAN_CAP)


def test_a_proven_no_is_not_reported_as_truncated():
    """`truncated` has to separate "no" from "not found in budget", so it must be
    False on a real no. `dst` has no edge out at all, so the BFS settles it with
    no enumeration."""
    res = reachable(_MESH, "dst", "src")
    assert (res["reachable"], res["paths"], res["truncated"]) == (False, [], False)


def test_a_filtered_probe_uses_the_witness_only_when_the_witness_answers_it():
    """The deliberate decision about the filtered case.

    The fallback cites ONE witness path, and a port/protocol/app filter applies to
    that path's last hop. So it may only stand in for the enumeration when its own
    last hop matches the request; otherwise the honest answer is "not found within
    the scan budget", which is False + truncated -- never a bare False, which
    would read as proof that nothing on that port can get through.
    """
    on_the_witness = reachable(_MESH, "src", "dst", port=8443)          # lb1 -> dst
    assert on_the_witness["reachable"] is True
    assert on_the_witness["truncated"] is True
    assert [p["path"] for p in on_the_witness["paths"]] == [["src", "lb1", "dst"]]

    off_the_witness = reachable(_MESH, "src", "dst", port=9443)         # lb2 -> dst
    assert off_the_witness["reachable"] is False
    assert off_the_witness["truncated"] is True, (
        "a False verdict from a truncated scan must say so: lb2 really does grant "
        "tcp/9443, the enumeration just never got that far")


def test_the_seeded_snapshot_never_trips_the_cap(g):
    """Nothing above is describing the demo: on the shipped 25-asset graph every
    enumeration completes, so the golden output is untouched by the fallback."""
    truncated = [(s, t) for t in sorted(g.nodes) for s in sorted(g.nodes)
                 if reachable(g, s, t)["truncated"]]
    assert truncated == []


# --------------------------------------------------------------------------
# _grant_matches: the structured request/grant match
# --------------------------------------------------------------------------

_TCP443 = {"protocol": "tcp", "port": 443, "port_end": None, "l7_app": None}
_TCP_RANGE = {"protocol": "tcp", "port": 1, "port_end": 65535, "l7_app": None}
_ANY = {"protocol": "any", "port": None, "port_end": None, "l7_app": None}
_QUIC = {"protocol": "udp", "port": 443, "port_end": None, "l7_app": "quic"}


@pytest.mark.parametrize("grant,port,protocol,app,ok", [
    (_TCP443, None, None, None, True),               # unconstrained request
    (_TCP443, 443, "tcp", None, True),
    (_TCP443, 444, "tcp", None, False),              # single port is a closed interval
    (_TCP443, 443, "udp", None, False),              # protocol must match
    (_TCP443, 443, "any", None, True),               # 'any' request matches any protocol
    (_TCP443, None, None, "quic", False),            # no App-ID on the grant
    (_TCP_RANGE, 3389, "tcp", None, True),           # port_end makes it a range
    (_TCP_RANGE, 65536, "tcp", None, False),
    (_ANY, 3389, "tcp", None, True),                 # wildcard grant matches anything
    (_ANY, None, None, "quic", True),
    (_QUIC, None, None, "QUIC", True),               # App-ID match is case-insensitive
    (_QUIC, None, None, "http", False),
    (_QUIC, 9999, "tcp", "quic", True),              # app, when asked for, decides alone
    ({"protocol": "tcp", "port": None, "port_end": None}, 443, "tcp", None, False),
])
def test_grant_matches(grant, port, protocol, app, ok):
    assert _grant_matches(grant, port, protocol, app) is ok


# --------------------------------------------------------------------------
# The internet is a place, not a string (audit B1 -- workstream A1 + A2)
# --------------------------------------------------------------------------
#
# `cross_tool_paths` looked its entry point up by the literal key "0.0.0.0/0"
# and returned [] when it was absent, so an export spelling its internet source
# `any`, `ANY-EXTERNAL` or as a named group produced ZERO cross-tool findings --
# from the analyzer this product is sold on, and rendered as "no
# internet-to-crown-jewel path exists". `who_can_reach` held the same literal
# (`internet_exposed`), and so did the change gate (`simulate.py`, covered in
# `test_change_simulate.py`).
#
# Everything below drives the REAL normalizers. The estate is two hops through
# two tools, which is the minimum that makes a cross-tool finding possible:
#
#   AlgoSec:    <entry> -> app-server-07  tcp/443
#   Guardicore: app-server-07 -> db-prod-01 tcp/5432   (db-prod-01 is `pci`)
#
# Nothing is hand-built, for the reason `test_analyzers.py`'s own matrix gives:
# a fixture that supplies `ip_set=["0.0.0.0/0"]` for a group object supplies the
# very fact the pipeline was losing, and the test then passes while the property
# is false.


def _two_tool_estate(token: str, objects: dict, *, second_hop: bool = True):
    """normalize(algosec) + normalize(guardicore) -> (graph, alias_map).

    `second_hop` False leaves only the internet ingress in place, which is what
    the change-gate test needs: the proposed rule supplies the second hop.
    """
    algo = {
        "device": "afa-edge-fw-01",
        "objects": {**objects,
                    "app-server-07": {"type": "host", "value": "10.30.7.7", "tags": ["prod"]},
                    "db-prod-01": {"type": "host", "value": "10.50.0.10", "tags": ["pci"]}},
        "rules": [{"rule_id": "R1", "order": 1, "src": token, "dst": "app-server-07",
                   "service": "tcp/443", "action": "allow"}],
    }
    gc = {
        "labels": {"app-server-07": {"role": "app", "env": "prod", "tags": ["prod"],
                                     "cidr": "10.30.7.7/32"},
                   "db-prod-01": {"role": "db", "env": "prod", "tags": ["pci"],
                                  "cidr": "10.50.0.10/32"}},
        "policies": ([{"policy_id": "GC-1", "src_label": "app-server-07",
                       "dst_label": "db-prod-01", "port": 5432, "protocol": "tcp",
                       "action": "allow"}] if second_hop else []),
    }
    res = NormalizeResult()
    res.extend(algosec.normalize(algo))
    res.extend(guardicore.normalize(gc))
    ident = resolve_identities(res.entities)
    return res, ident, build_graph(res.records, ident.assets, ident.alias_map)


@pytest.mark.parametrize("name,token,objects", FOUR_ENCODINGS, ids=[e[0] for e in FOUR_ENCODINGS])
def test_every_spelling_of_the_internet_is_an_entry(name, token, objects):
    """`internet_entries` is the zone layer's answer, so all four spellings qualify.

    The node key is whatever the export wrote -- `zones.zone_of` classifies it
    from the address space it resolves to -- so this also pins that the entry set
    is keyed by NAME, which is the fact the string lookup got wrong.
    """
    _res, ident, g = _two_tool_estate(token, objects)
    node = ident.alias_map.get(token, token)
    assert g.nodes[node]["zone"] == "internet", name
    assert internet_entries(g) == [node], name


@pytest.mark.parametrize("name,token,objects", FOUR_ENCODINGS, ids=[e[0] for e in FOUR_ENCODINGS])
def test_the_four_encodings_produce_one_cross_tool_finding(name, token, objects):
    """The A1 exit criterion. One estate, four spellings, ONE finding each --
    identical severity, band, forced flag, terminal, tools and hop count.

    Measured before the fix: the literal /0 gave 1 finding at 100/critical/forced
    and the other three gave 0, which the UI renders as "no
    internet-to-crown-jewel path exists".

    The entry NODE legitimately differs between spellings (it is the object name
    the operator sees in their own console, and the finding cites it), so it is
    excluded from the comparison and asserted separately.
    """
    def one(tok, objs):
        _res, ident, g = _two_tool_estate(tok, objs)
        fs = path_trace.analyze(g)
        assert len(fs) == 1, (tok, [f.title for f in fs])
        f = fs[0]
        return f, (f.severity, f.severity_band, f.forced_critical,
                   f.signals["terminal"], f.signals["terminal_tags"],
                   tuple(f.signals["tools"]), tuple(f.signals["hops_tools"]),
                   f.signals["boundary"], f.signals["reaches_sensitive"],
                   f.signals["severity_vector"])

    baseline, baseline_key = one("0.0.0.0/0", {})
    finding, key = one(token, objects)

    assert key == baseline_key, name
    assert key[:3] == (100, "critical", True), name
    # ...and the one thing that DOES differ is the operator's own label for the
    # entry, which is the only place the spelling may survive.
    assert finding.signals["path"][1:] == baseline.signals["path"][1:] == \
        ["app-server-07", "db-prod-01"]
    assert finding.signals["entry"] == token


@pytest.mark.parametrize("name,token,objects", FOUR_ENCODINGS, ids=[e[0] for e in FOUR_ENCODINGS])
def test_the_four_encodings_agree_about_internet_exposure(name, token, objects):
    """`who_can_reach`'s half of the same defect: `internet_exposed` was
    `INTERNET_CIDR in witnesses`, so the assistant told an operator a PCI database
    reachable through `ANY-EXTERNAL` was not internet-exposed."""
    _res, ident, g = _two_tool_estate(token, objects)
    node = ident.alias_map.get(token, token)
    policy = who_can_reach(g, "db-prod-01")

    assert policy["internet_exposed"] is True, name
    assert policy["internet_entries"] == [node], name
    assert policy["internet_path"]["path"] == [node, "app-server-07", "db-prod-01"], name
    # and the tool payload the assistant actually reads carries it too
    ctx = types.SimpleNamespace(graph=g, alias_map=ident.alias_map)
    assert tools.effective_policy(ctx, "db-prod-01")["internet_entries"] == [node], name


def test_an_explicit_source_is_a_probe_and_not_the_default():
    """The `sources` hatch still answers about ONE entry -- which is exactly the
    old behaviour, and exactly why it must not be the default. Pinned so the
    regression (a caller passing the literal string again) is visible as a
    deliberate narrowing rather than as an empty finding list."""
    _res, _ident, g = _two_tool_estate("ANY-EXTERNAL",
                                       {"ANY-EXTERNAL": {"type": "network", "value": "0.0.0.0/0"}})
    assert len(cross_tool_paths(g, SENSITIVE_TAGS)) == 1
    assert cross_tool_paths(g, SENSITIVE_TAGS, sources=[INTERNET_CIDR]) == []
    assert len(cross_tool_paths(g, SENSITIVE_TAGS, sources=["ANY-EXTERNAL"])) == 1

    # The old call shape must not be answerable at all: a bare string iterates as
    # characters, so it would filter to nothing and return [] -- a silent zero
    # from the differentiator, which is the whole defect wearing a new hat.
    with pytest.raises(TypeError, match="LIST of entry nodes"):
        cross_tool_paths(g, SENSITIVE_TAGS, INTERNET_CIDR)


@pytest.mark.parametrize("name,token,objects", FOUR_ENCODINGS, ids=[e[0] for e in FOUR_ENCODINGS])
def test_describe_path_emits_the_entrys_resolved_address_space(name, token, objects):
    """The A2 exit criterion, and the proof the key is load-bearing rather than
    decorative.

    `severity.score_cross_tool_path` has always read `path.get("entry_cidrs")` so
    a named entry could be scored on the space it dereferences to -- and nothing
    produced the key, so the branch was dead code and every named entry fell back
    to its LABEL, scoring E_IDENTITY (0.1, one host) for a chain entered from the
    whole internet. Stripping the key here reproduces exactly that: E collapses
    0.1 and severity 100 -> 59, two bands, on an identical estate.
    """
    _res, ident, g = _two_tool_estate(token, objects)
    node = ident.alias_map.get(token, token)
    path = cross_tool_paths(g, SENSITIVE_TAGS)[0]

    assert path["entry_cidrs"] == sorted(g.nodes[node]["ip_set"]), name
    assert INTERNET_CIDR in path["entry_cidrs"], name
    assert score_cross_tool_path(path)["vector"]["E"] == 1.0, name

    without = score_cross_tool_path({k: v for k, v in path.items() if k != "entry_cidrs"})
    if token == INTERNET_CIDR or token == "any":
        # These two spell the address space in the label itself, so the label is
        # already enough -- which is precisely why the defect was invisible.
        assert without["vector"]["E"] == 1.0, name
    else:
        assert without["vector"]["E"] == 0.1, name
        assert without["severity"] < score_cross_tool_path(path)["severity"], name
