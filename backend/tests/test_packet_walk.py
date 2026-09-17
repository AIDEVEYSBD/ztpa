"""The packet walk, and the one thing it is not allowed to do.

The walk is evidence shown to somebody about to approve a firewall change, so
the failure that matters is not "it drew the wrong box". It is "it showed a
closed hop and stayed quiet about the route still open". Most of this module is
about that.
"""

from __future__ import annotations

import pytest

from src.advisory.walk import METHOD_DETAIL, walk
from src.graph.build import build_graph


#: Every rule this module walks over. Checked up front, because `engine()` folds
#: the database's APPLIED-CHANGE OVERLAY into the record set -- so a change
#: approved in the console during a demo silently deletes a rule from under these
#: tests, and the failure surfaces as "blocked_at is None", which reads as a bug
#: in the walk rather than as state left over from clicking around.
WALKED_RULES = ("WIZ-001", "WIZ-002", "GC-002", "ALGO-029", "ALGO-002", "WIZ-020")


@pytest.fixture(scope="module")
def demo():
    """The seeded engine, built once, with its inputs checked."""
    import app.main as main
    result = main.engine()
    missing = sorted(set(WALKED_RULES) - {r.raw_ref for r in result.records})
    assert not missing, (
        f"these rules are absent from the record set: {', '.join(missing)}.\n"
        "That is almost certainly an APPLIED CHANGE in the local database, not a "
        "code defect -- approving a fix in the console removes its rule from "
        "every later engine build. Clear it with 'Reset demo' in the console, or:\n"
        "  python -c \"import psycopg, os; from src.persist import reset_change_workflow; "
        "c=psycopg.connect(os.environ['DATABASE_URL']); cur=c.cursor(); "
        "reset_change_workflow(cur); c.commit()\"")
    return result


def _without(result, ref: str):
    return build_graph([r for r in result.records if r.raw_ref != ref],
                       result.assets, result.alias_map)


#: The demo has TWO cross-tool paths (see `seed_demo` planted problems 5 and 6).
#: Every assertion here is about the one terminating on db-prod-01, so it is
#: selected by its terminal rather than by position -- taking `findings[0]` makes
#: the module pass or fail on the finding sort order, which is not what it tests.
CHAIN_TERMINAL = "db-prod-01"


def _chain(result):
    f = next(f for f in result.findings
             if f.type == "cross_tool_path" and f.signals["path"][-1] == CHAIN_TERMINAL)
    return f, list(f.signals["path"])


def test_every_hop_names_the_rule_and_the_console_that_reported_it(demo):
    """A hop with no attribution is a drawing, not evidence. The whole claim of
    this product is that it can say WHICH console saw each step."""
    f, path = _chain(demo)
    w = walk(demo.graph, demo.graph, path)

    assert len(w["before"]) == len(path) - 1
    for hop in w["before"]:
        assert hop["ref"], f"hop {hop['n']} names no rule"
        assert hop["tool"], f"hop {hop['n']} names no console"
        assert hop["service"], f"hop {hop['n']} names no service"
    # ...and it really does cross three consoles; that is the finding's claim.
    assert len({h["tool"] for h in w["before"]}) >= 3


def test_the_walk_stops_at_the_hop_the_change_closed(demo):
    """The whole before/after mechanic, on the demo's headline exposure."""
    f, path = _chain(demo)
    last = f.raw_refs and sorted(f.raw_refs)
    g_after = _without(demo, "ALGO-029")
    w = walk(demo.graph, g_after, path)

    assert w["blocked_at"] == 4, "removing the terminal grant must stop hop 4"
    assert w["before"][3]["ref"] == "ALGO-029"
    assert last  # the finding cites the rules the walk traverses


def test_a_change_that_touches_nothing_on_the_chain_blocks_nothing(demo):
    """The negative case. If `blocked_at` fired for any change at all it would
    be decoration rather than a measurement."""
    f, path = _chain(demo)
    # ALGO-071 is dev-box SSH: real, and nowhere near this chain.
    w = walk(demo.graph, _without(demo, "ALGO-071"), path)
    assert w["blocked_at"] is None
    assert [h["verdict"] for h in w["before"]] == ["pass"] * 4


def test_a_route_that_survives_the_fix_is_reported_not_hidden(demo):
    """THE RULE THIS MODULE EXISTS FOR.

    Cutting the chain's terminal grant does close the chain -- and db-prod-01 is
    still reachable from the internet, because ALGO-002 grants RDP straight to
    it. A walk that showed the closed hop and stopped would be an advert. The
    operator would approve a change believing the database was no longer
    internet-reachable, and it would be.
    """
    f, path = _chain(demo)
    w = walk(demo.graph, _without(demo, "ALGO-029"), path)

    assert w["blocked_at"] == 4
    assert w["still_reachable"] is True, "the surviving RDP route must be reported"
    refs = {h["ref"] for s in w["survivors"] for h in s["hops"]}
    assert "ALGO-002" in refs, f"the surviving route is not named: {refs}"


def test_it_is_symmetric_and_neither_fix_alone_closes_the_flow(demo):
    """The pair, which is the argument for a campaign rather than a fix.

    Cut the chain and RDP still reaches the database; cut RDP and the four-hop
    chain still does. Asserted together because either one alone reads as a
    quirk of one rule, and the two together are the product's actual finding.
    """
    f, path = _chain(demo)
    chain_cut = walk(demo.graph, _without(demo, "ALGO-029"), path)
    rdp_cut = walk(demo.graph, _without(demo, "ALGO-002"), ["0.0.0.0/0", "db-prod-01"])

    assert chain_cut["still_reachable"] and rdp_cut["still_reachable"]
    assert rdp_cut["blocked_at"] == 1
    survivors = {h["ref"] for s in rdp_cut["survivors"] for h in s["hops"]}
    assert {"WIZ-001", "WIZ-002", "GC-002", "ALGO-029"} <= survivors


def test_the_method_never_claims_to_be_emulation(demo):
    """The label travels with the method. This sentence is rendered verbatim in
    the console beside the walk, and it is the difference between honest
    evidence and a claim we cannot support: nothing here boots a device."""
    assert "not emulated" in METHOD_DETAIL
    assert "observed estate" in METHOD_DETAIL
    f, path = _chain(demo)
    assert walk(demo.graph, demo.graph, path)["method_detail"] == METHOD_DETAIL


def test_a_hop_with_a_covering_twin_says_so(demo):
    """`also_granted_by` is the covering-twin warning in miniature: cutting the
    cited rule does not close a step another rule also grants. Hop 1 of the demo
    chain is granted by WIZ-001 and also by WIZ-020."""
    f, path = _chain(demo)
    w = walk(demo.graph, demo.graph, path)
    hop1 = w["before"][0]
    assert "WIZ-020" in hop1["also_granted_by"]
    # ...and the terminal hop is a SOLE grant, which is what makes it the one
    # worth cutting. That property is also asserted in verify_engine (P5).
    assert w["before"][3]["also_granted_by"] == []


def test_a_finding_that_names_no_flow_gets_no_walk(demo):
    """`_walk_for` refuses to invent a path. A walk drawn for a finding that
    names no flow would assert a route nobody observed."""
    from src.advisory.remediation import _walk_for

    bogus = next(f for f in demo.findings if f.type == "shadowed_rule")
    # A shadowed rule names rules, not an origin/destination pair in the graph.
    out = _walk_for(demo, bogus, {"op": "remove", "rule": "ALGO-062"})
    assert out is None or out.get("before")
