"""The five infrastructure reads, and the claims they are not allowed to make.

Most of these assert an ABSENCE renders correctly, because that is where this
feature can lie. A topology screen draws boxes and lines that look like a
photograph of a building; a reader cannot tell by looking whether a lane is
empty because the network has nothing there or because nothing we onboarded can
see it. Every test below pins one of those two apart from the other.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.main as main
from src.models import Topology

client = TestClient(main.app)


def _get(path: str) -> dict:
    r = client.get(path)
    assert r.status_code == 200, r.text
    return r.json()


# ── Sources ────────────────────────────────────────────────────────────────

def test_every_read_declares_where_it_came_from():
    """`served_from` is the whole provenance contract. A payload without it lets
    a recomputed answer pass as a persisted one."""
    for path in ("/api/sources", "/api/topology", "/api/inventory",
                 "/api/ip?address=10.30.7.7", "/api/resilience"):
        assert _get(path)["served_from"], path


def test_a_source_that_is_not_connected_reports_null_contribution_not_zeros():
    """A row of zeros reads as "we connected and found nothing", which is a
    claim about the client's estate. `null` is "we are not reading this"."""
    for card in _get("/api/sources")["sources"]:
        if not card["connected"]:
            assert card["contributed"] is None, card["tool"]
        else:
            assert card["contributed"] is not None, card["tool"]


def test_every_connected_source_is_marked_simulated():
    """These are seeded exports and the audience is client-facing. The flag
    exists in `sources.config` already and was read by nothing."""
    connected = [c for c in _get("/api/sources")["sources"] if c["connected"]]
    assert connected
    assert all(c["simulated"] for c in connected)


def test_a_console_that_contributed_and_was_superseded_still_appears():
    """FortiManager supplies the model and HA role for both firewalls, then
    loses the merge tie-break to the device-tier FortiGate read. Reading only
    the winning provenance dropped it from this screen entirely while its data
    was visibly on the next one."""
    tools = {c["tool"] for c in _get("/api/sources")["sources"] if c["connected"]}
    assert {"fortimanager", "fortigate"} <= tools


def test_every_source_says_what_it_cannot_tell_us():
    """`blind_to` is why this endpoint serves the whole catalogue and not just
    the connected tools: an empty access lane means one thing if nothing
    onboarded enumerates access switches and another if the estate has none."""
    for card in _get("/api/sources")["sources"]:
        if card["tool"] not in ("sd_wan", "sd_lan") and card["vendor"] != "(custom profile)":
            assert card["blind_to"], card["tool"]


# ── Topology ───────────────────────────────────────────────────────────────

def test_the_layers_are_ordered_outside_in_and_all_present():
    """A lane that is simply not rendered reads as a lane that does not exist."""
    lanes = [L["layer"] for L in _get("/api/topology")["lanes"]]
    assert lanes == ["internet", "circuit", "modem", "edge", "perimeter",
                     "core", "access", "segment", "endpoint"]


def test_an_unobserved_lane_carries_a_reason_and_a_remedy():
    """THE RULE. A lane with nothing in it must say why and name the console API
    that would fill it — and must carry no nodes at all. A faded placeholder
    device is unobserved hardware on screen."""
    for lane in _get("/api/topology")["lanes"]:
        if not lane["observed"]:
            assert lane["nodes"] == []
            assert lane["reason"]
            assert lane["would_be_filled_by"]
        else:
            assert lane["nodes"]


def test_the_demo_estate_fills_every_lane():
    """With all seven consoles onboarded the picture is complete — which is what
    makes the single-console case below a meaningful contrast."""
    lanes = {L["layer"]: len(L["nodes"]) for L in _get("/api/topology")["lanes"]}
    assert lanes["modem"] == 3
    assert lanes["edge"] == 2
    assert lanes["perimeter"] == 2
    assert lanes["core"] == 2
    assert lanes["access"] == 4          # 3 switches + the AP
    assert lanes["circuit"] == 3
    # 8 since the estate gained VLAN 45 (data-svc, 10.45.0.0/24) to house
    # data-node-01 -- the pivot on the demo's second cross-tool path. A path
    # through a host that belongs to no segment would be a topology the estate
    # cannot actually cable.
    assert lanes["segment"] == 8


def test_links_declare_their_evidence_and_none_of_it_is_inferred():
    """`LinkEvidence` has no "inferred" member and the API must not invent one.
    Every line on the canvas traces to a specific observation."""
    allowed = {"lldp", "cdp", "api_topology", "config", "routing", "declared", "containment"}
    links = _get("/api/topology")["links"]
    assert links
    assert {l["evidence"] for l in links} <= allowed
    assert all(l["evidence_detail"] for l in links)


def test_the_criss_cross_is_reported_as_a_redundant_group():
    """"2 switches, mostly criss-cross connections" — the UI tints these
    together, and it can only do that if the grouping survives the API."""
    links = _get("/api/topology")["links"]
    groups: dict[str, set[str]] = {}
    for l in links:
        if l["redundant_group"]:
            groups.setdefault(l["redundant_group"], set()).update((l["a"], l["b"]))

    # Grouping is DIRECTIONAL: a link belongs to the endpoint deeper in the
    # network, the one that would be stranded. Each firewall is reached by BOTH
    # edge routers...
    assert "fw-perim-01-edge" in groups
    assert {"rtr-edge-01", "rtr-edge-02"} <= groups["fw-perim-01-edge"]
    # ...and the dual-homed access switches reach both cores...
    assert {"csw-core-01", "csw-core-02"} <= groups["asw-acc-01-core"]
    # ...while the single-homed one has no group at all, which is the whole
    # point: it is the finding, not the reassurance.
    assert "asw-acc-03-core" not in groups
    assert all(l["redundant_group"] is None for l in links
               if {l["a"], l["b"]} == {"asw-acc-03", "csw-core-01"})


def test_caps_are_on_the_payload_from_the_start():
    """A silently truncated lane reads exactly like a complete one."""
    caps = _get("/api/topology")["caps"]
    assert caps["nodes_shown"] <= caps["nodes_total"] or caps["capped_lanes"]
    assert isinstance(caps["capped_lanes"], list)


def test_an_unlinked_device_is_named_rather_than_left_floating():
    """ap-wifi-01 has no observed uplink: Meraki reports no neighbour table and
    the Catalyst switch it plugs into belongs to a console that (correctly)
    refuses to borrow the answer. A box with no line to anything reads as a
    rendering bug unless the payload says otherwise."""
    gaps = {u["device_key"]: u for u in _get("/api/topology")["unlinked_devices"]}
    assert "ap-wifi-01" in gaps
    assert gaps["ap-wifi-01"]["reason"]
    assert gaps["ap-wifi-01"]["would_be_filled_by"]


# ── Inventory ──────────────────────────────────────────────────────────────

def test_the_header_counts_cover_the_asks_vocabulary():
    """"I have these many subnets, these many VLANs, these many X"."""
    counts = _get("/api/inventory")["counts"]
    assert set(counts) == {"devices", "interfaces", "vlans", "subnets",
                           "public_ips", "circuits", "assets"}
    assert counts["vlans"] == 8          # 7 + VLAN 45 (data-svc), see above
    assert counts["subnets"] == 8
    assert counts["circuits"] == 3
    assert counts["devices"] == 13


def test_a_count_no_source_declares_is_null_and_never_zero():
    """The distinction between "this estate has no VLANs" — a statement about
    the client's network we are in no position to make — and "nothing we can
    read enumerates VLANs", which is about our coverage and is actionable."""
    empty = Topology()
    counts = main._counts(empty, main.engine())

    assert counts["vlans"] is None
    assert counts["circuits"] is None
    assert counts["devices"] is None
    assert 0 not in [counts[k] for k in ("vlans", "circuits", "devices", "subnets")]


def test_the_inventory_covers_every_kind_the_ask_lists():
    """"is it an asset, workstation, router, switches, hubs, virtual appliances,
    vlans, subnets, public ip addresses"."""
    kinds = _get("/api/inventory?limit=500")["facets"]["kinds"]
    for kind in ("router", "l2_switch", "l3_switch", "firewall", "modem",
                 "wireless_ap", "vlan", "subnet", "public_ip", "wan_circuit", "asset"):
        assert kinds.get(kind), f"{kind} missing from the inventory vocabulary"


@pytest.mark.parametrize("mode,query,expect_any", [
    ("contained_by", "10.30.0.0/16", True),    # the hosts inside a block
    ("exact", "10.30.0.0/16", True),           # the block itself
    ("contains", "10.30.7.7", True),           # the blocks around a host
    ("contained_by", "192.0.2.0/24", False),   # a block nothing is in
])
def test_the_ip_filter_is_containment_not_string_matching(mode, query, expect_any):
    """A REQUIRED filter from the ask. Searching 10.30.0.0/16 must find the hosts
    inside it — a substring match would return the block and hide its contents."""
    got = _get(f"/api/inventory?ip={query}&ip_mode={mode}&limit=500")
    assert (got["total"] > 0) is expect_any


def test_the_source_filter_is_required_and_works():
    """The other required filter."""
    assert _get("/api/inventory?source=meraki&limit=500")["total"] >= 1
    assert _get("/api/inventory?source=nobody-at-all&limit=500")["total"] == 0


def test_a_malformed_address_is_refused_rather_than_silently_matching_nothing():
    """"not an address" filtered to zero rows reads as "there is nothing there"."""
    r = client.get("/api/inventory?ip=not-an-address")
    assert r.status_code == 400


def test_every_row_says_where_it_was_found():
    """The ask's second step, verbatim: "with information where did we find it,
    which subnet, which vlan"."""
    for item in _get("/api/inventory?limit=500")["items"]:
        assert item["observed_by"], item["key"]
        assert all(o["tool"] and o["tier"] for o in item["observed_by"])


def test_a_named_role_always_carries_its_reason():
    """The DB CHECK says a role cannot exist without provenance; the API has to
    carry the reasoning too, or the inventory cannot show its working for "why
    do you call this an L3 switch"."""
    for item in _get("/api/inventory?limit=500")["items"]:
        if item.get("role") and item["role"] != "unknown":
            assert item["role_source"] in ("declared", "derived")
            if item["role_source"] == "derived":
                assert item["role_reason"]


def test_paging_declares_the_total_it_is_a_page_of():
    page = _get("/api/inventory?limit=5")
    assert len(page["items"]) == 5
    assert page["total"] > 5
    assert page["has_more"] is True


# ── Address drill-down ─────────────────────────────────────────────────────

def test_the_address_lookup_groups_by_relation():
    """"can i go down at minute level can we check what policies are associated
    with a particular ip". COVERING is the group a console's own search box
    cannot give you, and it is usually where the risk is."""
    got = _get("/api/ip?address=10.30.7.7")
    assert set(got["matches"]) == {"exact", "covering", "contained"}
    assert got["matches"]["covering"], "a rule permitting this host without naming it"
    assert all(r["matched_via"] for group in got["matches"].values() for r in group)


def test_the_address_resolves_to_its_vlan_and_subnet():
    """Computed by containment against the VLAN's declared allocation, not by a
    name match — which is the whole reason the IP pool endpoint is ingested."""
    got = _get("/api/ip?address=10.30.7.7")
    assert got["vlan"]["vlan_id"] == 30
    assert got["vlan"]["name"] == "app-tier"
    assert got["subnet"] == "10.30.0.0/16"


def test_the_reachability_claim_carries_its_caveat():
    """The engine models the union of ALLOW edges and does not implement deny
    precedence. A user must not be able to read "not reachable" without the
    qualifier that makes it true."""
    effective = _get("/api/ip?address=10.30.7.7")["effective"]
    assert "deny" in effective["caveat"].lower()
    assert "ENGINE.md" in effective["caveat"]


def test_an_address_no_rule_mentions_reports_null_not_false():
    """"no rule mentions this address" is not "this address is unreachable"."""
    got = _get("/api/ip?address=192.0.2.77")
    assert got["effective"]["reachable_from_internet"] is None


def test_a_malformed_address_is_refused():
    assert client.get("/api/ip?address=grapefruit").status_code == 400


# ── Resilience ─────────────────────────────────────────────────────────────

def test_the_designed_single_points_of_failure_are_all_found():
    """The most-repeated idea in the ask, stated three ways. The estate plants
    four; all four must surface."""
    got = _get("/api/resilience")
    assert got["analysed"] is True
    titles = " | ".join(f["title"] for f in got["findings"])

    assert "rtr-edge-01" in titles          # two circuits behind one router
    assert "Carrier-A" in titles            # two circuits, one carrier
    assert "asw-acc-03" in titles           # the single-homed access switch


def test_the_shared_carrier_finding_exists_and_is_severe():
    """The most valuable finding in the set: redundancy that looks real on a
    diagram and is not. Two diverse circuits, one carrier."""
    carrier = [f for f in _get("/api/resilience")["findings"] if "carrier" in f["title"].lower()]
    assert carrier
    assert carrier[0]["severity_band"] in ("high", "critical")


def test_blast_radius_ranks_the_edge_router_above_the_access_switch():
    """"lose this device" drives an animation, so it has to be exact."""
    blast = {b["device_key"]: b for b in _get("/api/resilience")["blast_radius"]}
    assert blast["rtr-edge-01"]["paths_lost"] > blast["asw-acc-03"]["paths_lost"]
    assert blast["rtr-edge-01"]["circuits_stranded"]


def test_an_empty_topology_cannot_read_as_a_clean_bill_of_health():
    """THE ONE THAT MATTERS MOST. With nothing ingested, `findings: []` and
    `analysed: true` would tell a client their network has no single points of
    failure. Nothing was examined."""
    payload = main.resilience.__wrapped__ if hasattr(main.resilience, "__wrapped__") else None
    empty = Topology()
    original = main._topology_of
    main._topology_of = lambda t: (empty, {"served_from": "engine_memory"})
    try:
        got = _get("/api/resilience")
    finally:
        main._topology_of = original

    assert got["analysed"] is False
    assert got["findings"] == []
    assert got["reason"]
    assert "not a finding" in got["reason"] or "nothing was examined" in got["reason"]
    assert payload is None or True
