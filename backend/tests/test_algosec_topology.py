"""AlgoSec's topology side: what it sees, what it cannot, and how it says so.

The properties pinned here are the ones the partial-onboarding claim rests on.

1. **The export contains four boxes and no fifth.** AlgoSec manages enforcement
   points. An export that grew a switch, a modem or an access point would be a
   projection inventing coverage this integration does not have, and it would do
   it in the most persuasive possible way -- by making the picture look finished.
2. **"IPs behind interface" survives.** It is the single most useful field a
   policy product exposes for reconstructing topology, and it is what lets a
   firewall be placed relative to segments carried by devices AlgoSec cannot see.
3. **A link is drawn only where a next hop actually resolves.** Two thirds of the
   routes in this export point at core switches AlgoSec does not manage; those
   draw nothing.
4. **An AlgoSec-only estate reports the lanes it cannot see.** This is the test
   that matters more than the rest: the alternative is a three-lane network
   rendered with no explanation of the six lanes that are missing, which reads to
   an operator as a fact about their network rather than about our coverage.
"""

from __future__ import annotations

import json

import pytest

from src import estate, sources
from src.connectors import algosec_topology as connector
from src.connectors.algosec_topology import (
    BEHIND_KEY, DEVICES_PATH, INTERFACES_PATH, ROUTING_PATH, ZONES_PATH,
    algosec_topology_export,
)
from src.estate import DeviceSpec, Estate, IfaceSpec
from src.normalizers import algosec_topology
from src.normalizers.profile import NormalizeError
from src.topology import reconstruct

ENFORCEMENT_POINTS = {"fw-perim-01", "fw-perim-02", "rtr-edge-01", "rtr-edge-02"}


def _raw() -> dict:
    return algosec_topology_export(estate.build())


def _result():
    return algosec_topology.normalize(_raw())


# ── Coverage: four boxes, and no fifth ─────────────────────────────────────

def test_algosec_exports_exactly_the_four_enforcement_points():
    """AlgoSec's slice is `seen_by`, not the estate. Pinned against the estate
    itself so adding a device to one cannot silently widen the other."""
    raw = _raw()
    assert {d["id"] for d in raw[DEVICES_PATH]} == ENFORCEMENT_POINTS
    assert {d.key for d in estate.build().devices_seen_by("algosec")} == ENFORCEMENT_POINTS
    assert {d.device_key for d in _result().devices} == ENFORCEMENT_POINTS


def test_no_switch_modem_or_access_point_reaches_the_export():
    """The product's core honesty demonstration. AlgoSec is not a network
    inventory product; a projection that emitted a switch to round the picture
    out would be selling coverage this integration does not have."""
    res = _result()
    keys = {d.device_key for d in res.devices} | {i.device_key for i in res.interfaces}
    invisible = {d.key for d in estate.build().devices if d.key not in ENFORCEMENT_POINTS}
    assert invisible & keys == set()
    assert not any(k.startswith(("csw-", "asw-", "mdm-", "ap-")) for k in keys)


def test_the_console_declares_the_role_rather_than_us_deriving_it():
    """AlgoSec states outright whether a managed device is a firewall or a
    router. That statement is the entire reason `role_source="declared"` exists
    as a value distinct from "derived", and losing it would hand the reconstruction
    engine a guess to make that it did not need to make."""
    by_key = {d.device_key: d for d in _result().devices}
    assert by_key["fw-perim-01"].role == "firewall"
    assert by_key["rtr-edge-02"].role == "router"
    for dev in by_key.values():
        assert dev.role_source == "declared"
        assert "AlgoSec" in dev.role_reason


def test_a_device_type_we_do_not_model_leaves_the_role_for_the_engine():
    """A Check Point management server or an SDN controller is a real AlgoSec
    device type and is not a `DeviceRole`. Mapping it to the nearest member we do
    model would be us guessing while the row claimed the vendor had told us."""
    raw = _raw()
    raw[DEVICES_PATH][0]["type"] = "smart-center"
    device = algosec_topology.normalize(raw).devices[0]
    assert device.role == "unknown"
    assert device.role_source == "unknown"


# ── Addressing and "IPs behind interface" ──────────────────────────────────

def test_addresses_round_trip_through_the_dotted_netmask_form():
    """AlgoSec reports an address as ip + dotted netmask. `10.254.2.1` +
    `255.255.255.252` has to come back as `10.254.2.1/30` -- the host bits kept,
    the prefix recovered -- or every containment link the reconstruction engine
    would derive from this device goes with it."""
    est = estate.build()
    expected = {
        f"{d.key}:{i.name}": list(i.addresses)
        for d in est.devices_seen_by("algosec")
        for i in est.interfaces_of(d.key)
    }
    got = {i.interface_key: i.addresses for i in _result().interfaces}
    assert got == expected


def test_networks_behind_is_populated_for_the_firewall_interfaces():
    """The field the whole integration is worth having for. An AlgoSec-only
    estate can still place fw-perim-01 relative to the app and database tiers,
    even though the switches carrying them are invisible to it."""
    behind = {i.interface_key: i.networks_behind for i in _result().interfaces}
    for firewall in ("fw-perim-01", "fw-perim-02"):
        core_facing = [v for k, v in behind.items()
                       if k.startswith(f"{firewall}:") and v]
        assert core_facing, f"{firewall} reports no networks behind any interface"
    # The two segments the policy engine already knows: VLAN 30 holds
    # app-server-07/08/09, VLAN 50 holds db-prod-01. This is what lets the
    # topology screen answer "where does this finding live".
    assert "10.30.0.0/16" in behind["fw-perim-01:port3"]
    assert "10.50.0.0/24" in behind["fw-perim-01:port3"]


def test_the_export_keeps_algosecs_own_label_for_the_field():
    """"IPs behind interface", spaces and all. A reader who meets that key in our
    output can find the identical string in ASMS's own interface report, and
    knows we reported the field rather than computed something and named it
    after one."""
    rows = {row["deviceId"]: row["interfaces"] for row in _raw()[INTERFACES_PATH]}
    assert all(BEHIND_KEY in iface for iface in rows["fw-perim-01"])


def test_networks_behind_names_the_segment_not_the_svi_prefix():
    """VLAN 30's SVI is `10.30.0.1/24`; the segment is `10.30.0.0/16`, and it is
    the segment a route points at. Reporting the SVI's own /24 would understate
    the block the app tier actually lives in by a factor of 256."""
    behind = {i.interface_key: i.networks_behind for i in _result().interfaces}
    assert "10.30.0.0/24" not in behind["fw-perim-01:port3"]
    assert "10.40.0.0/16" in behind["fw-perim-01:port3"]


def test_the_exterior_direction_is_empty_rather_than_a_fabricated_default():
    """A WAN-facing interface's real answer is whatever the default route says,
    and this estate declares none. `0.0.0.0/0` here would be indistinguishable in
    the output from a collected fact, and would make every device in the estate
    look like it sits behind the edge router."""
    behind = {i.interface_key: i.networks_behind for i in _result().interfaces}
    assert behind["rtr-edge-01:Gi0/0/0"] == []
    assert behind["rtr-edge-01:mgmt"] == []
    assert not any("0.0.0.0/0" in v for v in behind.values())


def test_interface_state_is_unreported_rather_than_down():
    """AlgoSec's interface record carries no admin or oper state. None means NOT
    REPORTED; defaulting either to False would grey out every port on the
    diagram and invent an outage across the whole perimeter."""
    for iface in _result().interfaces:
        assert iface.admin_up is None
        assert iface.oper_up is None
        assert iface.vlan_id is None      # AlgoSec is blind to VLAN membership


# ── Links: only where the next hop resolves ────────────────────────────────

def test_routing_links_exist_only_where_the_next_hop_resolves():
    """The four router->firewall next hops resolve to interfaces in this same
    export and become `routing` links. Nothing else does."""
    res = _result()
    assert {(l.a_device, l.b_device) for l in res.links} == {
        ("rtr-edge-01", "fw-perim-01"), ("rtr-edge-01", "fw-perim-02"),
        ("rtr-edge-02", "fw-perim-01"), ("rtr-edge-02", "fw-perim-02"),
    }
    exported = {d.device_key for d in res.devices}
    for link in res.links:
        assert link.evidence == "routing"
        assert {link.a_device, link.b_device} <= exported
        assert "is the address of" in link.evidence_detail


def test_a_next_hop_that_resolves_to_nothing_draws_no_link():
    """The firewalls route toward core switches AlgoSec does not manage. Those
    routes are IN the export and must draw nothing: a line to a device nobody
    observed is the claim `LinkEvidence` refuses to carry, and it has no
    "inferred" member precisely so this cannot be fudged."""
    raw = _raw()
    routes = {r["gatewayIp"]
              for row in raw[ROUTING_PATH] if row["deviceId"] == "fw-perim-01"
              for r in row["routes"]}
    assert routes, "fw-perim-01 reports no routes at all; the premise is gone"
    # 10.254.2.2 / 10.254.2.6 are csw-core-01 / csw-core-02, which are not in
    # this export and therefore cannot be linked to.
    assert "10.254.2.2" in routes
    assert not any(l.a_device == "fw-perim-01" for l in _result().links)


def test_a_gateway_merely_inside_a_block_is_not_routing_evidence():
    """A next hop that is not the address of any exported interface, but sits in
    the same /30 as one, says the two are on one subnet -- which is the weaker
    `containment` claim the reconstruction engine derives itself and labels as
    such. Calling it "routing" would dress an address coincidence up as a
    next-hop observation."""
    raw = _raw()
    for row in raw[ROUTING_PATH]:
        for route in row["routes"]:
            if route["gatewayIp"] == "10.254.1.2":       # fw-perim-01:port1
                route["gatewayIp"] = "10.254.1.1"        # its /30 neighbour
    links = algosec_topology.normalize(raw).links
    assert not any(l.b_interface == "fw-perim-01:port1" for l in links)


def test_an_ambiguous_next_hop_draws_no_link():
    """Two interfaces claiming one address is a real condition -- overlapping
    VRFs, a duplicated management address, a stale export. We cannot say which
    box the next hop is, so we say nothing: resolving to whichever interface
    sorted first would draw a cable to an arbitrary device and label it
    "routing"."""
    raw = _raw()
    for row in raw[INTERFACES_PATH]:
        if row["deviceId"] == "fw-perim-02":
            for iface in row["interfaces"]:
                if iface["hwName"] == "port1":          # steal fw-perim-01:port1's ip
                    iface["ip"], iface["netmask"] = "10.254.1.2", "255.255.255.252"
    links = algosec_topology.normalize(raw).links
    assert not any(l.b_device in ("fw-perim-01", "fw-perim-02")
                   and l.a_device == "rtr-edge-01" and "10.254.1.2" in l.evidence_detail
                   for l in links)


# ── Failure never looks like emptiness ─────────────────────────────────────

@pytest.mark.parametrize("path", [DEVICES_PATH, INTERFACES_PATH, ROUTING_PATH, ZONES_PATH])
def test_a_missing_endpoint_is_a_failure_not_an_empty_estate(path):
    """An export whose `/api/v1/devices` never came back would otherwise ingest
    cleanly as "AlgoSec manages nothing" -- a statement about the operator's
    network rather than about our collector."""
    raw = _raw()
    del raw[path]
    with pytest.raises(NormalizeError) as err:
        algosec_topology.normalize(raw)
    assert path in str(err.value)


def test_an_endpoint_that_returned_nothing_is_an_observation_not_a_failure():
    """The other half of the same rule. Present and empty normalizes silently to
    no rows; only ABSENT is a failure."""
    raw = _raw()
    for path in (DEVICES_PATH, INTERFACES_PATH, ROUTING_PATH, ZONES_PATH):
        raw[path] = []
    res = algosec_topology.normalize(raw)
    assert (res.devices, res.interfaces, res.links) == ([], [], [])


def test_the_zones_endpoint_is_exported_empty_rather_than_omitted():
    """This estate declares zones only on the carrier-facing modem interfaces,
    and AlgoSec sees no modem. An entry per device with an empty zone list says
    "we asked and there are none"; omitting the endpoint would say "we never
    asked", and the normalizer treats those two differently on purpose."""
    zones = _raw()[ZONES_PATH]
    assert {row["deviceId"] for row in zones} == ENFORCEMENT_POINTS
    assert all(row["zones"] == [] for row in zones)
    assert all(i.zone is None for i in _result().interfaces)


def test_a_second_address_on_an_interface_is_refused_rather_than_dropped():
    """AlgoSec's interface record carries one ip/netmask pair. A silently halved
    interface looks exactly like an interface that only ever had one address --
    and it stops participating in every containment link derived from the block
    that was dropped."""
    est = Estate(
        devices=[DeviceSpec("fw-x", "fw-x", "firewall", "ACME", "M1", "1.0",
                            "10.255.0.9", seen_by=("algosec",))],
        interfaces=[IfaceSpec("fw-x", "port1", ("10.1.1.1/24", "10.1.2.1/24"))],
    )
    with pytest.raises(ValueError, match="holds 2 addresses"):
        algosec_topology_export(est)


def test_the_topology_side_emits_no_policy_rows():
    """`normalizers/algosec.py` owns this console's policy side. Ingesting the
    topology side must not move a record, a path or the golden snapshot by one
    byte -- a cable is not a grant."""
    res = _result()
    assert res.records == []
    assert res.entities == []
    assert res.resolved == []
    assert (res.vlans, res.subnets, res.circuits) == ([], [], [])


def test_the_export_is_deterministic():
    """Two builds, byte-identical. `filterwarnings = ["error"]` and the snapshot
    fingerprint both depend on there being no clock, no randomness and no set
    iteration on the way out."""
    assert json.dumps(_raw()) == json.dumps(algosec_topology_export(estate.build()))


def test_the_projection_and_the_registry_agree_on_the_rung():
    """`sources.py` is the one copy of what each tool is and where it sits, and
    it exists because five copies of that list drifted. The connector states the
    tier it speaks from; this is what stops it becoming a sixth."""
    assert connector.TOOL == "algosec"
    assert connector.TIER == sources.tier_of(connector.TOOL)


def test_every_row_carries_the_console_it_came_from():
    """`Provenance.raw_ref` is the identifier IN ALGOSEC -- the device id, the
    interfaceId -- so a row on any screen can be taken back to the console."""
    res = _result()
    for row in list(res.devices) + list(res.interfaces) + list(res.links):
        assert row.provenance.source_tool == "algosec"
        assert row.provenance.source_tier == "aggregator"
        assert row.provenance.simulated is True
        assert row.provenance.raw_ref
    keys = {i.interface_key for i in res.interfaces}
    assert {i.provenance.raw_ref for i in res.interfaces} == keys


# ── The one that matters most ──────────────────────────────────────────────

def test_an_algosec_only_estate_reports_the_lanes_it_cannot_see():
    """THE test for partial onboarding.

    Given nothing but AlgoSec, the reconstruction must come back with the modem,
    core and access lanes NAMED as unobserved, each with the console that would
    fill it. The alternative -- a two-lane picture with six lanes silently
    missing -- reads to an operator as "this estate has no core switching"
    rather than "nothing we can read knows about the core switching", and that
    misreading is the single most expensive thing this product could cause.
    """
    res = _result()
    top = reconstruct(res.devices, res.interfaces, res.links, [], [], [])

    placed = {d.device_key: d.layer for d in top.devices}
    assert placed == {"rtr-edge-01": "edge", "rtr-edge-02": "edge",
                      "fw-perim-01": "perimeter", "fw-perim-02": "perimeter"}

    unobserved = {u["layer"]: u for u in top.unobserved_layers}
    for lane in ("modem", "core", "access"):
        assert lane in unobserved, f"the {lane} lane is missing without explanation"
        assert unobserved[lane]["would_be_filled_by"].strip(), (
            f"the {lane} lane is reported unobserved with nothing an operator "
            f"could do about it")
        assert unobserved[lane]["reason"].strip()
    # The lanes AlgoSec DID cover must not be reported as absences, or the
    # report degrades into "we saw nothing", which is not what happened.
    assert "edge" not in unobserved
    assert "perimeter" not in unobserved


def test_the_unobserved_lanes_name_a_real_console_not_a_shrug():
    """`would_be_filled_by` is the actionable half. "Not observed" is only useful
    if it says what connecting would mean, and the hints are the concrete API
    families from `topology.reconstruct.LANE_SOURCE_HINT`."""
    res = _result()
    top = reconstruct(res.devices, res.interfaces, res.links, [], [], [])
    hints = {u["layer"]: u["would_be_filled_by"] for u in top.unobserved_layers}
    assert "carrier portal" in hints["modem"]
    assert "Catalyst Center" in hints["core"]
