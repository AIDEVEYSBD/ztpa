"""Junos Space's device inventory, and the links it is right NOT to emit.

Two properties carry this module.

1. **Space sees one box.** It is a Juniper-only platform and this estate has one
   Juniper device. A one-device export is the correct export, not a degraded one.
2. **It emits zero links, deliberately.** Space's device list reports no
   adjacency: no neighbour table, no topology call behind it, nothing in the
   response naming a peer. `LinkEvidence` has no "inferred" member, so there is
   no honest evidence class available -- and the adjacency is not lost, because
   `reconstruct` derives it from the /30s both ends hold and stores it as the
   weaker `containment` evidence it is. The test below is named for the
   intention, because a reader meeting `links == []` needs to know it was a
   decision rather than an omission.
"""

from __future__ import annotations

import json

import pytest

from src import estate, sources
from src.connectors import juniper as connector
from src.connectors.juniper import DEVICES_PATH, INTERFACES_KEY, junos_space_export
from src.models import NetDevice, NetInterface, Provenance
from src.normalizers import juniper
from src.normalizers.profile import NormalizeError
from src.topology import reconstruct


def _raw() -> dict:
    return junos_space_export(estate.build())


def _result():
    return juniper.normalize(_raw())


def _records(raw: dict) -> list:
    """The device list, out of Space's own collection envelope."""
    return raw[DEVICES_PATH]["devices"]["device"]


# ── Coverage ───────────────────────────────────────────────────────────────

def test_junos_space_sees_only_the_juniper_edge_router():
    """Space manages Junos devices and nothing else. A projection that grew the
    Cisco edge router, the FortiGates or a switch would be claiming cross-vendor
    coverage from a single-vendor platform."""
    res = _result()
    assert [d.device_key for d in res.devices] == ["rtr-edge-02"]
    assert {d.key for d in estate.build().devices_seen_by("junos_space")} == {"rtr-edge-02"}
    assert {i.device_key for i in res.interfaces} == {"rtr-edge-02"}


def test_interfaces_match_the_estate_exactly():
    """Every port the box has, none that it does not, addressed as the estate
    addresses them."""
    est = estate.build()
    expected = {f"rtr-edge-02:{i.name}": list(i.addresses)
                for i in est.interfaces_of("rtr-edge-02")}
    assert {i.interface_key: i.addresses for i in _result().interfaces} == expected


# ── The links that are not there ───────────────────────────────────────────

def test_junos_space_emits_no_links_because_it_reports_no_adjacency():
    """EMITTING NOTHING IS THE CORRECT OUTPUT HERE, and this test exists so that
    is legible as a decision.

    Space's device list carries no neighbour information of any kind. Every
    `LinkEvidence` member names a specific observation -- a neighbour protocol, a
    topology API, a config stanza, a next hop, an outright assertion -- and this
    export supports none of them. A line drawn anyway would be a claim about
    somebody's cabling that nobody made.
    """
    device = _records(_raw())[0]
    for entry in device[INTERFACES_KEY]:
        assert "neighbor" not in json.dumps(entry).lower()
    assert _result().links == []


def test_the_missing_adjacency_comes_back_as_containment_not_as_a_cable():
    """The link is not lost, it is downgraded to what was actually observed.
    rtr-edge-02:edge-fw-1 holds 10.254.1.9/30 and fw-perim-01:port2 holds
    10.254.1.10/30; two interfaces provably in one block is a real L3
    observation, and it is stored as `containment` rather than being passed off
    as a cable."""
    res = _result()
    peer_prov = Provenance(source_tool="algosec", source_tier="aggregator",
                           raw_ref="fw-perim-01:port2", simulated=True)
    peer = NetDevice(device_key="fw-perim-01", name="fw-perim-01", role="firewall",
                     role_source="declared", provenance=peer_prov)
    peer_iface = NetInterface(interface_key="fw-perim-01:port2", device_key="fw-perim-01",
                              name="port2", addresses=["10.254.1.10/30"],
                              provenance=peer_prov)
    top = reconstruct(list(res.devices) + [peer], list(res.interfaces) + [peer_iface],
                      res.links, [], [], [])
    derived = [l for l in top.links
               if {l.a_device, l.b_device} == {"rtr-edge-02", "fw-perim-01"}]
    assert len(derived) == 1
    assert derived[0].evidence == "containment"


def test_the_prefix_survives_so_containment_has_something_to_find():
    """`10.254.0.6/30` must not arrive as a bare host. A /32 shares a block with
    nothing, so an export that drops the prefix deletes every derived edge this
    device would have contributed -- and the picture does not break, it just
    quietly has fewer links, which is the harder failure to notice."""
    for iface in _result().interfaces:
        for address in iface.addresses:
            assert not address.endswith("/32")
    assert [i for i in _result().interfaces
            if i.interface_key == "rtr-edge-02:ge-0/0/0"][0].addresses == ["10.254.0.6/30"]


# ── What Space states, and what it does not ────────────────────────────────

def test_the_role_is_left_unknown_because_space_states_a_platform_not_a_purpose():
    """"MX204" and "junos" say what the box is made of, not what it does -- an MX
    router, an EX switch and an SRX firewall are all "junos". Guessing "router"
    from the model string would be us deriving while the row claimed the vendor
    had told us."""
    device = _result().devices[0]
    assert device.role == "unknown"
    assert device.role_source == "unknown"
    assert device.model == "MX204"
    assert device.os_version == "Junos 21.4R3-S4"


def test_the_engine_derives_the_role_space_did_not_declare():
    """The other half: leaving the role unknown is only safe because
    `reconstruct` works it out from what the box terminates. Four distinct
    address blocks and no VLANs is a router, and the reason says so."""
    res = _result()
    device = reconstruct(res.devices, res.interfaces, res.links, [], [], []).devices[0]
    assert device.role == "router"
    assert device.role_source == "derived"
    assert "address blocks" in device.role_reason
    assert device.layer == "edge"


def test_an_absent_oper_state_is_not_reported_rather_than_down():
    """Space returns both statuses; this estate declares only the admin one.
    Copying admin into oper would manufacture a second observation out of one,
    and defaulting oper to False would grey out a healthy port."""
    for iface in _result().interfaces:
        assert iface.admin_up is True
        assert iface.oper_up is None


def test_a_unit_bearing_speed_is_dropped_rather_than_guessed():
    """Some Space versions return "1g" instead of an integer. Guessing a unit is
    how a 1Gb port becomes a 1Mb one on a capacity screen; an unreported speed
    is a fact we can render, a wrong one is not."""
    raw = _raw()
    _records(raw)[0][INTERFACES_KEY][0]["speed"] = "1g"
    assert juniper.normalize(raw).interfaces[0].speed_mbps is None
    assert _result().interfaces[0].speed_mbps == 1000


def test_the_serial_is_the_raw_ref_so_a_row_traces_back_to_space():
    """`Provenance.raw_ref` is the identifier IN THE SOURCE SYSTEM. The chassis
    serial is what Space keys the device on and what an operator can search."""
    res = _result()
    assert res.devices[0].serial == "JN12F8A2B"
    assert res.devices[0].provenance.raw_ref == "JN12F8A2B"
    for iface in res.interfaces:
        assert iface.provenance.raw_ref.startswith("JN12F8A2B:")
        assert iface.provenance.source_tool == "junos_space"
        assert iface.provenance.source_tier == "aggregator"
        assert iface.provenance.simulated is True


def test_the_management_session_state_is_not_folded_into_the_data_plane():
    """`connectionStatus` describes Space's own link to the box. It maps to no
    field in the canonical model, and folding it into an interface's admin state
    would turn a management outage into a network outage on the diagram."""
    assert _records(_raw())[0]["connectionStatus"] == "connected"
    raw = _raw()
    _records(raw)[0]["connectionStatus"] = "down"
    assert [i.admin_up for i in juniper.normalize(raw).interfaces] == [True] * 4


# ── Failure never looks like emptiness ─────────────────────────────────────

def test_a_missing_endpoint_is_a_failure_not_an_empty_inventory():
    """An export whose device call never came back must not ingest as "Space
    manages nothing" -- that is a statement about the operator's estate rather
    than about our collector."""
    with pytest.raises(NormalizeError) as err:
        juniper.normalize({})
    assert DEVICES_PATH in str(err.value)


def test_an_endpoint_that_returned_nothing_is_an_observation():
    """Present and empty is a Space with no managed devices, which is a real
    state and normalizes silently to no rows."""
    res = juniper.normalize({DEVICES_PATH: {"devices": {"@size": 0, "device": []}}})
    assert (res.devices, res.interfaces, res.links) == ([], [], [])


def test_a_truncated_page_is_refused_rather_than_counted_as_the_inventory():
    """Space states the collection's size in the response. A page carrying fewer
    records than it claims is a pagination bug, and ingesting 1 of 60 devices as
    a complete inventory is the quietest way to under-report an estate -- the
    count that contradicts it is right there in the payload."""
    raw = _raw()
    raw[DEVICES_PATH]["devices"]["@size"] = 60
    with pytest.raises(NormalizeError) as err:
        juniper.normalize(raw)
    assert "@size=60" in str(err.value)


def test_the_projection_and_the_registry_agree_on_the_rung():
    """`sources.py` is the one copy of what each tool is and where it sits. The
    connector states the tier it speaks from; this stops it becoming a second."""
    assert connector.TOOL == "junos_space"
    assert connector.TIER == sources.tier_of(connector.TOOL)


def test_the_topology_side_emits_no_policy_rows():
    """Space's policy API is a different family and is not onboarded here.
    Ingesting this export must not move a record or the golden snapshot."""
    res = _result()
    assert res.records == []
    assert res.entities == []
    assert res.resolved == []
    assert (res.vlans, res.subnets, res.circuits) == ([], [], [])


def test_the_export_is_deterministic():
    """No clock, no randomness, no set iteration on the way out."""
    assert json.dumps(_raw()) == json.dumps(junos_space_export(estate.build()))
