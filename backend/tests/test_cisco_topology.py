"""The Cisco console projections, and the two things they must never do.

Catalyst Center is the only source in the product that reports PHYSICAL
ADJACENCY. Every other console's links reach `topology.reconstruct` as addresses
and come back out as `containment`, which is a real L3 observation but is not a
cable. So the tests that matter most here are not the round-trip counts:

  * the links come back as `evidence='cdp'`, because a neighbour protocol is
    what saw them; and
  * a switch's LANE is derived from the SVIs it holds, NOT from its hostname and
    NOT from the CORE/ACCESS label sitting right there in the export. That label
    is operator-assigned and stale on every real estate, and reading it would
    switch off the one component capable of noticing.

Everything else in here pins a way an absent fact could quietly become a present
one: a missing endpoint reported as an empty console, a maskless address assumed
to be a host route, an unreported port state rendered as an outage.
"""

from __future__ import annotations

import copy
import ipaddress
import json

import pytest

from src import estate
from src.connectors.cisco import (
    CATALYST_TOOL, DNA_DEVICES, DNA_INTERFACES, DNA_PHYSICAL_TOPOLOGY,
    DNA_GLOBAL_POOL, DNA_VLAN_NAMES, MERAKI_APPLIANCE_VLANS, MERAKI_DEVICES, MERAKI_TOOL,
    MERAKI_UPLINK_ADDRESSES, catalyst_center_export, meraki_export,
)
from src.normalizers.cisco import normalize_catalyst, normalize_meraki
from src.normalizers.profile import NormalizeError
from src.topology.reconstruct import reconstruct

EST = estate.build()
CATALYST_KEYS = {d.key for d in EST.devices_seen_by(CATALYST_TOOL)}
MERAKI_KEYS = {d.key for d in EST.devices_seen_by(MERAKI_TOOL)}


def _catalyst() -> dict:
    return catalyst_center_export(EST)


def _meraki() -> dict:
    return meraki_export(EST)


def _topology(*results):
    """Reconstruct from nothing but the given normalizer results."""
    devices, interfaces, links, vlans, subnets, circuits = [], [], [], [], [], []
    for res in results:
        devices += res.devices
        interfaces += res.interfaces
        links += res.links
        vlans += res.vlans
        subnets += res.subnets
        circuits += res.circuits
    return reconstruct(devices, interfaces, links, vlans, subnets, circuits)


def _by_key(topo):
    return {d.device_key: d for d in topo.devices}


# ── Coverage: a console reports its own slice and no more ──────────────────

def test_catalyst_center_reports_exactly_the_devices_its_inventory_can_see():
    """Partial coverage is the feature. A projection that quietly filled in the
    FortiGates or the Juniper would turn "six consoles, one picture" into one
    console that already knew everything -- which is the demo that proves
    nothing."""
    res = normalize_catalyst(_catalyst())

    assert {d.device_key for d in res.devices} == CATALYST_KEYS
    for absent in ("fw-perim-01", "rtr-edge-02", "mdm-mpls-01", "ap-wifi-01"):
        assert absent not in CATALYST_KEYS
        assert absent not in {d.device_key for d in res.devices}


def test_no_structural_field_names_a_device_outside_the_inventory():
    """A device outside `seen_by` must not appear as a device row, a topology
    node or a link endpoint in ANY endpoint of the export.

    Deliberately scoped to the STRUCTURAL fields. `asw-acc-01`'s port
    `Gi1/0/24` is described "to ap-wifi-01 wired0" -- that is the switch's own
    config text naming its CDP neighbour, and Catalyst Center genuinely returns
    it. Reporting the port is not the same as claiming to manage the AP on the
    other end, and the cable to it is exactly what does NOT appear below."""
    raw = _catalyst()
    outsiders = {d.key for d in EST.devices} - CATALYST_KEYS

    named = {row["id"] for row in raw[DNA_DEVICES]["response"]}
    named |= {row["deviceId"] for row in raw[DNA_INTERFACES]["response"]}
    named |= {node["id"] for node in raw[DNA_PHYSICAL_TOPOLOGY]["response"]["nodes"]}
    for link in raw[DNA_PHYSICAL_TOPOLOGY]["response"]["links"]:
        named |= {link["source"], link["target"]}

    assert named == CATALYST_KEYS
    assert not named & outsiders


def test_every_port_of_every_visible_device_survives_the_round_trip():
    """The projection narrows by DEVICE, never by interface. A console that sees
    a switch sees all of its ports, and dropping one would silently remove an
    address -- which is a containment adjacency the reconstruction engine would
    then never draw."""
    res = normalize_catalyst(_catalyst())

    expected = {f"{d.key}:{i.name}"
                for d in EST.devices_seen_by(CATALYST_TOOL)
                for i in EST.interfaces_of(d.key)}
    assert {i.interface_key for i in res.interfaces} == expected
    assert all(i.device_key in CATALYST_KEYS for i in res.interfaces)


# ── The one console that sees cables ───────────────────────────────────────

def test_the_physical_topology_links_come_back_as_cdp_evidence():
    """`evidence='cdp'`, not `api_topology`: Catalyst Center keeps no adjacency
    table of its own, it renders the CDP/LLDP neighbour tables its managed
    devices already maintain. The evidence class has to name the OBSERVATION --
    a switch saw a neighbour on a port -- rather than the transport we read it
    over, because that is the distinction every consumer downstream acts on."""
    res = normalize_catalyst(_catalyst())

    assert res.links
    assert {l.evidence for l in res.links} == {"cdp"}

    expected = {
        tuple(sorted(((l.a_device, l.a_interface), (l.b_device, l.b_interface))))
        for l in EST.links
        if {l.a_device, l.b_device} <= CATALYST_KEYS
    }
    assert {((l.a_device, l.a_interface), (l.b_device, l.b_interface))
            for l in res.links} == expected


def test_the_cable_to_a_device_this_console_does_not_manage_is_not_reported():
    """`asw-acc-01:Gi1/0/24` runs to the Meraki AP. Catalyst Center manages the
    switch and not the AP, so the port is reported and the CABLE IS NOT -- an
    adjacency to a node no endpoint returned is a link drawn to nothing.

    That gap is the product's subject, not a defect in it: the AP rejoins the
    picture through `containment` on the management block once the Meraki
    console is onboarded too."""
    res = normalize_catalyst(_catalyst())

    port = next(i for i in res.interfaces if i.interface_key == "asw-acc-01:Gi1/0/24")
    assert port.neighbor_device is None
    assert all("ap-wifi-01" not in (l.a_device, l.b_device) for l in res.links)
    # ...while the ports that DO have a managed neighbour carry it.
    uplink = next(i for i in res.interfaces if i.interface_key == "asw-acc-01:Gi1/0/48")
    assert (uplink.neighbor_device, uplink.neighbor_interface) == ("csw-core-01", "Gi1/0/1")


def test_the_single_homed_access_switch_is_visible_from_this_console_alone():
    """SPOF #3 in the estate: every access switch is criss-crossed to both cores
    except `asw-acc-03`. Catalyst Center is the only source that can show it,
    because it is the only one that reports cables at all."""
    res = normalize_catalyst(_catalyst())

    uplinks = {d: len([l for l in res.links if d in (l.a_device, l.b_device)])
               for d in ("asw-acc-01", "asw-acc-02", "asw-acc-03")}
    assert uplinks == {"asw-acc-01": 2, "asw-acc-02": 2, "asw-acc-03": 1}


# ── The label that must not become a lane ──────────────────────────────────

def test_a_switch_keeps_role_unknown_rather_than_the_consoles_operator_label():
    """THE REGRESSION THIS FILE EXISTS FOR.

    Catalyst Center's `role` column says CORE for the core pair and ACCESS for
    the access switches, and mapping it onto `l3_switch`/`l2_switch` would look
    correct on this estate and be correct nowhere else. `role` is assigned by
    the platform at discovery and edited from a dropdown thereafter: it records
    intent, not behaviour.

    Worse, a `declared` role SWITCHES OFF `reconstruct._derive_role` for that
    device. So a mislabelled switch would be drawn in the wrong lane with
    `declared` provenance beside it, and the component that could have caught it
    would have been disabled by the very label that was wrong."""
    raw = _catalyst()
    labels = {r["id"]: r["role"] for r in raw[DNA_DEVICES]["response"]}
    assert labels["csw-core-01"] == "CORE" and labels["asw-acc-01"] == "ACCESS"

    res = normalize_catalyst(raw)
    by_key = {d.device_key: d for d in res.devices}

    for switch in ("csw-core-01", "csw-core-02", "asw-acc-01", "asw-acc-02", "asw-acc-03"):
        assert by_key[switch].role == "unknown", "the engine derives this, not the label"
        assert by_key[switch].role_source == "unknown"


def test_the_router_is_declared_because_family_is_hardware_not_a_label():
    """`family` is what the platform reports itself as -- the same class of fact
    as the model number -- so a box in the "Routers" family is a router whether
    or not anybody ever looked at it. That one IS believed, and it is believed
    from `family`, never from the `BORDER ROUTER` role label next to it."""
    res = normalize_catalyst(_catalyst())
    router = next(d for d in res.devices if d.device_key == "rtr-edge-01")

    assert (router.role, router.role_source) == ("router", "declared")
    assert "family" in router.role_reason and "Routers" in router.role_reason
    assert "BORDER ROUTER" not in router.role_reason


def test_the_lane_comes_from_the_svis_not_from_the_hostname_or_the_label():
    """THE FLAGSHIP. Given ONLY Catalyst Center's export -- no circuits, no
    firewalls, no other console -- the reconstruction engine still puts
    `csw-core-01` in the core lane and `asw-acc-01` in access.

    Then the estate is renamed and the vendor's labels are swapped, and nothing
    moves: `printer-3` holds addressed SVIs on seven VLANs, so it forwards
    between them and it is core, whatever it is called and whatever the console
    was told to call it. Name-matching is the failure mode that makes a
    reconstruction engine look right on a demo and collapse on a real estate."""
    honest = _by_key(_topology(normalize_catalyst(_catalyst())))
    assert honest["csw-core-01"].layer == "core"
    assert honest["asw-acc-01"].layer == "access"
    assert honest["csw-core-01"].layer_source == "derived"
    assert "SVI" in honest["csw-core-01"].layer_reason

    # Rename the core switch everywhere the export mentions it, and hand the
    # core's label to the access switch and vice versa.
    disguised = json.loads(json.dumps(_catalyst()).replace("csw-core-01", "printer-3"))
    for row in disguised[DNA_DEVICES]["response"]:
        if row["id"] == "printer-3":
            row["role"] = "ACCESS"
        if row["id"] == "asw-acc-01":
            row["role"] = "CORE"

    lied_to = _by_key(_topology(normalize_catalyst(disguised)))

    assert "csw-core-01" not in lied_to
    assert lied_to["printer-3"].layer == "core"
    assert lied_to["asw-acc-01"].layer == "access"


# ── Three-valued state: not reported is not "down" ─────────────────────────

def test_admin_up_is_none_when_the_console_did_not_report_it():
    """`None` and `False` are different facts. A port whose state the console
    never returned is not a port that is shut, and a picture that greys out
    every unreported port invents an outage somebody then goes looking for.

    Both spellings of "did not say" -- an explicit JSON null and an absent key
    -- have to land on the same answer, because a paginated real export uses
    whichever one the platform version felt like."""
    raw = _catalyst()
    rows = raw[DNA_INTERFACES]["response"]
    rows[0]["adminStatus"] = None
    del rows[1]["adminStatus"]
    silent = {rows[0]["id"], rows[1]["id"]}

    res = normalize_catalyst(raw)
    by_key = {i.interface_key: i for i in res.interfaces}

    for key in silent:
        assert by_key[key].admin_up is None
        assert by_key[key].admin_up is not False
    # ...and a port the console DID report still carries its state.
    assert by_key["csw-core-01:Vlan30"].admin_up is True


def test_the_operational_state_is_never_borrowed_from_the_admin_state():
    """DNAC's `status` is the operational column and `adminStatus` the
    configured one. The estate records only the latter, and copying it across
    would report a port that is admin-up and operationally DOWN -- precisely the
    condition an operator is hunting for -- as healthy."""
    raw = _catalyst()
    assert {row["status"] for row in raw[DNA_INTERFACES]["response"]} == {None}

    res = normalize_catalyst(raw)
    assert all(i.oper_up is None for i in res.interfaces)
    assert any(i.admin_up is True for i in res.interfaces)


def test_meraki_reports_no_port_state_at_all_and_says_so():
    """`devices/uplinks/addresses/byDevice` returns addressing and nothing about
    whether the port is up; device reachability is a different endpoint that is
    not read here. So every Meraki interface is honestly three-valued `None`
    rather than defaulted to a state."""
    res = normalize_meraki(_meraki())

    assert res.interfaces
    assert all(i.admin_up is None and i.oper_up is None for i in res.interfaces)


# ── Meraki ─────────────────────────────────────────────────────────────────

def test_meraki_declares_the_ap_from_its_product_type():
    """`productType` is the SKU family, derived from the model number: a
    hardware fact, so the role is `declared`. The uplink addresses are the whole
    reason this console is worth onboarding -- they are the only thing that
    attaches the AP to the rest of the picture."""
    res = normalize_meraki(_meraki())

    assert {d.device_key for d in res.devices} == MERAKI_KEYS == {"ap-wifi-01"}
    ap = res.devices[0]
    assert (ap.role, ap.role_source) == ("wireless_ap", "declared")
    assert "productType" in ap.role_reason
    assert [i.addresses for i in res.interfaces] == [["10.255.0.51/24"]]


def test_meraki_firmware_is_unmangled_into_a_comparable_version():
    """The Dashboard writes firmware as `<productType>-<version with dashes>`.
    Stored raw, "wireless-29-7-1" matches no vulnerability feed and no other
    console's spelling of the same build, so the device silently stops being
    comparable with itself."""
    raw = _meraki()
    assert raw[MERAKI_DEVICES][0]["firmware"] == "wireless-29-7-1"

    res = normalize_meraki(raw)
    assert res.devices[0].os_version == "29.7.1"


def test_meraki_emits_no_links_rather_than_a_plausible_one():
    """The Dashboard knows the AP has an uplink and what address is on it, and
    has no idea what is at the other end of the cable. `LinkEvidence` has no
    member for a link we would like to exist, so none is emitted -- the AP
    reaches the picture through containment on the management block instead."""
    res = normalize_meraki(_meraki())

    assert res.links == []
    assert res.devices and res.interfaces, "it observed plenty; just not adjacency"


def test_the_gateway_address_does_not_become_a_device():
    """The most tempting field in this export: a gateway IP looks exactly like a
    device waiting to be drawn. It is evidence that SOMETHING answers at an
    address, not an observation of a box, and a node invented from it would be a
    device on screen that nobody observed."""
    raw = _meraki()
    gateway = raw[MERAKI_UPLINK_ADDRESSES][0]["uplinks"][0]["addresses"][0]["gateway"]
    assert gateway == "10.255.0.1"

    res = normalize_meraki(raw)
    assert {d.device_key for d in res.devices} == {"ap-wifi-01"}
    assert all(gateway not in (d.mgmt_ip, d.device_key) for d in res.devices)


def test_the_ap_has_no_observed_uplink_and_the_picture_says_so():
    """Neither console can see the cable between `asw-acc-01` and the AP, and
    nothing here invents one.

    This test used to assert the opposite -- that the AP joined the picture via
    `containment` on the management block. That link was real arithmetic and a
    false claim about cabling: EVERY device on this estate holds an address in
    10.255.0.0/24, so the rule that produced it produced a near-complete mesh
    (34 fabricated links on a 13-device network). `reconstruct._containment_links`
    now emits a link only when a block has exactly two devices in it; three or
    more is a broadcast domain, which the VLAN and subnet layers already model.

    The consequence is that the AP is genuinely unlinked, and that is the honest
    answer: Meraki manages it and reports no neighbour table, and the Catalyst
    switch on the other end of the cable belongs to a console that (correctly)
    refuses to borrow the answer from an estate it cannot see.

    So the requirement is not "the AP must be connected". It is "the AP must not
    float free WITHOUT EXPLANATION" -- a box with no line to anything reads as a
    rendering bug, and this one is a coverage gap with a named remedy.
    """
    topo = _topology(normalize_catalyst(_catalyst()), normalize_meraki(_meraki()))
    by_key = _by_key(topo)

    # Still placed: its role was declared, so the lane does not depend on cabling.
    assert by_key["ap-wifi-01"].layer == "access"
    assert not [l for l in topo.links if "ap-wifi-01" in (l.a_device, l.b_device)]

    gap = next(u for u in topo.unlinked_devices if u["device_key"] == "ap-wifi-01")
    assert "no onboarded source reported an adjacency" in gap["reason"]
    assert gap["would_be_filled_by"], "an unexplained gap is worse than no gap"
    assert "meraki" in gap["observed_by"]


def test_the_management_block_does_not_become_a_mesh():
    """The rule that decides whether any of this works.

    Pairwise-linking everything that shares an address block turned one
    out-of-band /24 into 34 fabricated adjacencies. A mesh has no articulation
    points and no bridges, so the resilience analyzer -- whose whole job is
    finding the single modem and the single-homed switch -- would have reported
    a flawless network. The most valuable findings in the product would have
    been deleted by a drawing heuristic.
    """
    topo = _topology(normalize_catalyst(_catalyst()), normalize_meraki(_meraki()))
    mgmt_links = [l for l in topo.links
                  if l.evidence == "containment" and "10.255.0.0/24" in l.evidence_detail]

    assert mgmt_links == []


# ── Absence, and the difference between two kinds of it ────────────────────

def test_an_empty_appliance_vlan_list_is_not_a_missing_one():
    """THE MOAT, in three lines. This org has no MX, so the appliance VLAN
    endpoint honestly returns `[]` and normalizes to zero VLANs. An endpoint we
    could not read is a different fact, and answering it with `.get(path, [])`
    would report that estate as having no VLANs with nothing anywhere to say
    otherwise."""
    raw = _meraki()
    assert raw[MERAKI_APPLIANCE_VLANS] == []
    assert normalize_meraki(raw).vlans == []

    unread = copy.deepcopy(raw)
    del unread[MERAKI_APPLIANCE_VLANS]
    with pytest.raises(NormalizeError, match=MERAKI_APPLIANCE_VLANS):
        normalize_meraki(unread)


@pytest.mark.parametrize("path", [DNA_DEVICES, DNA_INTERFACES,
                                  DNA_PHYSICAL_TOPOLOGY, DNA_VLAN_NAMES])
def test_every_catalyst_endpoint_refuses_to_go_missing_quietly(path):
    """Same rule, per endpoint. A dropped `/interface` page would otherwise
    produce an estate of devices with no ports -- and therefore no addresses, no
    containment adjacency and no VLANs -- reported as a clean read."""
    raw = _catalyst()
    del raw[path]

    with pytest.raises(NormalizeError, match=path):
        normalize_catalyst(raw)


def test_an_appliance_vlan_that_exists_is_carried_with_its_subnet():
    """The contrast that makes the empty list meaningful. Meraki's endpoint
    STATES the subnet, so a Meraki VLAN carries one and also yields a `Subnet`
    row -- unlike Catalyst Center, which returns only ids."""
    raw = _meraki()
    raw[MERAKI_APPLIANCE_VLANS] = [
        {"id": 100, "name": "guest", "subnet": "10.100.0.0/24", "applianceIp": "10.100.0.1"},
    ]

    res = normalize_meraki(raw)

    assert [(v.vlan_id, v.name, v.subnets, v.gateways) for v in res.vlans] == [
        (100, "guest", ["10.100.0.0/24"], ["10.100.0.1"])]
    assert [(s.cidr, s.vlan_id) for s in res.subnets] == [("10.100.0.0/24", 100)]


def test_a_vlan_subnet_comes_from_the_pool_and_never_from_the_gateway_mask():
    """The guarantee this test has always made, now that there is a legitimate
    source for the answer.

    The SVI's mask describes the GATEWAY'S INTERFACE, not the VLAN's allocation,
    and inferring one from the other is wrong in the direction that HIDES HOSTS:
    VLAN 30 carries 10.30.0.0/16 while its SVI reads 10.30.0.1/24, so a subnet
    taken off the mask would put app-server-07 (10.30.7.7) outside the VLAN it is
    actually on — and "where does this finding live" is the question the segment
    lane exists to answer.

    `/dna/intent/api/v1/global-pool` is Catalyst Center's own IP pool inventory
    and is where the real answer lives. So the subnet is now populated, and the
    assertion is that it came from THERE: it must equal the pool's cidr and must
    NOT equal the /24 the mask would have produced.
    """
    res = normalize_catalyst(_catalyst())
    vlan30 = next(v for v in res.vlans if v.vlan_id == 30)

    assert "10.30.0.1" in vlan30.gateways, "the gateway IS observed"
    assert vlan30.subnets == ["10.30.0.0/16"], "the pool's allocation, not the SVI's mask"
    assert "10.30.0.0/24" not in vlan30.subnets, "that is what the mask would have given"
    # The whole point, stated as the containment the inventory actually performs.
    assert ipaddress.ip_address("10.30.7.7") in ipaddress.ip_network(vlan30.subnets[0])
    assert ipaddress.ip_address("10.30.7.7") not in ipaddress.ip_network("10.30.0.0/24")


def test_a_vlan_with_no_pool_entry_still_carries_no_invented_subnet():
    """Remove the pool endpoint and the VLANs come back WITHOUT subnets rather
    than falling back to the mask. Absent is the correct answer; the fallback is
    the bug this file has always been about."""
    raw = _catalyst()
    del raw[DNA_GLOBAL_POOL]

    res = normalize_catalyst(raw)

    assert all(v.subnets == [] for v in res.vlans)
    assert all(v.name is None for v in res.vlans)
    # ...and the gateways, which ARE observed, still arrive.
    assert next(v for v in res.vlans if v.vlan_id == 30).gateways == ["10.30.0.1"]


def test_a_vlan_name_comes_from_the_pool_and_never_from_an_svi_description():
    """`vlan-names` returns ids. The operator's word for VLAN 30 is ALSO sitting
    in the SVI's free-text description ("SVI app-tier"), and scraping it out of
    there is how a normalizer starts reporting `no L3)` as the name of a VLAN.

    The pool's `ipPoolName` is a structured field and is the right source."""
    raw = _catalyst()
    assert raw[DNA_VLAN_NAMES]["response"] == ["10", "20", "30", "40", "50", "60", "70"]

    res = normalize_catalyst(raw)

    assert {v.vlan_id for v in res.vlans} == {10, 20, 30, 40, 50, 60, 70}
    assert next(v for v in res.vlans if v.vlan_id == 30).name == "app-tier"
    # No VLAN is named after a fragment of an interface description.
    assert all("no L3" not in (v.name or "") for v in res.vlans)


# ── Refusals: a guessed fact is worse than a named failure ─────────────────

def test_an_address_with_no_mask_is_refused_rather_than_assumed_to_be_a_host():
    """/32 is not a cautious guess. `reconstruct._containment_links` derives
    adjacency from two interfaces sharing a block, and a host route shares a
    block with nothing -- so assuming the mask would delete the very evidence
    the address was carried for, silently and in the safe-looking direction."""
    raw = _catalyst()
    svi = next(r for r in raw[DNA_INTERFACES]["response"]
               if r["id"] == "csw-core-01:Vlan30")
    svi["ipv4Mask"] = None

    with pytest.raises(NormalizeError, match="ipv4Mask"):
        normalize_catalyst(raw)

    # A port with no ADDRESS is untouched by the rule: an unaddressed switchport
    # is the normal case, not a defect, and refusing those would refuse the
    # entire access layer.
    assert normalize_catalyst(_catalyst()).interfaces

    uplinks = _meraki()
    address = uplinks[MERAKI_UPLINK_ADDRESSES][0]["uplinks"][0]["addresses"][0]
    address["address"] = "10.255.0.51"
    with pytest.raises(NormalizeError, match="prefix"):
        normalize_meraki(uplinks)


def test_a_link_or_interface_naming_an_unknown_device_is_refused():
    """An export disagreeing with itself. Stored, it is an edge or a port whose
    device has no row: the persistence layer fails on the foreign key and the
    topology screen draws a link to nothing."""
    raw = _catalyst()
    raw[DNA_DEVICES]["response"] = [
        r for r in raw[DNA_DEVICES]["response"] if r["id"] != "asw-acc-03"]

    with pytest.raises(NormalizeError, match="asw-acc-03"):
        normalize_catalyst(raw)


def test_a_vlan_named_rather_than_numbered_is_refused_not_dropped():
    """`Vlan.vlan_id` is an int, so a named VLAN cannot be carried at all.
    Dropping it would shrink the segment lane with nothing to notice it by."""
    raw = _catalyst()
    raw[DNA_VLAN_NAMES]["response"] = ["10", "VOICE"]

    with pytest.raises(NormalizeError, match="VOICE"):
        normalize_catalyst(raw)


def test_interface_speed_is_read_as_the_kilobits_catalyst_center_reports():
    """DNAC reports speed in KILObits as a string. Read as megabits it makes
    every gigabit port a terabit one, and headroom is one of the few numbers on
    this picture somebody might act on."""
    raw = _catalyst()
    port = next(r for r in raw[DNA_INTERFACES]["response"]
                if r["id"] == "csw-core-01:Te1/1/1")
    assert port["speed"] == "10000000"

    res = normalize_catalyst(raw)
    by_key = {i.interface_key: i for i in res.interfaces}
    assert by_key["csw-core-01:Te1/1/1"].speed_mbps == 10000
    assert by_key["csw-core-01:Gi1/0/1"].speed_mbps == 1000
    # A port the console gave no speed for reports none, not zero.
    assert by_key["csw-core-01:Vlan30"].speed_mbps is None


# ── Contracts the rest of the engine leans on ─────────────────────────────

def test_neither_normalizer_emits_policy():
    """These are network consoles, not policy products. `verify_engine` asserts
    the cross-tool paths are byte-identical with and without the infrastructure
    layer present, and the golden snapshot must not move because a switch was
    onboarded. A cable is not a grant."""
    for res in (normalize_catalyst(_catalyst()), normalize_meraki(_meraki())):
        assert res.records == []
        assert res.entities == []
        assert res.resolved == []


def test_no_normalizer_assigns_a_lane_it_did_not_observe():
    """`layer` is derived by `topology.reconstruct` from graph position. A
    normalizer that set it would be asserting a lane on the strength of a label
    -- which is the same defect as reading the CORE/ACCESS column, wearing a
    different hat."""
    for res in (normalize_catalyst(_catalyst()), normalize_meraki(_meraki())):
        for device in res.devices:
            assert device.layer is None
            assert device.layer_source == "unknown"
            assert device.layer_reason == ""


def test_every_fact_traces_back_to_the_console_that_reported_it():
    """`raw_ref` is the identifier IN THE SOURCE SYSTEM, so any row on any screen
    can be taken back to the console it came from. `simulated` is set at the
    point of creation rather than patched in downstream, because a screen that
    has to print "simulated" cannot depend on a later layer remembering to."""
    catalyst = normalize_catalyst(_catalyst())
    meraki = normalize_meraki(_meraki())

    for res, tool in ((catalyst, CATALYST_TOOL), (meraki, MERAKI_TOOL)):
        rows = res.devices + res.interfaces + res.links + res.vlans + res.subnets
        assert rows
        for row in rows:
            assert row.provenance.source_tool == tool
            assert row.provenance.source_tier == "management_console"
            assert row.provenance.simulated is True
            assert row.provenance.raw_ref.strip()

    by_key = {d.device_key: d for d in catalyst.devices}
    assert by_key["csw-core-01"].provenance.raw_ref == "csw-core-01"
    iface = next(i for i in catalyst.interfaces if i.interface_key == "csw-core-01:Vlan30")
    assert iface.provenance.raw_ref == "csw-core-01:Vlan30"
    assert next(v for v in catalyst.vlans if v.vlan_id == 30).provenance.raw_ref == "30"


def test_both_exports_are_byte_stable_across_runs():
    """No clock, no randomness, no set iteration in an output path. The snapshot
    fingerprint is an equality check over these rows, so an export whose order
    depended on a set's hash seed would make two identical reads look like a
    change to the network."""
    first = (json.dumps(catalyst_center_export(estate.build())),
             json.dumps(meraki_export(estate.build())))
    second = (json.dumps(catalyst_center_export(estate.build())),
              json.dumps(meraki_export(estate.build())))

    assert first == second
