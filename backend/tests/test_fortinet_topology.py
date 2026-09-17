"""The Fortinet projections, and the 200-on-failure trap they exist to refuse.

FortiManager answers HTTP 200 to calls that failed. The transport worked; the
request did not; the only thing that says so is `result[].status.code`. A reader
that skips it gets a well-formed envelope with an empty `data` array, ingests it
cleanly, and reports "0 devices" — which reads to a reviewer as a clean run of an
estate with no firewalls in it.

That is the defect these tests exist to pin dead, and it is why several of them
are about refusing to read something rather than about reading it correctly: a
leaf-polled Security Fabric tree, a block with no status, blocks from two
different serials. Each of those has an empty-looking answer that is wrong in the
same direction.

The rest pin the round trip — the estate, projected into each console's payload
and normalized back — and the three facts a Fortinet console does NOT report,
which must come back as None rather than as a plausible default.
"""

from __future__ import annotations

import pytest

from src import estate
from src.connectors.fortinet import fortigate_export, fortimanager_export
from src.normalizers import fortinet
from src.normalizers.profile import NormalizeError

DEVICE_URL = "/dvmdb/adom/root/device"
DYNAMIC_URL = "/pm/config/adom/root/obj/dynamic/interface"


def _fm_payload() -> dict:
    return fortimanager_export(estate.build())


def _fg_payload() -> dict:
    return fortigate_export(estate.build())


def _envelope(devices: list[dict], dynamic: list[dict] | None = None) -> dict:
    """A hand-built FortiManager envelope, for the shapes the estate cannot produce."""
    return {
        "id": 1,
        "result": [
            {"status": {"code": 0, "message": "OK"}, "url": DEVICE_URL, "data": devices},
            {"status": {"code": 0, "message": "OK"}, "url": DYNAMIC_URL,
             "data": dynamic or []},
        ],
    }


def _fg_host(interfaces: list[dict], ha: dict | None = None,
             csf: dict | None = None, serial: str = "FG200F1234567890") -> dict:
    """One box's FortiOS read, for the shapes the estate cannot produce."""
    def block(name: str, results) -> dict:
        return {"http_status": 200, "status": "success", "serial": serial,
                "version": "v7.4.3", "vdom": "root", "path": "system",
                "name": name, "results": results}

    blocks = {"cmdb/system/interface": block("interface", interfaces)}
    if ha is not None:
        blocks["cmdb/system/ha"] = block("ha", ha)
    if csf is not None:
        blocks["monitor/system/csf"] = block("csf", csf)
    return blocks


# ── The trap ───────────────────────────────────────────────────────────────

def test_a_nonzero_status_code_raises_rather_than_ingesting_zero_devices():
    """THE one. FortiManager returned HTTP 200, the call failed, and `data` is
    empty — which is byte-identical to a successful read of an ADOM with no
    firewalls in it, except for the status code.

    A normalizer that ingests this reports "0 devices" for a permission error,
    and 0 findings reads to a client as clean. It must fail, loudly, naming the
    code."""
    payload = _fm_payload()
    payload["result"][0]["status"] = {"code": -11,
                                      "message": "No permission for the resource"}
    payload["result"][0]["data"] = []

    with pytest.raises(NormalizeError) as err:
        fortinet.normalize(payload)
    assert "-11" in str(err.value)
    assert "No permission" in str(err.value)
    assert DEVICE_URL in str(err.value)


def test_the_status_code_is_the_only_thing_that_separates_empty_from_failed():
    """The mirror of the test above, and the reason it has to be the code that
    decides: the SAME empty envelope with `code: 0` is a real empty ADOM and must
    normalize to nothing without complaint.

    Over-raising here would be its own defect — a console that manages nothing
    yet is not a console we failed to read."""
    payload = _fm_payload()
    payload["result"][0]["data"] = []
    payload["result"][1]["data"] = []

    res = fortinet.normalize(payload)
    assert res.devices == []
    assert res.interfaces == []
    assert res.links == []


def test_a_result_block_with_no_status_is_not_read_as_success():
    """Absence of the only readable signal is not evidence that the call worked.

    A truncated or proxied response that loses the status block would otherwise
    take the same silent path as the failure above."""
    payload = _fm_payload()
    del payload["result"][0]["status"]

    with pytest.raises(NormalizeError, match="no status block"):
        fortinet.normalize(payload)


def test_an_unread_block_is_still_status_checked():
    """A failed call is a failed call whether or not this module wanted its rows.

    The dynamic-interface block feeds zones, not the device inventory; ingesting
    the devices around a failure in it would report a partial read as a whole
    one."""
    payload = _fm_payload()
    payload["result"][1]["status"] = {"code": -3, "message": "Object does not exist"}

    with pytest.raises(NormalizeError, match="-3"):
        fortinet.normalize(payload)


def test_an_envelope_with_no_result_blocks_is_a_failed_call():
    """`result: []` is not an ADOM with nothing in it — JSON-RPC always answers
    the call it was given."""
    with pytest.raises(NormalizeError, match="no result blocks"):
        fortinet.normalize({"id": 1, "result": []})


def test_an_unrecognised_payload_is_refused_rather_than_returned_empty():
    """"We could not tell what this file was" and "this console manages nothing"
    are the two facts that must never arrive looking the same."""
    with pytest.raises(NormalizeError, match="neither a FortiManager"):
        fortinet.normalize({"devices": [{"name": "fw-perim-01"}]})
    with pytest.raises(NormalizeError):
        fortinet.normalize({})


# ── FortiManager: the slice, and what it can say about it ──────────────────

def test_fortimanager_sees_its_own_pair_and_nothing_else_in_the_estate():
    """Partial coverage is the feature. FortiManager manages two FortiGates in a
    13-device estate, and a projection that emitted the routers, switches or
    modems would make the demo's coverage story a fiction."""
    est = estate.build()
    res = fortinet.normalize(fortimanager_export(est))

    assert [d.device_key for d in res.devices] == ["fw-perim-01", "fw-perim-02"]
    visible = {d.key for d in est.devices_seen_by("fortimanager")}
    assert {d.device_key for d in res.devices} == visible
    assert {i.device_key for i in res.interfaces} <= visible


def test_fortimanager_round_trips_the_device_facts_it_holds():
    """Platform, firmware and HA membership are what an aggregator is FOR, and
    they have to survive the trip through FortiManager's own field names —
    `platform_str`, the three firmware columns, `master`/`slave`."""
    res = fortinet.normalize(_fm_payload())
    first, second = res.devices

    assert (first.model, first.os_version) == ("FortiGate-200F", "FortiOS 7.4.3")
    assert first.serial == "FG200F1234567890"
    assert first.mgmt_ip == "10.255.0.21"
    assert (first.ha_group, first.ha_role) == ("perim-ha", "primary")
    assert (second.ha_group, second.ha_role) == ("perim-ha", "secondary")
    assert (first.role, first.role_source) == ("firewall", "declared")
    assert first.provenance.raw_ref == first.serial
    assert first.provenance.source_tier == "aggregator"
    assert first.provenance.simulated is True


def test_fortimanager_reports_no_link_state_so_admin_up_stays_none():
    """`admin_up` is three-valued for exactly this source.

    FortiManager's policy objects say a port EXISTS and which normalized
    interface it answers to. They say nothing about whether it is up. Defaulting
    to False would grey out every port on both firewalls and invent an outage;
    defaulting to True would claim a health check nobody ran."""
    res = fortinet.normalize(_fm_payload())

    assert res.interfaces, "the normalized interfaces should resolve to real ports"
    assert all(i.admin_up is None for i in res.interfaces)
    assert all(i.oper_up is None for i in res.interfaces)
    assert all(i.speed_mbps is None for i in res.interfaces)


def test_a_normalized_interface_that_merely_renames_a_port_declares_no_zone():
    """FortiManager creates one normalized interface per port name as devices are
    added. When the normalized name EQUALS the local port, there is no
    abstraction — and labelling that port with a zone called "port1" would put a
    security construct on the picture that nobody configured."""
    res = fortinet.normalize(_fm_payload())
    assert all(i.zone is None for i in res.interfaces)

    named = _envelope(
        [{"name": "fw-perim-01", "platform_str": "FortiGate-200F", "sn": "FG1"}],
        [{"name": "untrust", "dynamic_mapping": [
            {"_scope": [{"name": "fw-perim-01", "vdom": "root"}],
             "local-intf": ["port1"]}]}],
    )
    zoned = fortinet.normalize(named).interfaces
    assert [(i.name, i.zone) for i in zoned] == [("port1", "untrust")]


def test_a_device_scoped_mapping_wins_over_the_platform_mapping():
    """`sources.py` records that a policy's interface must be resolved per DEVICE
    before falling back to per PLATFORM, "or the zone graph is fiction".

    A device-specific mapping silently losing to a platform default puts the
    policy on the wrong port of a picture that still looks right."""
    payload = _envelope(
        [{"name": "fw-perim-01", "platform_str": "FortiGate-200F", "sn": "FG1"},
         {"name": "fw-perim-02", "platform_str": "FortiGate-200F", "sn": "FG2"}],
        [{"name": "untrust",
          "dynamic_mapping": [{"_scope": [{"name": "fw-perim-01", "vdom": "root"}],
                               "local-intf": ["port7"]}],
          "platform_mapping": [{"name": "FortiGate-200F", "intf-zone": "port1"}]}],
    )
    by_device = {i.device_key: i.name for i in fortinet.normalize(payload).interfaces}

    assert by_device["fw-perim-01"] == "port7", "the device's own mapping must win"
    assert by_device["fw-perim-02"] == "port1", "the platform default fills the rest"


def test_a_mapping_scoped_to_a_device_this_export_never_described_is_skipped():
    """The aggregator told us a policy references that box. It did not tell us
    what that box is, and emitting it would put a device on the picture that no
    source ever described."""
    payload = _envelope(
        [{"name": "fw-perim-01", "platform_str": "FortiGate-200F", "sn": "FG1"}],
        [{"name": "untrust", "dynamic_mapping": [
            {"_scope": [{"name": "fw-branch-99", "vdom": "root"}],
             "local-intf": ["port1"]}]}],
    )
    res = fortinet.normalize(payload)

    assert [d.device_key for d in res.devices] == ["fw-perim-01"]
    assert res.interfaces == []


def test_a_platform_that_declares_no_type_leaves_the_role_unknown():
    """FortiManager manages FortiAnalyzers and FortiSwitches too. `role` is
    'declared' only when the platform string actually states the type; the
    reconstruction engine derives the rest from what the box terminates, and a
    normalizer guessing on its behalf would overwrite an observation with a
    vendor prefix."""
    payload = _envelope([{"name": "faz-01", "platform_str": "FortiAnalyzer-400E",
                          "sn": "FAZ1"}])
    device = fortinet.normalize(payload).devices[0]

    assert (device.role, device.role_source) == ("unknown", "unknown")
    assert device.layer is None and device.layer_source == "unknown"


# ── FortiGate: the box's own view ──────────────────────────────────────────

def test_fortigate_round_trips_interface_addressing_and_admin_state():
    """The device rung is where addresses and admin state come from: FortiOS
    writes an address as "addr mask", and `status` is the admin state the
    `admin_up` column means."""
    res = fortinet.normalize(_fg_payload())
    by_key = {i.interface_key: i for i in res.interfaces}

    port1 = by_key["fw-perim-01:port1"]
    assert port1.addresses == ["10.254.1.2/30"]
    assert port1.admin_up is True
    assert port1.speed_mbps == 1000
    assert port1.provenance.raw_ref == "cmdb/system/interface/port1"
    assert port1.provenance.source_tier == "device"
    # The operational state lives in a table this read does not take, and is not
    # mirrored from the admin one.
    assert port1.oper_up is None
    assert by_key["fw-perim-01:mgmt"].addresses == ["10.255.0.21/24"]


def test_fortigate_does_not_report_a_platform_and_says_so():
    """The ladder, visible in one field. None of the four tables read here
    carries the model — the aggregator has it and this rung does not — so `model`
    comes back None rather than being reconstructed from the serial prefix."""
    device = fortinet.normalize(_fg_payload()).devices[0]

    assert device.model is None
    assert device.os_version == "FortiOS 7.4.3", "both consoles must agree on firmware"
    assert device.ha_group == "perim-ha"
    # Which member leads is an election outcome, not a config stanza.
    assert device.ha_role is None


def test_an_unnumbered_interface_does_not_become_a_default_route():
    """`0.0.0.0 0.0.0.0` is FortiOS for "this port holds no address".

    Read as 0.0.0.0/0 it would place every device in the estate inside one block,
    and `topology.reconstruct` would then draw a containment link from everything
    to everything."""
    payload = {"fw-perim-01": _fg_host([{"name": "port9", "ip": "0.0.0.0 0.0.0.0"}])}
    iface = fortinet.normalize(payload).interfaces[0]

    assert iface.addresses == []


def test_auto_negotiation_is_not_a_measured_speed():
    """`speed: "auto"` is a setting, not a rate. Putting a number on the picture
    that nobody observed is the same class of defect as inventing a link."""
    payload = {"fw-perim-01": _fg_host([
        {"name": "port1", "ip": "0.0.0.0 0.0.0.0", "speed": "auto"},
        {"name": "port2", "ip": "0.0.0.0 0.0.0.0", "speed": "10000full"},
    ])}
    speeds = {i.name: i.speed_mbps for i in fortinet.normalize(payload).interfaces}

    assert speeds == {"port1": None, "port2": 10000}


def test_a_port_with_no_reported_status_keeps_admin_up_none():
    """"The source did not say" and "the port is down" are different facts, and
    the column is three-valued at the model for exactly this reason."""
    payload = {"fw-perim-01": _fg_host([
        {"name": "port1", "ip": "0.0.0.0 0.0.0.0"},
        {"name": "port2", "ip": "0.0.0.0 0.0.0.0", "status": "down"},
    ])}
    states = {i.name: i.admin_up for i in fortinet.normalize(payload).interfaces}

    assert states == {"port1": None, "port2": False}


def test_the_vlan_id_comes_from_vlanid_or_from_the_dotted_subinterface_name():
    """`vlanid: 0` is FortiOS for "not a VLAN subinterface" — ingesting it as VLAN
    0 would invent a broadcast domain and hang every physical port off it. A
    FortiOS VLAN subinterface is named `<parent>.<vlanid>`, which is the fallback
    for exports that carry the name without the field."""
    payload = {"fw-perim-01": _fg_host([
        {"name": "port5", "ip": "0.0.0.0 0.0.0.0", "vlanid": 0},
        {"name": "port5.30", "ip": "10.30.0.2 255.255.0.0", "interface": "port5"},
        {"name": "port6.40", "ip": "0.0.0.0 0.0.0.0", "vlanid": 40, "interface": "port6"},
    ])}
    res = fortinet.normalize(payload)
    vlans = {i.name: i.vlan_id for i in res.interfaces}

    assert vlans == {"port5": None, "port5.30": 30, "port6.40": 40}
    assert [(v.vlan_id, v.subnets) for v in res.vlans] == [
        (30, ["10.30.0.0/16"]), (40, []),
    ]
    # The box knows the tag on its own subinterface. It does not know what the
    # VLAN is called on the switch that owns it, nor where the gateway lives.
    assert all(v.name is None and v.gateways == [] for v in res.vlans)


def test_blocks_captured_from_two_serials_are_not_one_device():
    """A merged capture would attribute one firewall's interfaces to its HA peer,
    which is worse than having taken no read at all."""
    host = _fg_host([{"name": "port1", "ip": "0.0.0.0 0.0.0.0"}],
                    ha={"group-name": "perim-ha", "mode": "a-p"})
    host["cmdb/system/ha"]["serial"] = "FG200F0987654321"

    with pytest.raises(NormalizeError, match="different serials"):
        fortinet.normalize({"fw-perim-01": host})


def test_a_fortios_response_that_did_not_return_200_is_refused():
    """Same discipline as the FortiManager status check: a table we could not
    read is not a table with nothing in it."""
    payload = _fg_payload()
    payload["fw-perim-01"]["cmdb/system/interface"]["http_status"] = 403

    with pytest.raises(NormalizeError, match="HTTP 403"):
        fortinet.normalize(payload)

    stripped = _fg_payload()
    del stripped["fw-perim-01"]["cmdb/system/interface"]["http_status"]
    with pytest.raises(NormalizeError, match="no http_status"):
        fortinet.normalize(stripped)


# ── The HA pair, and the fabric tree that must not redraw it ───────────────

def test_the_ha_pair_is_one_config_link_and_both_consoles_agree_on_its_key():
    """An HA group is a config stanza, not a cable — `evidence='config'` says so,
    and both ends carry no interface because the heartbeat port is in neither
    table.

    The key names the ADJACENCY rather than the observation, so the manager's
    view of the cluster and the members' own view of it collapse to one line
    instead of drawing the pair twice."""
    from_manager = fortinet.normalize(_fm_payload()).links
    from_box = fortinet.normalize(_fg_payload()).links

    assert [l.link_key for l in from_manager] == ["ha:perim-ha:fw-perim-01~fw-perim-02"]
    assert [l.link_key for l in from_box] == [l.link_key for l in from_manager]
    link = from_manager[0]
    assert link.evidence == "config"
    assert link.a_interface is None and link.b_interface is None
    assert "not a cable" in link.evidence_detail


def test_the_fabric_tree_does_not_redraw_the_ha_pair_as_topology():
    """This estate's two FortiGates are the two members of ONE cluster, and a
    cluster is one Security Fabric node — the members are listed in `ha_members`,
    not as children.

    Rendering the peer as a downstream child would assert a fabric registration
    the estate does not contain and draw a second line between two boxes that
    have exactly one relationship."""
    res = fortinet.normalize(_fg_payload())

    assert [l.evidence for l in res.links] == ["config"]
    assert not [l for l in res.links if l.evidence == "api_topology"]


def test_a_downstream_fabric_member_arrives_as_api_topology():
    """What csf is actually for: the console returned this adjacency AS topology,
    which is precisely what that evidence class names."""
    payload = {"fw-perim-01": _fg_host(
        [{"name": "port1", "ip": "0.0.0.0 0.0.0.0"}],
        csf={"name": "fw-perim-01", "serial": "FG200F1234567890",
             "ip": "10.255.0.21", "is_root": True, "authorized": True,
             "ha_members": ["FG200F1234567890"],
             "children": [{"name": "fw-branch-01", "serial": "FG40F9", "ip": "10.255.9.1",
                           "authorized": True, "children": []}]},
    )}
    res = fortinet.normalize(payload)
    fabric = [l for l in res.links if l.evidence == "api_topology"]

    assert [(l.a_device, l.b_device) for l in fabric] == [("fw-perim-01", "fw-branch-01")]
    assert [d.device_key for d in res.devices] == ["fw-branch-01", "fw-perim-01"]
    branch = res.devices[0]
    assert (branch.role, branch.role_source) == ("firewall", "declared")
    assert branch.provenance.raw_ref == "monitor/system/csf/FG40F9"


def test_a_fabric_tree_polled_from_a_leaf_is_refused():
    """A leaf read omits everything upstream of it, so it arrives looking like a
    complete SMALLER fabric rather than like a partial capture.

    `sources.py` records that csf must be read from the fabric root; this is that
    rule with teeth, because the wrong answer here is an under-count that looks
    like an inventory."""
    payload = {"fw-perim-02": _fg_host(
        [{"name": "port1", "ip": "0.0.0.0 0.0.0.0"}],
        csf={"name": "fw-perim-02", "serial": "FG200F0987654321", "is_root": False,
             "children": []},
        serial="FG200F0987654321",
    )}

    with pytest.raises(NormalizeError, match="non-root"):
        fortinet.normalize(payload)


# ── The line this module must not cross ────────────────────────────────────

def test_neither_fortinet_projection_emits_policy_records():
    """Both Fortinet consoles carry policy, and reading it is a different job.

    `verify_engine` asserts the cross-tool paths are byte-identical with and
    without the infrastructure layer present; a normalizer that quietly started
    producing grants here would move the golden snapshot and every finding count
    with it."""
    for payload in (_fm_payload(), _fg_payload()):
        res = fortinet.normalize(payload)
        assert res.records == []
        assert res.entities == []
        assert res.resolved == []
        assert res.circuits == [], "a firewall console does not sell circuits"


def test_the_projections_are_deterministic():
    """No clock, no randomness, no set iteration in an output path: two runs over
    one estate must be byte-identical, or the snapshot fingerprint means
    nothing."""
    for build in (fortimanager_export, fortigate_export):
        first, second = build(estate.build()), build(estate.build())
        assert first == second

    once = fortinet.normalize(_fg_payload())
    twice = fortinet.normalize(_fg_payload())
    assert [i.model_dump() for i in once.interfaces] == \
           [i.model_dump() for i in twice.interfaces]
    assert [l.model_dump() for l in once.links] == [l.model_dump() for l in twice.links]


def test_no_projection_sets_a_layer():
    """Lanes are assigned by `topology.reconstruct` from graph position. A
    normalizer that set one would be asserting a position it did not observe —
    and `layer is None` and `layer_source == 'unknown'` are one state, enforced
    by a database CHECK."""
    for payload in (_fm_payload(), _fg_payload()):
        for device in fortinet.normalize(payload).devices:
            assert device.layer is None
            assert device.layer_source == "unknown"
            assert device.layer_reason == ""


def test_the_status_block_is_not_shared_between_result_blocks():
    """A module-level status constant would let one caller's edit reach every
    other reader of the payload — turning one failed block into an envelope in
    which every call failed, which is a different diagnosis."""
    payload = _fm_payload()
    payload["result"][0]["status"]["code"] = -11

    assert payload["result"][1]["status"]["code"] == 0
