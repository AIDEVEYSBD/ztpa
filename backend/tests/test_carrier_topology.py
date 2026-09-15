"""The carrier-portal projection: the only source that sees the modem layer.

Nothing else in the registry can tell you that two diverse-looking circuits were
sold by one carrier — which is the difference between redundancy and a
correlated failure wearing its costume, and the fact the resilience analyzer
exists to find. So the round trip below is not just a parsing test: if the
provider does not survive it, the estate's designed-in SPOF #2 becomes
invisible.

The rest of these pin what a service order does NOT carry. It is an order, not a
live read: no firmware, no link state, and no address on the customer side of the
demarc. Each of those has to come back as None rather than as a plausible
default, because the lane this source fills is one nothing else can check.
"""

from __future__ import annotations

import pytest

from src import estate
from src.connectors.carrier import carrier_portal_export
from src.normalizers import carrier
from src.normalizers.profile import NormalizeError


def _payload() -> dict:
    return carrier_portal_export(estate.build())


def _extract(**overrides) -> dict:
    """A one-row extract, for the shapes the estate cannot produce."""
    row = {
        "circuit_id": "CIRC-X", "service_type": "MPLS", "carrier": "Carrier-Z",
        "bandwidth_mbps": 100, "wan_ip_block": "203.0.113.16/29",
        "cpe_name": "mdm-x-01", "cpe_model": "CPE-1", "cpe_serial": "",
        "cpe_mgmt_ip": "10.255.0.9", "cpe_wan_port": "wan",
        "cpe_handoff_port": "lan", "demarc_location": "hq", "status": "up",
        "handoff_device": "rtr-edge-01", "handoff_interface": "Gi0/0/5",
    }
    row.update(overrides)
    return {"source": "carrier portal service-order extract", "circuits": [row]}


# ── The slice ──────────────────────────────────────────────────────────────

def test_the_portal_sees_the_cpe_and_nothing_on_the_customer_side_of_it():
    """Partial coverage is the feature. The portal enumerates three modems out of
    a 13-device estate, and a projection that reached past the demarc would make
    the coverage story a fiction — as well as claiming a carrier can see a
    customer's switching fabric, which no carrier can."""
    est = estate.build()
    res = carrier.normalize(carrier_portal_export(est))

    assert [d.device_key for d in res.devices] == [
        "mdm-bb-01", "mdm-isdn-01", "mdm-mpls-01",
    ]
    assert {d.device_key for d in res.devices} == {
        d.key for d in est.devices_seen_by("carrier_portal")
    }
    assert all(d.role == "modem" and d.role_source == "declared" for d in res.devices)


def test_the_handoff_router_is_linked_but_never_enumerated():
    """The order names the customer router the demarc hands off to, so the link
    is real and is evidenced as `declared` — a human wrote it on a service order,
    and the picture should say exactly that.

    Naming a box is not observing it, though: a carrier portal that enumerated
    the customer's routers would be a carrier portal that does not exist."""
    res = carrier.normalize(_payload())
    peers = {l.b_device for l in res.links}

    assert peers == {"rtr-edge-01", "rtr-edge-02"}
    assert peers.isdisjoint({d.device_key for d in res.devices})
    assert all(l.evidence == "declared" for l in res.links)
    link = next(l for l in res.links if l.a_device == "mdm-mpls-01")
    assert (link.a_interface, link.b_interface) == ("lan", "Gi0/0/0")
    assert "CIRC-A" in link.evidence_detail


def test_the_circuits_round_trip_with_their_provider_and_technology():
    """The provider is the whole reason this source is onboarded. Lose it and the
    estate's designed-in correlated failure — two circuits, two technologies, one
    carrier — stops being visible to anything."""
    res = carrier.normalize(_payload())
    by_id = {c.circuit_id: c for c in res.circuits}

    assert sorted(by_id) == ["CIRC-A", "CIRC-B", "CIRC-C"]
    mpls = by_id["CIRC-A"]
    assert (mpls.provider, mpls.technology, mpls.bandwidth_mbps) == ("Carrier-A", "mpls", 200)
    assert mpls.public_ips == ["203.0.113.0/29"]
    assert (mpls.device_key, mpls.interface) == ("mdm-mpls-01", "wan")
    assert mpls.provenance.raw_ref == "CIRC-A"
    assert mpls.provenance.source_tool == "carrier_portal"
    assert mpls.provenance.simulated is True


def test_two_diverse_looking_circuits_share_one_carrier_and_it_shows():
    """SPOF #2, as this source alone can report it: an MPLS circuit and an ISDN
    backup, bought separately, sold by the same carrier. Diverse links, one
    failure domain."""
    res = carrier.normalize(_payload())
    providers = {c.circuit_id: c.provider for c in res.circuits}

    assert providers["CIRC-A"] == providers["CIRC-C"] == "Carrier-A"
    assert providers["CIRC-B"] == "Carrier-B"


def test_a_standby_circuit_is_standby_and_not_down():
    """The ISDN backup is doing exactly what it was bought to do. Reporting it as
    down would put an outage on the picture; reporting it as up would claim a
    path that is not carrying traffic."""
    res = carrier.normalize(_payload())
    states = {c.circuit_id: c.state for c in res.circuits}

    assert states == {"CIRC-A": "up", "CIRC-B": "up", "CIRC-C": "standby"}


# ── What a service order does not carry ────────────────────────────────────

def test_admin_up_is_none_because_the_order_reports_circuit_state_not_link_state():
    """The `status` column on a service order is the CIRCUIT's, and it is already
    carried on `Circuit.state`.

    Copying it onto the CPE's ports would report a standby ISDN circuit's modem
    as administratively down — an outage the portal never claimed — and
    defaulting to False would do the same to all three. None is the column's way
    of saying the source did not tell us."""
    res = carrier.normalize(_payload())

    assert res.interfaces, "the portal does see the CPE's ports"
    assert all(i.admin_up is None for i in res.interfaces)
    assert all(i.oper_up is None for i in res.interfaces)


def test_the_handoff_port_carries_no_address_because_that_is_past_the_demarc():
    """The carrier assigns the WAN block and hands off on a port. Whatever the
    customer configured on the inside is not the carrier's to report, and an
    empty address list says so without inventing one."""
    res = carrier.normalize(_payload())
    by_key = {i.interface_key: i for i in res.interfaces}

    assert by_key["mdm-mpls-01:wan"].addresses == ["203.0.113.0/29"]
    assert by_key["mdm-mpls-01:wan"].speed_mbps == 200
    assert by_key["mdm-mpls-01:lan"].addresses == []


def test_the_order_carries_no_firmware_so_the_version_stays_unreported():
    """A service order records what was sold and installed, not what is running.

    The estate knows these CPE firmwares; this source does not, and back-filling
    one from the model number would be a guess on a lane no other onboarded
    console can correct."""
    res = carrier.normalize(_payload())

    assert all(d.os_version is None for d in res.devices)
    assert [d.model for d in res.devices] == ["FiberCPE-900", "BRI-128", "CPE-2200"]


def test_a_blank_cpe_serial_is_not_a_serial():
    """`cpe_serial: ""` means the order does not carry one. Stored as the empty
    string it would put a serial column on screen that looks populated and
    identifies nothing — so the device is keyed on the circuit instead, which is
    how the portal itself indexes its CPE."""
    res = carrier.normalize(_extract())
    device = res.devices[0]

    assert device.serial is None
    assert device.provenance.raw_ref == "CIRC-X"


def test_the_public_block_is_carried_verbatim_rather_than_canonicalised():
    """Which address in the block the WAN port holds is exactly what an operator
    needs; `203.0.113.17/29` collapsed to its network throws that away.
    Canonical blocks belong on `Subnet.cidr`, not on an interface."""
    res = carrier.normalize(_extract(wan_ip_block="203.0.113.17/29"))
    by_key = {i.interface_key: i for i in res.interfaces}

    assert by_key["mdm-x-01:wan"].addresses == ["203.0.113.17/29"]
    assert res.circuits[0].public_ips == ["203.0.113.17/29"]


# ── Failure never looks like emptiness ─────────────────────────────────────

def test_an_absent_circuit_list_is_a_failure_not_an_estate_with_no_way_out():
    """A truncated portal download yields no rows. "This estate has no circuits"
    is a conclusion a reviewer would act on, and it would be false."""
    with pytest.raises(NormalizeError, match="no 'circuits' list"):
        carrier.normalize({"source": "carrier portal service-order extract"})
    with pytest.raises(NormalizeError):
        carrier.normalize({"circuits": "CIRC-A,CIRC-B"})


def test_an_empty_circuit_list_is_a_real_empty():
    """The mirror: a portal account with nothing provisioned on it normalizes to
    nothing, without complaint. Over-raising would be its own defect."""
    res = carrier.normalize({"circuits": []})

    assert (res.devices, res.interfaces, res.links, res.circuits) == ([], [], [], [])


def test_a_row_with_no_circuit_id_is_refused():
    """The circuit id is the only identifier this source has, and the only trail
    back into the portal. A row without one cannot be traced by anybody."""
    payload = _extract()
    del payload["circuits"][0]["circuit_id"]

    with pytest.raises(NormalizeError, match="no circuit_id"):
        carrier.normalize(payload)


def test_a_malformed_public_block_fails_diagnosably():
    """This field is the customer's entire public footprint on that circuit.
    Dropping an unparseable one silently would understate internet exposure, so
    it raises naming the circuit and the token."""
    with pytest.raises(NormalizeError, match="CIRC-X"):
        carrier.normalize(_extract(wan_ip_block="203.0.113.0/33"))


def test_an_unrecognised_service_type_is_unknown_not_the_nearest_member():
    """A portal that starts writing "Ethernet-P2P" must widen the model
    deliberately. Rounding it to `p2p` here would file a service under a
    technology nobody sold."""
    res = carrier.normalize(_extract(service_type="Ethernet-P2P"))

    assert res.circuits[0].technology == "unknown"
    assert res.circuits[0].provider == "Carrier-Z", "the carrier is still known"


def test_a_row_naming_no_cpe_still_yields_the_circuit():
    """The circuit is real whether or not the order names the equipment. What is
    unreported is the CPE, and `device_key=None` says that rather than inventing
    a modem to hang it on."""
    payload = _extract()
    del payload["circuits"][0]["cpe_name"]
    res = carrier.normalize(payload)

    assert res.devices == [] and res.interfaces == [] and res.links == []
    assert res.circuits[0].device_key is None
    assert res.circuits[0].circuit_id == "CIRC-X"


# ── The line this module must not cross ────────────────────────────────────

def test_the_portal_emits_no_policy_records():
    """A carrier has no policy to report, and `verify_engine` asserts the
    cross-tool paths are byte-identical with and without the infrastructure layer
    present. A normalizer that started producing grants here would move the
    golden snapshot and every finding count with it."""
    res = carrier.normalize(_payload())

    assert res.records == []
    assert res.entities == []
    assert res.resolved == []
    assert res.vlans == [] and res.subnets == []


def test_no_projection_sets_a_layer():
    """Lanes are assigned by `topology.reconstruct` from graph position. The
    modem lane is the one this source populates, and it populates it by reporting
    a modem — not by claiming the lane."""
    for device in carrier.normalize(_payload()).devices:
        assert device.layer is None
        assert device.layer_source == "unknown"
        assert device.layer_reason == ""


def test_the_projection_is_deterministic():
    """No clock, no randomness, no set iteration in an output path: two runs over
    one estate must be byte-identical, or the snapshot fingerprint means
    nothing."""
    assert carrier_portal_export(estate.build()) == carrier_portal_export(estate.build())

    once, twice = carrier.normalize(_payload()), carrier.normalize(_payload())
    assert [c.model_dump() for c in once.circuits] == [c.model_dump() for c in twice.circuits]
    assert [l.model_dump() for l in once.links] == [l.model_dump() for l in twice.links]
