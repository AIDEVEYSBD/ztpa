"""The resilience analyzer, against the estate that was built to break it.

`estate.py` designs four single points of failure in and criss-crosses
everything else, so this file has two jobs of equal weight:

  * the TRUE POSITIVES — all four designed SPOFs are found, with the reason that
    makes each one checkable by an engineer who does not trust us; and
  * the FALSE POSITIVES — the criss-crossed uplinks, the LAG peer link and the
    properly cabled HA pair are NOT reported. An analyzer that flags every edge
    finds all four SPOFs too, and is worthless. The suppression tests assert
    POSITIVELY (the reason is published in `suppressed`) rather than merely
    asserting an absence, because an absence also passes when the analyzer
    crashes into an empty list.

The third job is the honesty one: an estate nobody observed must not render as
an estate with no single points of failure.

No database, no clock, no randomness: the topology is built from `estate.build()`
and run through the real `topology.reconstruct`, so these numbers describe the
pipeline the product ships rather than a fixture shaped to agree with it.
"""

from __future__ import annotations

from src import estate
from src.analyzers.resilience import (
    BLAST_BASIS_CIRCUIT, BLAST_BASIS_CONNECTIVITY, DOMAIN_SHARED_CARRIER,
    DOMAIN_SHARED_HANDOFF, LAYER_WEIGHT, analyze, assess,
)
from src.analyzers.severity import band
from src.models import Circuit, NetDevice, NetInterface, NetLink, Provenance, Topology
from src.sources import tier_of
from src.topology import reconstruct


# ── Fixtures: the estate, through the real reconstruction engine ───────────

def _prov(tool: str, raw_ref: str) -> Provenance:
    return Provenance(source_tool=tool, source_tier=tier_of(tool), raw_ref=raw_ref,
                      simulated=True)


def _estate_topology(*, with_circuits: bool = True) -> Topology:
    """The whole estate as one console would see it if one console saw all of it.

    Deliberately NOT a hand-written graph: it is `estate.build()` run through
    `topology.reconstruct`, so everything the reconstruction engine adds — in
    particular the containment adjacencies it derives from shared address blocks
    — is present exactly as it will be in production.
    """
    est = estate.build()
    devices = [
        NetDevice(
            device_key=spec.key, name=spec.name, role=spec.role, role_source="declared",
            role_reason=f"{spec.seen_by[0]} reports the device type",
            vendor=spec.vendor, model=spec.model, os_version=spec.os_version,
            serial=spec.serial or None, mgmt_ip=spec.mgmt_ip, site=spec.site,
            ha_group=spec.ha_group, ha_role=spec.ha_role,
            provenance=_prov(spec.seen_by[0], spec.serial or spec.key),
        )
        for spec in est.devices
    ]
    seen_by = {spec.key: spec.seen_by[0] for spec in est.devices}
    interfaces = [
        NetInterface(
            interface_key=f"{i.device}:{i.name}", device_key=i.device, name=i.name,
            description=i.description or None, addresses=list(i.addresses),
            vlan_id=i.vlan_id, zone=i.zone, admin_up=i.admin_up,
            speed_mbps=i.speed_mbps, lag_group=i.lag_group,
            neighbor_device=i.neighbor_device, neighbor_interface=i.neighbor_interface,
            provenance=_prov(seen_by[i.device], i.name),
        )
        for i in est.interfaces
    ]
    links = [
        NetLink(
            link_key=f"{ln.a_device}:{ln.a_interface}~{ln.b_device}:{ln.b_interface}",
            a_device=ln.a_device, a_interface=ln.a_interface,
            b_device=ln.b_device, b_interface=ln.b_interface,
            # A LAG is a config stanza; every other cable here is a neighbour
            # table entry, which is what the estate's interfaces carry.
            evidence="config" if ln.aggregated else "lldp",
            evidence_detail=f"{ln.a_device} {ln.a_interface} -> {ln.b_device} {ln.b_interface}",
            redundant_group=ln.redundant_group, aggregated=ln.aggregated,
            member_count=ln.member_count,
            provenance=_prov(seen_by[ln.a_device], f"{ln.a_device}:{ln.a_interface}"),
        )
        for ln in est.links
    ]
    circuits = [
        Circuit(
            circuit_id=c.circuit_id, provider=c.provider, technology=c.technology,
            bandwidth_mbps=c.bandwidth_mbps, public_ips=[c.public_block],
            device_key=c.device, interface=c.interface, state=c.state,
            provenance=_prov("carrier_portal", c.circuit_id),
        )
        for c in est.circuits
    ] if with_circuits else []
    return reconstruct(devices, interfaces, links, [], [], circuits)


def _synthetic(devices: list[tuple[str, str]], links: list[tuple],
               circuits: list[tuple[str, str, str]] = (),
               ha: dict[str, str] | None = None) -> Topology:
    """A small hand-built topology for the code paths the estate does not contain.

    devices: (key, role). links: (a, b, redundant_group, aggregated, member_count).
    circuits: (circuit_id, provider, terminating device key).
    """
    ha = ha or {}
    nets = [
        NetDevice(device_key=key, name=key, role=role, role_source="declared",
                  role_reason="fixture", ha_group=ha.get(key),
                  ha_role="primary" if ha.get(key) else None, site="hq",
                  provenance=_prov("catalyst_center", key))
        for key, role in devices
    ]
    netlinks = [
        NetLink(link_key=f"{a}~{b}", a_device=a, b_device=b, evidence="lldp",
                evidence_detail="fixture", redundant_group=group,
                aggregated=aggregated, member_count=members,
                provenance=_prov("catalyst_center", f"{a}~{b}"))
        for a, b, group, aggregated, members in links
    ]
    netcircuits = [
        Circuit(circuit_id=cid, provider=provider, technology="broadband",
                device_key=device, state="up", provenance=_prov("carrier_portal", cid))
        for cid, provider, device in circuits
    ]
    return reconstruct(nets, [], netlinks, [], [], netcircuits)


def _by_id(report) -> dict[str, object]:
    return {f.id: f for f in report.findings}


# ── The four designed single points of failure ─────────────────────────────

def test_the_router_terminating_two_circuits_is_found():
    """SPOF #1: rtr-edge-01 is the only path to CIRC-A and CIRC-C.

    Pins that the shared handoff is derived from the GRAPH, not from a handoff
    field — `models.Circuit` carries the CPE and not the router behind it, so a
    field-based rule would find nothing at all here."""
    report = assess(_estate_topology())
    finding = _by_id(report)["resilience:shared_circuit_handoff:rtr-edge-01"]

    assert finding.kind == "shared_circuit_handoff"
    assert finding.failing == ("rtr-edge-01",)
    assert finding.circuits == ("CIRC-A", "CIRC-C")
    assert "CIRC-B" in finding.detail          # what survives is part of the reason
    assert finding.blast.circuits_stranded == ("CIRC-A", "CIRC-C")
    assert finding.severity == 93
    assert finding.severity_band == "critical"


def test_two_circuits_from_one_carrier_are_found():
    """SPOF #2, the most valuable finding in the set: CIRC-A and CIRC-C are
    diverse in every visible way — two technologies, two CPE, two lines on the
    diagram — and both ride Carrier-A.

    Also pins that CIRC-B (Carrier-B) is not swept into the group: a finding
    that lumps in the one genuinely diverse circuit is worse than no finding."""
    report = assess(_estate_topology())
    finding = _by_id(report)["resilience:shared_carrier:Carrier-A"]

    assert finding.kind == "shared_carrier"
    assert finding.circuits == ("CIRC-A", "CIRC-C")
    assert "CIRC-B" not in finding.circuits
    assert finding.devices == ("mdm-isdn-01", "mdm-mpls-01")
    assert finding.vector["S"] == DOMAIN_SHARED_CARRIER
    assert finding.severity == 90
    assert finding.severity_band == "critical"


def test_the_single_homed_access_switch_is_found():
    """SPOF #3: asw-acc-03 has one uplink where asw-acc-01 and asw-acc-02 have two.

    The detail must name the peer it could have homed to, because "this is
    single-homed" is an observation and "csw-core-02 is right there" is the
    remediation."""
    report = assess(_estate_topology())
    finding = _by_id(report)["resilience:single_homed_device:asw-acc-03"]

    assert finding.kind == "single_homed_device"
    assert finding.devices == ("asw-acc-03", "csw-core-01")
    assert finding.failing == ("csw-core-01",)
    assert "csw-core-02" in finding.detail
    # Losing its one parent takes asw-acc-03 off the network entirely.
    assert finding.blast.devices_isolated == ("asw-acc-03",)
    assert finding.severity == 7
    assert finding.severity_band == "low"


def test_the_ap_behind_one_access_switch_is_found():
    """SPOF #4: ap-wifi-01 hangs off asw-acc-01 alone, which makes asw-acc-01 an
    articulation point for it."""
    report = assess(_estate_topology())
    finding = _by_id(report)["resilience:single_homed_device:ap-wifi-01"]

    assert finding.failing == ("asw-acc-01",)
    assert finding.blast.devices_isolated == ("ap-wifi-01",)
    assert finding.severity == 5


def test_the_estate_yields_exactly_these_findings():
    """The whole point, pinned as a set: four designed SPOFs plus the one honest
    extra (rtr-edge-02 strands CIRC-B), and nothing else.

    This is the test that fails when somebody makes the analyzer "more
    thorough": every additional finding on this estate is a false positive, and
    fourteen findings would bury the four that matter."""
    report = assess(_estate_topology())
    assert [f.id for f in report.findings] == [
        "resilience:shared_circuit_handoff:rtr-edge-01",   # 93
        "resilience:shared_carrier:Carrier-A",             # 90
        "resilience:articulation_point:rtr-edge-02",       # 36
        "resilience:single_homed_device:asw-acc-03",       # 7
        "resilience:single_homed_device:ap-wifi-01",       # 5
    ]
    assert [f.severity for f in report.findings] == [93, 90, 36, 7, 5]


# ── The false positives that matter more ───────────────────────────────────

def test_the_criss_crossed_devices_are_never_the_failing_element():
    """Everything the estate cables properly must be invisible to this analyzer.

    Either edge router reaches either firewall, either firewall reaches either
    core, asw-acc-01/02 are dual-homed: none of those devices can be the failing
    element of any finding, and none of them is a cut vertex."""
    report = assess(_estate_topology())
    failing = {key for f in report.findings for key in f.failing}
    for key in ("fw-perim-01", "fw-perim-02", "csw-core-02", "asw-acc-02"):
        assert key not in failing, f"{key} is criss-crossed and must not be reported"


def test_the_criss_crossed_links_are_never_reported_as_fragile():
    """No link in a redundant group — and not the core LAG either — may appear in
    a finding. This is the regression that a naive `nx.bridges` over the link
    graph would fail, and it is why `_live_sibling` runs before anything is
    emitted."""
    report = assess(_estate_topology())
    reported = {key for f in report.findings for key in f.links}
    crossed = {ln.link_key for ln in _estate_topology().links
               if ln.redundant_group in ("edge-perimeter", "perimeter-core",
                                         "core-peer", "uplink-asw-acc-01",
                                         "uplink-asw-acc-02")}
    assert crossed, "fixture no longer contains the criss-cross"
    assert not (reported & crossed)
    assert not any(f.kind == "fragile_link" for f in report.findings)


def test_the_wan_handoff_modems_are_suppressed_with_their_reason():
    """The three CPE each have exactly one uplink, and none of them is a finding.

    Not because modems are special: because each uplink sits in the `wan-handoff`
    redundant group with a live sibling landing on a different router, so the
    purpose the link serves survives. The residual — that two of those siblings
    land on the SAME router — is reported by `shared_circuit_handoff`, once.

    Asserted on the published reason rather than on absence, so a crash that
    returned nothing could not pass this test."""
    report = assess(_estate_topology())
    suppressed = {s["candidate"]: s for s in report.suppressed
                  if s["kind"] == "single_homed_device"}

    assert set(suppressed) == {"mdm-mpls-01", "mdm-bb-01", "mdm-isdn-01"}
    for entry in suppressed.values():
        assert entry["reason"] == "redundant group has a live sibling"
        assert "wan-handoff" in entry["detail"]


def test_the_properly_cabled_ha_pair_is_not_a_finding():
    """fw-perim-01/02 are an HA pair, both at site hq, same model, same firmware
    — and none of that is a finding.

    Matched firmware is REQUIRED by every vendor across a cluster, and a shared
    site distinguishes nothing in a single-site estate. What would be a finding
    is a third device whose loss defeats both members, and the criss-cross means
    there isn't one."""
    report = assess(_estate_topology())
    assert not any(f.kind == "ha_shared_failure_domain" for f in report.findings)
    entry = next(s for s in report.suppressed if s["kind"] == "ha_shared_failure_domain")
    assert entry["candidate"] == "perim-ha"
    assert "only site" in entry["detail"]
    assert "firmware" in entry["detail"]


def test_the_management_vlan_cannot_fake_redundancy():
    """The regression that decides whether this analyzer works at all — now
    fixed one layer UPSTREAM, with this guard kept as the second line.

    Every device holds a management address in 10.255.0.0/24. The original
    `reconstruct._containment_links` linked every pair sharing a block, turning
    that one out-of-band /24 into a near-complete mesh. A mesh has no
    articulation points and no bridges, so this analyzer came back clean on a
    network with four designed single points of failure.

    This analyzer defended itself by refusing those adjacencies
    (`shared_segment_not_a_path`). That was right, and it was not enough: the
    fabricated links were still persisted to `topology_links`, still drawn on the
    canvas and still counted in the inventory — the analyzer only protected the
    analyzer. So `reconstruct` now emits a containment link ONLY when a block has
    exactly two devices in it; three or more is a broadcast domain, which the
    VLAN and subnet layers already model.

    The estate therefore reaches this analyzer with no mesh to refuse, and the
    assertion is that the SURVIVING graph is the cabled one. The exclusion rule
    is exercised directly in
    `test_a_shared_segment_adjacency_is_refused_even_if_one_reaches_here`, which
    is the right level for a defence-in-depth guard: synthetically, not by
    depending on an upstream bug to supply its input.
    """
    topology = _estate_topology()
    report = assess(topology)

    mgmt = [ln for ln in topology.links
            if ln.evidence == "containment" and "10.255.0.0/24" in ln.evidence_detail]
    assert mgmt == [], "the management /24 is a broadcast domain, not 60 cables"
    assert report.adjacency_count == 18
    assert report.findings, "the mesh swallowed every single point of failure"


def test_a_shared_segment_adjacency_is_refused_even_if_one_reaches_here():
    """Defence in depth, tested at its own level.

    `reconstruct` no longer emits these, but this analyzer must not start
    trusting that. A future source could declare a shared-segment adjacency
    outright, and counting a broadcast domain as a bundle of point-to-point
    cables is how every single point of failure in the estate disappears.
    """
    topology = _estate_topology()
    victim = topology.devices[0].device_key
    others = [d.device_key for d in topology.devices[1:6]]
    topology.links.extend(
        NetLink(link_key=f"mesh:{victim}~{o}", a_device=victim, b_device=o,
                evidence="containment",
                evidence_detail=f"{victim} and {o} both hold addresses in 10.255.0.0/24",
                provenance=topology.devices[0].provenance)
        for o in others
    )

    report = assess(topology)

    excluded = [x for x in report.excluded_adjacencies
                if x["reason"] == "shared_segment_not_a_path"]
    assert len(excluded) == len(others)
    assert all("10.255.0.0/24" in x["detail"] for x in excluded)
    assert report.adjacency_count == 18


# ── Blast radius ───────────────────────────────────────────────────────────

def test_blast_radius_is_exact_and_ranks_the_edge_router_above_the_access_switch():
    """"Lose this device" has to be answered exactly, not sampled.

    rtr-edge-01 takes two of three circuits with it and costs 24 of the 36
    device-to-circuit paths the other twelve devices had. asw-acc-03 is a leaf:
    losing it costs nobody anything, which is precisely why the finding about it
    is filed against csw-core-01 and scores low."""
    report = assess(_estate_topology())
    blast = {b.device_key: b for b in report.blast_radius}
    assert report.blast_basis == BLAST_BASIS_CIRCUIT
    assert len(blast) == 13

    edge, access = blast["rtr-edge-01"], blast["asw-acc-03"]
    assert edge.paths_lost > access.paths_lost

    assert (edge.paths_lost, edge.paths_before, edge.fraction) == (24, 36, 0.6667)
    assert edge.circuits_stranded == ("CIRC-A", "CIRC-C")
    assert edge.components_after == 3
    # Nothing goes fully dark: the criss-cross to rtr-edge-02 holds, and saying
    # otherwise would overstate the outage.
    assert edge.devices_isolated == ()
    assert edge.devices_degraded == 12

    assert (access.paths_lost, access.paths_before, access.fraction) == (0, 36, 0.0)
    assert access.devices_isolated == ()
    assert access.circuits_stranded == ()

    # The device the finding is actually filed against.
    core = blast["csw-core-01"]
    assert (core.paths_lost, core.fraction) == (3, 0.0833)
    assert core.devices_isolated == ("asw-acc-03",)


def test_severity_is_reproducible_by_hand_from_the_published_vector():
    """The property the whole vector exists for: a client takes R, L and S off a
    finding and recomputes the severity with a calculator. R is rounded before it
    is multiplied so that the published numbers reproduce the published score
    exactly rather than to within a rounding error."""
    for finding in assess(_estate_topology()).findings:
        vector = finding.vector
        expected = round(100 * min(vector["R"] * vector["L"] * vector["S"], 1.0))
        assert finding.severity == expected, finding.id
        assert finding.severity_band == band(finding.severity)
        assert vector["R"] == finding.blast.fraction
        assert vector["L"] in set(LAYER_WEIGHT.values()) | {1.0}


def test_the_handoff_and_carrier_multipliers_are_the_published_constants():
    """The two multipliers that carry the argument, pinned so a tuning pass has
    to be a deliberate edit of a documented constant rather than a magic number
    drifting inside a scoring function."""
    findings = _by_id(assess(_estate_topology()))
    assert findings["resilience:shared_circuit_handoff:rtr-edge-01"].vector["S"] \
        == DOMAIN_SHARED_HANDOFF
    assert findings["resilience:shared_carrier:Carrier-A"].vector["S"] \
        == DOMAIN_SHARED_CARRIER
    # Carrier prices above handoff: it is the failure the diagram cannot show.
    assert DOMAIN_SHARED_CARRIER > DOMAIN_SHARED_HANDOFF


# ── Honesty: empty is not clean ────────────────────────────────────────────

def test_an_unobserved_estate_is_not_a_clean_bill_of_health():
    """A device no console reported cannot be a single point of failure, and an
    empty snapshot is not a resilient network.

    `analyze()` returns [] as documented — and the report that comes with it
    refuses to let that read as "no single points of failure"."""
    empty = Topology()
    assert analyze(empty) == []

    report = assess(empty)
    assert report.findings == ()
    assert report.analysable is False
    assert report.clean is False
    assert report.not_analysable_reasons
    summary = report.summary()
    assert "NOT analysed" in summary
    assert "no single point of failure" not in summary.lower()


def test_devices_with_no_observed_adjacency_are_not_read_as_resilient():
    """The subtler half of the same defect: thirteen devices and no cable between
    them yields no cut vertex and a zero blast radius everywhere, which renders
    as a perfect network. It means we cannot see a single link."""
    report = assess(_synthetic([("a", "router"), ("b", "l3_switch")], []))

    assert report.analysable is False
    assert report.clean is False
    assert report.findings == ()
    assert any("UNAVAILABLE" in reason for reason in report.not_analysable_reasons)


def test_a_clean_estate_says_what_it_observed():
    """The opposite case must be distinguishable: a genuinely criss-crossed
    topology reports clean, and the sentence it prints is still scoped to what
    was observed rather than to the estate."""
    report = assess(_synthetic(
        [("r1", "router"), ("r2", "router"), ("s1", "l3_switch"), ("s2", "l3_switch")],
        [("r1", "s1", "mesh", False, 1), ("r1", "s2", "mesh", False, 1),
         ("r2", "s1", "mesh", False, 1), ("r2", "s2", "mesh", False, 1)],
        circuits=[("CIRC-1", "Carrier-A", "r1"), ("CIRC-2", "Carrier-B", "r2")],
    ))
    assert report.analysable is True
    assert report.findings == ()
    assert report.clean is True
    assert "No single point of failure" in report.summary()
    assert "observed" in report.summary()


def test_a_topology_without_circuits_publishes_the_weaker_basis():
    """With no circuit in the snapshot there is no "path to the internet" to
    count, so blast radius falls back to loss of contact with the body of the
    estate. That is a different question, so the report says which one it
    answered instead of quietly substituting it."""
    report = assess(_estate_topology(with_circuits=False))

    assert report.blast_basis == BLAST_BASIS_CONNECTIVITY
    assert any("different questions" in c for c in report.caveats)
    assert all(f.blast.circuits_stranded == () for f in report.findings)
    # The structural findings survive; the circuit-shaped ones cannot be made.
    assert not any(f.kind in ("shared_circuit_handoff", "shared_carrier")
                   for f in report.findings)
    assert "resilience:single_homed_device:asw-acc-03" in _by_id(report)


def test_a_circuit_with_no_provider_is_never_grouped_with_another():
    """"Unknown" is not a carrier. Two circuits whose provider the source did not
    report are not known to share one, and a finding saying they do would be
    invented — so the unverifiable diversity is stated as a caveat instead."""
    report = assess(_synthetic(
        [("m1", "modem"), ("m2", "modem"), ("r1", "router")],
        [("m1", "r1", None, False, 1), ("m2", "r1", None, False, 1)],
        circuits=[("CIRC-1", "", "m1"), ("CIRC-2", "", "m2")],
    ))
    assert not any(f.kind == "shared_carrier" for f in report.findings)
    assert any("CANNOT be confirmed" in c for c in report.caveats)


# ── The code paths this estate does not contain ────────────────────────────

def test_a_single_cable_between_two_halves_is_reported():
    """Neither end is single-homed and neither is a leaf — the cable itself is
    the single point of failure, which is the one shape `single_homed_device`
    cannot express."""
    report = assess(_synthetic(
        [("a1", "l2_switch"), ("a2", "l2_switch"), ("a3", "modem"),
         ("b1", "l2_switch"), ("b2", "l2_switch"), ("b3", "l2_switch")],
        [("a1", "a2", None, False, 1), ("a2", "a3", None, False, 1),
         ("a3", "a1", None, False, 1), ("b1", "b2", None, False, 1),
         ("b2", "b3", None, False, 1), ("b3", "b1", None, False, 1),
         ("a1", "b1", None, False, 1)],
        circuits=[("CIRC-1", "Carrier-A", "a3")],
    ))
    finding = _by_id(report)["resilience:fragile_link:a1~b1"]
    assert finding.kind == "fragile_link"
    assert finding.links == ("a1~b1",)
    assert sorted(finding.blast.devices_isolated) == ["b1", "b2", "b3"]


def test_an_aggregate_is_not_a_single_cable():
    """The same shape, joined by a two-member LAG: losing one member does not
    lose the adjacency, so it is not a fragile cable — and the member count that
    justifies not reporting it is published."""
    report = assess(_synthetic(
        [("a1", "l2_switch"), ("a2", "l2_switch"), ("a3", "modem"),
         ("b1", "l2_switch"), ("b2", "l2_switch"), ("b3", "l2_switch")],
        [("a1", "a2", None, False, 1), ("a2", "a3", None, False, 1),
         ("a3", "a1", None, False, 1), ("b1", "b2", None, False, 1),
         ("b2", "b3", None, False, 1), ("b3", "b1", None, False, 1),
         ("a1", "b1", None, True, 2)],
        circuits=[("CIRC-1", "Carrier-A", "a3")],
    ))
    assert not any(f.kind == "fragile_link" for f in report.findings)
    entry = next(s for s in report.suppressed if s["kind"] == "fragile_link")
    assert entry["candidate"] == "a1~b1"
    assert entry["reason"] == "adjacency carried by more than one member"
    assert "2 members" in entry["detail"]


def test_a_host_with_one_uplink_is_not_a_finding():
    """A server with a single NIC is the design, not a defect.

    This estate has no endpoints, so nothing here would catch it — and an
    analyzer that files a finding against every host in a real estate has filed
    nothing. The reason is published rather than applied silently."""
    report = assess(_synthetic(
        [("m1", "modem"), ("r1", "router"), ("sw1", "l3_switch"), ("host1", "server")],
        [("m1", "r1", None, False, 1), ("r1", "sw1", None, False, 1),
         ("sw1", "host1", None, False, 1)],
        circuits=[("CIRC-1", "Carrier-A", "m1")],
    ))
    assert "resilience:single_homed_device:host1" not in _by_id(report)
    entry = next(s for s in report.suppressed if s["candidate"] == "host1")
    assert entry["reason"] == "endpoint with one uplink"


def test_an_ha_pair_behind_one_switch_is_reported():
    """The HA finding worth having: the cluster fails over exactly as designed,
    and has nothing to fail over to, because one device's loss cuts both members
    off from every circuit.

    Two circuits on two CPE deliberately, so the only device that defeats the
    pair is the shared upstream — an estate with one circuit would make its
    single modem defeat every HA pair in it, which is a finding about the
    circuit, not about the cluster."""
    report = assess(_synthetic(
        [("m1", "modem"), ("m2", "modem"), ("sw1", "l3_switch"),
         ("fw1", "firewall"), ("fw2", "firewall")],
        [("m1", "sw1", None, False, 1), ("m2", "sw1", None, False, 1),
         ("sw1", "fw1", None, False, 1), ("sw1", "fw2", None, False, 1)],
        circuits=[("CIRC-1", "Carrier-A", "m1"), ("CIRC-2", "Carrier-B", "m2")],
        ha={"fw1": "pair-ha", "fw2": "pair-ha"},
    ))
    finding = _by_id(report)["resilience:ha_shared_failure_domain:pair-ha"]
    assert finding.failing == ("sw1",)
    assert set(finding.devices) == {"fw1", "fw2", "sw1"}
    assert "nothing to fail over to" in finding.detail
    # The pair is scored on what losing sw1 costs, not on losing both members.
    assert finding.blast.device_key == "sw1"
    assert sorted(finding.blast.devices_isolated) == ["fw1", "fw2"]


# ── Determinism ────────────────────────────────────────────────────────────

def test_two_runs_over_one_estate_are_byte_identical():
    """Everything in this system hangs off a content hash, so an analyzer whose
    output depends on set iteration order would make two identical snapshots
    disagree about themselves."""
    first, second = assess(_estate_topology()), assess(_estate_topology())
    assert first == second
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert first.suppressed == second.suppressed
