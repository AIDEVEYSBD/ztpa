"""The canonical demo estate — one truth, projected into each vendor's view.

Why this module exists rather than six hand-written JSON files
-------------------------------------------------------------
The product's whole claim is that it assembles one picture from consoles that
each see a different slice. Demonstrating that needs those slices to be slices
OF SOMETHING — six independently authored export files would drift within a week
and the "partial onboarding" story would quietly become six unrelated networks
drawn on one canvas.

So the estate is defined once, here, and each vendor export is a PROJECTION of
it: AlgoSec sees the enforcement points and their interfaces; Catalyst Center
sees the Cisco switching fabric and its CDP neighbours; FortiManager sees its own
two firewalls in depth; the carrier portal sees circuits and the CPE terminating
them; Wiz sees the cloud and nothing on the floor. No projection may emit a fact
this module does not contain, and none of them sees all of it — which is the
point being demonstrated.

It also makes the scale dataset honest: `build(scale=N)` grows the same estate
rather than generating a differently-shaped one, so a timing number measured on
it describes the real algorithm on a real topology.

⚠ THIS IS FABRICATED DATA, AND EVERY SURFACE THAT RENDERS IT MUST SAY SO.
   `Provenance.simulated` is True on every fact this module produces. It is a
   plausible mid-size retail estate, not any real client's network, and the
   addresses are all from RFC 5737 / RFC 1918 documentation ranges.

How it relates to the existing policy demo
------------------------------------------
The VLAN subnets deliberately CONTAIN the assets the policy engine already
knows: VLAN 30 is 10.30.0.0/16 (app-server-07/08/09), VLAN 50 is 10.50.0.0/24
(db-prod-01, rds-prod-customers). That is what lets the topology screen answer
"where does this finding live" — the flagship cross-tool path terminates on a
host that now has a VLAN, a subnet, an access switch and a floor.

Device management addresses sit in 10.255.0.0/24, which no existing asset uses
and which carries no declared scope. That is deliberate and load-bearing: the
identity layer therefore withholds any merge between a device and an existing
asset as `unscoped_ip` rather than fusing them, so adding this estate cannot
move the five-hop cross-tool path or the 35-finding baseline.

The single points of failure below are DESIGNED IN, because they are what the
resilience analyzer exists to find and what the reviewer asked about three
separate ways:

  1. rtr-edge-01 terminates BOTH the MPLS and the ISDN circuits. Lose it and two
     of three internet paths go with it.
  2. CIRC-A (MPLS) and CIRC-C (ISDN) are both Carrier-A. Diverse links, one
     carrier: a correlated failure dressed as redundancy.
  3. asw-acc-03 is single-homed to csw-core-01. Every other access switch is
     criss-crossed to both cores.

`ap-wifi-01` is NOT a fourth one, and this docstring used to say it was. It is
the COVERAGE gap, not a resilience finding: Meraki inventories the AP and reports
no neighbour table, and Catalyst Center will not describe a cable to a device it
does not manage, so the AP arrives with no observed adjacency at all and lands in
`Topology.unlinked_devices` rather than in the resilience report (verified: the
assessed estate reports six findings and none of them names it). The cable below
is real in this module and is deliberately projected by nobody — a fixture fact
the product refuses to state is the sharpest demonstration in the set, and a
docstring naming a finding the code does not produce is the same class of error
as a screen that does.

THE SECOND ESTATE
-----------------
`build_resilient()` is the same site built properly, and it exists so the
product's greens can be EARNED rather than asserted: every designed weakness
above has a named counterpart there that removes it. It is a different network,
not a filtered view of this one, and the two never sit on disk at once — a
scenario switch writes all ten exports (see `src/scenarios.py`).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DeviceSpec:
    key: str
    name: str
    role: str
    vendor: str
    model: str
    os_version: str
    mgmt_ip: str
    site: str = "hq"
    ha_group: str | None = None
    ha_role: str | None = None
    serial: str = ""
    # Which onboarded consoles can see this device at all. THE central fact of
    # the partial-onboarding story: a device no source sees is invisible, and a
    # device only an aggregator sees is known second-hand.
    seen_by: tuple[str, ...] = ()


@dataclass(frozen=True)
class IfaceSpec:
    device: str
    name: str
    addresses: tuple[str, ...] = ()
    vlan_id: int | None = None
    zone: str | None = None
    description: str = ""
    lag_group: str | None = None
    speed_mbps: int | None = None
    admin_up: bool | None = None
    # LLDP/CDP neighbour, when a device-tier or console-tier source read one.
    neighbor_device: str | None = None
    neighbor_interface: str | None = None


@dataclass(frozen=True)
class VlanSpec:
    vlan_id: int
    name: str
    subnet: str
    gateway: str
    # Which devices carry it. The L3 ones hold the SVI; the L2 ones just trunk it.
    on_devices: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class CircuitSpec:
    circuit_id: str
    provider: str
    technology: str
    bandwidth_mbps: int
    public_block: str
    device: str                       # the CPE terminating it
    interface: str
    state: str = "up"
    # The router the CPE hands off to. Two circuits sharing one is SPOF #1.
    handoff_device: str = ""
    handoff_interface: str = ""

    # A PROTECTED (dual-handoff) service is one entry PER LEG, sharing a
    # circuit_id. That is not a trick to get two links out of one circuit: the
    # carrier portal extract is a row-per-handoff CSV off a service order, and a
    # protected Ethernet service is sold and documented as one circuit delivered
    # on two handoff ports. Both halves of the product already handle it
    # correctly and independently -- `normalizers.carrier` keys its links on
    # (cpe port, peer, peer port) so both legs survive, and `merge_circuits` keys
    # on circuit_id so the two rows collapse back into ONE circuit. The estate
    # therefore states the second leg the same way the order does, rather than
    # through a field no console reports.


@dataclass(frozen=True)
class LinkSpec:
    a_device: str
    a_interface: str
    b_device: str
    b_interface: str
    # Alternate paths for one purpose — the criss-cross. Read by the resilience
    # analyzer, which must not report a bridge that has a live sibling.
    redundant_group: str | None = None
    aggregated: bool = False
    member_count: int = 1
    transit: str = ""                 # the /30 both ends sit in, when routed


@dataclass
class Estate:
    devices: list[DeviceSpec] = field(default_factory=list)
    interfaces: list[IfaceSpec] = field(default_factory=list)
    vlans: list[VlanSpec] = field(default_factory=list)
    circuits: list[CircuitSpec] = field(default_factory=list)
    links: list[LinkSpec] = field(default_factory=list)

    #: Lazily-built device -> interfaces index. Not a micro-optimisation: five
    #: connectors call `interfaces_of` once per device, so the linear scan this
    #: replaces made projection O(devices x interfaces). Measured with
    #: `bench_topology.py`: 1.6 ms at 13 devices and 592 ms at 1,013 -- a 78x
    #: estate costing 370x the time, which is the signature of an accidental
    #: quadratic and would have been 15 s at 5,000 devices.
    _iface_index: dict[str, list[IfaceSpec]] | None = field(default=None, repr=False,
                                                            compare=False)

    def devices_seen_by(self, tool: str) -> list[DeviceSpec]:
        return [d for d in self.devices if tool in d.seen_by]

    def interfaces_of(self, device: str) -> list[IfaceSpec]:
        if self._iface_index is None:
            index: dict[str, list[IfaceSpec]] = {}
            for iface in self.interfaces:
                index.setdefault(iface.device, []).append(iface)
            self._iface_index = index
        return self._iface_index.get(device, [])


# ── The estate ─────────────────────────────────────────────────────────────

# Management plane. No existing asset uses this range and it carries no declared
# scope, so the identity layer withholds rather than fuses (see module docstring).
MGMT = "10.255.0.0/24"

_DEVICES = [
    # --- CPE, seen only by the carrier's portal. The modem lane is exactly the
    #     lane an estate with no carrier onboarding cannot draw, which is why it
    #     is sourced from a device-tier portal and nothing else.
    DeviceSpec("mdm-mpls-01", "mdm-mpls-01", "modem", "Carrier-A", "CPE-2200", "4.1.2",
               "10.255.0.2", seen_by=("carrier_portal",)),
    DeviceSpec("mdm-bb-01", "mdm-bb-01", "modem", "Carrier-B", "FiberCPE-900", "2.8.0",
               "10.255.0.3", seen_by=("carrier_portal",)),
    DeviceSpec("mdm-isdn-01", "mdm-isdn-01", "modem", "Carrier-A", "BRI-128", "1.4.7",
               "10.255.0.4", seen_by=("carrier_portal",)),

    # --- Edge routers. Different make and model, as asked: one Cisco, one
    #     Juniper, each visible only to its own vendor's console plus AlgoSec.
    DeviceSpec("rtr-edge-01", "rtr-edge-01", "router", "Cisco", "ISR4331", "IOS-XE 17.9.4",
               "10.255.0.11", serial="FDO24120ABC",
               seen_by=("catalyst_center", "algosec")),
    DeviceSpec("rtr-edge-02", "rtr-edge-02", "router", "Juniper", "MX204", "Junos 21.4R3-S4",
               "10.255.0.12", serial="JN12F8A2B",
               seen_by=("junos_space", "algosec")),

    # --- Perimeter firewall HA pair.
    DeviceSpec("fw-perim-01", "fw-perim-01", "firewall", "Fortinet", "FortiGate-200F",
               "FortiOS 7.4.3", "10.255.0.21", ha_group="perim-ha", ha_role="primary",
               serial="FG200F1234567890",
               seen_by=("fortimanager", "fortigate", "algosec")),
    DeviceSpec("fw-perim-02", "fw-perim-02", "firewall", "Fortinet", "FortiGate-200F",
               "FortiOS 7.4.3", "10.255.0.22", ha_group="perim-ha", ha_role="secondary",
               serial="FG200F0987654321",
               seen_by=("fortimanager", "fortigate", "algosec")),

    # --- Core. Two L3 switches, criss-crossed, sharing every SVI via FHRP.
    DeviceSpec("csw-core-01", "csw-core-01", "l3_switch", "Cisco", "C9300-48P",
               "IOS-XE 17.9.4", "10.255.0.31", serial="FCW2310L0A1",
               seen_by=("catalyst_center",)),
    DeviceSpec("csw-core-02", "csw-core-02", "l3_switch", "Cisco", "C9300-48P",
               "IOS-XE 17.9.4", "10.255.0.32", serial="FCW2310L0A2",
               seen_by=("catalyst_center",)),

    # --- Access. asw-acc-03 is deliberately single-homed (SPOF #3).
    DeviceSpec("asw-acc-01", "asw-acc-01", "l2_switch", "Cisco", "C9200-24T",
               "IOS-XE 17.9.4", "10.255.0.41", seen_by=("catalyst_center",)),
    DeviceSpec("asw-acc-02", "asw-acc-02", "l2_switch", "Cisco", "C9200-24T",
               "IOS-XE 17.9.4", "10.255.0.42", seen_by=("catalyst_center",)),
    DeviceSpec("asw-acc-03", "asw-acc-03", "l2_switch", "Cisco", "C9200-24T",
               "IOS-XE 17.9.4", "10.255.0.43", seen_by=("catalyst_center",)),

    # --- Wireless, behind asw-acc-01 alone (SPOF #4).
    DeviceSpec("ap-wifi-01", "ap-wifi-01", "wireless_ap", "Cisco Meraki", "MR46",
               "29.7.1", "10.255.0.51", seen_by=("meraki",)),
]

# VLAN subnets deliberately contain the assets the policy engine already knows,
# so a finding can be located on the picture.
_VLANS = [
    VlanSpec(10, "mgmt", MGMT, "10.255.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-01", "asw-acc-02", "asw-acc-03"),
             ("mgmt",)),
    VlanSpec(20, "dmz", "10.20.0.0/24", "10.20.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-01"), ("dmz",)),
    VlanSpec(30, "app-tier", "10.30.0.0/16", "10.30.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-01", "asw-acc-02"), ("prod",)),
    VlanSpec(40, "internal-app", "10.40.0.0/16", "10.40.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-02"), ("prod", "internal-app")),
    # The data-service segment. It exists so the SECOND cross-tool path is
    # drawable end to end: `data-node-01` (10.45.0.9) is path B's pivot, and
    # without a VLAN containing it the path's middle hop would be a host floating
    # in the endpoint lane with no floor under it. Carried by asw-acc-02, the
    # same access switch as VLAN 40 and 50 -- which is what the estate actually
    # looks like when the app, data and database tiers share a rack.
    VlanSpec(45, "data-svc", "10.45.0.0/24", "10.45.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-02"), ("prod", "data-svc")),
    # 10.50.0.0/24 contains db-prod-01 (.10), rds-prod-customers (.20) AND
    # db-prod-02 (.30), so BOTH paths terminate somewhere on the canvas.
    VlanSpec(50, "db-tier", "10.50.0.0/24", "10.50.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-02"), ("pci", "customer-data", "prod")),
    VlanSpec(60, "dev", "10.31.0.0/24", "10.31.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-03"), ("dev",)),
    VlanSpec(70, "users", "10.60.0.0/24", "10.60.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-03"), ("users",)),
]

# RFC 5737 documentation ranges throughout.
_CIRCUITS = [
    CircuitSpec("CIRC-A", "Carrier-A", "mpls", 200, "203.0.113.0/29",
                "mdm-mpls-01", "wan", handoff_device="rtr-edge-01", handoff_interface="Gi0/0/0"),
    CircuitSpec("CIRC-B", "Carrier-B", "broadband", 500, "198.51.100.0/29",
                "mdm-bb-01", "wan", handoff_device="rtr-edge-02", handoff_interface="ge-0/0/0"),
    # SPOF #2: same carrier as CIRC-A. SPOF #1: same handoff router as CIRC-A.
    CircuitSpec("CIRC-C", "Carrier-A", "isdn", 1, "203.0.113.8/29",
                "mdm-isdn-01", "wan", state="standby",
                handoff_device="rtr-edge-01", handoff_interface="Gi0/0/2"),
]


def _build_links() -> list[LinkSpec]:
    """The cabling. Criss-cross everywhere except where a SPOF is intended."""
    links: list[LinkSpec] = []

    # CPE -> edge. Both Carrier-A circuits land on rtr-edge-01 (SPOF #1).
    for c in _CIRCUITS:
        links.append(LinkSpec(c.device, "lan", c.handoff_device, c.handoff_interface,
                              redundant_group="wan-handoff",
                              transit=f"10.254.0.{4 * _CIRCUITS.index(c)}/30"))

    # Edge routers -> firewall pair. Full criss-cross: either router reaches
    # either firewall, which is what "you don't want to go down because of one
    # edge router failing" looks like when it is done properly.
    for ri, rtr in enumerate(("rtr-edge-01", "rtr-edge-02")):
        for fi, fw in enumerate(("fw-perim-01", "fw-perim-02")):
            n = ri * 2 + fi
            links.append(LinkSpec(rtr, f"edge-fw-{fi + 1}", fw, f"port{ri + 1}",
                                  redundant_group="edge-perimeter",
                                  transit=f"10.254.1.{4 * n}/30"))

    # Firewall pair -> core pair. Criss-cross again.
    for fi, fw in enumerate(("fw-perim-01", "fw-perim-02")):
        for ci, csw in enumerate(("csw-core-01", "csw-core-02")):
            n = fi * 2 + ci
            links.append(LinkSpec(fw, f"port{ci + 3}", csw, f"Te1/1/{fi + 1}",
                                  redundant_group="perimeter-core",
                                  transit=f"10.254.2.{4 * n}/30"))

    # Core peer link: a 2-member aggregate, so losing one member is survivable
    # and the analyzer must not call it a bridge.
    links.append(LinkSpec("csw-core-01", "Po1", "csw-core-02", "Po1",
                          aggregated=True, member_count=2, redundant_group="core-peer"))

    # Core -> access. asw-acc-01 and -02 are dual-homed; asw-acc-03 is not
    # (SPOF #3), which is the one the picture should make obvious at a glance.
    for asw, cores in (("asw-acc-01", ("csw-core-01", "csw-core-02")),
                       ("asw-acc-02", ("csw-core-01", "csw-core-02")),
                       ("asw-acc-03", ("csw-core-01",))):
        for ci, csw in enumerate(cores):
            links.append(LinkSpec(csw, f"Gi1/0/{asw[-1]}", asw, f"Gi1/0/{48 - ci}",
                                  redundant_group=f"uplink-{asw}" if len(cores) > 1 else None))

    # The AP hangs off one access switch (SPOF #4).
    links.append(LinkSpec("asw-acc-01", "Gi1/0/24", "ap-wifi-01", "wired0"))
    return links


def _build_interfaces(links: list[LinkSpec] | None = None,
                      vlans: list[VlanSpec] | None = None,
                      devices: list[DeviceSpec] | None = None,
                      circuits: list[CircuitSpec] | None = None) -> list[IfaceSpec]:
    """Every port, SVI and WAN interface, derived from the links and VLANs.

    Derived rather than listed so an interface cannot exist without a cable or a
    VLAN behind it -- the same discipline the reconstruction engine applies to
    the output, applied to the fixture that feeds it.

    `circuits` is a parameter rather than the module global it used to read. The
    WAN loop below closed over `_CIRCUITS`, so building ANY estate with a
    different circuit set raised `KeyError: 'mdm-isdn-01'` -- the flagship's CPE,
    reached through a caller that had never heard of it. A fixture module that
    cannot express a second estate is a fixture module that guarantees the
    scenario switch stays broken, which is the defect this whole change is about.
    """
    links = _build_links() if links is None else links
    vlans = _VLANS if vlans is None else vlans
    devices = _DEVICES if devices is None else devices
    circuits = _CIRCUITS if circuits is None else circuits
    ifaces: list[IfaceSpec] = []
    by_device: dict[str, set[str]] = {}

    # Management interface on everything.
    for d in devices:
        ifaces.append(IfaceSpec(d.key, "mgmt", (f"{d.mgmt_ip}/24",), vlan_id=10,
                                description="out-of-band management", admin_up=True))
        by_device.setdefault(d.key, set()).add("mgmt")

    # WAN side of each modem: the public block the carrier assigned.
    for c in circuits:
        # Guarded because a PROTECTED service is one entry per handoff leg (see
        # `CircuitSpec`), and both legs are the same physical WAN port. Emitting
        # it twice would put a duplicate interface in the export, which the
        # normalizer would dedup silently -- and a fixture that relies on a
        # downstream dedup is a fixture that is wrong and looks right.
        if c.interface in by_device.setdefault(c.device, set()):
            continue
        by_device[c.device].add(c.interface)
        ifaces.append(IfaceSpec(c.device, c.interface, (c.public_block,),
                                zone="untrust",
                                description=f"{c.provider} {c.technology.upper()} {c.circuit_id}",
                                speed_mbps=c.bandwidth_mbps, admin_up=c.state != "down"))

    # Both ends of every cable, addressed when the link is routed.
    for ln in links:
        a_addr = b_addr = ()
        if ln.transit:
            net = ln.transit.split("/")[0].rsplit(".", 1)
            a_addr = (f"{net[0]}.{int(net[1]) + 1}/30",)
            b_addr = (f"{net[0]}.{int(net[1]) + 2}/30",)
        for dev, name, addr, peer, peer_if in (
            (ln.a_device, ln.a_interface, a_addr, ln.b_device, ln.b_interface),
            (ln.b_device, ln.b_interface, b_addr, ln.a_device, ln.a_interface),
        ):
            if name in by_device.setdefault(dev, set()):
                continue
            by_device[dev].add(name)
            ifaces.append(IfaceSpec(
                dev, name, addr,
                lag_group="Po1" if ln.aggregated else None,
                speed_mbps=10000 if name.startswith(("Te", "Po")) else 1000,
                admin_up=True, neighbor_device=peer, neighbor_interface=peer_if,
                description=f"to {peer} {peer_if}",
            ))

    # SVIs on the L3 switches; trunk membership on the L2 ones. This is the
    # distinction the whole "unless this switch is L3, you can't do routes" ask
    # turns on, and it is the signal the reconstruction engine reads to tell a
    # core switch from an access switch without looking at either one's name.
    l3 = {d.key for d in devices if d.role in ("l3_switch", "router")}
    for v in vlans:
        for dev in v.on_devices:
            if dev in l3:
                ifaces.append(IfaceSpec(dev, f"Vlan{v.vlan_id}", (f"{v.gateway}/24",),
                                        vlan_id=v.vlan_id, admin_up=True,
                                        description=f"SVI {v.name}"))
            else:
                ifaces.append(IfaceSpec(dev, f"Vlan{v.vlan_id}", (), vlan_id=v.vlan_id,
                                        admin_up=True,
                                        description=f"trunked {v.name} (no L3)"))
    return ifaces


def _branch(n: int) -> tuple[list[DeviceSpec], list[VlanSpec], list[LinkSpec]]:
    """One branch site: a router, two access switches, an AP, and its own VLAN.

    Shaped like the HQ rather than like filler, because the point of the scale
    dataset is to answer "how long does this take on a real network" and a
    thousand disconnected nodes would answer a different question. Each branch
    dual-homes its router to BOTH core switches, so the graph stays 2-connected
    and the resilience analyzer has to do real work rather than finding a
    thousand trivial bridges.

    Addresses come from 10.128.0.0/9, which no HQ VLAN uses, so growing the
    estate cannot collide with the assets the policy engine already knows.
    """
    base = 128 + (n // 250)
    third = n % 250
    rtr = f"br{n:04d}-rtr-01"
    devices = [
        DeviceSpec(rtr, rtr, "router", "Cisco", "ISR1111", "IOS-XE 17.9.4",
                   f"10.255.{1 + n // 250}.{third}", site=f"branch-{n:04d}",
                   seen_by=("catalyst_center",)),
    ]
    links = [
        LinkSpec(core, f"Gi1/1/{n % 48}", rtr, f"Gi0/0/{i}",
                 redundant_group=f"uplink-{rtr}")
        for i, core in enumerate(("csw-core-01", "csw-core-02"))
    ]
    for sw in (1, 2):
        key = f"br{n:04d}-asw-{sw:02d}"
        devices.append(DeviceSpec(
            key, key, "l2_switch", "Cisco", "C9200-24T", "IOS-XE 17.9.4",
            f"10.255.{1 + n // 250}.{third}", site=f"branch-{n:04d}",
            seen_by=("catalyst_center",)))
        links.append(LinkSpec(rtr, f"Gi0/1/{sw}", key, "Gi1/0/48"))
    ap = f"br{n:04d}-ap-01"
    devices.append(DeviceSpec(ap, ap, "wireless_ap", "Cisco Meraki", "MR46", "29.7.1",
                              f"10.255.{1 + n // 250}.{third}",
                              site=f"branch-{n:04d}", seen_by=("meraki",)))
    links.append(LinkSpec(f"br{n:04d}-asw-01", "Gi1/0/24", ap, "wired0"))

    vlan_id = 100 + (n % 3800)
    # BOTH access switches carry the branch VLAN. With the VLAN on `asw-01`
    # only, `asw-02` reached the reconstruction engine with a single addressed
    # interface and no forwarding state, so `_derive_role` correctly called it a
    # SERVER and drew it in the endpoint lane: at 250 branches that is 250 Cisco
    # C9200s sitting among the workstations. The engine was right and the fixture
    # was starving it -- an access switch trunks the site's VLAN on both members
    # of an access pair, which is the whole reason there are two of them.
    vlans = [VlanSpec(vlan_id, f"branch-{n:04d}", f"10.{base}.{third}.0/24",
                      f"10.{base}.{third}.1",
                      (rtr, f"br{n:04d}-asw-01", f"br{n:04d}-asw-02"), ("branch",))]
    return devices, vlans, links


def _assemble(devices: list[DeviceSpec], vlans: list[VlanSpec],
              circuits: list[CircuitSpec], links: list[LinkSpec]) -> Estate:
    """The one place an Estate is constructed.

    Every builder goes through here so a variant estate cannot acquire a second
    code path: interfaces are DERIVED from the links, VLANs and circuits handed
    in, so a grown estate and a hand-built one get them on identical terms. The
    grown estate used to be assembled by a branch of `build()` and the base one
    by another, which is precisely the drift this module exists to prevent.
    """
    return Estate(devices=devices,
                  interfaces=_build_interfaces(links, vlans, devices, circuits),
                  vlans=vlans, circuits=circuits, links=links)


def build(branches: int = 0) -> Estate:
    """The flagship estate. Deterministic: no clock, no randomness, stable ordering.

    `branches` grows it by that many branch sites, each the same shape as the
    HQ's access layer and each dual-homed to the core pair. Use it to measure
    what the engine actually costs on a network of a given size -- see
    `backend/scripts/bench_topology.py`.
    """
    devices = list(_DEVICES)
    vlans = list(_VLANS)
    links = _build_links()
    for n in range(branches):
        d, v, l = _branch(n)
        devices.extend(d)
        vlans.extend(v)
        links.extend(l)
    return _assemble(devices, vlans, list(_CIRCUITS), links)


# ── The resilient estate ───────────────────────────────────────────────────
#
# THE CONTROL CASE. `demo` proves the analyzers find what is there; this proves
# they do not invent what is not, which is the harder and less popular half. Its
# whole job is to come back with NOTHING on both graphs -- so every weakness
# designed into the estate above has a named counterpart here that removes it,
# and each one is listed beside the finding it exists to kill:
#
#   demo                                    resilient
#   ------------------------------------    ------------------------------------
#   CIRC-A and CIRC-C are both Carrier-A    one circuit per carrier, so no
#     -> shared_carrier, 90/critical          provider group has two members
#   both land on rtr-edge-01                 each circuit is PROTECTED: one
#     -> shared_circuit_handoff, 93/crit      service, two handoff legs, one to
#                                             each edge router, so no device
#                                             stands between the estate and two
#   three CPE are leaves                     every CPE has two adjacencies, so
#     -> 3x single_homed_device               none is single-homed and neither
#                                             edge router is a cut vertex
#   asw-acc-03 is single-homed               both access switches are
#     -> single_homed_device                  criss-crossed to both cores
#   ap-wifi-01 has no observed cable         no wireless: nothing is inventoried
#     -> unlinked_devices                     that no console can cable
#
# What it does NOT do is fake the absence. It keeps the HA pair (which produces a
# published SUPPRESSION naming why it was considered and declined), it keeps the
# two-member core aggregate (which the analyzer must not call a bridge), and it
# still reports the endpoint lane as unobserved, because no console in it
# enumerates a workstation. A product that prints an unqualified all-clear is the
# one you cannot trust when it prints red.

_RESILIENT_DEVICES = [
    # --- CPE. One per carrier, each terminating a PROTECTED service: the order
    #     sells one circuit on two handoff ports, so neither CPE is a leaf.
    DeviceSpec("mdm-fib-a-01", "mdm-fib-a-01", "modem", "Carrier-A", "FiberCPE-900",
               "3.2.1", "10.255.0.2", seen_by=("carrier_portal",)),
    DeviceSpec("mdm-fib-b-01", "mdm-fib-b-01", "modem", "Carrier-B", "FiberCPE-900",
               "2.8.0", "10.255.0.3", seen_by=("carrier_portal",)),

    # --- Edge. Still two vendors: a clean estate is not a homogeneous one, and
    #     the multi-vendor merge has to keep working on the scenario that has
    #     nothing else going on.
    DeviceSpec("rtr-edge-01", "rtr-edge-01", "router", "Cisco", "ISR4331", "IOS-XE 17.9.4",
               "10.255.0.11", serial="FDO24120ABC",
               seen_by=("catalyst_center", "algosec")),
    DeviceSpec("rtr-edge-02", "rtr-edge-02", "router", "Juniper", "MX204", "Junos 21.4R3-S4",
               "10.255.0.12", serial="JN12F8A2B",
               seen_by=("junos_space", "algosec")),

    # --- Perimeter HA pair, criss-crossed to both routers and both cores. Kept
    #     deliberately: `_ha_findings` examines it, finds no device whose loss
    #     defeats both members, and PUBLISHES that as a suppression. A clean
    #     report that shows its working is worth more than an empty one.
    DeviceSpec("fw-perim-01", "fw-perim-01", "firewall", "Fortinet", "FortiGate-200F",
               "FortiOS 7.4.6", "10.255.0.21", ha_group="perim-ha", ha_role="primary",
               serial="FG200F1234567890",
               seen_by=("fortimanager", "fortigate", "algosec")),
    DeviceSpec("fw-perim-02", "fw-perim-02", "firewall", "Fortinet", "FortiGate-200F",
               "FortiOS 7.4.6", "10.255.0.22", ha_group="perim-ha", ha_role="secondary",
               serial="FG200F0987654321",
               seen_by=("fortimanager", "fortigate", "algosec")),

    # --- Core pair on a two-member aggregate.
    DeviceSpec("csw-core-01", "csw-core-01", "l3_switch", "Cisco", "C9300-48P",
               "IOS-XE 17.9.4", "10.255.0.31", serial="FCW2310L0A1",
               seen_by=("catalyst_center",)),
    DeviceSpec("csw-core-02", "csw-core-02", "l3_switch", "Cisco", "C9300-48P",
               "IOS-XE 17.9.4", "10.255.0.32", serial="FCW2310L0A2",
               seen_by=("catalyst_center",)),

    # --- Access. BOTH dual-homed -- the one-line difference from asw-acc-03.
    DeviceSpec("asw-acc-01", "asw-acc-01", "l2_switch", "Cisco", "C9200-24T",
               "IOS-XE 17.9.4", "10.255.0.41", seen_by=("catalyst_center",)),
    DeviceSpec("asw-acc-02", "asw-acc-02", "l2_switch", "Cisco", "C9200-24T",
               "IOS-XE 17.9.4", "10.255.0.42", seen_by=("catalyst_center",)),
]

# Every VLAN is carried by BOTH access switches, so no segment has a sole
# access-layer carrier. The subnets contain the clean policy fixture's assets the
# same way the flagship's do (see `scripts/seed_demo.clean_*_export`), so a
# finding -- if there were one -- would have a floor and a switch port.
_RESILIENT_VLANS = [
    VlanSpec(10, "mgmt", MGMT, "10.255.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-01", "asw-acc-02"), ("mgmt",)),
    VlanSpec(20, "dmz", "10.20.0.0/24", "10.20.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-01", "asw-acc-02"), ("dmz",)),
    VlanSpec(30, "app-tier", "10.30.0.0/16", "10.30.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-01", "asw-acc-02"), ("prod",)),
    VlanSpec(50, "db-tier", "10.50.0.0/24", "10.50.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-01", "asw-acc-02"),
             ("pci", "customer-data", "prod")),
    VlanSpec(70, "users", "10.60.0.0/24", "10.60.0.1",
             ("csw-core-01", "csw-core-02", "asw-acc-01", "asw-acc-02"), ("users",)),
]

# Two circuits, two carriers, FOUR rows: a protected service is one row per
# handoff leg (see `CircuitSpec`). The legs deliberately cross -- CIRC-P's
# primary lands on rtr-edge-01 and its protect leg on rtr-edge-02, CIRC-Q the
# other way round -- so neither router is the only path to anything.
_RESILIENT_CIRCUITS = [
    CircuitSpec("CIRC-P", "Carrier-A", "fiber", 500, "203.0.113.16/29",
                "mdm-fib-a-01", "wan",
                handoff_device="rtr-edge-01", handoff_interface="Gi0/0/0"),
    CircuitSpec("CIRC-P", "Carrier-A", "fiber", 500, "203.0.113.16/29",
                "mdm-fib-a-01", "wan",
                handoff_device="rtr-edge-02", handoff_interface="ge-0/0/0"),
    CircuitSpec("CIRC-Q", "Carrier-B", "fiber", 500, "198.51.100.16/29",
                "mdm-fib-b-01", "wan",
                handoff_device="rtr-edge-02", handoff_interface="ge-0/0/1"),
    CircuitSpec("CIRC-Q", "Carrier-B", "fiber", 500, "198.51.100.16/29",
                "mdm-fib-b-01", "wan",
                handoff_device="rtr-edge-01", handoff_interface="Gi0/0/1"),
]


def _resilient_links() -> list[LinkSpec]:
    """The cabling, criss-crossed everywhere with no exception.

    `redundant_group` is set here for the same reason it is set in
    `_build_links` -- it is what the estate means -- and it reaches the analyzer
    on NO link in either estate, because no connector emits it and no normalizer
    reads it back (measured: `NetLink.redundant_group` is None on all 18 of the
    flagship's links). That is a gap in the connector layer, not in this one, and
    this estate is built so that it does not matter: nothing here relies on a
    suppression to come back clean. Every finding is absent because the SHAPE
    removes it, which is a fact two consoles independently report.
    """
    links: list[LinkSpec] = []

    # CPE -> both edge routers. One LinkSpec per handoff leg, and the carrier's
    # own extract carries both of them -- this is the only cable in the estate
    # that no console but the carrier portal can see.
    for n, c in enumerate(_RESILIENT_CIRCUITS):
        leg = 1 + sum(1 for prev in _RESILIENT_CIRCUITS[:n] if prev.circuit_id == c.circuit_id)
        links.append(LinkSpec(c.device, f"lan{leg}", c.handoff_device, c.handoff_interface,
                              redundant_group=f"protected-handoff:{c.circuit_id}",
                              transit=f"10.254.0.{4 * n}/30"))

    # Edge -> perimeter, full criss-cross.
    for ri, rtr in enumerate(("rtr-edge-01", "rtr-edge-02")):
        for fi, fw in enumerate(("fw-perim-01", "fw-perim-02")):
            n = ri * 2 + fi
            links.append(LinkSpec(rtr, f"edge-fw-{fi + 1}", fw, f"port{ri + 1}",
                                  redundant_group="edge-perimeter",
                                  transit=f"10.254.1.{4 * n}/30"))

    # Perimeter -> core, full criss-cross.
    for fi, fw in enumerate(("fw-perim-01", "fw-perim-02")):
        for ci, csw in enumerate(("csw-core-01", "csw-core-02")):
            n = fi * 2 + ci
            links.append(LinkSpec(fw, f"port{ci + 3}", csw, f"Te1/1/{fi + 1}",
                                  redundant_group="perimeter-core",
                                  transit=f"10.254.2.{4 * n}/30"))

    # Core peer link: a 2-member aggregate. The analyzer must not call it a
    # bridge, and in this estate it is not one either way -- both cores are
    # reachable through the perimeter pair.
    links.append(LinkSpec("csw-core-01", "Po1", "csw-core-02", "Po1",
                          aggregated=True, member_count=2, redundant_group="core-peer"))

    # Core -> access. BOTH access switches to BOTH cores.
    for asw in ("asw-acc-01", "asw-acc-02"):
        for ci, csw in enumerate(("csw-core-01", "csw-core-02")):
            links.append(LinkSpec(csw, f"Gi1/0/{asw[-1]}", asw, f"Gi1/0/{48 - ci}",
                                  redundant_group=f"uplink-{asw}"))
    return links


def build_resilient() -> Estate:
    """The same site built properly. Deterministic, and measured to be clean.

    Ten devices, two carriers, two protected circuits, four adjacency-bearing
    tiers and nothing dangling. `analyzers.resilience.assess` returns
    `analysable=True` with NO findings and one published suppression -- which is
    the only version of "clean" that survives a technical evaluation, because it
    can be told apart from "we could not see the network".
    """
    return _assemble(list(_RESILIENT_DEVICES), list(_RESILIENT_VLANS),
                     list(_RESILIENT_CIRCUITS), _resilient_links())


#: Consoles that can see any of it, and what each one's view covers. Used by the
#: seed scripts to decide which projection emits which device, and by the Sources
#: screen to say what each source contributed.
COVERAGE: dict[str, str] = {
    "carrier_portal": "circuits, the CPE terminating them, and the assigned public blocks",
    "catalyst_center": "the Cisco switching fabric, its VLANs and CDP/LLDP neighbours",
    "meraki": "the wireless AP and its uplink addressing",
    "fortimanager": "the FortiGate HA pair: model, firmware, policy package, zones",
    "fortigate": "SD-WAN members, interface addressing and HA cluster state",
    "junos_space": "the Juniper edge router and its interfaces",
    "algosec": "enforcement points, their interfaces and the networks behind them",
}
