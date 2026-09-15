"""Reconstruct the layered network picture from observed facts.

The problem this module exists to solve
---------------------------------------
Nobody hands you a network diagram. What you get is whatever the onboarded
consoles happen to know: an AlgoSec that models the enforcement points and their
interfaces; a FortiManager that knows its own fleet's models and firmware; a
Meraki org that knows every uplink's public IP; a Wiz that knows the cloud and
nothing on the floor. Coverage is always partial and is partial in a DIFFERENT
WAY at every client — which is exactly why "we take additional console access"
is the normal case rather than the degraded one.

So the layers are **derived from the observed connections**, never from names.
`csw-core-01` is not placed in the core lane because it is called `core`; it is
placed there because it terminates SVIs for four VLANs and forwards between
them. Rename it `printer-3` and it still lands in the core lane. There is a test
that asserts precisely this, because name-matching is the failure mode that
makes a reconstruction engine look right on the demo estate and collapse on a
real one.

What every placement owes you
-----------------------------
Three fields travel with every device, and they move together:

  layer          the lane, or None
  layer_source   "declared" | "derived" | "unknown"
  layer_reason   the specific observation that put it there

`layer is None` and `layer_source == "unknown"` are the same state, enforced by a
database CHECK. A node we cannot place goes to the unplaced rail with its reason
showing — it is never quietly dropped (which hides an unknown) and never nudged
into a neighbouring lane (which invents one).

What this module will not do
----------------------------
It will not draw a link it did not observe. `LinkEvidence` has no "inferred"
member. Where no neighbour protocol was read, adjacency is derived only from
`containment` — two interfaces on different devices holding addresses inside one
block — which is a real, checkable L3 observation, is labelled as the weaker
evidence it is, and is refused when either side's block is a default route or
the whole internet (which would make every device adjacent to every other).

It will not invent a lane's contents. A layer with no observed node is reported
in `unobserved_layers` with the reason and the concrete API that would fill it,
so the UI can render a named absence. A ghost device drawn at low opacity is
still a device on screen that nobody observed.
"""

from __future__ import annotations

from collections import deque
from typing import Iterable, Optional

from ..models import (
    Circuit, LinkEvidence, NetDevice, NetInterface, NetLink, Provenance,
    Subnet, Topology, TopologyLayer, Vlan,
)
from ..netaddr import is_public, parse_net

# ── Lane assignment ────────────────────────────────────────────────────────
#
# The lane a KNOWN role belongs in. Deliberately a plain table rather than a
# computation: the published picture has to be explainable to a network engineer
# in one sentence per box, and a lookup is explainable in a way a heuristic
# score is not.
#
# `load_balancer` is absent on purpose — it sits at the perimeter or in the core
# depending on whether it holds public address space, which is a structural
# question answered in `_lane_for`, not a fact about the role.
LANE_OF_ROLE: dict[str, TopologyLayer] = {
    "modem": "modem",
    "router": "edge",
    "firewall": "perimeter",
    "l3_switch": "core",
    "l2_switch": "access",
    "hub": "access",
    "bridge": "access",
    "wireless_ap": "access",
    "server": "endpoint",
    "workstation": "endpoint",
    "virtual_appliance": "endpoint",
}

# Ordered outside-in. The index is the drawing order and the BFS's notion of
# "further in", so it is defined once, here.
LANE_ORDER: tuple[TopologyLayer, ...] = (
    "internet", "circuit", "modem", "edge", "perimeter",
    "core", "access", "segment", "endpoint",
)

# What would populate a lane we saw nothing in. Rendered verbatim next to the
# empty lane, because "not observed" is only useful to an operator if it comes
# with the thing they would have to do about it.
LANE_SOURCE_HINT: dict[TopologyLayer, str] = {
    "circuit": "Meraki `/devices/uplinks/addresses/byDevice`, FortiGate "
               "`cmdb/system/sdwan`, or the carrier's own portal",
    "modem": "the CPE's own console, or the carrier portal that provisioned it",
    "edge": "Catalyst Center `/dna/intent/api/v1/network-device`, or the "
            "router's own NETCONF/REST",
    "perimeter": "FortiManager `/dvmdb/adom/{adom}/device`, Panorama "
                 "`type=config` device tree, or FMC `/devices/devicerecords`",
    "core": "Catalyst Center `/dna/intent/api/v1/network-device` + "
            "`/topology/physical-topology`",
    "access": "Catalyst Center physical topology, Meraki "
              "`/organizations/{id}/devices`, or ISE pxGrid session data "
              "(nasIpAddress + nasPortId gives endpoint→switch→port with no "
              "switch access at all)",
    "segment": "Catalyst Center `/topology/vlan/vlan-names`, Meraki "
               "`/networks/{id}/appliance/vlans`, or FortiGate "
               "`cmdb/system/interface` VLAN subinterfaces",
    "endpoint": "Wiz `CloudResource`, Guardicore `/api/v3.0/assets`, or ISE "
                "endpoint profiling",
}

# A block so large that "these two interfaces share it" says nothing about
# adjacency. Containment links are refused across these, or a default route
# would make every device in the estate a neighbour of every other.
_CONTAINMENT_MIN_PREFIX = 8


def _iface_addr_blocks(iface: NetInterface) -> list:
    """The parsed blocks an interface holds, skipping unusable ones."""
    out = []
    for raw in iface.addresses:
        net = parse_net(raw)
        if net is None or net.prefixlen < _CONTAINMENT_MIN_PREFIX:
            continue
        out.append(net)
    return out


# ── Role derivation ────────────────────────────────────────────────────────

def _derive_role(dev: NetDevice, ifaces: list[NetInterface],
                 circuits_by_device: dict[str, list[Circuit]]) -> tuple[str, str]:
    """Work out what a box IS from what it terminates. Returns (role, reason).

    Only ever called for a device whose source declared no role. The order is
    most-specific-first, and every branch names the observation it fired on so
    the inventory row can show its working.
    """
    terminates_circuit = bool(circuits_by_device.get(dev.device_key))
    svis = [i for i in ifaces if i.vlan_id is not None and i.addresses]
    vlan_only = [i for i in ifaces if i.vlan_id is not None and not i.addresses]
    addressed = [i for i in ifaces if i.addresses]
    public = [i for i in ifaces
              for a in i.addresses
              if (n := parse_net(a)) is not None and is_public(str(n))]

    # Terminates a circuit and routes nothing behind it: customer premises
    # equipment, i.e. a modem.
    if terminates_circuit and not svis and len(addressed) <= 2:
        return "modem", (
            f"terminates circuit {circuits_by_device[dev.device_key][0].circuit_id} "
            f"and holds no routed segments"
        )
    # Terminates a circuit AND carries interior segments: an edge router.
    if terminates_circuit:
        return "router", (
            f"terminates circuit {circuits_by_device[dev.device_key][0].circuit_id} "
            f"and carries {len(addressed)} addressed interfaces"
        )
    # Holds switched virtual interfaces for more than one VLAN: it routes
    # between VLANs, which is the entire distinction the ask turns on
    # ("unless this switch is L3, you can't do routes").
    if len({i.vlan_id for i in svis}) >= 2:
        vids = sorted({i.vlan_id for i in svis if i.vlan_id is not None})
        return "l3_switch", (
            f"holds SVIs with addresses on {len(vids)} VLANs "
            f"({', '.join(str(v) for v in vids[:4])}"
            f"{'…' if len(vids) > 4 else ''}) — it forwards between them"
        )
    # Carries VLANs but holds no address on any of them: pure L2.
    if vlan_only and not svis:
        return "l2_switch", (
            f"carries {len({i.vlan_id for i in vlan_only})} VLANs and holds no "
            f"address on any of them — it switches, it does not route"
        )
    # Addressed on two or more DISTINCT blocks and carrying no VLANs: it sits
    # between subnets and forwards between them, which is what a router is. The
    # blocks have to be distinct — two interfaces in one /30 is a device with a
    # spare port, not a device with a routing table.
    blocks = {str(n) for i in addressed for n in _iface_addr_blocks(i)}
    if len(blocks) >= 2 and not svis and not vlan_only:
        shown = sorted(blocks)[:3]
        return "router", (
            f"forwards between {len(blocks)} distinct address blocks "
            f"({', '.join(shown)}{'…' if len(blocks) > 3 else ''}) and carries no VLANs"
        )
    # Holds public space without terminating a circuit: it is in front of
    # something rather than being the way out.
    if public and not terminates_circuit:
        return "load_balancer", (
            f"holds public address space ({public[0]}) without terminating a circuit"
        )
    if len(addressed) == 1 and not svis:
        return "server", "a single addressed interface and no forwarding state"
    return "unknown", "no interface pattern in this snapshot identifies what it is"


def _lane_for(dev: NetDevice, ifaces: list[NetInterface],
              depth: Optional[int]) -> tuple[Optional[TopologyLayer], str]:
    """Which lane this device draws in, and why. (lane, reason)."""
    role = dev.role
    if role == "load_balancer":
        holds_public = any(
            (n := parse_net(a)) is not None and is_public(str(n))
            for i in ifaces for a in i.addresses
        )
        if holds_public:
            return "perimeter", "load balancer holding public address space"
        return "core", "load balancer holding only interior address space"
    lane = LANE_OF_ROLE.get(role)
    if lane is not None:
        src = "declared by " + dev.provenance.source_tool if dev.role_source == "declared" \
            else dev.role_reason or "derived from its interfaces"
        return lane, f"role {role} ({src})"
    # Role genuinely unknown. Depth from the outside is the only structural
    # signal left, and it is enough to place a box between two known ones -- but
    # not enough on its own, so a device with no path to the edge stays
    # unplaced rather than being guessed into the endpoint lane.
    if depth is None:
        return None, ("no role could be derived and it has no observed path to "
                      "the network edge")
    if depth <= 1:
        return "edge", f"unidentified device {depth} hop(s) from a circuit termination"
    if depth == 2:
        return "perimeter", "unidentified device 2 hops from a circuit termination"
    if depth == 3:
        return "core", "unidentified device 3 hops from a circuit termination"
    return "access", f"unidentified device {depth} hops from a circuit termination"


# ── Containment links ──────────────────────────────────────────────────────

def _containment_links(interfaces: list[NetInterface],
                       known: set[tuple[str, str]]) -> list[NetLink]:
    """Adjacency derived from two interfaces sharing one address block.

    This is the fallback for an estate whose consoles report no neighbour
    protocol -- which is most estates, since LLDP/CDP data needs device-tier
    access. It is a REAL observation (both sides' addresses were read off their
    own interfaces and they provably sit in one block), which is why it is
    allowed at all; and it is the weakest evidence class we store, which is why
    it is labelled rather than blended in with a cable.

    Refused when the shared block is broader than a /8, and when the two
    interfaces belong to the same device.
    """
    by_block: dict[str, list[NetInterface]] = {}
    for iface in interfaces:
        for net in _iface_addr_blocks(iface):
            by_block.setdefault(str(net), []).append(iface)

    out: list[NetLink] = []
    for block in sorted(by_block):
        members = by_block[block]
        # Order-independent: sorted so the emitted link set cannot depend on
        # which normalizer ran first, which the snapshot fingerprint depends on.
        members = sorted(members, key=lambda i: i.interface_key)
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                if a.device_key == b.device_key:
                    continue
                pair = tuple(sorted((a.device_key, b.device_key)))
                if pair in known:
                    continue
                known.add(pair)
                out.append(NetLink(
                    link_key=f"contain:{pair[0]}~{pair[1]}:{block}",
                    a_device=pair[0], b_device=pair[1],
                    a_interface=a.interface_key if a.device_key == pair[0] else b.interface_key,
                    b_interface=b.interface_key if b.device_key == pair[1] else a.interface_key,
                    evidence="containment",
                    evidence_detail=(
                        f"{a.device_key}:{a.name} and {b.device_key}:{b.name} both hold "
                        f"addresses in {block}"
                    ),
                    provenance=Provenance(
                        source_tool=a.provenance.source_tool,
                        source_tier=a.provenance.source_tier,
                        raw_ref=f"{a.provenance.raw_ref}+{b.provenance.raw_ref}",
                        simulated=a.provenance.simulated or b.provenance.simulated,
                    ),
                ))
    return out


# ── Depth from the outside ─────────────────────────────────────────────────

def _depths(devices: list[NetDevice], links: list[NetLink],
            circuits: list[Circuit]) -> dict[str, int]:
    """Hop distance from the nearest circuit-terminating device.

    This is the structural backbone of the whole reconstruction: it is what makes
    the lane assignment a property of POSITION rather than of naming. Devices
    with no observed path to a circuit get no entry, and `_lane_for` refuses to
    place them.
    """
    adj: dict[str, set[str]] = {d.device_key: set() for d in devices}
    for ln in links:
        if ln.a_device in adj and ln.b_device in adj:
            adj[ln.a_device].add(ln.b_device)
            adj[ln.b_device].add(ln.a_device)

    seeds = sorted({c.device_key for c in circuits if c.device_key and c.device_key in adj})
    depth: dict[str, int] = {s: 0 for s in seeds}
    q = deque(seeds)
    while q:
        cur = q.popleft()
        for nxt in sorted(adj.get(cur, ())):
            if nxt not in depth:
                depth[nxt] = depth[cur] + 1
                q.append(nxt)
    return depth


# ── Entry point ────────────────────────────────────────────────────────────

def reconstruct(devices: Iterable[NetDevice], interfaces: Iterable[NetInterface],
                links: Iterable[NetLink], vlans: Iterable[Vlan],
                subnets: Iterable[Subnet], circuits: Iterable[Circuit]) -> Topology:
    """Assemble the layered picture from observed facts.

    Pure: no I/O, no clock, no set iteration in an output path. Every output list
    is sorted by a stable key, so two runs over the same observations produce
    byte-identical output and the snapshot fingerprint is meaningful.
    """
    devs = sorted(devices, key=lambda d: d.device_key)
    ifaces = sorted(interfaces, key=lambda i: i.interface_key)
    observed_links = sorted(links, key=lambda l: l.link_key)
    vls = sorted(vlans, key=lambda v: v.vlan_id)
    subs = sorted(subnets, key=lambda s: s.cidr)
    circs = sorted(circuits, key=lambda c: c.circuit_id)

    ifaces_by_dev: dict[str, list[NetInterface]] = {}
    for iface in ifaces:
        ifaces_by_dev.setdefault(iface.device_key, []).append(iface)
    circuits_by_dev: dict[str, list[Circuit]] = {}
    for c in circs:
        if c.device_key:
            circuits_by_dev.setdefault(c.device_key, []).append(c)

    # 1. Fill in roles nobody declared, from what each box terminates.
    for dev in devs:
        if dev.role != "unknown" and dev.role_source == "declared":
            continue
        role, reason = _derive_role(dev, ifaces_by_dev.get(dev.device_key, []), circuits_by_dev)
        dev.role = role
        dev.role_source = "derived" if role != "unknown" else "unknown"
        dev.role_reason = reason

    # 2. Add the adjacencies implied by shared address blocks, for the links no
    #    neighbour protocol reported. Observed links win: a pair already linked
    #    by LLDP is not re-linked by containment.
    known_pairs = {tuple(sorted((l.a_device, l.b_device))) for l in observed_links}
    all_links = observed_links + _containment_links(ifaces, known_pairs)
    all_links.sort(key=lambda l: l.link_key)

    # 3. Place every device by its position in that link graph.
    depth = _depths(devs, all_links, circs)
    for dev in devs:
        lane, reason = _lane_for(dev, ifaces_by_dev.get(dev.device_key, []),
                                 depth.get(dev.device_key))
        dev.layer = lane
        dev.layer_source = "derived" if lane is not None else "unknown"
        dev.layer_reason = reason

    # 4. Name the lanes we observed nothing in. A lane that is simply not drawn
    #    reads as a lane that does not exist, which is the difference between
    #    "this estate has no DMZ" and "nothing we can read knows about the DMZ".
    populated: set[str] = {d.layer for d in devs if d.layer}
    if circs:
        populated.add("circuit")
    if vls or subs:
        populated.add("segment")
    unobserved = [
        {
            "layer": lane,
            "reason": f"no onboarded source reported a device at the {lane} layer",
            "would_be_filled_by": LANE_SOURCE_HINT[lane],
        }
        for lane in LANE_ORDER
        if lane not in populated and lane in LANE_SOURCE_HINT
    ]

    return Topology(
        devices=devs, interfaces=ifaces, links=all_links,
        vlans=vls, subnets=subs, circuits=circs,
        unobserved_layers=unobserved,
    )
