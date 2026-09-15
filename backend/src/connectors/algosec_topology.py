"""AlgoSec ASMS, projected onto the four endpoints that describe the NETWORK.

Why this is a separate module from the AlgoSec policy normalizer
---------------------------------------------------------------
One console, two products' worth of data. `/api/v1/rules` is POLICY and is
already owned by `normalizers/algosec.py`; everything here is
`/api/v1/devices`, `/api/v1/interfaces`, `/api/v1/interfaces/routingInformation`
and `/api/v1/deviceZones` -- the enforcement points themselves, their addressing,
and what each interface routes toward. Keeping the two apart means the topology
side can be onboarded (or fail) without moving a single PolicyRecord: the golden
snapshot is byte-identical with this module present and absent.

What AlgoSec can see here, and why the gaps are the point
---------------------------------------------------------
AlgoSec manages ENFORCEMENT POINTS. In this estate that is exactly four boxes --
rtr-edge-01, rtr-edge-02, fw-perim-01, fw-perim-02 -- and that is the whole of
what this export contains. There are no switches in it, no modems, no access
point, because there are none in AlgoSec. An operator whose only onboarded
source is AlgoSec has a two-lane picture, and the product's job is to say so:
`topology.reconstruct` reports the modem, core and access lanes as unobserved
with the console that would fill each, instead of drawing a plausible campus.
Softening that -- projecting a switch AlgoSec never returned so the picture looks
finished -- would be selling coverage this integration does not have.

"IPs behind interface"
----------------------
The single most valuable field a policy product exposes for reconstructing
topology, and the reason an AlgoSec-only estate is still worth drawing: it names
the networks reachable THROUGH an interface, so a firewall can be placed
relative to the segments behind it even though the devices carrying those
segments are invisible. ASMS computes it from the routing tables it collects off
the devices it manages. This projection computes the same thing from the
estate's link graph, under three rules that keep it an observation rather than a
decoration:

  * INTERIOR DIRECTION ONLY. A network is "behind" an interface when it lies
    further from the demarcation point than the device does -- the same
    position-from-the-outside measure `reconstruct._depths` uses, so the two
    layers cannot disagree about which way is out.
  * THE EXTERIOR DIRECTION IS EMPTY, NOT `0.0.0.0/0`. A WAN interface's real
    answer is whatever the default route says, and this estate declares no
    default route. A fabricated default is indistinguishable in the output from
    a collected one, which is precisely the class of fact this product exists
    not to emit.
  * A DEVICE'S OWN CONNECTED NETWORKS ARE BEHIND NOTHING. They are subtracted,
    or every criss-crossed transit would be reported as sitting behind the
    interface that runs parallel to it.

The exported segment is the VLAN's declared subnet where the far side is an SVI:
VLAN 30's SVI is `10.30.0.1/24` but the segment is `10.30.0.0/16`, and it is the
segment a route points at. Reporting the SVI's own /24 would understate the
block that the app tier -- the assets the policy engine already knows -- actually
lives in.

Zones
-----
`/api/v1/deviceZones` comes back with an entry per device and no zones in it,
because this estate declares zones only on the carrier-facing modem interfaces
and AlgoSec does not see a modem. The endpoint is exported anyway, empty, rather
than omitted: an absent key means "we never asked", an empty list means "we
asked and there are none", and a normalizer that cannot tell those apart is the
failure mode this codebase is built around.
"""

from __future__ import annotations

import ipaddress
from collections import deque
from dataclasses import dataclass

from ..estate import Estate, IfaceSpec

TOOL = "algosec"
# The rung this console speaks from. `sources.py` is the authority and the
# normalizer reads it from there, never from an export -- this constant is the
# projection's own statement of the same fact, asserted equal to the registry by
# test so a connector and the registry cannot drift the way five copies of the
# tool list once did.
TIER = "aggregator"

# Keyed BY PATH rather than by a tidy name of our own, because the key is the
# thing an operator can curl. When a row on a screen is wrong the question is
# always "which call said that", and a key spelled `devices` does not answer it.
DEVICES_PATH = "/api/v1/devices"
INTERFACES_PATH = "/api/v1/interfaces"
ROUTING_PATH = "/api/v1/interfaces/routingInformation"
ZONES_PATH = "/api/v1/deviceZones"

# AlgoSec's own label for the field, spaces and all. Renaming it to a tidy
# camelCase would cost the one thing the key is for: a reader who meets it in our
# output can find the identical string in ASMS's interface report and knows we
# reported it rather than computed it.
BEHIND_KEY = "IPs behind interface"


def _network(addr: str) -> str | None:
    """The block an interface address sits in. None when it will not parse."""
    try:
        return str(ipaddress.ip_network(addr, strict=False))
    except ValueError:
        return None


def _sort_key(cidr: str) -> tuple[int, int, int]:
    """Numeric ordering for address space, so `10.9` never sorts after `10.10`."""
    net = ipaddress.ip_network(cidr, strict=False)
    return (net.version, int(net.network_address), net.prefixlen)


@dataclass(frozen=True)
class _Fabric:
    """The estate's link graph, indexed for the one question this module asks.

    Built once per export: `interfaces_of` is a linear scan and behind-ness asks
    for it once per device per hop.
    """

    est: Estate
    adjacency: dict[str, set[str]]
    # Hops from the nearest circuit-terminating device -- the demarcation point.
    # A device absent from this map has no observed path to the outside, and is
    # therefore excluded from every behind-ness answer rather than being assumed
    # to be interior: "I could not place it" must not become "it is inside".
    demarc_depth: dict[str, int]
    vlan_subnet: dict[int, str]

    def networks_on(self, device: str) -> set[str]:
        out: set[str] = set()
        for iface in self.est.interfaces_of(device):
            out |= self._networks_of(iface)
        return out

    def _networks_of(self, iface: IfaceSpec) -> set[str]:
        out: set[str] = set()
        for addr in iface.addresses:
            # An SVI's address is a /24 into a segment that may be far larger.
            # A route points at the segment, so the VLAN's declared subnet wins
            # wherever the interface carries one.
            if iface.vlan_id is not None and iface.vlan_id in self.vlan_subnet:
                out.add(self.vlan_subnet[iface.vlan_id])
                continue
            net = _network(addr)
            if net is not None:
                out.add(net)
        return out

    def behind(self, device: str, iface: IfaceSpec) -> list[str]:
        """The networks reachable THROUGH `iface`, interior direction only."""
        peer = iface.neighbor_device
        if peer is None:
            return []
        here = self.demarc_depth.get(device)
        there = self.demarc_depth.get(peer)
        # `there <= here` is the exterior (or a lateral peer link). Not empty
        # because we found nothing -- empty because the honest answer is the
        # default route, and nobody declared one.
        if here is None or there is None or there <= here:
            return []
        seen = {device, peer}
        queue = deque([peer])
        nets: set[str] = set()
        while queue:
            cur = queue.popleft()
            nets |= self.networks_on(cur)
            for nxt in sorted(self.adjacency.get(cur, ())):
                # Walking back out through a device nearer the demarc would drag
                # the entire estate behind one interior port: the criss-crossed
                # perimeter means every box is connectable to every other if
                # direction is ignored.
                if nxt in seen or self.demarc_depth.get(nxt, -1) < there:
                    continue
                seen.add(nxt)
                queue.append(nxt)
        return sorted(nets - self.networks_on(device), key=_sort_key)

    def next_hop_ip(self, iface: IfaceSpec) -> str | None:
        """The peer interface's address -- the gateway a route would name.

        None when the far end holds no address (an unrouted access link). A next
        hop we cannot name is not a route we can state, so the caller emits no
        route at all rather than a route with a blank gateway.
        """
        if iface.neighbor_device is None or iface.neighbor_interface is None:
            return None
        for peer in self.est.interfaces_of(iface.neighbor_device):
            if peer.name != iface.neighbor_interface or not peer.addresses:
                continue
            return str(ipaddress.ip_interface(peer.addresses[0]).ip)
        return None


def _fabric(est: Estate) -> _Fabric:
    """Index the estate once: adjacency, and hops from the demarcation point.

    This walks the WHOLE estate, including devices that never reach the export,
    and that is not a cheat -- it is what the field being rendered actually is.
    AlgoSec reports the networks behind an interface WITHOUT reporting the
    devices carrying them, because it computes them from the routing tables of
    the enforcement points it manages. The estate's link graph stands in for
    those routing tables; what comes out is address space, never a device the
    export is not entitled to name.

    The depth measure is the same position-from-the-outside one
    `reconstruct._depths` computes over the observed graph, so the projection
    and the reconstruction cannot disagree about which way is out.
    """
    adjacency: dict[str, set[str]] = {d.key: set() for d in est.devices}
    for link in est.links:
        if link.a_device in adjacency and link.b_device in adjacency:
            adjacency[link.a_device].add(link.b_device)
            adjacency[link.b_device].add(link.a_device)

    seeds = sorted({c.device for c in est.circuits if c.device in adjacency})
    depth = {s: 0 for s in seeds}
    queue = deque(seeds)
    while queue:
        cur = queue.popleft()
        for nxt in sorted(adjacency[cur]):
            if nxt not in depth:
                depth[nxt] = depth[cur] + 1
                queue.append(nxt)

    return _Fabric(est=est, adjacency=adjacency, demarc_depth=depth,
                   vlan_subnet={v.vlan_id: v.subnet for v in est.vlans})


def _ip_and_netmask(device: str, iface: IfaceSpec) -> tuple[str | None, str | None]:
    """The interface's address as AlgoSec reports it: host ip + dotted netmask.

    AlgoSec's interface record carries ONE ip/netmask pair, and every interface
    in this estate holds at most one address. A second one would have to be
    dropped here, so it raises instead: a projection that cannot render its
    input faithfully has to say so, because a silently halved interface looks
    exactly like an interface that only ever had one address.
    """
    if not iface.addresses:
        return None, None
    if len(iface.addresses) > 1:
        raise ValueError(
            f"{TOOL}: {device}:{iface.name} holds {len(iface.addresses)} addresses; "
            f"AlgoSec's interface record carries one ip/netmask pair and this "
            f"projection will not silently drop the rest"
        )
    parsed = ipaddress.ip_interface(iface.addresses[0])
    return str(parsed.ip), str(parsed.netmask)


def _interface_row(fab: _Fabric, device: str, iface: IfaceSpec) -> dict:
    ip, netmask = _ip_and_netmask(device, iface)
    return {
        "interfaceId": f"{device}:{iface.name}",
        "hwName": iface.name,
        # ASMS returns both because on many platforms they differ (a FortiGate
        # port with an alias, a Check Point logical name). Nothing in this estate
        # declares an alias, and two equal names is what such a device returns --
        # inventing a distinct logical name would invent an operator's label.
        "logicalName": iface.name,
        "ip": ip,
        "netmask": netmask,
        "zone": iface.zone,
        # ASMS classifies a zone external/internal. The estate names zones and
        # never classifies them, and reading "untrust" as external is a naming
        # convention, not an observation -- so this stays null.
        "zoneType": None,
        # Empty rather than absent: this estate declares no virtual IPs anywhere,
        # which is not the same fact as a collector that did not ask for them.
        "vips": [],
        BEHIND_KEY: fab.behind(device, iface),
    }


def _route_rows(fab: _Fabric, device: str, ifaces: list[IfaceSpec]) -> list[dict]:
    """The device's routing table as ASMS returns it: dest, mask, gateway, source.

    One route per network behind an interface, which is the same derivation
    behind-ness uses -- they are two renderings of one fact and must not be able
    to disagree. An interface whose far end holds no address yields no routes at
    all rather than routes with a blank gateway.
    """
    rows: list[dict] = []
    for iface in ifaces:
        gateway = fab.next_hop_ip(iface)
        if gateway is None:
            continue
        for cidr in fab.behind(device, iface):
            net = ipaddress.ip_network(cidr, strict=False)
            rows.append({
                "dest": str(net.network_address),
                "mask": str(net.netmask),
                "gatewayIp": gateway,
                "sourceInterface": iface.name,
            })
    return sorted(rows, key=lambda r: (r["sourceInterface"],
                                       _sort_key(f"{r['dest']}/{r['mask']}")))


def _zone_rows(device: str, ifaces: list[IfaceSpec]) -> list[dict]:
    members: dict[str, list[str]] = {}
    for iface in ifaces:
        if iface.zone:
            members.setdefault(iface.zone, []).append(f"{device}:{iface.name}")
    return [{"zoneName": zone, "zoneType": None, "interfaces": sorted(members[zone])}
            for zone in sorted(members)]


def algosec_topology_export(est: Estate) -> dict:
    """Render the AlgoSec topology endpoints for the devices AlgoSec manages.

    Keyed by path, one entry per call, with each value shaped as that call's own
    response -- there is no wrapper of ours around it. A reader holding this dict
    is holding what four `curl`s would have returned.

    Deterministic: every list is sorted, nothing reads a clock, and no set is
    iterated on the way out.
    """
    fab = _fabric(est)
    devices = sorted(est.devices_seen_by(TOOL), key=lambda d: d.key)
    ifaces = {d.key: sorted(est.interfaces_of(d.key), key=lambda i: i.name)
              for d in devices}

    return {
        DEVICES_PATH: [
            {
                # ASMS keys devices by a numeric id in its URLs. Minting one here
                # would be a fabricated identifier that no operator could paste
                # back into their console, so the id is the name ASMS shows on
                # its device tree -- which IS an estate fact.
                "id": d.key,
                "name": d.name,
                "vendor": d.vendor,
                "model": d.model,
                # AlgoSec states outright whether a managed device is a firewall
                # or a router. That statement is the whole reason devices from
                # this source carry role_source="declared".
                "type": d.role,
                "version": d.os_version,
                "managementIp": d.mgmt_ip,
            }
            for d in devices
        ],
        INTERFACES_PATH: [
            {
                "deviceId": d.key,
                "interfaces": [_interface_row(fab, d.key, i) for i in ifaces[d.key]],
            }
            for d in devices
        ],
        ROUTING_PATH: [
            {
                "deviceId": d.key,
                # The endpoint repeats a thin interface list alongside the
                # routes; it is kept because it is what the API returns, and the
                # normalizer reads addressing from `/interfaces` only, so the two
                # copies cannot disagree in our output.
                "interfaces": [
                    {"interfaceId": f"{d.key}:{i.name}", "hwName": i.name,
                     "ip": _ip_and_netmask(d.key, i)[0],
                     "netmask": _ip_and_netmask(d.key, i)[1]}
                    for i in ifaces[d.key]
                ],
                "routes": _route_rows(fab, d.key, ifaces[d.key]),
            }
            for d in devices
        ],
        ZONES_PATH: [
            {"deviceId": d.key, "zones": _zone_rows(d.key, ifaces[d.key])}
            for d in devices
        ],
    }
