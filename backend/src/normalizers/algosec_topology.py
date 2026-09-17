"""AlgoSec's topology endpoints -> the canonical infrastructure models.

The split from `normalizers/algosec.py`
---------------------------------------
That module owns this console's POLICY side and nothing here touches it. This
one emits infrastructure ONLY -- no PolicyRecord, no ObservedEntity, no
ResolvedObject -- so ingesting the topology side cannot move a finding, a path or
the golden snapshot by one byte. The two halves come from one console and are
deliberately not one module: an estate can onboard AlgoSec for policy and never
turn the topology collection on, and the failure of one must not look like the
failure of the other.

What survives normalization, and what cannot
--------------------------------------------
  devices          from `/api/v1/devices`, with role DECLARED -- AlgoSec states
                   outright whether a managed box is a firewall or a router, and
                   that statement is the entire reason `role_source="declared"`
                   exists as a value distinct from "derived".
  interfaces       from `/api/v1/interfaces`: addressing, and `networks_behind`
                   from AlgoSec's "IPs behind interface", which is what lets an
                   AlgoSec-only estate place a firewall relative to segments
                   carried by devices AlgoSec cannot see.
  links            from `/api/v1/interfaces/routingInformation`, and ONLY where a
                   route's next hop resolves to an interface address in this same
                   export. See below.
  routes           are not stored. The canonical model has no route row, so a
                   route survives only as the evidence behind a link and as the
                   behind-ness already carried on the interface. That is a
                   modelling limit, written down here so a reader does not read
                   it as a parsing gap.

`vlan_id` stays None on every interface this module emits, and no Vlan or Subnet
row is produced, because AlgoSec is blind to VLAN membership (`sources.py`
says so in `blind_to`). Minting a Subnet out of a "network behind" would fill the
segment lane from a console that cannot see a segment -- the picture would look
more complete and would be less true.

Why most next hops resolve to nothing, and why that is correct
--------------------------------------------------------------
Two thirds of the routes in this export point at core switches AlgoSec does not
manage. Those gateways resolve to no interface here, so no link is drawn for
them: a line to a device nobody observed is exactly the claim `LinkEvidence`
refuses to carry (it has no "inferred" member and must never grow one). The
router->firewall next hops DO resolve, and those four links are emitted with
evidence "routing" and the route quoted in `evidence_detail`. The missing
adjacency is reported honestly one layer up, by `reconstruct` naming the core
lane unobserved with the console that would fill it.

Failure is never silence
------------------------
A missing endpoint key is a COLLECTION FAILURE and raises `NormalizeError`
naming the path; an endpoint present and empty is an OBSERVATION and yields no
rows. An export where `/api/v1/devices` never came back would otherwise ingest
cleanly as "AlgoSec manages nothing", which reads to an operator as a fact about
their network rather than about our collector.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from ..connectors.algosec_topology import (
    BEHIND_KEY, DEVICES_PATH, INTERFACES_PATH, ROUTING_PATH, TOOL, ZONES_PATH,
)
from ..models import DeviceRole, NetDevice, NetInterface, NetLink, Provenance
from ..sources import tier_of
from .common import NormalizeResult
from .profile import NormalizeError

# Every endpoint this normalizer reads. All four must be PRESENT; any of them may
# be empty.
REQUIRED_PATHS: tuple[str, ...] = (DEVICES_PATH, INTERFACES_PATH, ROUTING_PATH, ZONES_PATH)

# The role vocabulary we can honour, taken from the model's own Literal so the
# two cannot drift. "unknown" is excluded deliberately: it is the ABSENCE of a
# declaration, and a source that hands it to us has declared nothing.
_DECLARABLE_ROLES: frozenset[str] = frozenset(DeviceRole.__args__) - {"unknown"}


def _checked(raw: dict) -> dict:
    """The export, checked call by call, or a failure naming the missing path."""
    if not isinstance(raw, dict):
        raise NormalizeError(
            f"{TOOL}: export must be an object keyed by API path "
            f"({', '.join(REQUIRED_PATHS)}), got {type(raw).__name__}")
    for path in REQUIRED_PATHS:
        if path not in raw:
            raise NormalizeError(
                f"{TOOL}: `{path}` is absent from the export. A collection that did "
                f"not return this endpoint is a failure, not an empty estate; an "
                f"endpoint that returned nothing must be present and empty")
        if not isinstance(raw[path], list):
            raise NormalizeError(
                f"{TOOL}: `{path}` must be a list, got {type(raw[path]).__name__}")
    return raw


def _provenance(raw_ref: str) -> Provenance:
    # The tier comes from the registry, never from the export: `sources.py`
    # exists because five copies of that list drifted, and a payload that could
    # name its own rung would be a sixth.
    #
    # `simulated` is True because this module's input is a projection of the
    # demo estate. It is hardcoded rather than read from the payload on purpose:
    # a real AlgoSec response has no field that says "I am fabricated", so an
    # export that claimed otherwise could only be lying, and the direction that
    # matters is the one this constant forecloses -- fabricated facts rendering
    # as real on a client-facing screen. A live connector will set it from the
    # `sources.config.mode` the persistence layer already writes.
    return Provenance(source_tool=TOOL, source_tier=tier_of(TOOL),
                      raw_ref=raw_ref, simulated=True)


def _text(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _address(ip: object, netmask: object, *, where: str) -> Optional[str]:
    """AlgoSec's ip + dotted netmask -> one canonical CIDR on the interface.

    An interface with no ip is an interface AlgoSec reported without an address,
    which is a fact. A malformed one is not: it raises rather than being dropped,
    because an interface that silently loses its address stops participating in
    every containment link the reconstruction engine would have drawn from it,
    and the picture just quietly has fewer edges.
    """
    host = _text(ip)
    if host is None:
        return None
    mask = _text(netmask)
    token = f"{host}/{mask}" if mask else host
    try:
        return str(ipaddress.ip_interface(token))
    except ValueError as exc:
        raise NormalizeError(
            f"{TOOL}: {where}: cannot read address {token!r} ({exc})") from exc


def _cidr(value: object, *, where: str) -> str:
    try:
        return str(ipaddress.ip_network(str(value).strip(), strict=False))
    except ValueError as exc:
        raise NormalizeError(
            f"{TOOL}: {where}: cannot read network {value!r} ({exc})") from exc


def _sort_key(cidr: str) -> tuple[int, int, int]:
    net = ipaddress.ip_network(cidr, strict=False)
    return (net.version, int(net.network_address), net.prefixlen)


def _devices(rows: list) -> list[NetDevice]:
    out: list[NetDevice] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise NormalizeError(f"{TOOL}: {DEVICES_PATH} #{index + 1} is not an object")
        key = _text(row.get("id")) or _text(row.get("name"))
        if key is None:
            raise NormalizeError(
                f"{TOOL}: {DEVICES_PATH} #{index + 1} has neither `id` nor `name`; "
                f"a device with no identifier cannot be traced back to the console")
        declared = (_text(row.get("type")) or "").lower()
        # A type we do not model -- a Check Point management server, an SDN
        # controller -- leaves the role unknown so `reconstruct` can derive it
        # from what the box terminates. Mapping it to the nearest member we do
        # model would be us guessing while the row said "declared by AlgoSec".
        known = declared in _DECLARABLE_ROLES
        out.append(NetDevice(
            device_key=key,
            name=_text(row.get("name")) or key,
            role=declared if known else "unknown",
            role_source="declared" if known else "unknown",
            role_reason=f"AlgoSec reports device type '{declared}'" if known else "",
            vendor=_text(row.get("vendor")),
            model=_text(row.get("model")),
            os_version=_text(row.get("version")),
            # AlgoSec's device list does not carry a serial. Left None rather
            # than filled from anywhere else: not reported is not the same fact
            # as not present.
            mgmt_ip=_text(row.get("managementIp")),
            provenance=_provenance(key),
        ))
    return sorted(out, key=lambda d: d.device_key)


def _zone_of_interface(rows: list) -> dict[str, str]:
    """interfaceId -> zone name, from `/api/v1/deviceZones`.

    The zone endpoint is the authority on membership; `/interfaces` repeats the
    zone per interface and the two are merged with the zone endpoint winning,
    because a zone whose member list disagrees with an interface's own label is
    a real AlgoSec condition (an interface moved between zones since the last
    device analysis) and the membership list is the one an operator's policy is
    written against.
    """
    zones: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        for zone in row.get("zones") or []:
            name = _text(zone.get("zoneName"))
            if name is None:
                continue
            for member in zone.get("interfaces") or []:
                member_id = _text(member)
                if member_id is not None:
                    zones[member_id] = name
    return zones


def _interfaces(rows: list, zone_of: dict[str, str]) -> list[NetInterface]:
    out: list[NetInterface] = []
    for row in rows:
        if not isinstance(row, dict):
            raise NormalizeError(f"{TOOL}: {INTERFACES_PATH} row is not an object")
        device = _text(row.get("deviceId"))
        if device is None:
            raise NormalizeError(f"{TOOL}: {INTERFACES_PATH} row has no `deviceId`")
        for entry in row.get("interfaces") or []:
            name = _text(entry.get("hwName"))
            if name is None:
                raise NormalizeError(
                    f"{TOOL}: {INTERFACES_PATH}: {device} has an interface with no "
                    f"`hwName`")
            raw_ref = _text(entry.get("interfaceId")) or f"{device}:{name}"
            where = f"{INTERFACES_PATH} {raw_ref}"
            address = _address(entry.get("ip"), entry.get("netmask"), where=where)
            behind = sorted(
                {_cidr(net, where=f"{where} {BEHIND_KEY}")
                 for net in entry.get(BEHIND_KEY) or []},
                key=_sort_key,
            )
            logical = _text(entry.get("logicalName"))
            out.append(NetInterface(
                interface_key=f"{device}:{name}",
                device_key=device,
                name=name,
                # The operator-visible alias, where the platform has one. Carried
                # as the description because it is the only human label AlgoSec
                # returns for an interface, and dropping it would lose the one
                # string an operator would recognise on their own console.
                description=logical if logical and logical != name else None,
                addresses=[address] if address else [],
                networks_behind=behind,
                zone=_text(zone_of.get(raw_ref)) or _text(entry.get("zone")),
                # `vlan_id`, `admin_up` and `oper_up` are deliberately not set.
                # AlgoSec's interface record carries none of them, and None here
                # means NOT REPORTED: "the source did not say" is a different
                # fact from "the port is down", and a diagram that greys out
                # every unreported port invents an outage across the perimeter.
                provenance=_provenance(raw_ref),
            ))
    return sorted(out, key=lambda i: i.interface_key)


def _routing_links(rows: list, interfaces: list[NetInterface]) -> list[NetLink]:
    """Links for the next hops that RESOLVE, and nothing for the ones that do not.

    "Resolves" means the gateway is the address of an interface in this same
    export. A gateway that merely falls inside some interface's block is not
    routing evidence -- it says the two are on one subnet, which is exactly the
    weaker `containment` claim `reconstruct` derives itself and labels as such.
    Calling that "routing" would dress an address-block coincidence up as a
    next-hop observation.
    """
    by_address: dict[str, list[NetInterface]] = {}
    for iface in interfaces:
        for addr in iface.addresses:
            by_address.setdefault(str(ipaddress.ip_interface(addr).ip), []).append(iface)

    seen: set[tuple[str, str]] = set()
    out: list[NetLink] = []
    for row in rows:
        if not isinstance(row, dict):
            raise NormalizeError(f"{TOOL}: {ROUTING_PATH} row is not an object")
        device = _text(row.get("deviceId"))
        if device is None:
            raise NormalizeError(f"{TOOL}: {ROUTING_PATH} row has no `deviceId`")
        for route in row.get("routes") or []:
            gateway = _text(route.get("gatewayIp"))
            if gateway is None:
                continue
            # Nothing claims this gateway, or SEVERAL do. Neither is a defect
            # and neither is a link: the first is the core switch AlgoSec does
            # not manage, the second is a real condition (overlapping VRFs, a
            # duplicated management address, a stale export) in which we cannot
            # say which box the next hop is -- and picking one would draw a cable
            # to whichever interface happened to sort first.
            claimants = by_address.get(gateway) or []
            if len(claimants) != 1:
                continue
            hop = claimants[0]
            # A connected route: the gateway is this device's own address.
            if hop.device_key == device:
                continue
            source = _text(route.get("sourceInterface"))
            source_key = f"{device}:{source}" if source else device
            pair = (source_key, hop.interface_key)
            if pair in seen:
                continue
            seen.add(pair)
            dest = _text(route.get("dest"))
            mask = _text(route.get("mask"))
            out.append(NetLink(
                link_key=f"routing:{source_key}~{hop.interface_key}",
                a_device=device, a_interface=source_key,
                b_device=hop.device_key, b_interface=hop.interface_key,
                evidence="routing",
                evidence_detail=(
                    f"{device} routes {dest}/{mask} via {gateway} out {source}; "
                    f"{gateway} is the address of {hop.interface_key}"
                ),
                provenance=_provenance(source_key),
            ))
    return sorted(out, key=lambda l: l.link_key)


def normalize(raw: dict) -> NormalizeResult:
    """One AlgoSec topology export -> infrastructure rows. No policy, ever."""
    endpoints = _checked(raw)
    interfaces = _interfaces(endpoints[INTERFACES_PATH],
                             _zone_of_interface(endpoints[ZONES_PATH]))
    return NormalizeResult(
        devices=_devices(endpoints[DEVICES_PATH]),
        interfaces=interfaces,
        links=_routing_links(endpoints[ROUTING_PATH], interfaces),
    )
