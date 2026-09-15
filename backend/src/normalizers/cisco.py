"""Catalyst Center and Meraki Dashboard exports -> canonical infrastructure facts.

INFRASTRUCTURE ONLY. Neither of these consoles is a policy product: Catalyst
Center models a switching fabric and Meraki's L3 firewall rules are a different
endpoint from the three read here. So no `PolicyRecord` and no `ObservedEntity`
leaves this module, and the policy graph -- and the snapshot fingerprint over it
-- is byte-identical with and without these normalizers in the pipeline. A cable
is not a grant.

The two decisions this module exists to get right
-------------------------------------------------
1. **Catalyst Center's physical topology becomes `evidence='cdp'`.** It is the
   only adjacency in the whole registry that a neighbour protocol actually
   reported; everything else in the product reaches `topology.reconstruct` as
   addresses and comes out the other side as `containment`, which is a genuine L3
   observation but is not a cable. Getting this one right is what makes the core
   and access lanes structural rather than inferred.

2. **Catalyst Center's `role` column is not read for switches.** It is the most
   tempting field in the export and the one that would quietly destroy the
   engine's premise. The full reasoning is on `_catalyst_role`.

Where a fact is absent it stays absent. `NetInterface.admin_up` is left `None`
whenever the export did not say -- never `False` -- because "the console did not
report this port's state" and "this port is shut" are different facts and only
one of them is an outage.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from ..connectors.cisco import (
    DNA_GLOBAL_POOL,
    CATALYST_TOOL, DNA_DEVICES, DNA_INTERFACES, DNA_PHYSICAL_TOPOLOGY,
    DNA_VLAN_NAMES, MERAKI_APPLIANCE_VLANS, MERAKI_DEVICES, MERAKI_TOOL,
    MERAKI_UPLINK_ADDRESSES,
)
from ..models import NetDevice, NetInterface, NetLink, Provenance, Subnet, Vlan
from ..sources import tier_of
from .common import NormalizeResult
from .profile import NormalizeError

# Catalyst Center manages Cisco hardware and nothing else; the Dashboard manages
# Meraki hardware and nothing else. The vendor is therefore a property of the
# CONSOLE, not a column either export returns -- the one thing a single-vendor
# manager can state about every device in it without having observed anything.
_CATALYST_VENDOR = "Cisco"
_MERAKI_VENDOR = "Cisco Meraki"

# `family` is what the platform reports itself as. Only the entries below are
# specific enough to name a role; "Wireless Controller", "Unified AP" and the
# rest are left for `topology.reconstruct` to derive, because a role asserted
# here is a role the engine will not re-derive.
_ROLE_OF_FAMILY: dict[str, str] = {
    "Routers": "router",
}

# Meraki's `productType` is the SKU family, derived from the model number: also a
# hardware fact. `"switch"` is deliberately ABSENT for the same reason Catalyst
# Center's `role` is ignored below -- it says the box is an MS, which is true,
# but `DeviceRole` makes us choose between `l2_switch` and `l3_switch` and the
# product type does not know which. The engine decides that from the SVIs.
_ROLE_OF_PRODUCT_TYPE: dict[str, str] = {
    "wireless": "wireless_ap",
    "appliance": "firewall",
    "cellularGateway": "modem",
}


def _prov(tool: str, raw_ref: str) -> Provenance:
    """Provenance for one row.

    `source_tier` is read from the source registry rather than spelled here: the
    registry docstring exists because that list previously lived in five places
    that had no way to disagree loudly, and a sixth copy in a normalizer would be
    the one nobody thinks to check.

    `simulated` is True at the point of creation, not patched in downstream.
    These exports are projections of `estate.py`, which is fabricated by
    construction, and a screen that has to print "simulated" next to a fact
    cannot depend on somebody remembering to set the flag three layers later.
    """
    return Provenance(source_tool=tool, source_tier=tier_of(tool),
                      raw_ref=raw_ref, simulated=True)


# ── Reading the export without inventing one ───────────────────────────────

def _endpoint(raw: object, path: str, tool: str) -> Any:
    """One endpoint's payload, or a refusal that names the endpoint.

    THE LINE THAT KEEPS "NOTHING THERE" APART FROM "WE COULD NOT LOOK". A key
    that is present and empty is a console with nothing in it -- a Meraki org
    with no MX genuinely has no appliance VLANs, and that is an answer. A key
    that is MISSING is an export we did not manage to read, and answering it with
    `.get(path, [])` would report that estate as having no VLANs, no interfaces
    or no devices with nothing anywhere to say otherwise.
    """
    if not isinstance(raw, dict):
        raise NormalizeError(
            f"{tool}: export must be an object keyed by endpoint path, got "
            f"{type(raw).__name__}")
    if path not in raw:
        raise NormalizeError(
            f"{tool}: export carries no `{path}` key. An endpoint that was not "
            f"read is not an endpoint that returned nothing, and this normalizer "
            f"will not report one as the other")
    return raw[path]


def _dna_response(raw: object, path: str) -> Any:
    """Unwrap Catalyst Center's `{"response": ...}` envelope.

    Every Intent API payload carries it. A payload without it is not an Intent
    API payload -- most often it is a Meraki export handed to the wrong
    normalizer -- and `.get("response", [])` would turn that mistake into a
    Catalyst Center with no devices in it.
    """
    payload = _endpoint(raw, path, CATALYST_TOOL)
    if not isinstance(payload, dict) or "response" not in payload:
        raise NormalizeError(
            f"{CATALYST_TOOL} {path}: payload is not wrapped in the Intent API's "
            f"`response` envelope (got {type(payload).__name__})")
    return payload["response"]


def _rows(value: object, *, tool: str, what: str) -> list:
    """A payload that must be a list of rows."""
    if isinstance(value, list):
        return value
    raise NormalizeError(
        f"{tool}: {what} must be a list, got {type(value).__name__}")


def _require(row: dict, field: str, *, tool: str, where: str) -> Any:
    """A field the canonical row cannot be built without."""
    value = row.get(field)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise NormalizeError(f"{tool} {where}: missing required field {field!r}")
    return value


def _text(value: object) -> Optional[str]:
    """An optional string column. Blank and absent are the same fact: not reported.

    Everything a console leaves empty arrives here as `""`, `"  "` or `None`
    depending on the platform version, and all three have to land on `None` --
    an empty-string serial or model renders on screen as a field somebody filled
    in with nothing, which reads as an observation rather than as a gap.
    """
    if value is None:
        return None
    text = str(value).strip()
    return text or None


# ── Catalyst Center ────────────────────────────────────────────────────────

def _catalyst_role(family: Optional[str]) -> tuple[str, str, str]:
    """What the inventory row licenses us to say this box IS. (role, source, reason)

    `family` is read. It is what the PLATFORM reports itself as -- a hardware
    fact, the same class of fact as the model number -- so a device in the
    "Routers" family is a router whether or not anybody has ever looked at it.
    That is a `declared` role and the engine will not second-guess it.

    `role` -- the column holding CORE / DISTRIBUTION / ACCESS / BORDER ROUTER --
    IS DELIBERATELY NOT READ FOR SWITCHES, AND THAT IS THE SUBTLEST DECISION IN
    THIS MODULE.

    Catalyst Center's `role` is an OPERATOR-ASSIGNED LABEL. The platform guesses
    it once at discovery and anyone with write access changes it from a dropdown
    thereafter; it records what somebody intended a box to be, not anything the
    box was observed doing. This product's entire reconstruction premise is that
    lanes come from STRUCTURE: `reconstruct._derive_role` calls a switch an
    `l3_switch` because it holds addressed SVIs on two or more VLANs and
    therefore forwards between them, and an `l2_switch` because it carries VLANs
    and holds an address on none of them.

    Mapping `role="CORE"` to `l3_switch` would not merely duplicate that answer,
    it would REPLACE it -- `reconstruct` skips derivation entirely for any device
    whose role arrived `declared`. So the access switch somebody promoted to CORE
    in the dropdown three years ago, and the core pair still labelled ACCESS from
    the day they were racked, would each be drawn in the wrong lane with
    `declared` provenance next to them, and the one component capable of noticing
    would have been switched off by the very label that was wrong.

    It would also be silently correct on this estate, where the labels happen to
    match the cabling. An engine that reads labels looks right on a demo and
    collapses on the first client whose inventory was last tidied in 2019, which
    is the failure mode this whole module is arranged to avoid.

    So a switch leaves here as `unknown`/`unknown` and the engine does the work.
    """
    if family is None:
        return "unknown", "unknown", ""
    role = _ROLE_OF_FAMILY.get(family)
    if role is None:
        # Includes "Switches and Hubs". See above: not a refusal, a handover.
        return "unknown", "unknown", ""
    return role, "declared", f"Catalyst Center reports family {family!r}"


def _interface_addresses(row: dict, where: str) -> list[str]:
    """The interface's addresses as canonical CIDRs.

    A reported address with NO MASK is a refusal rather than an assumed /32. A
    /32 is not a smaller version of the truth here: `reconstruct._containment_links`
    derives adjacency from two interfaces sharing a block, and a host route
    shares a block with nothing, so guessing the mask would delete the evidence
    the address was carried for.
    """
    address = row.get("ipv4Address")
    if address is None or not str(address).strip():
        return []
    mask = row.get("ipv4Mask")
    if mask is None or not str(mask).strip():
        raise NormalizeError(
            f"{CATALYST_TOOL} {where}: ipv4Address {address!r} arrived with no "
            f"ipv4Mask; an address without a mask cannot be made into a CIDR "
            f"without assuming /32, which would erase the containment adjacency "
            f"it is the evidence for")
    try:
        return [str(ipaddress.ip_interface(f"{address}/{mask}"))]
    except ValueError as exc:
        raise NormalizeError(
            f"{CATALYST_TOOL} {where}: {address}/{mask} is not an address ({exc})"
        ) from exc


def _admin_up(value: object) -> Optional[bool]:
    """"UP"/"DOWN" -> True/False. ANYTHING ELSE -> None, which means NOT REPORTED.

    Never `False` by default. A missing `adminStatus` and a port that is shut are
    different facts, and a picture that greys out every unreported port invents
    an outage the operator then goes looking for.
    """
    if not isinstance(value, str):
        return None
    token = value.strip().upper()
    if token == "UP":
        return True
    if token == "DOWN":
        return False
    return None


def _speed_mbps(value: object, where: str) -> Optional[int]:
    """Catalyst Center reports interface speed as a string in KILObits/second.

    Read as megabits it makes every gigabit port a terabit one, and capacity
    headroom is one of the few numbers on this picture somebody might act on.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        kbps = int(value)
    except (TypeError, ValueError) as exc:
        raise NormalizeError(
            f"{CATALYST_TOOL} {where}: speed {value!r} is not a number of kbps"
        ) from exc
    # A sub-megabit port floors to zero, and "0 Mbps" is a false statement about
    # a working link. Not-reported is the honest one of the two wrong answers.
    return (kbps // 1000) or None


def _vlan_of(value: object) -> Optional[int]:
    """`vlanId` as an int. 0 and unparseable spellings mean no VLAN.

    Catalyst Center writes 0 into this column for routed ports. VLAN 0 does not
    exist, and a `Vlan(vlan_id=0)` row would put a phantom segment on the picture
    carrying every routed port in the estate.
    """
    if isinstance(value, bool) or value is None:
        return None
    try:
        vlan_id = int(value)
    except (TypeError, ValueError):
        return None
    return vlan_id or None


def _catalyst_links(rows: list, known: set[str]) -> list[NetLink]:
    """Physical-topology adjacencies -> `NetLink`s with `evidence='cdp'`.

    WHY 'cdp' AND NOT 'api_topology'. `api_topology` describes the transport we
    happened to read the fact over; `cdp` describes the observation. Catalyst
    Center does not maintain an adjacency table of its own -- this endpoint is a
    rendering of the CDP/LLDP neighbour tables its managed devices already keep,
    so a link here means a switch saw a neighbour on a port. That is the
    distinction every consumer downstream cares about: a neighbour protocol saw
    a cable, as opposed to a console asserting a relationship. On an all-Cisco
    fabric CDP is the protocol that reports it.

    What is NOT set, because this endpoint does not return it: `redundant_group`
    and `aggregated`. The estate knows `Po1` is a two-member port-channel and
    knows which uplinks are alternate paths for one purpose; Catalyst Center's
    topology endpoint says neither, and reading "aggregated" off a port NAMED
    `Po1` would be exactly the string-matching this module refuses one function
    up. The port name travels on `a_interface`/`b_interface`, where a human can
    see it for what it is.
    """
    links: dict[str, NetLink] = {}
    for index, row in enumerate(rows):
        where = f"topology link #{index}"
        if not isinstance(row, dict):
            raise NormalizeError(
                f"{CATALYST_TOOL} {where}: expected an object, got {type(row).__name__}")
        source = str(_require(row, "source", tool=CATALYST_TOOL, where=where))
        target = str(_require(row, "target", tool=CATALYST_TOOL, where=where))
        for device in (source, target):
            if device not in known:
                # A link naming a device the inventory endpoint did not return is
                # an export disagreeing with itself. Stored, it is an edge whose
                # endpoint has no device row: the persistence layer fails on the
                # foreign key and the topology screen draws a link to nothing.
                raise NormalizeError(
                    f"{CATALYST_TOOL} {where}: names device {device!r}, which "
                    f"`{DNA_DEVICES}` did not return")
        start = row.get("startPortName")
        end = row.get("endPortName")
        # Canonical end ordering, so one cable yields one key no matter which way
        # round the console listed it -- the snapshot fingerprint is an equality
        # check over these and must not depend on export order.
        a, b = sorted(((source, start or ""), (target, end or "")))
        key = f"cdp:{a[0]}:{a[1]}~{b[0]}:{b[1]}"
        if key in links:
            continue
        links[key] = NetLink(
            link_key=key,
            a_device=a[0], a_interface=a[1] or None,
            b_device=b[0], b_interface=b[1] or None,
            evidence="cdp",
            evidence_detail=(
                f"Catalyst Center physical topology reports {a[0]} {a[1] or '?'} "
                f"adjacent to {b[0]} {b[1] or '?'} (CDP/LLDP neighbour)"),
            provenance=_prov(CATALYST_TOOL, key.removeprefix("cdp:")),
        )
    return [links[key] for key in sorted(links)]


def normalize_catalyst(raw: dict) -> NormalizeResult:
    """One Catalyst Center export -> devices, interfaces, links and VLANs."""
    out = NormalizeResult()

    device_rows = _rows(_dna_response(raw, DNA_DEVICES),
                        tool=CATALYST_TOOL, what=DNA_DEVICES)
    interface_rows = _rows(_dna_response(raw, DNA_INTERFACES),
                           tool=CATALYST_TOOL, what=DNA_INTERFACES)
    topology = _dna_response(raw, DNA_PHYSICAL_TOPOLOGY)
    if not isinstance(topology, dict):
        raise NormalizeError(
            f"{CATALYST_TOOL} {DNA_PHYSICAL_TOPOLOGY}: expected an object with "
            f"`nodes` and `links`, got {type(topology).__name__}")
    for half in ("nodes", "links"):
        if half not in topology:
            raise NormalizeError(
                f"{CATALYST_TOOL} {DNA_PHYSICAL_TOPOLOGY}: payload carries no "
                f"`{half}`. A topology with no links and a topology we failed to "
                f"read are the same picture and must not be the same value")
    node_rows = _rows(topology["nodes"], tool=CATALYST_TOOL,
                      what=f"{DNA_PHYSICAL_TOPOLOGY} nodes")
    link_rows = _rows(topology["links"], tool=CATALYST_TOOL,
                      what=f"{DNA_PHYSICAL_TOPOLOGY} links")
    vlan_names = _rows(_dna_response(raw, DNA_VLAN_NAMES),
                       tool=CATALYST_TOOL, what=DNA_VLAN_NAMES)

    for index, row in enumerate(device_rows):
        where = f"device #{index}"
        if not isinstance(row, dict):
            raise NormalizeError(
                f"{CATALYST_TOOL} {where}: expected an object, got {type(row).__name__}")
        device_id = str(_require(row, "id", tool=CATALYST_TOOL, where=where))
        hostname = str(row.get("hostname") or device_id)
        role, role_source, role_reason = _catalyst_role(row.get("family"))
        software = " ".join(
            str(part) for part in (row.get("softwareType"), row.get("softwareVersion"))
            if part
        )
        out.devices.append(NetDevice(
            device_key=hostname,
            name=hostname,
            role=role, role_source=role_source, role_reason=role_reason,
            vendor=_CATALYST_VENDOR,
            model=_text(row.get("platformId")),
            os_version=software or None,
            serial=_text(row.get("serialNumber")),
            mgmt_ip=_text(row.get("managementIpAddress")),
            # `site` is left unset: the four endpoints read here do not return a
            # site hierarchy. `/dna/intent/api/v1/site` does, and onboarding it
            # is what would fill this in.
            provenance=_prov(CATALYST_TOOL, device_id),
        ))

    # Keyed by the console's device id AND by hostname, because the interface
    # endpoint joins on `deviceId` while the topology endpoint names nodes by
    # whichever id the console renders them under.
    device_key_of: dict[str, str] = {}
    for device, row in zip(out.devices, device_rows):
        device_key_of[str(row.get("id"))] = device.device_key
        device_key_of[device.device_key] = device.device_key

    # The topology nodes carry nothing the inventory endpoint does not already
    # state, so nothing is built from them -- but they are checked, because this
    # is the one place a device outside the console's own inventory could enter
    # the picture, and a node nobody validated is a box drawn from a list nobody
    # read.
    for index, node in enumerate(node_rows):
        if not isinstance(node, dict):
            raise NormalizeError(
                f"{CATALYST_TOOL} topology node #{index}: expected an object, got "
                f"{type(node).__name__}")
        node_id = str(_require(node, "id", tool=CATALYST_TOOL,
                               where=f"topology node #{index}"))
        if node_id not in device_key_of:
            raise NormalizeError(
                f"{CATALYST_TOOL} topology node #{index}: names device {node_id!r}, "
                f"which `{DNA_DEVICES}` did not return")

    links = _catalyst_links(link_rows, set(device_key_of))
    # The neighbour a port saw, indexed so it can be hung back on the interface.
    # Catalyst Center's `/interface` resource has no neighbour column of its own;
    # physical-topology is where the CDP/LLDP reading surfaces, so attributing it
    # to the port it was seen on is accurate rather than convenient.
    neighbor_of: dict[tuple[str, str], tuple[str, Optional[str]]] = {}
    for link in links:
        if link.a_interface:
            neighbor_of[(link.a_device, link.a_interface)] = (link.b_device, link.b_interface)
        if link.b_interface:
            neighbor_of[(link.b_device, link.b_interface)] = (link.a_device, link.a_interface)
    out.links.extend(links)

    for index, row in enumerate(interface_rows):
        where = f"interface #{index}"
        if not isinstance(row, dict):
            raise NormalizeError(
                f"{CATALYST_TOOL} {where}: expected an object, got {type(row).__name__}")
        device_id = str(_require(row, "deviceId", tool=CATALYST_TOOL, where=where))
        if device_id not in device_key_of:
            # Same class of defect as a dangling link: an interface whose device
            # the inventory did not return is a row pointing at a device_key no
            # device has, which the persistence layer refuses and the topology
            # screen would render as a port belonging to nobody.
            raise NormalizeError(
                f"{CATALYST_TOOL} {where}: deviceId {device_id!r} was not returned "
                f"by `{DNA_DEVICES}`")
        device_key = device_key_of[device_id]
        port = str(_require(row, "portName", tool=CATALYST_TOOL, where=where))
        raw_ref = str(row.get("id") or f"{device_id}:{port}")
        neighbor = neighbor_of.get((device_key, port))
        out.interfaces.append(NetInterface(
            interface_key=f"{device_key}:{port}",
            device_key=device_key,
            name=port,
            description=_text(row.get("description")),
            addresses=_interface_addresses(row, f"{where} ({device_key}:{port})"),
            # `networks_behind` and `zone` stay empty: Catalyst Center models
            # neither. "IPs behind interface" is AlgoSec's field and zones are a
            # firewall vendor's; that the two tiers answer different questions is
            # why the ladder in `sources.py` has rungs.
            vlan_id=_vlan_of(row.get("vlanId")),
            admin_up=_admin_up(row.get("adminStatus")),
            # DNAC's `status` is the OPERATIONAL state, a separate fact from
            # `adminStatus`. Reading one into the other would report a shut port
            # as forwarding, or a broken one as healthy.
            oper_up=_admin_up(row.get("status")),
            speed_mbps=_speed_mbps(row.get("speed"), f"{where} ({device_key}:{port})"),
            neighbor_device=neighbor[0] if neighbor else None,
            neighbor_interface=neighbor[1] if neighbor else None,
            provenance=_prov(CATALYST_TOOL, raw_ref),
        ))

    # Optional by design: an older Catalyst Center, or one whose pools an
    # operator never reserved, simply does not carry this endpoint. Absent is a
    # coverage gap -- the VLAN column goes empty and the inventory says so --
    # rather than a failure. An endpoint that IS present and unreadable is still
    # refused by `_rows`, which is the distinction that matters.
    _pool_block = raw.get(DNA_GLOBAL_POOL)
    _pool_rows = ([] if _pool_block is None
                  else _rows(_dna_response(raw, DNA_GLOBAL_POOL),
                             tool=CATALYST_TOOL, what=f"{DNA_GLOBAL_POOL} response"))
    out.vlans.extend(_catalyst_vlans(vlan_names, out.interfaces, _pool_rows))
    # Sorted on the way out rather than relying on the export's order: the
    # snapshot fingerprint is an equality check over these rows, so a console
    # that paginated differently between two reads would otherwise look like a
    # change to the network.
    out.devices.sort(key=lambda d: d.device_key)
    out.interfaces.sort(key=lambda i: i.interface_key)
    out.links.sort(key=lambda l: l.link_key)
    return out


def _catalyst_vlans(vlan_names: list, interfaces: list[NetInterface],
                    pool_rows: list) -> list[Vlan]:
    """VLANs, from `vlan-names` UNIONED with the VLANs the interfaces carry.

    Unioned rather than intersected. A VLAN an interface carries that
    `vlan-names` omits is still a VLAN we observed; an id in `vlan-names` that no
    interface carries is still a VLAN the fabric declares. Either subtraction
    reports a smaller network than the console described.

    Two fields are left empty on purpose:

    `name` -- `vlan-names` returns IDS, not names, so the operator's word for
    VLAN 30 is not in this export. It IS sitting in the SVI's description
    ("SVI app-tier"), and scraping it out of there is how a normalizer starts
    reporting `no L3)` as the name of a VLAN.

    `subnets` -- the SVI's mask describes the GATEWAY'S INTERFACE, not the
    VLAN's allocation, and back-forming one from the other is wrong in the
    direction that hides hosts. In this estate VLAN 30 carries 10.30.0.0/16
    while its SVI reads 10.30.0.1/24, so a subnet inferred from the mask would
    place app-server-07 (10.30.7.7) outside the VLAN it is actually on -- and
    "where does this finding live" is the question the segment lane exists to
    answer. `/dna/intent/api/v1/global-pool` is the endpoint that would tell us,
    and it is not read here.
    """
    observed: dict[int, str] = {}
    for entry in vlan_names:
        token = str(entry).strip()
        try:
            vlan_id = int(token)
        except ValueError as exc:
            # `Vlan.vlan_id` is an int, so a named VLAN cannot be carried at all.
            # Dropping it silently would shrink the segment lane with nothing to
            # notice it by; refusing by name says which entry to go look at.
            raise NormalizeError(
                f"{CATALYST_TOOL} {DNA_VLAN_NAMES}: {token!r} is not a VLAN id, and "
                f"a VLAN named rather than numbered cannot be carried") from exc
        observed[vlan_id] = token
    for iface in interfaces:
        if iface.vlan_id is not None:
            observed.setdefault(iface.vlan_id, str(iface.vlan_id))

    # The IP pool inventory, keyed by VLAN. This is where a VLAN's SUBNET and
    # human NAME come from: `vlan-names` carries ids and nothing else, so without
    # it every "which VLAN is this host in" answer in the product is empty.
    #
    # NOT back-formed from the SVI mask, which is the available shortcut and is
    # wrong: VLAN 30's gateway reads 10.30.0.1/24 while the VLAN carries
    # 10.30.0.0/16, so a host at 10.30.7.7 would be placed outside its own VLAN.
    pools: dict[int, dict] = {}
    # Optional by design: an older Catalyst Center, or one whose pools an
    # operator never reserved, simply does not carry it. Absent is a coverage
    # gap (the VLAN column goes empty and says so), not a failure -- unlike an
    # endpoint that IS present and unreadable, which `_rows` still refuses.
    for row in pool_rows:
        vid = _vlan_of(row.get("vlanId"))
        if vid is not None:
            pools[vid] = row

    vlans: list[Vlan] = []
    for vlan_id in sorted(observed):
        on = [i for i in interfaces if i.vlan_id == vlan_id]
        gateways = sorted({
            str(ipaddress.ip_interface(address).ip)
            for iface in on for address in iface.addresses
        })
        pool = pools.get(vlan_id, {})
        cidr = pool.get("ipPoolCidr")
        vlans.append(Vlan(
            vlan_id=vlan_id,
            # None when no pool declares one -- the id is not a name, and
            # rendering "VLAN 30" as though someone had called it that is a small
            # invention that reads exactly like an observation.
            name=pool.get("ipPoolName") or None,
            subnets=[cidr] if cidr else [],
            # Pool gateways where declared, SVI addresses otherwise. Both are
            # observations; the pool's is the authoritative one.
            gateways=sorted({*(g for g in pool.get("gateways", ()) if g), *gateways}),
            device_keys=sorted({i.device_key for i in on}),
            provenance=_prov(CATALYST_TOOL, observed[vlan_id]),
        ))
    return vlans


# ── Meraki Dashboard ───────────────────────────────────────────────────────

def _meraki_os_version(firmware: object, product_type: Optional[str]) -> Optional[str]:
    """Meraki firmware strings -> a plain version.

    The Dashboard writes `<productType>-<version, dots replaced by dashes>`:
    `wireless-29-7-1` for what every other surface in the world calls 29.7.1.
    Carried raw into `os_version` that string matches no vulnerability feed and
    no other console's spelling of the same build, so the device quietly stops
    being comparable with itself.

    Anything not carrying the productType prefix passes through untouched --
    this column also returns literal statuses like "Not running configured
    version", and mangling one of those into a version number would be worse
    than leaving it legible.
    """
    if firmware is None or not str(firmware).strip():
        return None
    text = str(firmware).strip()
    prefix = f"{product_type}-" if product_type else ""
    if prefix and text.startswith(prefix):
        return text[len(prefix):].replace("-", ".")
    return text


def _meraki_addresses(uplink: dict, where: str) -> list[str]:
    """The addresses on one uplink, as canonical CIDRs.

    An entry with no `address` is a configured uplink slot holding no address --
    a real state, and recording nothing for it is the correct answer. An address
    WITHOUT a prefix is refused for the same reason Catalyst Center's maskless
    address is: /32 is not a cautious guess, it is the one value that deletes the
    containment evidence this endpoint exists to provide.
    """
    addresses: list[str] = []
    for entry in uplink.get("addresses") or []:
        if not isinstance(entry, dict):
            raise NormalizeError(
                f"{MERAKI_TOOL} {where}: address entry must be an object, got "
                f"{type(entry).__name__}")
        value = entry.get("address")
        if value is None or not str(value).strip():
            continue
        token = str(value).strip()
        if "/" not in token:
            raise NormalizeError(
                f"{MERAKI_TOOL} {where}: uplink address {token!r} carries no prefix "
                f"length; assuming /32 would erase the only adjacency evidence "
                f"this device contributes")
        try:
            addresses.append(str(ipaddress.ip_interface(token)))
        except ValueError as exc:
            raise NormalizeError(
                f"{MERAKI_TOOL} {where}: {token!r} is not an address ({exc})") from exc
    return sorted(addresses)


def normalize_meraki(raw: dict) -> NormalizeResult:
    """One Meraki Dashboard export -> devices, uplink interfaces and appliance VLANs.

    NO LINKS. The three endpoints read here return no adjacency of any kind: the
    Dashboard knows the AP has an uplink and what address is on it, and has no
    idea what is at the other end of the cable. `LinkEvidence` has no member for
    a link we would like to exist, so none is emitted and
    `reconstruct._containment_links` attaches the AP to the picture through the
    management block its address provably sits in -- weaker evidence, labelled as
    such, and true.
    """
    out = NormalizeResult()

    device_rows = _rows(_endpoint(raw, MERAKI_DEVICES, MERAKI_TOOL),
                        tool=MERAKI_TOOL, what=MERAKI_DEVICES)
    uplink_rows = _rows(_endpoint(raw, MERAKI_UPLINK_ADDRESSES, MERAKI_TOOL),
                        tool=MERAKI_TOOL, what=MERAKI_UPLINK_ADDRESSES)
    vlan_rows = _rows(_endpoint(raw, MERAKI_APPLIANCE_VLANS, MERAKI_TOOL),
                      tool=MERAKI_TOOL, what=MERAKI_APPLIANCE_VLANS)

    # Both identifiers point at the device key, because the uplink endpoint joins
    # on serial and this estate has no serial for the AP. A device the uplink rows
    # cannot be attributed to lands in the inventory with no address at all --
    # and an address is the only thing that attaches a Meraki device to the rest
    # of the picture, so losing the join loses the device.
    device_key_of: dict[str, str] = {}
    raw_ref_of: dict[str, str] = {}
    for index, row in enumerate(device_rows):
        where = f"device #{index}"
        if not isinstance(row, dict):
            raise NormalizeError(
                f"{MERAKI_TOOL} {where}: expected an object, got {type(row).__name__}")
        serial = str(row.get("serial") or "").strip()
        name = str(row.get("name") or "").strip()
        if not name and not serial:
            raise NormalizeError(
                f"{MERAKI_TOOL} {where}: row carries neither `serial` nor `name`, so "
                f"there is no identifier to record it under")
        # The Dashboard's own key is the serial, and that is what `raw_ref`
        # carries so a row can be taken back to it. `device_key` has to be the
        # NAME: it is the only identifier this device shares with any other
        # console's view of it, and a device_key no other source can produce is a
        # device that can never be joined to one.
        device_key = name or serial
        product_type = str(row.get("productType") or "").strip() or None
        role = _ROLE_OF_PRODUCT_TYPE.get(product_type or "")
        device_key_of[device_key] = device_key
        if serial:
            device_key_of[serial] = device_key
        raw_ref_of[device_key] = serial or name
        out.devices.append(NetDevice(
            device_key=device_key,
            name=name or serial,
            role=role or "unknown",
            role_source="declared" if role else "unknown",
            role_reason=(f"Meraki reports productType {product_type!r}" if role else ""),
            vendor=_MERAKI_VENDOR,
            model=_text(row.get("model")),
            os_version=_meraki_os_version(row.get("firmware"), product_type),
            serial=serial or None,
            mgmt_ip=_text(row.get("lanIp")),
            provenance=_prov(MERAKI_TOOL, raw_ref_of[device_key]),
        ))

    for index, row in enumerate(uplink_rows):
        where = f"uplink row #{index}"
        if not isinstance(row, dict):
            raise NormalizeError(
                f"{MERAKI_TOOL} {where}: expected an object, got {type(row).__name__}")
        serial = str(row.get("serial") or "").strip()
        name = str(row.get("name") or "").strip()
        device_key = device_key_of.get(serial) or device_key_of.get(name)
        if device_key is None:
            raise NormalizeError(
                f"{MERAKI_TOOL} {where}: uplink addresses for serial {serial!r} / name "
                f"{name!r}, which `{MERAKI_DEVICES}` did not return")
        for uplink in _rows(row.get("uplinks") or [], tool=MERAKI_TOOL,
                            what=f"{where} uplinks"):
            if not isinstance(uplink, dict):
                raise NormalizeError(
                    f"{MERAKI_TOOL} {where}: uplink must be an object, got "
                    f"{type(uplink).__name__}")
            port = str(_require(uplink, "interface", tool=MERAKI_TOOL, where=where))
            out.interfaces.append(NetInterface(
                interface_key=f"{device_key}:{port}",
                device_key=device_key,
                name=port,
                addresses=_meraki_addresses(uplink, f"{where} ({device_key}:{port})"),
                # `admin_up` and `oper_up` stay None. This endpoint reports
                # neither; device reachability lives on
                # `/organizations/{orgId}/devices/statuses`, which is not read
                # here. None means NOT REPORTED, and a Meraki AP drawn as down
                # because nobody asked is a support call.
                #
                # The `gateway` on each address is deliberately not turned into
                # anything. It is the most tempting field in this export -- a
                # gateway IP looks exactly like a device waiting to be drawn --
                # but it is evidence that something answers at an address, not an
                # observation of a box, and `LinkEvidence` has no member for a
                # device we inferred into existence.
                provenance=_prov(
                    MERAKI_TOOL,
                    f"{raw_ref_of.get(device_key, device_key)}:{port}"),
            ))

    for index, row in enumerate(vlan_rows):
        where = f"appliance vlan #{index}"
        if not isinstance(row, dict):
            raise NormalizeError(
                f"{MERAKI_TOOL} {where}: expected an object, got {type(row).__name__}")
        vlan_id = _vlan_of(_require(row, "id", tool=MERAKI_TOOL, where=where))
        if vlan_id is None:
            raise NormalizeError(f"{MERAKI_TOOL} {where}: `id` is not a VLAN id")
        name = _text(row.get("name"))
        subnet = str(row.get("subnet") or "").strip()
        appliance_ip = str(row.get("applianceIp") or "").strip()
        gateways = [appliance_ip] if appliance_ip else []
        out.vlans.append(Vlan(
            vlan_id=vlan_id,
            name=name,
            # Unlike Catalyst Center, this endpoint STATES the subnet rather than
            # leaving it to be guessed off a gateway's mask, which is why a
            # Meraki VLAN carries one and a Catalyst VLAN does not.
            subnets=[subnet] if subnet else [],
            gateways=gateways,
            # The endpoint is scoped to a NETWORK, not to a device: it does not
            # say which appliance terminates the VLAN, so no device is named.
            device_keys=[],
            provenance=_prov(MERAKI_TOOL, str(vlan_id)),
        ))
        if subnet:
            out.subnets.append(Subnet(
                cidr=subnet,
                name=name,
                vlan_id=vlan_id,
                gateways=gateways,
                provenance=_prov(MERAKI_TOOL, subnet),
            ))

    # Same reason as the Catalyst half: order is part of the output.
    out.devices.sort(key=lambda d: d.device_key)
    out.interfaces.sort(key=lambda i: i.interface_key)
    out.vlans.sort(key=lambda v: v.vlan_id)
    out.subnets.sort(key=lambda s: s.cidr)
    return out
