"""Cisco's two consoles, projected from the canonical estate.

Both of these are Cisco and they overlap in nothing, which is why they are two
functions rather than one with a flag. Catalyst Center manages the campus
switching fabric and the IOS-XE edge router; the Meraki Dashboard manages the
cloud-managed AP and knows nothing about the fabric it is plugged into. Neither
one can see the FortiGates, the Juniper, the modems or the circuits. That is not
a gap in this module -- it is the shape of the product, and `DeviceSpec.seen_by`
is where it is declared.

Why Catalyst Center is the one that matters
-------------------------------------------
`/dna/intent/api/v1/topology/physical-topology` is THE ONLY ENDPOINT IN THE WHOLE
REGISTRY THAT REPORTS PHYSICAL ADJACENCY DIRECTLY. Catalyst Center builds it from
the CDP/LLDP neighbour tables its managed devices already maintain, so a link
from it is a cable somebody's switch actually saw. Every other console here
forces `topology.reconstruct` to fall back on `containment` -- two interfaces
provably sharing an address block -- which is a real L3 observation but is not a
cable, and is labelled as the weaker evidence it is.

So this is the projection that makes the core and access lanes real rather than
derived, and it is the one to be most careful with.

What these functions will not do
--------------------------------
  * No device outside the console's own `seen_by` appears, in ANY endpoint --
    inventory, interface list, topology node or topology link. Catalyst Center
    can see `asw-acc-01`'s port `Gi1/0/24`, so the port is reported; the AP on
    the other end of that cable is a Meraki device, so neither the node nor the
    link is. The cable is genuinely unobserved by this console and the picture
    has to say so rather than borrowing the answer from the estate.
  * No value the estate does not carry. Where a real console would return
    something we have no fact for -- an interface's operational status, a
    device's uptime, an uplink's static-vs-dynamic assignment -- the key is
    rendered with `None`. A plausible value in that slot is indistinguishable
    from an observed one the moment it leaves this module.

The envelopes differ on purpose: Catalyst Center wraps every Intent API payload
in `{"response": ...}` and the Meraki Dashboard returns bare arrays. A normalizer
written against one shape and pointed at the other should fail loudly rather than
find `.get("response")` empty and report a console with nothing in it.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from ..estate import DeviceSpec, Estate, IfaceSpec

CATALYST_TOOL = "catalyst_center"
MERAKI_TOOL = "meraki"

# Endpoint paths, exported so the normalizer and the tests name the same strings
# rather than each keeping a copy. A path spelled two ways would read downstream
# as "this console returned nothing", which is the one thing the whole engine
# refuses to say.
DNA_DEVICES = "/dna/intent/api/v1/network-device"
DNA_INTERFACES = "/dna/intent/api/v1/interface"
DNA_PHYSICAL_TOPOLOGY = "/dna/intent/api/v1/topology/physical-topology"
DNA_VLAN_NAMES = "/dna/intent/api/v1/topology/vlan/vlan-names"

# The Meraki paths keep their `{orgId}` / `{netId}` placeholders LITERALLY. Those
# ids belong to a real Dashboard org; substituting an invented one would produce
# an export whose keys look like URLs an operator could paste into a browser and
# cannot. The placeholder says "this endpoint, in whichever org you connected".
MERAKI_DEVICES = "/organizations/{orgId}/devices"
MERAKI_UPLINK_ADDRESSES = "/organizations/{orgId}/devices/uplinks/addresses/byDevice"
MERAKI_APPLIANCE_VLANS = "/networks/{netId}/appliance/vlans"

# Catalyst Center's `family`. A HARDWARE FACT: it is what the platform reports
# itself as, not something an operator typed. The normalizer is allowed to
# believe it.
_DNA_FAMILY: dict[str, str] = {
    "router": "Routers",
    "l3_switch": "Switches and Hubs",
    "l2_switch": "Switches and Hubs",
}

# Catalyst Center's `role`. An OPERATOR-ASSIGNED LABEL, defaulted by the platform
# and editable by anyone with write access -- see the long comment in
# `normalizers/cisco.py`, which deliberately ignores it for switches. It is
# emitted here precisely so that there is something for the normalizer to be
# tested against ignoring.
_DNA_ROLE_LABEL: dict[str, str] = {
    "router": "BORDER ROUTER",
    "l3_switch": "CORE",
    "l2_switch": "ACCESS",
}

# Meraki's `productType`. Also a hardware fact -- it is the SKU family, derived
# from the model number -- which is why the normalizer declares a role from it.
_MERAKI_PRODUCT_TYPE: dict[str, str] = {
    "wireless_ap": "wireless",
    "firewall": "appliance",
    "l2_switch": "switch",
    "l3_switch": "switch",
    "modem": "cellularGateway",
}

# The Dashboard reports uplink SLOTS (`wan1`, `wan2`, ...), never the device's
# own port name. An MR's wired uplink is `wan1` even though the switch at the
# other end calls the same cable `Gi1/0/24`; that two consoles name one port
# differently is exactly what `Provenance.raw_ref` exists to survive. Numbered
# without a ceiling on purpose -- a fixed tuple of slot names would silently
# drop the fourth addressed interface on a device that grew one.
_MERAKI_UPLINK_SLOT = "wan{n}"


# ── Shared shape helpers ───────────────────────────────────────────────────

def _svi_vlan(name: str) -> Optional[int]:
    """The VLAN an SVI's NAME identifies, or None when the name is not an SVI.

    An SVI's VLAN is its identity (`Vlan30` IS VLAN 30), which is the one place
    reading a name is a statement of fact rather than a guess about a lane.
    """
    if len(name) > 4 and name[:4].lower() == "vlan" and name[4:].isdigit():
        return int(name[4:])
    return None


def _interface_type(name: str) -> str:
    """Catalyst Center's `interfaceType`: "Physical" or "Virtual"."""
    lowered = name.lower()
    virtual = _svi_vlan(name) is not None or lowered.startswith(
        ("po", "port-channel", "loopback", "tunnel", "vlan"))
    return "Virtual" if virtual else "Physical"


def _vlan_id(iface: IfaceSpec) -> Optional[int]:
    """The `vlanId` Catalyst Center reports for one interface.

    DNAC populates this for the two kinds of interface that HAVE a VLAN: an SVI,
    whose VLAN is its identity, and a switchport, whose access VLAN is configured
    on it. A ROUTED port has neither, and the estate's out-of-band management
    port is a routed port -- it holds an address in the management subnet and is
    not a switchport (`description="out-of-band management"`).

    This distinction is load-bearing rather than cosmetic. `reconstruct._derive_role`
    reads "carries VLANs and holds an address on one of them" as an SVI, and an
    access switch whose management port reported a VLAN would therefore look like
    a device with exactly one SVI: not two, so not an `l3_switch`, and not zero,
    so not an `l2_switch` either. It would fall through every branch and land in
    the inventory as role `unknown` with no lane -- i.e. reporting a VLAN on a
    management port would erase the entire access layer from the picture.
    """
    if iface.vlan_id is None:
        return None
    if _svi_vlan(iface.name) is not None or not iface.addresses:
        return iface.vlan_id
    return None


def _port_mode(iface: IfaceSpec) -> Optional[str]:
    """DNAC's `portMode`. Rendered for shape fidelity and read by nothing.

    Deliberately not consumed by the normalizer: no field of the canonical model
    is derived from it, so a wrong answer here cannot become a wrong fact
    downstream.
    """
    if iface.addresses:
        return "routed"
    if iface.vlan_id is not None:
        return "access"
    if iface.neighbor_device:
        return "trunk"
    return None


def _ipv4(addresses: tuple[str, ...]) -> tuple[Optional[str], Optional[str]]:
    """The interface's v4 address and dotted mask, as DNAC's two columns.

    DNAC's interface resource has room for exactly ONE v4 address; a secondary
    address is not representable in this shape and would be lost here. No
    interface in this estate carries one -- if one ever does, this is the line
    that drops it.
    """
    for raw in addresses:
        addr = ipaddress.ip_interface(raw)
        if isinstance(addr, ipaddress.IPv4Interface):
            return str(addr.ip), str(addr.netmask)
    return None, None


def _admin_status(iface: IfaceSpec) -> Optional[str]:
    """"UP" / "DOWN", or None when the estate does not say.

    None is NOT "DOWN". `NetInterface.admin_up` is three-valued for the same
    reason: a diagram that greys out every un-reported port invents an outage.
    """
    if iface.admin_up is None:
        return None
    return "UP" if iface.admin_up else "DOWN"


def _speed_kbps(iface: IfaceSpec) -> Optional[str]:
    """DNAC reports interface speed as a string in KILObits per second.

    A normalizer that reads `"1000000"` as megabits reports a gigabit port as a
    terabit one, so the unit is converted in exactly two places -- here and in
    `normalizers.cisco` -- and nowhere else.
    """
    if iface.speed_mbps is None:
        return None
    return str(iface.speed_mbps * 1000)


def _software(os_version: str) -> tuple[Optional[str], Optional[str]]:
    """Split "IOS-XE 17.9.4" into DNAC's `softwareType` and `softwareVersion`.

    A version string with no train in front of it yields no `softwareType`
    rather than a guessed one; the normalizer re-joins whatever it is given.
    """
    if not os_version:
        return None, None
    train, sep, version = os_version.rpartition(" ")
    if not sep:
        return None, os_version
    return train, version


def _reachable(est: Estate, dev: DeviceSpec) -> Optional[str]:
    """DNAC's `reachabilityStatus`, from the state of the management port.

    Reachability in Catalyst Center means "the console can poll this device over
    its management address", so it is projected from the admin state of the
    management interface the console polls -- not asserted because the device
    happens to be in the inventory. A device whose management port state the
    estate does not record reports nothing here.
    """
    for iface in sorted(est.interfaces_of(dev.key), key=lambda i: i.name):
        holds_mgmt = any(str(ipaddress.ip_interface(a).ip) == dev.mgmt_ip
                         for a in iface.addresses)
        if not holds_mgmt:
            continue
        if iface.admin_up is None:
            return None
        return "Reachable" if iface.admin_up else "Unreachable"
    return None


# ── Catalyst Center ────────────────────────────────────────────────────────

def catalyst_center_export(est: Estate) -> dict[str, Any]:
    """The Catalyst Center (DNA Center) Intent API view of the estate.

    Four endpoints, each under the `{"response": ...}` envelope the Intent API
    puts around everything. The interface list is flat and carries `deviceId`,
    exactly as the real paginated endpoint returns it.
    """
    seen = sorted(est.devices_seen_by(CATALYST_TOOL), key=lambda d: d.key)
    keys = {d.key for d in seen}

    devices: list[dict[str, Any]] = []
    for dev in seen:
        train, version = _software(dev.os_version)
        devices.append({
            # DNAC keys a device by an opaque instance UUID. The estate carries
            # no such id, and minting a UUID-shaped string would put a
            # `raw_ref` on every row that resolves to nothing in the console it
            # claims to come from. The hostname is the identifier an operator
            # can actually paste into the Catalyst Center search bar.
            "id": dev.key,
            "hostname": dev.name,
            "managementIpAddress": dev.mgmt_ip,
            "platformId": dev.model,
            "softwareType": train,
            "softwareVersion": version,
            # Absent for the access switches, and left absent. A serial is the
            # reference an operator raises a TAC case with; a generated one is
            # worse than none.
            "serialNumber": dev.serial or None,
            "family": _DNA_FAMILY.get(dev.role),
            "role": _DNA_ROLE_LABEL.get(dev.role),
            # The estate records no uptime, and a synthesized one would be both
            # a fabricated fact and a clock-dependent output in a module whose
            # whole contract is that two runs are byte-identical.
            "upTime": None,
            "reachabilityStatus": _reachable(est, dev),
        })

    interfaces: list[dict[str, Any]] = []
    for dev in seen:
        for iface in sorted(est.interfaces_of(dev.key), key=lambda i: i.name):
            address, mask = _ipv4(iface.addresses)
            interfaces.append({
                # Same reasoning as the device id: device + port is the
                # identifier that survives being handed back to a human.
                "id": f"{dev.key}:{iface.name}",
                "deviceId": dev.key,
                "portName": iface.name,
                "description": iface.description or None,
                "ipv4Address": address,
                "ipv4Mask": mask,
                "vlanId": _vlan_id(iface),
                # `status` is DNAC's OPERATIONAL state; `adminStatus` is the
                # configured one. The estate records only the latter, and
                # copying it into both columns would manufacture an
                # observation: a port that is admin-up and operationally down
                # is precisely the condition an operator is hunting for, and it
                # must not be rendered as healthy.
                "status": None,
                "adminStatus": _admin_status(iface),
                "speed": _speed_kbps(iface),
                "portMode": _port_mode(iface),
                "interfaceType": _interface_type(iface.name),
            })

    # Nodes and links are BOTH restricted to this console's inventory. A CDP
    # neighbour that Catalyst Center does not manage (the Meraki AP hanging off
    # `asw-acc-01`) is not a device this console can describe, so no node is
    # emitted for it and the cable to it is not reported. The port itself is --
    # it is a real port on a managed switch -- and the missing far end is the
    # partial-coverage story the product exists to make visible.
    nodes = [{"id": dev.key, "label": dev.name, "deviceType": dev.model} for dev in seen]

    links: list[dict[str, Any]] = []
    for link in est.links:
        if link.a_device not in keys or link.b_device not in keys:
            continue
        links.append({
            "source": link.a_device,
            "target": link.b_device,
            "startPortName": link.a_interface,
            "endPortName": link.b_interface,
            # Operational state again: the estate does not record whether a
            # cable is passing traffic, only that it exists.
            "linkStatus": None,
        })
    links.sort(key=lambda l: (l["source"], l["startPortName"], l["target"], l["endPortName"]))

    # `vlan-names` returns VLAN IDS AS STRINGS and nothing else -- no subnet, no
    # gateway, no human name. Everything else about a VLAN has to come from the
    # SVIs on the interface endpoint, which is why this projection can say that
    # VLAN 30 exists and where its gateway is but not that it is called
    # "app-tier".
    vlan_names = [
        str(vlan_id) for vlan_id in
        sorted({v.vlan_id for v in est.vlans if keys.intersection(v.on_devices)})
    ]

    return {
        DNA_DEVICES: {"response": devices},
        DNA_INTERFACES: {"response": interfaces},
        DNA_PHYSICAL_TOPOLOGY: {"response": {"nodes": nodes, "links": links}},
        DNA_VLAN_NAMES: {"response": vlan_names},
    }


# ── Meraki Dashboard ───────────────────────────────────────────────────────

def _default_gateway(est: Estate, address: str) -> Optional[str]:
    """The uplink's default gateway: the gateway of the block it sits in.

    This reads the estate's VLAN table to find out WHAT the device's gateway is;
    it does not report the VLAN. A Meraki AP genuinely knows its own default
    gateway and the Dashboard genuinely returns it, but the AP has no idea which
    VLAN number the switch upstream puts it in, and neither does this export.

    Longest prefix wins, as a router would resolve it, with the VLAN id breaking
    a tie so the answer cannot depend on the estate's declaration order.
    """
    host = ipaddress.ip_interface(address).ip
    matches = [
        (ipaddress.ip_network(v.subnet).prefixlen, -v.vlan_id, v.gateway)
        for v in est.vlans
        if host in ipaddress.ip_network(v.subnet)
    ]
    if not matches:
        return None
    return max(matches)[2]


def meraki_export(est: Estate) -> dict[str, list[dict[str, Any]]]:
    """The Meraki Dashboard view of the estate.

    Three endpoints, each returning a BARE ARRAY -- the Dashboard has no
    `{"response": ...}` envelope, unlike Catalyst Center.

    `devices/uplinks/addresses/byDevice` is the highest-yield endpoint in the
    entire source registry: private IP, public IP, gateway, DNS, VLAN tag and
    static-vs-dynamic assignment, for every uplink on every device in the org,
    in one paginated call. Nothing else here comes close on facts per
    integration -- the binding constraint on it is the Dashboard's 10 req/s
    org-wide rate limit, not data availability.
    """
    seen = sorted(est.devices_seen_by(MERAKI_TOOL), key=lambda d: d.key)
    keys = {d.key for d in seen}

    devices: list[dict[str, Any]] = []
    uplinks: list[dict[str, Any]] = []
    for dev in seen:
        product_type = _MERAKI_PRODUCT_TYPE.get(dev.role)
        devices.append({
            # The Dashboard keys everything by serial. This estate carries none
            # for the AP, and the honest answer is null -- see the join comment
            # on the uplink rows below, which is the part that would otherwise
            # break.
            "serial": dev.serial or None,
            "name": dev.name,
            "model": dev.model,
            # Neither MAC nor network id is a fact the estate holds. A Meraki
            # MAC is the identifier the identity layer would merge a switch's
            # CDP table against, so a fabricated one would not merely be noise:
            # it would fuse two devices that are not the same device.
            "mac": None,
            "networkId": None,
            # Meraki firmware strings are `<productType>-<version with dashes>`.
            # Stored raw as an os_version, "wireless-29-7-1" never matches a
            # vulnerability feed or another console's "29.7.1"; the normalizer
            # undoes this.
            "firmware": (f"{product_type}-{dev.os_version.replace('.', '-')}"
                         if product_type and dev.os_version else dev.os_version or None),
            "productType": product_type,
            "lanIp": dev.mgmt_ip,
        })

        addressed = sorted(
            (i for i in est.interfaces_of(dev.key) if i.addresses),
            key=lambda i: i.name,
        )
        slots: list[dict[str, Any]] = []
        for n, iface in enumerate(addressed, start=1):
            slots.append({
                "interface": _MERAKI_UPLINK_SLOT.format(n=n),
                "addresses": [{
                    "protocol": "ipv6" if ":" in address else "ipv4",
                    # Static-vs-dynamic is one of the most valuable bits this
                    # endpoint returns -- it is the difference between an
                    # address that will still be there tomorrow and one that
                    # will not -- and precisely because it is valuable it is the
                    # worst field in the export to guess. The estate does not
                    # record it.
                    "assignmentMode": None,
                    # Carried WITH its prefix. An address with no mask cannot
                    # become a CIDR without assuming /32, and a /32 erases the
                    # containment evidence that is the only thing joining this
                    # AP to the rest of the picture.
                    "address": address,
                    "gateway": _default_gateway(est, address),
                    # `[]` here would claim the device has no resolvers
                    # configured. It has some; this export does not know them.
                    "nameservers": None,
                } for address in sorted(iface.addresses)],
            })
        uplinks.append({
            # The Dashboard joins these rows to the device list by serial. With
            # no serial in this estate the name is carried alongside so the
            # normalizer can still attribute the addresses. Dropping them
            # instead would put the AP in the inventory with no address at all
            # -- and an AP with no address is invisible to the containment pass,
            # which is the only thing that attaches it to the picture.
            "serial": dev.serial or None,
            "name": dev.name,
            "networkId": None,
            "uplinks": slots,
        })

    # The MX appliance VLAN table. EMPTY BECAUSE THIS ESTATE HAS NO MX, not
    # because the call failed -- and the endpoint is emitted with its empty list
    # rather than omitted, so the normalizer can tell those two apart. An omitted
    # key is an export we could not read; `[]` is an org with no appliance in it.
    vlans = [
        {
            "id": v.vlan_id,
            "name": v.name,
            "subnet": v.subnet,
            "applianceIp": v.gateway,
        }
        for v in sorted(est.vlans, key=lambda v: v.vlan_id)
        if keys.intersection(v.on_devices)
    ]

    return {
        MERAKI_DEVICES: devices,
        MERAKI_UPLINK_ADDRESSES: uplinks,
        MERAKI_APPLIANCE_VLANS: vlans,
    }
