"""Fortinet normalizer: FortiManager's device DB and a FortiGate read -> topology.

⚠ THE ONE THING THIS MODULE EXISTS FOR
--------------------------------------
FortiManager answers **HTTP 200 to calls that failed**. The transport succeeded;
the request did not. Whether it worked is carried in `result[].status.code`, and
a reader that skips it gets a well-formed envelope with an empty (or absent)
`data` array — which ingests cleanly, reports "0 devices", and is
indistinguishable from an estate that genuinely has no firewalls in it.

That is not a parsing nicety. "0 devices" reads to a reviewer as a clean run, and
the whole product is the claim that an empty result and a failed one never look
alike here. So `_require_status` refuses the block, naming the code and the URL,
and a missing status block is refused too: the code is the only thing that makes
this envelope readable, and its absence means we cannot tell.

What each rung contributes, and why both exist
----------------------------------------------
FortiManager (aggregator) knows platform, firmware, HA membership and the
NORMALIZED INTERFACES its policies reference — for every box it manages, all of
it second-hand. It does not know whether a port is up, so every interface it
yields carries `admin_up=None`.

A FortiGate read (device tier) knows this box's interfaces, their addresses,
their admin state and its own HA stanza — and nothing about a box it is neither
clustered nor fabric-joined with. It does not report its own model through any
of the four tables read here, so `model` stays None and the aggregator fills it.

Neither is a superset of the other. That is the ladder working, not a gap.

What it will not do
-------------------
  * It emits NO PolicyRecords. Both Fortinet consoles carry policy, and reading
    it is a separate job; a normalizer that quietly started producing grants
    here would move the snapshot fingerprint and every finding count with it.
  * It does not parse interface descriptions into links. The estate's
    descriptions name the peer exactly as real configs do, and a description is
    a string an operator typed once — a stale one is the most common way a
    reconstructed topology grows a cable that was unplugged years ago.
  * It does not turn an SD-WAN member's `gateway` into a `routing` link. A
    gateway is an ADDRESS; the device holding it is not in a single-box read,
    and inventing one is how a picture grows a router nobody owns.
  * It does not read a Security Fabric tree polled from a non-root member. That
    read silently omits everything upstream, so it arrives looking like a
    complete smaller fabric — the same empty-versus-failed confusion in a
    different costume.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from ..models import NetDevice, NetInterface, NetLink, Provenance, Vlan
from ..netaddr import parse_net
from ..sources import tier_of
from .common import NormalizeResult
from .profile import NormalizeError

FORTIMANAGER = "fortimanager"
FORTIGATE = "fortigate"

FM_TIER = tier_of(FORTIMANAGER)
FG_TIER = tier_of(FORTIGATE)

# The FortiOS tables this module reads. Used to recognise a FortiGate payload and
# to name the path a fact came from in its `raw_ref`.
FG_INTERFACE = "cmdb/system/interface"
FG_SDWAN = "cmdb/system/sdwan"
FG_HA = "cmdb/system/ha"
FG_CSF = "monitor/system/csf"
FG_PATHS = (FG_INTERFACE, FG_SDWAN, FG_HA, FG_CSF)

# Platform string -> the role that platform DECLARES. Prefix-matched, lowercased.
#
# FortiSwitch is deliberately absent. `l2_switch` and `l3_switch` are distinct
# roles in this model because whether a switch routes decides whether inter-VLAN
# traffic is a policy decision on that box — and a platform string does not say
# which. `topology.reconstruct` derives that from the SVIs the device actually
# holds; guessing it here would overwrite an observation with a label.
_DECLARED_ROLE: tuple[tuple[str, str], ...] = (
    ("fortigate", "firewall"),
    ("fortiwifi", "firewall"),
    ("fortiap", "wireless_ap"),
)

# FortiManager's HA vocabulary -> the canonical one. Anything else is carried
# through as the console spelled it: `ha_role` is free text, and an operator
# recognising their own word for it beats a normalizer dropping what it does not
# know.
_HA_ROLE = {"master": "primary", "slave": "secondary",
            "primary": "primary", "secondary": "secondary"}

# FortiOS's own spelling for "this interface holds no address". It must never
# become 0.0.0.0/0: an unnumbered port read as a default route puts every device
# in the estate inside one block, and `topology.reconstruct` would then draw a
# containment link from everything to everything.
_UNNUMBERED = ipaddress.IPv4Address("0.0.0.0")


# ── Shared helpers ─────────────────────────────────────────────────────────

def _int(value: Any) -> Optional[int]:
    """An int field, or None. `bool` is excluded — `True` is a flag, not a 1."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: Any) -> Optional[str]:
    """A trimmed string, or None for absent/blank/non-string.

    Blank collapses to None: `ha_group_name: ""` is FortiManager for "this
    device is standalone", and storing the empty string would put a cluster on
    the picture whose name is nothing.
    """
    return value.strip() or None if isinstance(value, str) else None


def _declared_role(platform: Optional[str]) -> tuple[str, str]:
    """(role, role_source) for a platform string. ("unknown", "unknown") if silent.

    Leaving a role unknown is the correct answer, not a degraded one — the
    reconstruction engine derives roles it was not told, from what the device
    terminates, and a normalizer that guessed on its behalf would replace an
    observation with a vendor prefix.
    """
    name = (platform or "").lower()
    for prefix, role in _DECLARED_ROLE:
        if name.startswith(prefix):
            return role, "declared"
    return "unknown", "unknown"


def _ha_links(members: list[tuple[str, str, str]], tool: str, tier: str,
              stanza: str) -> list[NetLink]:
    """An HA cluster, rendered as links between its members.

    `evidence='config'` and not a cable, because that is exactly what it is: two
    devices naming one group in a config stanza. The heartbeat port is not in
    either table read here, so both ends carry no interface — None means "not
    reported", which is true.

    The link key names the ADJACENCY and not the observation, so FortiManager's
    view of a cluster and the cluster members' own view of it collapse to one
    line on the picture instead of drawing the pair twice.
    """
    by_group: dict[str, list[tuple[str, str]]] = {}
    for device_key, group, note in members:
        by_group.setdefault(group, []).append((device_key, note))

    out: list[NetLink] = []
    for group in sorted(by_group):
        pair = sorted(by_group[group])
        notes = {device: note for device, note in pair}
        for index, (a, _) in enumerate(pair):
            for b, _ in pair[index + 1:]:
                detail = (f"{a} and {b} both declare HA group {group!r} in {stanza} "
                          f"— a config stanza, not a cable")
                extra = "; ".join(n for n in (notes[a], notes[b]) if n)
                out.append(NetLink(
                    link_key=f"ha:{group}:{a}~{b}",
                    a_device=a, b_device=b,
                    evidence="config",
                    evidence_detail=f"{detail} ({extra})" if extra else detail,
                    provenance=Provenance(source_tool=tool, source_tier=tier,
                                          raw_ref=group, simulated=True),
                ))
    return out


# ── FortiManager ───────────────────────────────────────────────────────────

def _require_status(block: Any, index: int) -> dict:
    """Refuse a result block that did not succeed. THE load-bearing check.

    See the module docstring: FortiManager returns HTTP 200 for a call that
    failed, and the only thing that says otherwise is this code. A non-zero code
    with an empty `data` is the exact shape that would otherwise ingest as "this
    ADOM has no firewalls in it".

    A missing or non-integer status is refused for the same reason rather than
    being treated as success: absence of the only readable signal is not
    evidence that the call worked.
    """
    if not isinstance(block, dict):
        raise NormalizeError(
            f"{FORTIMANAGER}: result block #{index} is a {type(block).__name__}, "
            f"not a JSON-RPC result"
        )
    url = _text(block.get("url")) or f"result block #{index}"
    status = block.get("status")
    if not isinstance(status, dict):
        raise NormalizeError(
            f"{FORTIMANAGER}: {url} carries no status block. FortiManager answers "
            f"HTTP 200 to calls that failed; without result[].status.code there is "
            f"no way to tell this apart from a successful empty read"
        )
    code = _int(status.get("code"))
    if code is None:
        raise NormalizeError(
            f"{FORTIMANAGER}: {url} carries status.code "
            f"{status.get('code')!r}, which is not a status code"
        )
    if code != 0:
        message = _text(status.get("message")) or "no message"
        raise NormalizeError(
            f"{FORTIMANAGER}: {url} failed with status code {code} ({message}). "
            f"The HTTP response was 200 and the data array is not a device "
            f"inventory — it is the absence of one"
        )
    return block


def _rpc_data(block: dict) -> list[dict]:
    """The rows of a result block whose status has already been cleared.

    `data: null` and a missing `data` are accepted as empty ONLY because the
    status code said the call succeeded. Every bit of weight in that sentence
    rests on `_require_status` having run first.
    """
    data = block.get("data")
    if data is None:
        return []
    if not isinstance(data, list):
        raise NormalizeError(
            f"{FORTIMANAGER}: {_text(block.get('url')) or 'a result block'} carries "
            f"data of type {type(data).__name__}, which is not a row set"
        )
    return [row for row in data if isinstance(row, dict)]


def _fm_os_version(row: dict) -> Optional[str]:
    """FortiManager's three firmware columns -> one canonical string.

    `os_ver` is the major TRAIN, enumerated as "7.0"; `mr` and `patch` carry the
    rest. FortiOS reports the same firmware as `v7.4.3`. One estate, two
    spellings — and a firewall that appears twice because its firmware column
    differs per source is the defect this reassembly prevents.
    """
    os_ver = row.get("os_ver")
    if isinstance(os_ver, int) and not isinstance(os_ver, bool):
        os_ver = str(os_ver)
    if not isinstance(os_ver, str) or not os_ver.strip():
        return None
    os_ver = os_ver.strip()
    major = os_ver.split(".")[0]
    if not major.isdigit():
        return None
    mr, patch = _int(row.get("mr")), _int(row.get("patch"))
    if mr is None:
        # Only the train is known. Reported as the train, not padded with zeros
        # that would read as a specific patch level nobody stated.
        return f"FortiOS {os_ver}"
    nums = [major, str(mr)] + ([str(patch)] if patch is not None else [])
    return "FortiOS " + ".".join(nums)


def _fm_device(row: dict) -> Optional[NetDevice]:
    """One `/dvmdb/adom/{adom}/device` row -> a NetDevice.

    `raw_ref` is the SERIAL when the row carries one: it is the identity an
    operator can search FortiManager by and the one that survives a rename.

    `site` is left None even though FortiManager returns an ADOM. An ADOM is an
    administrative partition, not a place — filing every managed firewall under
    a site called "root" would be an invented fact on a screen that groups by
    location.
    """
    name = _text(row.get("name"))
    if name is None:
        raise NormalizeError(
            f"{FORTIMANAGER}: a device row carries no name; a managed device "
            f"cannot be keyed, and dropping it silently would shrink the estate"
        )
    platform = _text(row.get("platform_str"))
    role, role_source = _declared_role(platform)
    serial = _text(row.get("sn"))
    ha_role = _text(row.get("ha_role"))
    return NetDevice(
        device_key=name,
        name=name,
        role=role,
        role_source=role_source,
        role_reason=(f"FortiManager manages it as a {platform}" if role_source == "declared"
                     else ""),
        # Every device in a FortiManager device DB is a Fortinet device by
        # construction; that much the console does state.
        vendor="Fortinet",
        model=platform,
        os_version=_fm_os_version(row),
        serial=serial,
        mgmt_ip=_text(row.get("ip")),
        ha_group=_text(row.get("ha_group_name")),
        ha_role=_HA_ROLE.get((ha_role or "").lower(), ha_role),
        provenance=Provenance(source_tool=FORTIMANAGER, source_tier=FM_TIER,
                              raw_ref=serial or name, simulated=True),
    )


def _local_intfs(mapping: dict) -> list[str]:
    """`local-intf`, which FortiManager returns as a list and sometimes as a string."""
    value = mapping.get("local-intf")
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [v.strip() for v in value if isinstance(v, str) and v.strip()]
    return []


def _fm_interfaces(rows: list[dict], devices: dict[str, NetDevice]) -> list[NetInterface]:
    """`obj/dynamic/interface` -> the ports FortiManager's policies resolve to.

    A FortiManager policy never names a port; it names a NORMALIZED INTERFACE,
    which each managed device maps to one of its own. Resolving it is the whole
    job: `sources.py` records that you must resolve PER DEVICE before falling
    back to the per-PLATFORM mapping, "or the zone graph is fiction" — a
    device-specific mapping silently losing to a platform default puts policy on
    the wrong port, on the right-looking picture.

    Two things this refuses to do:

      * It will not invent a zone. When the normalized name EQUALS the local
        port it maps to — which is what FortiManager creates by default as
        devices are added — there is no abstraction, and labelling that port
        with a zone called "port1" would put a security construct on the picture
        that nobody configured.
      * It will not name a device this export did not describe. A mapping whose
        `_scope` points outside the returned device list is skipped: the
        aggregator told us a policy references that box, not what that box is.

    Every interface it yields carries `admin_up=None`. FortiManager's policy
    objects say this port EXISTS and which normalized interface it answers to.
    They say nothing whatever about whether it is up, and None is how this model
    spells that.
    """
    found: dict[str, NetInterface] = {}

    def remember(device_key: str, port: str, obj_name: str) -> None:
        key = f"{device_key}:{port}"
        if key in found:
            return
        found[key] = NetInterface(
            interface_key=key,
            device_key=device_key,
            name=port,
            zone=obj_name if obj_name != port else None,
            provenance=Provenance(
                source_tool=FORTIMANAGER, source_tier=FM_TIER,
                raw_ref=f"obj/dynamic/interface/{obj_name}:{port}", simulated=True,
            ),
        )

    for row in sorted(rows, key=lambda r: str(r.get("name", ""))):
        obj_name = _text(row.get("name"))
        if obj_name is None:
            raise NormalizeError(
                f"{FORTIMANAGER}: a dynamic interface object carries no name; it is "
                f"the name policies reference and nothing resolves without it"
            )
        mappings = row.get("dynamic_mapping")
        mapped: list[str] = []
        for mapping in mappings if isinstance(mappings, list) else []:
            if not isinstance(mapping, dict):
                continue
            scopes = mapping.get("_scope")
            for scope in scopes if isinstance(scopes, list) else []:
                device_key = _text(scope.get("name")) if isinstance(scope, dict) else None
                if device_key is None or device_key not in devices:
                    continue
                mapped.append(device_key)
                for port in _local_intfs(mapping):
                    remember(device_key, port, obj_name)

        # Per-platform fallback, and ONLY for devices no per-device mapping
        # covered. This ordering is the one `sources.py` warns about.
        platforms = row.get("platform_mapping")
        for entry in platforms if isinstance(platforms, list) else []:
            if not isinstance(entry, dict):
                continue
            platform = _text(entry.get("name"))
            port = _text(entry.get("intf-zone"))
            if platform is None or port is None:
                continue
            for device_key in sorted(devices):
                if device_key in mapped:
                    continue
                if (devices[device_key].model or "").lower() == platform.lower():
                    remember(device_key, port, obj_name)

    return [found[key] for key in sorted(found)]


def normalize_fortimanager(raw: dict) -> NormalizeResult:
    """A FortiManager JSON-RPC response -> the fleet it manages.

    Every result block is status-checked, including the ones this module does not
    read: a failed call is a failed call whether or not we wanted its rows, and
    ingesting the rest of the envelope around it would report a partial read as a
    whole one.
    """
    result = raw.get("result")
    if not isinstance(result, list) or not result:
        raise NormalizeError(
            f"{FORTIMANAGER}: the response carries no result blocks; a JSON-RPC "
            f"envelope with nothing in it is a failed call, not an empty ADOM"
        )

    device_rows: list[dict] = []
    dynamic_rows: list[dict] = []
    for index, block in enumerate(result, start=1):
        _require_status(block, index)
        url = _text(block.get("url")) or ""
        if url.endswith("/device"):
            device_rows.extend(_rpc_data(block))
        elif url.endswith("/obj/dynamic/interface"):
            dynamic_rows.extend(_rpc_data(block))

    res = NormalizeResult()
    devices: dict[str, NetDevice] = {}
    for row in device_rows:
        device = _fm_device(row)
        if device is not None:
            devices.setdefault(device.device_key, device)

    res.devices = [devices[key] for key in sorted(devices)]
    res.interfaces = _fm_interfaces(dynamic_rows, devices)
    res.links = _ha_links(
        [(d.device_key, d.ha_group, f"{d.device_key} is {d.ha_role}" if d.ha_role else "")
         for d in res.devices if d.ha_group],
        FORTIMANAGER, FM_TIER, "the FortiManager device DB",
    )
    return res


# ── FortiGate (direct) ─────────────────────────────────────────────────────

def _require_http_ok(host: str, path: str, block: Any) -> dict:
    """Refuse a FortiOS response that did not succeed.

    Same discipline as the FortiManager status check, for the same reason: a
    table we could not read is not a table with nothing in it. A response
    carrying no `http_status` is refused rather than assumed fine.
    """
    if not isinstance(block, dict):
        raise NormalizeError(
            f"{FORTIGATE}: {host} {path} is a {type(block).__name__}, not a response"
        )
    http_status = _int(block.get("http_status"))
    if http_status is None:
        raise NormalizeError(
            f"{FORTIGATE}: {host} {path} carries no http_status; an unreadable "
            f"response is not an empty table"
        )
    if http_status != 200:
        raise NormalizeError(
            f"{FORTIGATE}: {host} {path} returned HTTP {http_status}"
        )
    status = _text(block.get("status"))
    if status is not None and status.lower() != "success":
        raise NormalizeError(
            f"{FORTIGATE}: {host} {path} returned status {status!r}"
        )
    return block


def _fg_serial(host: str, blocks: dict) -> Optional[str]:
    """The serial every block of this host's read agrees on.

    Two different serials under one hostname means two boxes' responses were
    merged into one capture. That is refused: the rows would be attributed to
    whichever device the key happened to name, and a firewall's interfaces
    appearing on its HA peer is worse than no read at all.
    """
    serials = sorted({s for s in (_text(b.get("serial")) for b in blocks.values()
                                  if isinstance(b, dict)) if s})
    if len(serials) > 1:
        raise NormalizeError(
            f"{FORTIGATE}: the blocks captured for {host} carry {len(serials)} "
            f"different serials ({', '.join(serials)}); they are not one device"
        )
    return serials[0] if serials else None


def _fg_os_version(blocks: dict) -> Optional[str]:
    """FortiOS's `v7.4.3` -> the canonical "FortiOS 7.4.3". See `_fm_os_version`."""
    for block in blocks.values():
        version = _text(block.get("version")) if isinstance(block, dict) else None
        if version:
            return f"FortiOS {version.lstrip('vV')}"
    return None


def _fg_address(host: str, name: str, value: Any) -> Optional[str]:
    """FortiOS's `ip` -> a CIDR, or None for an unnumbered port.

    FortiOS writes an address as `"10.0.0.1 255.255.255.0"`, and some builds as
    a two-element list. `0.0.0.0 0.0.0.0` means the port holds no address at all
    and returns None — reading it as 0.0.0.0/0 would put every device in the
    estate inside one block and make them all adjacent.
    """
    if isinstance(value, list) and len(value) == 2:
        value = " ".join(str(v) for v in value)
    token = _text(value)
    if token is None:
        return None
    parts = token.replace("/", " ").split()
    if len(parts) != 2:
        raise NormalizeError(
            f"{FORTIGATE}: {host} {FG_INTERFACE}/{name} carries ip {token!r}, "
            f"which is not an address and a mask"
        )
    try:
        itf = ipaddress.ip_interface(f"{parts[0]}/{parts[1]}")
    except ValueError as exc:
        raise NormalizeError(
            f"{FORTIGATE}: {host} {FG_INTERFACE}/{name} carries ip {token!r}, "
            f"which does not parse as an address"
        ) from exc
    if itf.ip == _UNNUMBERED:
        return None
    return str(itf)


def _fg_addresses(host: str, name: str, entry: dict) -> list[str]:
    """The primary address plus any secondaries, in the order FortiOS lists them."""
    out: list[str] = []
    primary = _fg_address(host, name, entry.get("ip"))
    if primary is not None:
        out.append(primary)
    secondaries = entry.get("secondaryip")
    for secondary in secondaries if isinstance(secondaries, list) else []:
        if not isinstance(secondary, dict):
            continue
        extra = _fg_address(host, name, secondary.get("ip"))
        if extra is not None and extra not in out:
            out.append(extra)
    return out


def _fg_vlan_id(name: str, entry: dict) -> Optional[int]:
    """The VLAN a subinterface tags, from `vlanid` or from its own name.

    `vlanid: 0` is FortiOS for "this is not a VLAN subinterface". Ingesting it as
    VLAN 0 would invent a broadcast domain and hang every physical port off it.

    The dotted-name fallback (`port5.30` -> 30) is there because a FortiOS VLAN
    subinterface IS named `<parent>.<vlanid>`, and some exports carry the name
    without the field.
    """
    vlan_id = _int(entry.get("vlanid"))
    if vlan_id is not None and vlan_id > 0:
        return vlan_id
    if "." in name:
        suffix = name.rsplit(".", 1)[1]
        if suffix.isdigit() and int(suffix) > 0:
            return int(suffix)
    return None


def _fg_speed(value: Any) -> Optional[int]:
    """FortiOS's `speed` -> Mbps, or None.

    `auto` returns None on purpose: auto-negotiation is a SETTING, not a measured
    rate, and putting a number on the picture that nobody observed is the same
    class of defect as inventing a link.
    """
    token = _text(value)
    if token is None:
        return None
    digits = ""
    for char in token:
        if not char.isdigit():
            break
        digits += char
    return int(digits) if digits else None


def _fg_admin_up(entry: dict) -> Optional[bool]:
    """`status` -> admin_up. Absent stays None.

    This is the ADMIN state (`cmdb`), which is what `admin_up` means; the
    operational state lives in `monitor/system/interface`, which this read does
    not take, so `oper_up` is left unreported rather than mirrored from here.
    """
    return {"up": True, "down": False}.get((_text(entry.get("status")) or "").lower())


def _fg_interface(host: str, entry: dict) -> NetInterface:
    name = _text(entry.get("name"))
    if name is None:
        raise NormalizeError(
            f"{FORTIGATE}: {host} {FG_INTERFACE} carries an entry with no name"
        )
    return NetInterface(
        interface_key=f"{host}:{name}",
        device_key=host,
        name=name,
        # `alias` is the short label, `description` the long one; either is the
        # operator's own words. Neither is parsed for peers — see the module
        # docstring on stale descriptions.
        description=_text(entry.get("description")) or _text(entry.get("alias")),
        addresses=_fg_addresses(host, name, entry),
        vlan_id=_fg_vlan_id(name, entry),
        admin_up=_fg_admin_up(entry),
        speed_mbps=_fg_speed(entry.get("speed")),
        provenance=Provenance(source_tool=FORTIGATE, source_tier=FG_TIER,
                              raw_ref=f"{FG_INTERFACE}/{name}", simulated=True),
    )


def _fg_vlans(interfaces: list[NetInterface]) -> list[Vlan]:
    """The VLANs the interface table declares, and the blocks they carry.

    `name` and `gateways` stay empty: a FortiGate knows the tag on its own
    subinterface and the address that subinterface holds. It does not know what
    the VLAN is CALLED on the switch that owns it, and the gateway for the
    segment is an SVI somewhere else — a source that filled those in from its own
    interface would be describing the wrong device.
    """
    found: dict[int, dict[str, Any]] = {}
    for iface in interfaces:
        if iface.vlan_id is None:
            continue
        entry = found.setdefault(iface.vlan_id, {"devices": [], "subnets": [], "ref": ""})
        if iface.device_key not in entry["devices"]:
            entry["devices"].append(iface.device_key)
        for address in iface.addresses:
            net = parse_net(address)
            if net is not None and str(net) not in entry["subnets"]:
                entry["subnets"].append(str(net))
        entry["ref"] = entry["ref"] or iface.provenance.raw_ref
    return [
        Vlan(
            vlan_id=vlan_id,
            subnets=sorted(found[vlan_id]["subnets"]),
            device_keys=sorted(found[vlan_id]["devices"]),
            provenance=Provenance(source_tool=FORTIGATE, source_tier=FG_TIER,
                                  raw_ref=found[vlan_id]["ref"], simulated=True),
        )
        for vlan_id in sorted(found)
    ]


def _csf_node_name(host: str, node: dict) -> str:
    name = _text(node.get("name")) or _text(node.get("hostname"))
    if name is None:
        raise NormalizeError(
            f"{FORTIGATE}: {host} {FG_CSF} returned a fabric member with no name "
            f"(serial {_text(node.get('serial')) or 'unknown'}); dropping it would "
            f"report a smaller fabric than the one that answered"
        )
    return name


def _fg_csf(host: str, block: dict) -> tuple[Optional[str], list[NetDevice], list[NetLink]]:
    """The Security Fabric tree -> the root's own address, and its downstream tree.

    This is what the control plane on TCP/8013 registered — there is no API of
    its own, you read what it left behind, and ONLY from the root. A tree whose
    root node says `is_root: false` came from polling a leaf, which silently
    omits everything upstream and therefore arrives looking like a complete
    smaller fabric. That is refused rather than read.

    Downstream members are emitted as devices and as `api_topology` links: the
    console returned this adjacency as topology, which is exactly what that
    evidence class names. The HA PEER is not in this tree — a cluster is one
    fabric node, listed in `ha_members` — so the pair is linked once, from its
    config stanza, rather than drawn twice.
    """
    tree = block.get("results")
    if not isinstance(tree, dict) or not tree:
        raise NormalizeError(
            f"{FORTIGATE}: {host} {FG_CSF} returned no fabric tree"
        )
    if not tree.get("is_root"):
        raise NormalizeError(
            f"{FORTIGATE}: {host} {FG_CSF} was polled from a non-root fabric member. "
            f"A leaf read omits everything upstream of it, so it reads as a smaller "
            f"fabric rather than as a partial capture — poll the fabric root instead"
        )

    devices: list[NetDevice] = []
    links: list[NetLink] = []

    def walk(node: dict, parent: Optional[str]) -> None:
        name = _csf_node_name(host, node)
        serial = _text(node.get("serial"))
        if parent is not None:
            devices.append(NetDevice(
                device_key=name, name=name,
                role="firewall", role_source="declared",
                role_reason=f"registered with the Security Fabric root {host} as a "
                            f"downstream FortiGate",
                vendor="Fortinet",
                mgmt_ip=_text(node.get("ip")),
                serial=serial,
                provenance=Provenance(source_tool=FORTIGATE, source_tier=FG_TIER,
                                      raw_ref=f"{FG_CSF}/{serial or name}",
                                      simulated=True),
            ))
            links.append(NetLink(
                link_key=f"csf:{parent}~{name}",
                a_device=parent, b_device=name,
                evidence="api_topology",
                evidence_detail=(f"the Security Fabric tree returned by {host} lists "
                                 f"{name} as a member registered beneath {parent}"),
                provenance=Provenance(source_tool=FORTIGATE, source_tier=FG_TIER,
                                      raw_ref=f"{FG_CSF}/{serial or name}",
                                      simulated=True),
            ))
        children = node.get("children")
        for child in children if isinstance(children, list) else []:
            if isinstance(child, dict):
                walk(child, name)

    walk(tree, None)
    root_ip = _text(tree.get("ip")) if _csf_node_name(host, tree) == host else None
    return root_ip, devices, links


def _fg_ha_note(results: dict) -> str:
    """`priority` / `override` for the HA link's evidence detail.

    Read because a real export carries them and they are what decides which
    member holds primary. They are not turned into a role: the knobs are not the
    outcome, and a FortiGate that lost an election still has the higher priority.
    """
    bits = []
    priority = _int(results.get("priority"))
    if priority is not None:
        bits.append(f"priority {priority}")
    override = _text(results.get("override"))
    if override is not None:
        bits.append(f"override {override}")
    return ", ".join(bits)


def normalize_fortigate(raw: dict) -> NormalizeResult:
    """A set of FortiOS reads, keyed by hostname then by path, -> topology.

    Keyed by hostname because FortiOS's own response envelope identifies the box
    by serial only, and a firewall arriving under its serial from one source and
    its hostname from another is one firewall drawn as two.
    """
    res = NormalizeResult()
    devices: dict[str, NetDevice] = {}
    interfaces: list[NetInterface] = []
    links: list[NetLink] = []
    ha_members: list[tuple[str, str, str]] = []

    for host in sorted(raw):
        blocks = raw[host]
        if not isinstance(blocks, dict) or not blocks:
            raise NormalizeError(
                f"{FORTIGATE}: {host} carries no response blocks"
            )
        for path in sorted(blocks):
            _require_http_ok(host, path, blocks[path])

        serial = _fg_serial(host, blocks)
        ha_group: Optional[str] = None
        ha_note = ""
        ha_block = blocks.get(FG_HA)
        if isinstance(ha_block, dict) and isinstance(ha_block.get("results"), dict):
            ha_group = _text(ha_block["results"].get("group-name"))
            ha_note = _fg_ha_note(ha_block["results"])

        mgmt_ip: Optional[str] = None
        if FG_CSF in blocks:
            root_ip, fabric_devices, fabric_links = _fg_csf(host, blocks[FG_CSF])
            mgmt_ip = root_ip
            for device in fabric_devices:
                devices.setdefault(device.device_key, device)
            links.extend(fabric_links)

        interface_block = blocks.get(FG_INTERFACE)
        results = interface_block.get("results") if isinstance(interface_block, dict) else None
        for entry in results if isinstance(results, list) else []:
            if isinstance(entry, dict):
                interfaces.append(_fg_interface(host, entry))

        # `cmdb/system/sdwan` was status-checked above and is read for nothing
        # else, deliberately: a member names an interface the table above
        # already described, and its `gateway` is an ADDRESS whose device is not
        # in a single-box read — see the module docstring on why that does not
        # become a `routing` link.
        devices[host] = NetDevice(
            device_key=host,
            name=host,
            role="firewall",
            role_source="declared",
            role_reason="read directly from FortiOS: the device answering "
                        "cmdb/system/interface is a FortiGate",
            vendor="Fortinet",
            # NOT reported by any of the four tables read here. The aggregator
            # knows the platform; this rung does not, and None says so.
            model=None,
            os_version=_fg_os_version(blocks),
            serial=serial,
            mgmt_ip=mgmt_ip,
            ha_group=ha_group,
            # The HA stanza names the cluster, not who is leading it. That is an
            # election outcome, and it lives in a table this read does not take.
            ha_role=None,
            provenance=Provenance(source_tool=FORTIGATE, source_tier=FG_TIER,
                                  raw_ref=serial or host, simulated=True),
        )
        if ha_group:
            ha_members.append((host, ha_group, ha_note))

    links.extend(_ha_links(ha_members, FORTIGATE, FG_TIER, "cmdb/system/ha"))

    res.devices = [devices[key] for key in sorted(devices)]
    res.interfaces = sorted(interfaces, key=lambda i: i.interface_key)
    res.links = sorted(links, key=lambda l: l.link_key)
    res.vlans = _fg_vlans(res.interfaces)
    return res


# ── Entry point ────────────────────────────────────────────────────────────

def normalize(raw: dict) -> NormalizeResult:
    """Normalize either Fortinet payload, dispatched on its own shape.

    There is no discriminator field to read, because neither vendor payload has
    one — adding a wrapper would mean this module could only read exports it had
    produced itself. A payload that is neither shape is refused rather than
    returned empty: "we could not tell what this file was" and "this console
    manages nothing" are the two facts that must never look alike here.
    """
    if not isinstance(raw, dict) or not raw:
        raise NormalizeError(
            "fortinet: the payload is empty; there is nothing to tell a failed "
            "export apart from a console with no devices on it"
        )
    if "result" in raw:
        return normalize_fortimanager(raw)
    if any(isinstance(block, dict) and any(path in block for path in FG_PATHS)
           for block in raw.values()):
        return normalize_fortigate(raw)
    raise NormalizeError(
        "fortinet: the payload is neither a FortiManager JSON-RPC envelope (a "
        "'result' array) nor a FortiOS read (blocks keyed by "
        f"{', '.join(FG_PATHS)})"
    )
