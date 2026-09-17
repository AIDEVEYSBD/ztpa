"""Fortinet console projections: FortiManager's device DB, and a FortiGate read.

Two consoles, two rungs of the ladder, two different depths — which is the whole
reason both exist here rather than one "Fortinet export". FortiManager is an
AGGREGATOR: it knows platform, firmware, HA membership and the normalized
interfaces its policies reference, for every box it manages, and it knows them
second-hand. A FortiGate read is DEVICE tier: it knows this box's interfaces,
their addresses and their admin state, and it knows nothing about any box it is
not clustered or fabric-joined with. Neither is a superset of the other, and the
picture is assembled from both.

What these projections will not do
----------------------------------
Every value below comes from `src.estate`. Where the estate is silent, the
payload carries the vendor's own "not stated" token (`conn_status: "unknown"`,
`alias: ""`, an absent `speed`) or omits the key — it never carries a plausible
default. The distinction matters more here than anywhere else in the codebase,
because a FortiManager payload is the one an operator is most likely to believe
verbatim: `conn_status: "up"` is a claim that the manager currently holds a
tunnel to that firewall, and nothing in this estate measured that.

Two fields are therefore missing from the shapes below on purpose, and both are
named in the module that would otherwise want them:

  * `cmdb/system/ha` carries `priority` and `override` in a real export. They
    decide WHICH member holds primary; the estate states the outcome (`ha_role`)
    and not the knobs, so the projection omits them rather than shipping
    FortiOS's defaults on both members. The normalizer reads them when a real
    export supplies them.
  * `obj/dynamic/interface` carries `platform_mapping` in a real export. The
    estate declares no platform-level mapping, so none is emitted; the
    normalizer implements the per-device-before-per-platform resolution order
    anyway, because getting that order wrong is what `sources.py` warns makes
    "the zone graph fiction".
"""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from ..estate import DeviceSpec, Estate, IfaceSpec

FORTIMANAGER = "fortimanager"
FORTIGATE = "fortigate"

ADOM = "root"
VDOM = "root"

DEVICE_URL = f"/dvmdb/adom/{ADOM}/device"
DYNAMIC_INTERFACE_URL = f"/pm/config/adom/{ADOM}/obj/dynamic/interface"

# FortiOS's own spelling for "this interface holds no address". It must never be
# read as 0.0.0.0/0: an unnumbered port ingested as a default route would put
# every device in the estate inside one block, and `topology.reconstruct` would
# then draw a containment link from everything to everything.
UNNUMBERED = "0.0.0.0 0.0.0.0"

# The estate's HA vocabulary -> FortiManager's. Two spellings of one fact; the
# normalizer maps them back, so a picture built from FortiManager and a picture
# built from the box agree on which member is primary.
_FM_HA_ROLE = {"primary": "master", "secondary": "slave"}


def _ok() -> dict[str, Any]:
    """A fresh success status block.

    A fresh one per call, rather than a module-level constant, because these
    payloads are handed to callers that may mutate them — a shared status dict
    is how one test's edit to a failure code would reach every other caller.
    """
    return {"code": 0, "message": "OK"}


# ── Firmware, spelled two ways ─────────────────────────────────────────────
#
# One estate fact ("FortiOS 7.4.3"), two vendor spellings: FortiManager stores a
# firmware as three columns (a major TRAIN `os_ver`, spelled "7.0", plus `mr` and
# `patch`), and FortiOS reports it as the string `v7.4.3`. Both are rendered from
# the same parse, so the two projections cannot drift into describing two
# different firmwares on one box.

def _version_parts(os_version: str) -> tuple[Optional[int], Optional[int], Optional[int]]:
    """"FortiOS 7.4.3" -> (7, 4, 3). Anything else -> (None, None, None).

    Returning None rather than zeros is the point: `os_ver: "0.0"` reads
    downstream as a box running a firmware nobody has, which is worse than a
    device whose firmware column is honestly blank.
    """
    digits = "".join(ch if (ch.isdigit() or ch == ".") else " " for ch in os_version)
    parts = digits.split()
    if not parts:
        return (None, None, None)
    fields = [int(p) for p in parts[-1].split(".") if p.isdigit()]
    if not fields:
        return (None, None, None)
    fields += [None, None]                              # type: ignore[list-item]
    return (fields[0], fields[1], fields[2])


def _fortios_version(os_version: str) -> Optional[str]:
    """"FortiOS 7.4.3" -> "v7.4.3", the string FortiOS puts in every response."""
    major, mr, patch = _version_parts(os_version)
    if major is None:
        return None
    nums = [str(n) for n in (major, mr, patch) if n is not None]
    return "v" + ".".join(nums)


def _fortios_ip(iface: IfaceSpec, address: str) -> str:
    """"10.254.1.2/30" -> "10.254.1.2 255.255.255.252", FortiOS's `ip` format.

    Raises on an address FortiOS could not express, rather than passing the
    token through: a projection that emits a half-valid payload turns a defect
    in the estate into a defect in every consumer of the export.
    """
    try:
        itf = ipaddress.ip_interface(address)
    except ValueError as exc:
        raise ValueError(
            f"estate interface {iface.device}:{iface.name} carries an address "
            f"FortiOS cannot express: {address!r}"
        ) from exc
    return f"{itf.ip} {itf.network.netmask}"


# ── FortiManager ───────────────────────────────────────────────────────────

def _fm_device(dev: DeviceSpec) -> dict[str, Any]:
    """One row of `/dvmdb/adom/{adom}/device`, in FortiManager's field names."""
    major, mr, patch = _version_parts(dev.os_version)
    row: dict[str, Any] = {
        "name": dev.name,
        "sn": dev.serial,
        "platform_str": dev.model,
        "ip": dev.mgmt_ip,
        # An HA pair with one primary and one secondary IS active-passive; "AP"
        # is that stated fact in FortiManager's vocabulary, not a second one.
        "ha_mode": "AP" if dev.ha_group else "standalone",
        "ha_group_name": dev.ha_group or "",
        "ha_role": _FM_HA_ROLE.get(dev.ha_role or "", dev.ha_role or ""),
        # THE MANAGER'S VIEW OF ITSELF, NOT OF THE NETWORK. `conf_status` is
        # whether the device's config matches the manager's copy and
        # `conn_status` is whether the manager currently holds a tunnel to it.
        # Both are live measurements, the estate contains neither, and FortiManager
        # has a real "unknown" for exactly this state — so "unknown" is what a
        # simulated export is entitled to say. Shipping "insync"/"up" would put a
        # health claim on a client's screen that nothing measured.
        "conf_status": "unknown",
        "conn_status": "unknown",
        "adom": ADOM,
        "vdom": [{"name": VDOM}],
    }
    if major is not None:
        # FortiManager's `os_ver` is the major TRAIN, enumerated as "7.0"/"6.0",
        # with the minor release and patch in their own columns.
        row["os_ver"] = f"{major}.0"
        if mr is not None:
            row["mr"] = mr
        if patch is not None:
            row["patch"] = patch
    return row


def _fm_dynamic_interfaces(est: Estate, devices: list[DeviceSpec]) -> list[dict[str, Any]]:
    """`obj/dynamic/interface`: the names FortiManager policies actually reference.

    A FortiManager policy never names `port1` on a device; it names a NORMALIZED
    interface, which each managed device maps to one of its own local ports.
    FortiManager creates one per port name as devices are added, which is exactly
    what this renders — every name and every mapping below is an interface the
    estate already declares on a device this console can see. Nothing an operator
    would have had to configure by hand (a zone named `untrust`, a platform-level
    mapping) is invented, because the estate declares none.

    The consequence on this estate is that every normalized name equals the local
    port it maps to, so the mapping carries no zone information — and the
    normalizer is required to notice that rather than inventing a zone called
    "port1". See `normalizers/fortinet.py`.
    """
    keys = [d.key for d in devices]
    by_name: dict[str, list[str]] = {}
    for iface in est.interfaces:
        if iface.device in keys:
            by_name.setdefault(iface.name, []).append(iface.device)
    return [
        {
            "name": name,
            "description": "",
            "single-intf": 0,
            "default-mapping": 0,
            "dynamic_mapping": [
                {"_scope": [{"name": device, "vdom": VDOM}], "local-intf": [name]}
                for device in sorted(by_name[name])
            ],
        }
        for name in sorted(by_name)
    ]


def fortimanager_export(est: Estate) -> dict[str, Any]:
    """The estate as a FortiManager JSON-RPC response.

    ⚠ THE ENVELOPE IS THE POINT. FortiManager answers HTTP 200 to a call that
    failed; the only thing that says whether it worked is `result[].status.code`.
    A reader that skips it ingests a failed call as an estate with no firewalls
    in it, reports "0 devices", and looks exactly like a clean run. That is the
    single defect class this engine exists to refuse, so the shape is rendered in
    full — status block included — rather than being flattened to a device list.
    """
    devices = sorted(est.devices_seen_by(FORTIMANAGER), key=lambda d: d.name)
    return {
        "id": 1,
        "result": [
            {
                "status": _ok(),
                "url": DEVICE_URL,
                "data": [_fm_device(d) for d in devices],
            },
            {
                "status": _ok(),
                "url": DYNAMIC_INTERFACE_URL,
                "data": _fm_dynamic_interfaces(est, devices),
            },
        ],
    }


# ── FortiGate (direct) ─────────────────────────────────────────────────────

def _fg_interface(iface: IfaceSpec) -> dict[str, Any]:
    """One row of `cmdb/system/interface`."""
    addresses = list(iface.addresses)
    entry: dict[str, Any] = {
        "name": iface.name,
        "ip": _fortios_ip(iface, addresses[0]) if addresses else UNNUMBERED,
        # FortiOS spells a tagged subinterface `<parent>.<vlanid>` and carries the
        # parent in `interface`. The estate places the management port in VLAN 10
        # without naming a parent, so `interface` stays empty: the VLAN id is an
        # observed fact and the parent port is not, and inventing one to make the
        # name look native would put a port on the box that does not exist.
        "vlanid": iface.vlan_id or 0,
        "interface": iface.name.rsplit(".", 1)[0] if "." in iface.name else "",
        # A GUI grouping hint the operator picks. FortiOS's own default is
        # "undefined" and the estate declares no interface roles, so "undefined"
        # is what this says — and the normalizer maps it to nothing, because a
        # GUI hint is not a security zone.
        "role": "undefined",
        "alias": "",
        # Carried verbatim, and NEVER parsed into a link. The estate's
        # descriptions name the peer ("to rtr-edge-01 edge-fw-1") exactly as a
        # real config does, and a description is a string an operator typed once
        # — a stale one is the most common way a reconstructed topology grows a
        # cable that was unplugged years ago.
        "description": iface.description,
    }
    if len(addresses) > 1:
        entry["secondaryip"] = [
            {"id": n, "ip": _fortios_ip(iface, addr)}
            for n, addr in enumerate(addresses[1:], start=1)
        ]
    if iface.admin_up is not None:
        entry["status"] = "up" if iface.admin_up else "down"
    if iface.speed_mbps is not None:
        entry["speed"] = f"{iface.speed_mbps}full"
    return entry


def _fg_block(dev: DeviceSpec, path: str, name: str, results: Any) -> dict[str, Any]:
    """The response envelope FortiOS wraps every table in.

    `serial` and `version` travel on every block because that is where FortiOS
    puts them — which is also what lets the normalizer refuse an export whose
    blocks came from two different boxes.
    """
    return {
        "http_method": "GET",
        "status": "success",
        "http_status": 200,
        "serial": dev.serial,
        "version": _fortios_version(dev.os_version),
        "vdom": VDOM,
        "path": path,
        "name": name,
        "results": results,
    }


def _fg_ha(dev: DeviceSpec) -> dict[str, Any]:
    """`cmdb/system/ha`. See the module docstring on `priority`/`override`."""
    if not dev.ha_group:
        return {"mode": "standalone"}
    return {"group-name": dev.ha_group, "mode": "a-p"}


def _fg_csf(dev: DeviceSpec, cluster: list[DeviceSpec]) -> dict[str, Any]:
    """`monitor/system/csf`: the Security Fabric tree, as the ROOT sees it.

    This is what the control plane on TCP/8013 (the one Fortinet's documentation
    calls FortiTelemetry) registered — it has no API of its own, you read what it
    left behind, and only from the fabric root.

    `children` is empty here and that is the honest answer, not a stub: this
    estate's only two FortiGates are the two members of ONE cluster, and a
    cluster is one fabric node. They appear in `ha_members`, which is where a
    real csf response puts them. Rendering the HA peer as a downstream CHILD
    would assert a fabric registration the estate does not contain and would draw
    a second line between two boxes that have exactly one relationship.
    """
    return {
        "name": dev.name,
        "serial": dev.serial,
        "ip": dev.mgmt_ip,
        "authorized": True,
        "is_root": True,
        "ha_members": [m.serial for m in cluster],
        "children": [],
    }


def fortigate_export(est: Estate) -> dict[str, Any]:
    """The estate as a set of FortiOS REST reads, keyed by box and then by path.

    Keyed by HOSTNAME at the top level, because FortiOS's own response envelope
    identifies the box by SERIAL only. The rest of the system keys a device on
    its name, and a firewall that arrives under its serial from one source and
    its hostname from another is one firewall drawn as two.

    `monitor/system/csf` is emitted only on the fabric root. Polling a non-root
    member returns a tree rooted at that member with everything upstream missing,
    which reads as a smaller fabric rather than as a bad capture — so the
    projection does not produce a capture we would refuse to read.
    """
    devices = sorted(est.devices_seen_by(FORTIGATE), key=lambda d: d.name)
    out: dict[str, Any] = {}
    for dev in devices:
        cluster = [d for d in devices if dev.ha_group and d.ha_group == dev.ha_group]
        blocks: dict[str, Any] = {
            "cmdb/system/interface": _fg_block(
                dev, "system", "interface",
                [_fg_interface(i) for i in sorted(est.interfaces_of(dev.key),
                                                  key=lambda i: i.name)],
            ),
            # SD-WAN IS NOT CONFIGURED IN THIS ESTATE, AND SAYS SO. The perimeter
            # pair's upstream ports would make plausible members — they face two
            # different edge routers over two /30s — and rendering them as such
            # would put a load-balancing policy, a health check and a set of
            # next-hops into a client's picture that nobody configured. The table
            # exists, disabled, which is what an unconfigured FortiGate returns.
            "cmdb/system/sdwan": _fg_block(
                dev, "system", "sdwan",
                {"status": "disable", "members": [], "health-check": []},
            ),
            "cmdb/system/ha": _fg_block(dev, "system", "ha", _fg_ha(dev)),
        }
        # The HA primary is this estate's fabric root: the member that holds the
        # cluster's identity is the one the fabric registers against.
        if dev.ha_role == "primary" and cluster:
            blocks["monitor/system/csf"] = _fg_block(
                dev, "system", "csf", _fg_csf(dev, cluster),
            )
        out[dev.name] = blocks
    return out
