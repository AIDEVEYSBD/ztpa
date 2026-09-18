"""The source registry — one place that knows what we can read and from where.

Why this module exists
----------------------
The set of ingestible tools was previously spelled out in five places that had
no way to disagree loudly: the `models.SourceTool` Literal, `profile._KNOWN_TOOLS`,
the `sources.tool` CHECK in `db/schema.sql`, `persist._DEVICE`, and the prose in
`identity.MAX_IP_FANOUT` that reasoned about "the five ingestible source tools".
Adding a tool meant editing all five and remembering why the fifth mattered;
missing one failed in a different way each time. Worst of them was
`profile.py:813`, which relabelled any record from an unrecognised tool as
`source_tool="algosec"` — so onboarding a console we had not listed did not fail,
it silently attributed that console's rules to a different vendor's product.

So the registry is the source of truth, `SourceTool` is asserted against it by
test, and the numbers that used to be reasoned about in a comment are now
derived from it.

The collection ladder
---------------------
`tier` encodes the ladder a reviewer actually walks:

    aggregator  ->  management_console  ->  device

An aggregator (AlgoSec, Panorama, FortiManager, Wiz) is broad and second-hand:
it reports what the devices it manages told it. A management console is deep on
its own vendor and blind to every other. A device read is authoritative and does
not scale. Partial onboarding is the normal case — an AlgoSec that only ever had
the perimeter firewalls added to it is extremely common — and the ladder is how
the picture degrades honestly instead of going blank: the lanes the aggregator
cannot see are named, with the console that would fill them.

One correction this registry encodes, because it is the most common wrong
assumption in the room: **AlgoSec is not a network-inventory product.** It models
enforcement points, their policies and L3 reachability, and it does that better
than anything else here. It will not enumerate an access switch, a workstation or
a VLAN on an access port. `yields` says so per tool, so a screen can set the
expectation before an operator forms it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import SourceTier


@dataclass(frozen=True)
class SourceSpec:
    """What one ingestible source is, and what it can actually tell us."""

    key: str
    label: str
    vendor: str
    tier: SourceTier
    # The API family a live connector would speak. Shown verbatim on the Sources
    # screen: "not connected" is only actionable if it says what connecting means.
    api: str
    auth: str
    # Whether this tool names HOSTS. Read by `identity.MAX_IP_FANOUT`: the merge
    # guard's bound is "one name per tool that could observe this host", so a
    # tool that only describes links (an SD-WAN fabric) must not raise it.
    describes_hosts: bool
    # What it yields, in the vocabulary of the inventory. Used to render the
    # source card and -- more importantly -- to name which source would fill a
    # lane we observed nothing in.
    yields: tuple[str, ...]
    # What it will NOT give you, stated explicitly. The most useful field on the
    # card: it is what stops an operator concluding that an empty access lane
    # means an empty access layer.
    blind_to: tuple[str, ...] = ()
    # DECLARED BY THE VENDOR'S API AND NOT READ BY THIS BUILD.
    #
    # The third category, and it existed as a lie before it existed as a field.
    # `yields` was written from the API documentation, so FortiManager's card
    # advertised "firewall policies" and "address objects" directly above
    # "CONTRIBUTED: 0 RECORDS" -- because `normalizers/fortinet.py` reads the
    # device and interface endpoints and deliberately emits no PolicyRecord.
    # Both statements were on one card, on the one screen whose entire job is
    # saying what a source gives you and what it cannot.
    #
    # `blind_to` could not hold these: a FortiGate is not blind to its own
    # firewall policy. The gap is ours, not the vendor's, and a reader deciding
    # whether to onboard a console needs to know which of the two it is.
    unread: tuple[str, ...] = ()
    # The device/console identity a record from this tool is attributed to.
    # Replaces `persist._DEVICE`, whose three-entry `.get()` wrote NULL for
    # every other tool -- and `resolved_objects` is UNIQUE on
    # (snapshot_id, source_device, object_name, object_kind), so two unlisted
    # tools with a same-named object collided on insert.
    device: str = ""
    notes: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)


REGISTRY: tuple[SourceSpec, ...] = (
    # ── Aggregators ────────────────────────────────────────────────────────
    SourceSpec(
        key="algosec", label="AlgoSec ASMS", vendor="AlgoSec", tier="aggregator",
        api="/api/v1/devices · /api/v1/interfaces · /api/v1/interfaces/routingInformation "
            "· /api/v1/deviceZones · POST /api/v1/rules/hit-count",
        auth="session cookie or basic auth over HTTPS",
        describes_hosts=True,
        yields=("firewall rules", "network objects", "enforcement points",
                "device interfaces", "networks behind interface", "routing table",
                "zones", "rule hit counts"),
        blind_to=("access switches", "workstations", "VLANs on access ports",
                  "physical cabling"),
        device="afa-edge-fw-01",
        notes="Models enforcement points and policy, not network inventory. "
              "`/interfaces` returning 'IPs behind interface' is the single most "
              "useful field available for reconstructing topology from a policy "
              "product. Its hit-count endpoint is one of only three real sources "
              "of rule staleness.",
    ),
    SourceSpec(
        key="guardicore", label="Akamai Guardicore Segmentation", vendor="Akamai",
        tier="aggregator",
        api="/api/v3.0/assets · /api/v3.0/visibility/policy",
        auth="bearer token",
        describes_hosts=True,
        yields=("labelled assets", "east-west flows", "segmentation policy"),
        blind_to=("physical devices", "interfaces", "VLANs", "circuits"),
        device="guardicore-mgmt",
    ),
    SourceSpec(
        key="wiz", label="Wiz", vendor="Wiz", tier="aggregator",
        api="GraphQL: CloudResource · NetworkExposure · GraphSearch",
        auth="OAuth2 client credentials",
        describes_hosts=True,
        yields=("cloud resources", "VPCs and subnets", "security groups",
                "public IPs", "internet-exposure paths"),
        blind_to=("on-premise devices", "physical topology", "carrier circuits"),
        device="wiz-cloud-connector",
    ),
    SourceSpec(
        key="fortimanager", label="FortiManager", vendor="Fortinet", tier="aggregator",
        api="JSON-RPC: /dvmdb/adom/{adom}/device · /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy "
            "· /pm/config/.../firewall/address",
        auth="session-based JSON-RPC login, or API user token",
        describes_hosts=True,
        yields=("managed devices", "model and firmware", "device interfaces", "ADOMs"),
        unread=("policy packages", "firewall policies", "address objects", "zones"),
        blind_to=("non-Fortinet devices", "physical cabling outside the fabric"),
        device="fortimanager-01",
        notes="Returns HTTP 200 on failure — `result[].status.code` must be parsed "
              "or an empty result ingests as success, which is exactly the failure "
              "class this engine exists to refuse. Policies reference "
              "obj/dynamic/interface (normalized interfaces), not ports: resolve "
              "per-device before per-platform mapping or the zone graph is fiction.",
    ),
    SourceSpec(
        key="panorama", label="Panorama", vendor="Palo Alto Networks", tier="aggregator",
        api="XML API type=config · REST /restapi/v10.2/Policies/SecurityRules "
            "· op rule-hit-count (Policy Optimizer)",
        auth="API key via type=keygen",
        describes_hosts=True,
        yields=("device groups", "managed firewalls", "security rules",
                "address objects", "service objects", "templates", "zones",
                "rule hit counts"),
        blind_to=("switches", "routers", "access layer", "non-PAN devices"),
        device="panorama-01",
        notes="Policy Optimizer's rule-hit-count is the cleanest source of "
              "last-hit timestamps of any vendor here.",
    ),
    SourceSpec(
        key="junos_space", label="Junos Space / Security Director", vendor="Juniper",
        tier="aggregator",
        api="/api/space/device-management/devices · /api/juniper/sd/policy-management/firewall/policies",
        auth="basic auth over HTTPS",
        describes_hosts=True,
        yields=("managed devices", "platform and OS", "device interfaces"),
        unread=("firewall policies", "address objects", "zones"),
        blind_to=("non-Juniper devices", "campus access layer unless managed"),
        device="junos-space-01",
    ),

    # ── Management consoles ────────────────────────────────────────────────
    SourceSpec(
        key="catalyst_center", label="Cisco Catalyst Center", vendor="Cisco",
        tier="management_console",
        api="/dna/intent/api/v1/network-device · /topology/physical-topology "
            "· /topology/vlan/vlan-names · /interface · /global-pool",
        auth="token from /dna/system/api/v1/auth/token",
        describes_hosts=True,
        yields=("network devices", "platform, model and OS", "interfaces", "VLANs",
                "physical topology", "CDP/LLDP neighbours"),
        unread=("IP pools", "sites"),
        blind_to=("non-Cisco devices", "cloud workloads", "firewall policy"),
        device="catalyst-center-01",
        notes="The only source here that returns physical topology and neighbour "
              "adjacency directly, which is what makes cabled links observable "
              "rather than derived from address containment.",
    ),
    SourceSpec(
        key="meraki", label="Cisco Meraki Dashboard", vendor="Cisco",
        tier="management_console",
        api="/organizations/{id}/devices · /organizations/{id}/devices/uplinks/addresses/byDevice "
            "· /networks/{id}/appliance/vlans · /networks/{id}/appliance/firewall/l3FirewallRules",
        auth="X-Cisco-Meraki-API-Key header",
        describes_hosts=True,
        yields=("devices", "model and firmware", "per-uplink private and public IP",
                "VLANs"),
        unread=("L3/L7 firewall rules", "clients", "gateway and DNS"),
        blind_to=("non-Meraki devices", "on-premise datacentre fabric"),
        device="meraki-dashboard",
        notes="`devices/uplinks/addresses/byDevice` returns the entire multi-WAN "
              "picture — per-uplink private IP, public IP, gateway, DNS, VLAN, "
              "static vs dynamic — org-wide in one paginated call. Nothing else "
              "in this registry comes close on yield per integration. Rate limit "
              "is 10 req/s shared across every application in the org, which is "
              "the binding constraint, not data availability.",
    ),

    # ── Device tier ────────────────────────────────────────────────────────
    SourceSpec(
        key="fortigate", label="FortiGate (direct)", vendor="Fortinet", tier="device",
        api="cmdb/system/interface · cmdb/system/sdwan · cmdb/system/ha "
            "· monitor/router/ipv4 · monitor/system/csf (Security Fabric)",
        auth="API token, or session with trusted-host restriction",
        describes_hosts=True,
        yields=("interfaces and VLAN subinterfaces", "SD-WAN members and health",
                "HA cluster state", "fabric device tree"),
        unread=("firewall policy", "routing table", "ARP table", "DHCP leases"),
        blind_to=("anything not behind this firewall"),
        device="fortigate-direct",
        notes="`monitor/system/csf` is what the Security Fabric control plane "
              "(the protocol on TCP/8013 that Fortinet documentation calls "
              "FortiTelemetry) populates. It has no API of its own; you read what "
              "it registered, and only from the fabric ROOT — polling a leaf "
              "silently omits everything upstream. Not to be confused with the "
              "FortiOS digital-experience-monitoring feature of the same name.",
        aliases=("fortitelemetry", "security_fabric"),
    ),

    SourceSpec(
        key="carrier_portal", label="Carrier / ISP portal", vendor="(carrier)",
        tier="device",
        api="per-carrier; often no API at all (Airtel, BSNL and most regional "
            "carriers expose a web portal only). Circuit ID, technology, "
            "assigned public block and CPE model are usually obtainable from "
            "the service order rather than from a machine interface.",
        auth="portal credentials, per circuit",
        describes_hosts=False,
        yields=("WAN circuits", "carrier and technology", "assigned public IP blocks",
                "the CPE / modem terminating each circuit", "circuit state"),
        blind_to=("anything on the customer side of the demarc",),
        device="carrier-portal",
        notes="The only source that sees the MODEM layer at all. Nothing else in "
              "this registry can tell you that two diverse-looking circuits are "
              "sold by one carrier -- which is the difference between redundancy "
              "and a correlated failure wearing its costume.",
        aliases=("isp_portal", "demarc"),
    ),

    # ── Fabric / link-describing ───────────────────────────────────────────
    SourceSpec(
        key="sd_wan", label="SD-WAN fabric", vendor="(vendor-neutral)", tier="management_console",
        api="controller inventory + circuit/overlay APIs (vManage, Versa, VeloCloud)",
        auth="varies by controller",
        describes_hosts=False,
        yields=("sites", "WAN circuits", "overlay tunnels", "underlay transports"),
        blind_to=("hosts", "LAN switching", "policy on non-fabric devices"),
        device="sdwan-controller",
    ),
    SourceSpec(
        key="sd_lan", label="SD-LAN fabric", vendor="(vendor-neutral)", tier="management_console",
        api="campus fabric controller inventory",
        auth="varies by controller",
        describes_hosts=False,
        yields=("campus fabric links", "segments"),
        blind_to=("hosts", "WAN circuits", "firewall policy"),
        device="sdlan-controller",
    ),
)

BY_KEY: dict[str, SourceSpec] = {s.key: s for s in REGISTRY}

# Every ingestible tool key, sorted. Asserted equal to `models.SourceTool`'s
# members by test, so the Literal and the registry cannot drift apart.
TOOL_KEYS: tuple[str, ...] = tuple(sorted(BY_KEY))

# The tools that name HOSTS. This is the set `identity.MAX_IP_FANOUT` is derived
# from: the guard's bound is "one name per tool that could have observed this
# host", so a fabric controller that only describes links must not widen it.
HOST_DESCRIBING_TOOLS: tuple[str, ...] = tuple(
    sorted(s.key for s in REGISTRY if s.describes_hosts)
)


def tier_of(tool: str) -> SourceTier:
    """The ladder rung a tool sits on. Unknown tools are treated as device-tier.

    Device-tier is the conservative answer for an unrecognised source: it claims
    the narrowest scope, so an unknown tool cannot have its coverage overstated
    on a screen that tells an operator which lanes are accounted for.
    """
    spec = BY_KEY.get(tool)
    return spec.tier if spec else "device"


def device_of(tool: str) -> str:
    """The console/device identity records from this tool are attributed to.

    Falls back to the tool key itself rather than to None. `resolved_objects` is
    UNIQUE on (snapshot_id, source_device, object_name, object_kind), and the
    old three-entry map wrote NULL for everything outside it — so two unlisted
    tools exporting a same-named object collided on insert.
    """
    spec = BY_KEY.get(tool)
    return spec.device or tool if spec else tool
