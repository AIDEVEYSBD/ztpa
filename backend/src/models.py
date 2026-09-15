"""Canonical data model — the contracts the whole system shares.

These pydantic v2 models are the single source of truth that every layer
(normalizers, graph, analyzers, advisory, change pipeline, API) speaks. The
deterministic engine fills every *fact* field; the LLM advisory layer never
mutates a model instance — it only reads facts and returns separate language.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

from .netaddr import ANY_V4, is_any, parse_net

Tag = str  # e.g. "pci", "customer-data", "crown-jewel", "prod", "dev", "dmz"

# The tools this build ships a normalizer for. Hand-written rather than derived,
# because a pydantic Literal has to exist at class-definition time and `sources`
# imports FROM this module -- but `test_source_registry.py` asserts these members
# are exactly `sources.TOOL_KEYS`, so the two cannot drift.
#
# THIS IS THE CATALOGUE, NOT THE CONSTRAINT. `PolicyRecord.source_tool` is a
# plain `str`, deliberately, and the reason is a product feature rather than
# laxity: an operator can bring their own source via a declarative
# `SourceProfile` (normalizers/profile.py), and a profile IS a registration --
# the operator has told us, in their own words, what this source is called.
#
# The closed Literal used to be enforced here, and the way that played out is
# instructive. `profile.py` knew records had to satisfy it, so a record from any
# tool outside the list was relabelled `source_tool="algosec"` to make the
# insert succeed. Bringing your own connector therefore did not fail -- it
# ingested cleanly, the counts looked right, and every provenance claim
# downstream (the source badge on a finding, the "seen by" column, the rule
# reference an operator would click to go verify something in their own console,
# the audit trail) pointed at a different vendor's product.
#
# A constraint that a shipped feature has to lie to satisfy is a bug in the
# constraint. So the vocabulary is open, the tool is carried as given, and
# `sources.BY_KEY` decides only whether we can say anything ABOUT it -- an
# unrecognised tool renders as a custom source with the narrowest assumed
# scope, never as a tool it is not.
SourceTool = Literal[
    "algosec", "catalyst_center", "fortigate", "fortimanager", "guardicore",
    "junos_space", "meraki", "panorama", "sd_lan", "sd_wan", "wiz",
]
FindingType = Literal[
    "over_permissive", "cidr_overlap", "shadowed_rule", "cross_tool_path", "transport_exposure",
]
# L4 transport protocols we decode. "any" = every protocol/port (a wildcard rule)
# and is what the Palo/ASA keywords `ip` and `all` decode to -- they used to
# become plain "tcp", so a genuine any/any rule never tripped the guardrail.
# gre/esp/ah are carried as themselves rather than being rewritten to tcp: a
# VPN/tunnel grant reported as TCP is a false statement about the network.
Protocol = Literal["tcp", "udp", "icmp", "sctp", "gre", "esp", "ah", "any"]
L7Source = Literal["declared", "inferred"]
SeverityBand = Literal["low", "medium", "high", "critical"]


class PolicyRecord(BaseModel):
    """One canonical allow/deny grant, normalized from any source tool.

    "source X may reach destination Y on service Z" means the same thing here
    regardless of which tool it came from. This is the defensible IP.
    """

    id: str
    source_tool: str                                  # a TOOL_KEYS member, or a BYO profile's own name
    raw_ref: str                                      # rule id in the source tool
    source: str                                       # CIDR or identity/label
    source_kind: Literal["cidr", "identity"]
    destination: str
    destination_kind: Literal["cidr", "identity"]
    # The RESOLVED address space behind `source` / `destination`, canonical and
    # sorted. A named object ("ANY-EXTERNAL", "DC-SUBNETS") keeps its label in
    # `source`/`destination` -- that is what the operator sees in their console
    # and what raw_ref ties back to -- while the address space it dereferences to
    # lives here, so the analyzers can do subnet math on a named object instead
    # of scoring the string. An address group resolves to several entries.
    #
    # EMPTY MEANS GENUINELY UNRESOLVABLE, NOT "not looked up". This distinction
    # is load-bearing: `exposure_score` falls back to E_IDENTITY (0.1, the score
    # of a single host) ONLY on an empty list, so a normalizer that forgets to
    # populate these does not merely lose detail -- it silently reports a /0 as
    # a host. Every normalizer must fill them from the object catalog, and leave
    # them empty only for a token that names no address space at all (a user, a
    # tag, an application group, an object missing from the export's catalog).
    source_cidrs: list[str] = Field(default_factory=list)
    dest_cidrs: list[str] = Field(default_factory=list)
    # WHY `source_cidrs == []` IS NOT ONE FACT BUT TWO.
    #
    # `[]` above is a claim, and the claim covers two different worlds:
    #
    #   "this token names no address space"   a user group, a tag, an
    #                                         application group, an object the
    #                                         export simply does not define.
    #                                         E_IDENTITY (0.1) is the RIGHT
    #                                         answer -- a label is not exposure.
    #
    #   "this token claims address space      `10.0.0.0/33` (a fat-finger for
    #    and it did not resolve"               `/3`), `10.0.0.0-9.0.0.0`, an
    #                                         object group whose members do not
    #                                         dereference. E_IDENTITY is the
    #                                         WORST answer available: a typo in
    #                                         what is nearly always a BROAD rule
    #                                         scores as a single host, so bad
    #                                         input LOWERS the reported risk and
    #                                         the finding disappears entirely.
    #
    # This flag is the second world, set by the normalizer, which is the only
    # layer that ever sees the raw token and the object catalog together.
    # `severity.exposure_score` reads it and applies a conservative floor, so an
    # unresolvable NETWORK can no longer be scored as a host.
    #
    # It is deliberately consistent with `normalizers.profile.object_is_abstract`,
    # which already fails CLOSED on the identical signal ("we have no evidence it
    # is a host, and calling it one is precisely how a typo'd broad rule came to
    # score as a single host"). Abstractness and exposure now read the same fact
    # the same way; they used to disagree, and exposure was the half that failed
    # open.
    #
    # It is NOT evidence of internet exposure: `severity.is_internet_source`
    # ignores it on purpose. An unreadable token means "unknown breadth", not
    # "the whole internet", and forcing every typo critical would be the
    # mirror-image defect.
    source_unresolved: bool = False
    dest_tags: list[Tag] = Field(default_factory=list)
    service: str                                      # e.g. "tcp/3389", "quic", "tcp/8000-8100"
    port: Optional[int] = None                        # single port, or range start
    port_end: Optional[int] = None                    # range end (None = single port)
    protocol: Protocol = "tcp"
    l7_app: Optional[str] = None                      # decoded App-ID (e.g. "quic", "tls"); None if unknown
    l7_source: Optional[L7Source] = None              # how l7_app was decoded (provenance)
    action: Literal["allow", "deny"]
    order: Optional[int] = None                       # rule order within source (for shadowing)
    # Optional metadata carried for the graph / UI (never used by subnet math):
    source_ip: Optional[str] = None                   # concrete IP for named hosts
    dest_ip: Optional[str] = None
    note: Optional[str] = None                        # human label from the source export

    @field_validator("source_cidrs", "dest_cidrs", mode="after")
    @classmethod
    def _canonicalize_cidrs(cls, values: list[str]) -> list[str]:
        """Canonicalize + sort the resolved address space.

        Two normalizers spelling one network differently ("10.0.0.1/24" and
        "10.0.0.0/24") must produce one string, or the snapshot fingerprint --
        and every equality check downstream -- would depend on which export was
        read. So every entry goes through `ip_network(x, strict=False)`, the
        wildcard vocabulary collapses onto 0.0.0.0/0, duplicates are dropped and
        the result is sorted numerically (version, address, prefix). No sets
        reach the output: the sort is explicit and total.

        A token that names no address space is dropped rather than stored --
        garbage in this field would be scored as if it were a network. Dropping
        is safe precisely because empty is meaningful (see the field comment):
        an all-garbage list degrades to E_IDENTITY, never to a silent /0.
        """
        nets = []
        for raw in values:
            net = parse_net(raw)
            if net is None and is_any(raw):
                net = parse_net(ANY_V4)   # "any" / "all" / "*" -> the internet
            if net is not None:
                nets.append(net)
        ordered = sorted({(n.version, int(n.network_address), n.prefixlen): n
                          for n in nets}.items())
        return [str(net) for _key, net in ordered]


class Finding(BaseModel):
    """A structured fact emitted by a deterministic analyzer.

    `severity`, `severity_band`, `forced_critical`, and `signals` are all
    computed by plain Python. The LLM only ever *reads* these.
    """

    id: str
    type: FindingType
    title: str = ""                                   # deterministic short label (not LLM prose)
    severity: int                                     # 0-100 deterministic base score
    severity_band: SeverityBand
    forced_critical: bool = False                     # set by guardrail floor
    signals: dict = Field(default_factory=dict)       # hard facts (see analyzers)
    involved: list[str] = Field(default_factory=list)  # entity ids / refs
    raw_refs: list[str] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)


class ChangeRequest(BaseModel):
    id: str
    proposed: PolicyRecord                            # the rule being requested
    requested_by: Optional[str] = None
    justification: Optional[str] = None               # UNTRUSTED free text
    title: Optional[str] = None                       # human label for the demo UI


class ChangeDecision(BaseModel):
    request_id: str
    decision: Literal["auto_approve", "escalate"]
    criteria: dict[str, bool] = Field(default_factory=dict)  # each auto-approve criterion -> pass/fail
    triggering_reason: Optional[str] = None           # populated when escalated
    delta_summary: dict = Field(default_factory=dict)  # new_paths, new_exposed_assets, boundaries_crossed
    confidence: float = 0.0
    forced_escalate: bool = False                     # set by guardrail
    rationale: Optional[str] = None                   # LLM (or deterministic) prose explanation
    decided_by: Literal["llm", "engine_fallback"] = "engine_fallback"


class RankedAction(BaseModel):
    action_id: str
    title: str
    finding_ids: list[str]
    priority: int
    rationale: str
    severity_band: SeverityBand = "low"               # band of the worst finding in the group


class RankedActions(BaseModel):
    actions: list[RankedAction] = Field(default_factory=list)
    ranked_by: Literal["llm", "engine_fallback"] = "engine_fallback"


class Asset(BaseModel):
    """The identity layer. IP is an attribute; the key is a stable identity."""

    asset_key: str
    kind: Literal["concrete", "abstract"] = "concrete"   # abstract = internet/zone/subnet
    context: Optional[str] = None                         # vrf / segment / account / tenant
    identifiers: dict = Field(default_factory=dict)       # {cloud_id, hostname, mac, ...}
    ip_set: list[str] = Field(default_factory=list)       # canonical CIDRs
    tags: list[Tag] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)
    display_name: Optional[str] = None


class AssetCorrelation(BaseModel):
    """Entity-resolution audit row: which identities merged, with evidence."""

    asset_key: str
    match_key: Literal["cloud_id", "hostname", "mac", "context_ip", "manual_review"]
    confidence: float
    evidence: dict = Field(default_factory=dict)


class Snapshot(BaseModel):
    snapshot_id: str
    label: Optional[str] = None
    status: Literal["running", "complete", "failed"] = "complete"
    notes: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════
# THE INFRASTRUCTURE LAYER
#
# Everything above this line describes POLICY: who may reach what, and the
# findings that fall out of it. Everything below describes the NETWORK the
# policy runs on -- devices, the interfaces they terminate, the links between
# them, the segments those links carry, and the circuits that reach the
# internet.
#
# These are two different graphs and they are kept apart on purpose.
# `graph.reachability` traverses POLICY edges only. A topology link is a
# statement about cabling and adjacency; it is NOT a grant, and letting one
# become the other would let the engine report reachability that no rule
# permits. `verify_engine` asserts `cross_tool_paths` is byte-identical with
# and without any of the models below present.
#
# The unifying rule of this whole layer: EVERY fact carries the tool that
# observed it, the TIER that tool sits at, and the raw reference it came from.
# A device we were told about by an aggregator and a device we logged into are
# not the same quality of fact, and the UI is required to say which it has.
# ═══════════════════════════════════════════════════════════════════════════

# Where a source sits in the collection ladder. Stated as its own axis because
# it decides how much a fact is worth, not merely where it came from:
#
#   aggregator         -- a cross-vendor console (AlgoSec, Panorama, FortiManager,
#                         Wiz). Broad, and second-hand: it reports what it was
#                         told by the devices it manages, which is a subset of
#                         what those devices know. AlgoSec in particular models
#                         ENFORCEMENT POINTS and their policy -- it is not a
#                         network-inventory product and will not enumerate an
#                         access switch or a workstation.
#   management_console -- a vendor's own manager for its own fleet (Catalyst
#                         Center, Meraki Dashboard, Mist, FMC). Deep on its
#                         vendor, blind to every other.
#   device             -- read off the box itself (FortiGate REST, PAN-OS op,
#                         NETCONF). The most authoritative and the least
#                         scalable.
#
# The ladder is the answer to partial onboarding: an estate whose AlgoSec covers
# only the perimeter still yields a whole picture if the console tier fills the
# campus, and the picture says, per node, which rung it came from.
SourceTier = Literal["aggregator", "management_console", "device"]

# What a box IS. `l2_switch` and `l3_switch` are DISTINCT members rather than
# one "switch" with a flag: whether a switch routes decides whether inter-VLAN
# traffic is a policy decision on that device or a trip to the gateway, and a
# diagram that cannot show the difference cannot be used to reason about either.
DeviceRole = Literal[
    "modem", "router", "firewall", "l3_switch", "l2_switch", "hub", "bridge",
    "load_balancer", "wireless_ap", "server", "workstation", "virtual_appliance",
    "unknown",
]

# The lanes of the layered picture, ordered from the outside in. This is a
# DERIVED property of a device's position in the link graph, not a label a
# source hands us -- see `topology.reconstruct.assign_layers`.
TopologyLayer = Literal[
    "internet",    # the boundary itself; never a device we own
    "circuit",     # the carrier service (MPLS / P2P / ISDN / broadband / ...)
    "modem",       # the CPE terminating a circuit
    "edge",        # edge / gateway routers
    "perimeter",   # perimeter firewalls
    "core",        # core + distribution, where L3 switching happens
    "access",      # access-layer L2 switches, APs
    "segment",     # VLANs and subnets
    "endpoint",    # hosts, workloads, appliances
]

# How we know a link exists.
#
# THERE IS DELIBERATELY NO "inferred" MEMBER, and there must never be one.
# Every value here names a specific observation: a neighbour protocol reported
# it, a management API returned it as topology, a config declared it, a routing
# table pointed through it, or two interfaces provably share an address block.
# A line drawn between two boxes because the picture looked incomplete without
# it is a claim about someone's cabling that nobody made, and this product's
# entire moat is that it does not do that. The database CHECK mirrors this
# tuple, so an unevidenced link cannot be stored -- and therefore cannot be
# drawn -- rather than relying on a reviewer to catch it.
LinkEvidence = Literal[
    "lldp",           # LLDP neighbour table
    "cdp",            # CDP neighbour table
    "api_topology",   # the console returned this adjacency as topology
    "config",         # a config stanza names the peer (HA pair, LAG member)
    "routing",        # a route's next hop resolves to the peer's interface
    "declared",       # an operator or export asserted it outright
    "containment",    # two interfaces hold addresses in one block: an OBSERVED
                      # L3 adjacency, which is weaker than a cable and is
                      # labelled as such, not a guess at one
]

CircuitTechnology = Literal[
    "mpls", "p2p", "isdn", "broadband", "fiber", "lte", "satellite", "unknown",
]


class Provenance(BaseModel):
    """Who told us, from which rung, and what they called it.

    Carried by every infrastructure fact. `raw_ref` is the identifier in the
    source system -- the interface id, the device serial, the VLAN's own name --
    so any row on any screen can be taken back to the console it came from.
    """

    source_tool: str
    source_tier: SourceTier
    raw_ref: str
    # True when this came from a seeded export rather than a live connector.
    # Read from the `sources.config.mode` the persistence layer already writes
    # and which, until now, nothing read back. A client-facing screen has to be
    # able to say "simulated" without the operator having to remember.
    simulated: bool = False


class NetDevice(BaseModel):
    """One box. Physical or virtual, ours or the carrier's."""

    device_key: str                                   # canonical, stable
    name: str
    role: DeviceRole = "unknown"
    # Provenance of the ROLE, kept separate from provenance of the device,
    # because they genuinely differ: FortiManager tells us a FortiGate is a
    # firewall (declared), while a box that merely holds SVIs and forwards
    # between them is called an l3_switch by US (derived). The DB CHECK refuses
    # a named role whose source is "unknown", so a role can never appear
    # without a story behind it.
    role_source: Literal["declared", "derived", "unknown"] = "unknown"
    role_reason: str = ""
    vendor: Optional[str] = None                      # "Cisco", "Fortinet", ...
    model: Optional[str] = None                       # "ISR4331", "FortiGate-100F"
    os_version: Optional[str] = None
    serial: Optional[str] = None
    mgmt_ip: Optional[str] = None
    site: Optional[str] = None
    # HA membership. `ha_group` is the pair's name; two devices sharing one are
    # drawn bracketed. A pair whose members share a failure domain is a finding,
    # not a reassurance -- see `analyzers.resilience`.
    ha_group: Optional[str] = None
    ha_role: Optional[str] = None                     # primary | secondary | active | passive
    # Assigned by `topology.reconstruct.assign_layers`, never by a source.
    # `layer is None` and `layer_source == "unknown"` are the SAME state and the
    # DB CHECK enforces that they move together: a node we could not place must
    # say so on both columns or neither, so "unplaced" can never be silently
    # rendered as a lane.
    layer: Optional[TopologyLayer] = None
    layer_source: Literal["declared", "derived", "unknown"] = "unknown"
    layer_reason: str = ""
    tags: list[Tag] = Field(default_factory=list)
    provenance: Provenance


class NetInterface(BaseModel):
    """One port, SVI or logical interface on a device."""

    interface_key: str                                # f"{device_key}:{name}"
    device_key: str
    name: str                                         # "port5", "port5.30", "Gi0/0/1", "vlan30"
    description: Optional[str] = None
    addresses: list[str] = Field(default_factory=list)   # canonical CIDRs ON the interface
    # Everything reachable THROUGH this interface, when the source says so.
    # AlgoSec's "IPs behind interface" is the richest instance of this and is
    # the single most useful field available for reconstructing topology from a
    # policy product.
    networks_behind: list[str] = Field(default_factory=list)
    vlan_id: Optional[int] = None
    zone: Optional[str] = None
    # NULL MEANS NOT REPORTED. It must never default to False: "the source did
    # not tell us whether this port is up" and "this port is down" are different
    # facts, and a diagram that greys out every un-reported port invents an
    # outage. Three-valued at the column, not merely in the component.
    admin_up: Optional[bool] = None
    oper_up: Optional[bool] = None
    speed_mbps: Optional[int] = None
    lag_group: Optional[str] = None                   # port-channel / aggregate name
    mac: Optional[str] = None
    # Neighbour as the box itself reported it (LLDP/CDP). Present only when a
    # neighbour protocol was actually read.
    neighbor_device: Optional[str] = None
    neighbor_interface: Optional[str] = None
    provenance: Provenance


class NetLink(BaseModel):
    """An adjacency between two devices, and what makes us believe in it."""

    link_key: str
    a_device: str
    a_interface: Optional[str] = None
    b_device: str
    b_interface: Optional[str] = None
    evidence: LinkEvidence
    evidence_detail: str = ""                         # the specific observation, quoted
    # Links in one `redundant_group` are alternate paths for the same purpose --
    # the criss-cross uplinks between a core pair and an access switch. Drawn
    # tinted together, and read by the SPOF analyzer, which must not report a
    # bridge that has a live sibling.
    redundant_group: Optional[str] = None
    aggregated: bool = False                          # a LAG / port-channel
    member_count: int = 1
    provenance: Provenance


class Vlan(BaseModel):
    """A broadcast domain, and the subnets carried on it."""

    vlan_id: int
    name: Optional[str] = None
    subnets: list[str] = Field(default_factory=list)
    gateways: list[str] = Field(default_factory=list)   # SVI / FHRP addresses
    device_keys: list[str] = Field(default_factory=list)
    tags: list[Tag] = Field(default_factory=list)
    provenance: Provenance


class Subnet(BaseModel):
    """An addressable block, and where it lives."""

    cidr: str
    name: Optional[str] = None
    vlan_id: Optional[int] = None
    gateways: list[str] = Field(default_factory=list)
    device_keys: list[str] = Field(default_factory=list)
    zone: Optional[str] = None
    tags: list[Tag] = Field(default_factory=list)
    provenance: Provenance

    @field_validator("cidr", mode="after")
    @classmethod
    def _canonical(cls, v: str) -> str:
        net = parse_net(v)
        return str(net) if net is not None else v


class Circuit(BaseModel):
    """One path to the outside world.

    Modelled separately from the device that terminates it because the whole
    point of the redundancy question is that two circuits can share a modem, a
    router, a building entry or -- most expensively -- a carrier, and each of
    those is a different single point of failure. A circuit that is merely an
    attribute of an interface cannot express any of them.
    """

    circuit_id: str
    provider: Optional[str] = None                    # the carrier, e.g. "Airtel"
    technology: CircuitTechnology = "unknown"
    bandwidth_mbps: Optional[int] = None
    public_ips: list[str] = Field(default_factory=list)
    device_key: Optional[str] = None                  # the CPE terminating it
    interface: Optional[str] = None
    state: Literal["up", "down", "standby", "unknown"] = "unknown"
    provenance: Provenance


class Topology(BaseModel):
    """The reconstructed infrastructure view of one snapshot."""

    devices: list[NetDevice] = Field(default_factory=list)
    interfaces: list[NetInterface] = Field(default_factory=list)
    links: list[NetLink] = Field(default_factory=list)
    vlans: list[Vlan] = Field(default_factory=list)
    subnets: list[Subnet] = Field(default_factory=list)
    circuits: list[Circuit] = Field(default_factory=list)
    # Layers we have NO observed node for, each with the reason and the concrete
    # API that would fill it. Rendered as a named absence -- never as a ghost
    # device, and never silently omitted, because a lane that simply is not
    # drawn reads as a lane that does not exist.
    unobserved_layers: list[dict] = Field(default_factory=list)
