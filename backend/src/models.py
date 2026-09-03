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

SourceTool = Literal["algosec", "guardicore", "wiz", "sd_wan", "sd_lan"]
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
    source_tool: SourceTool
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
