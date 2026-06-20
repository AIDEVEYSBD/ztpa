"""Canonical data model — the contracts the whole system shares.

These pydantic v2 models are the single source of truth that every layer
(normalizers, graph, analyzers, advisory, change pipeline, API) speaks. The
deterministic engine fills every *fact* field; the LLM advisory layer never
mutates a model instance — it only reads facts and returns separate language.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

Tag = str  # e.g. "pci", "customer-data", "crown-jewel", "prod", "dev", "dmz"

SourceTool = Literal["algosec", "guardicore", "wiz", "sd_wan", "sd_lan"]
FindingType = Literal["over_permissive", "cidr_overlap", "shadowed_rule", "cross_tool_path"]
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
    dest_tags: list[Tag] = Field(default_factory=list)
    service: str                                      # e.g. "tcp/3389"
    port: Optional[int] = None
    protocol: Literal["tcp", "udp", "any"] = "tcp"
    action: Literal["allow", "deny"]
    order: Optional[int] = None                       # rule order within source (for shadowing)
    # Optional metadata carried for the graph / UI (never used by subnet math):
    source_ip: Optional[str] = None                   # concrete IP for named hosts
    dest_ip: Optional[str] = None
    note: Optional[str] = None                        # human label from the source export


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
