"""The rule inventory a firewall review is performed on.

`RuleMeta` is one rule as the administrator sees it in the console -- number,
name, enabled, expiry, hits, install targets -- with the canonical grants it
expanded into. `NatRule` is one translation. `ParsedRulebase` is everything an
export yielded, plus the LIMITATIONS of that reading: every place the parser had
to approximate (a negated cell, an application it cannot decode, a rule over the
expansion cap). Limitations are part of the output, never a log line, because
the review report must state them (FRR-03 "limitations").
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional

from ..normalizers.common import NormalizeResult


@dataclass
class RuleMeta:
    source_tool: str
    layer: str
    uid: str
    number: Optional[int]
    name: Optional[str]
    enabled: bool
    action: str                                # allow | deny | other (as written in `action_raw`)
    action_raw: str
    sources: list[str]
    destinations: list[str]
    services: list[str]
    source_negate: bool = False
    destination_negate: bool = False
    service_negate: bool = False
    expires_at: Optional[datetime] = None      # None = no expiry
    # None = the export did not carry hit counts. NOT zero: "never hit" and
    # "we were not told" are different facts and only one supports removal.
    hit_count: Optional[int] = None
    last_hit: Optional[datetime] = None
    install_on: list[str] = field(default_factory=list)
    section: Optional[str] = None
    comments: Optional[str] = None
    record_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"{self.layer} #{self.number}" if self.number is not None else f"{self.layer} {self.uid}"


@dataclass
class NatRule:
    source_tool: str
    package: str
    uid: str
    number: Optional[int]
    enabled: bool
    method: str                                # static | hide | other
    auto_generated: bool
    original_source: list[str]
    original_destination: list[str]
    original_service: list[str]
    translated_source: list[str]
    translated_destination: list[str]
    translated_service: list[str]
    original_source_cidrs: list[str] = field(default_factory=list)
    original_destination_cidrs: list[str] = field(default_factory=list)
    translated_source_cidrs: list[str] = field(default_factory=list)
    translated_destination_cidrs: list[str] = field(default_factory=list)
    install_on: list[str] = field(default_factory=list)
    comments: Optional[str] = None


@dataclass
class ParsedRulebase:
    source_tool: str
    result: NormalizeResult
    rules: list[RuleMeta] = field(default_factory=list)
    nat: list[NatRule] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    exported_at: Optional[datetime] = None
    layers: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "source_tool": self.source_tool,
            "layers": self.layers,
            "rules": len(self.rules),
            "rules_enabled": sum(1 for r in self.rules if r.enabled),
            "grants": len(self.result.records),
            "nat_rules": len(self.nat),
            "objects_resolved": len(self.result.resolved),
            "hit_counts_present": any(r.hit_count is not None for r in self.rules),
            "limitations": len(self.limitations) + sum(len(r.limitations) for r in self.rules),
            "exported_at": self.exported_at.isoformat() if self.exported_at else None,
        }

    def to_jsonable(self) -> dict[str, Any]:
        def enc(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, dict):
                return {k: enc(x) for k, x in v.items()}
            if isinstance(v, list):
                return [enc(x) for x in v]
            return v
        return {
            "summary": self.summary(),
            "limitations": self.limitations,
            "rules": [enc(asdict(r)) for r in self.rules],
            "nat": [enc(asdict(n)) for n in self.nat],
            "records": [r.model_dump(mode="json") for r in self.result.records],
        }


class ExportRejected(ValueError):
    """The export cannot be reviewed as given. The message says why, in terms
    the person who produced the export can act on. Never "empty estate"."""
