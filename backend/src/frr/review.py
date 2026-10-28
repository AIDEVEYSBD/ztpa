"""The deterministic firewall rule review: a rule-risk register built from one
parsed rulebase.

Two sources of checks, both deterministic (FRR-02: the engine decides; a model
may only narrate what this produces):

* GRANT checks run the existing engine analyzers over the rulebase's grants --
  any-any, exposed admin ports, broad sources (`over_permissive`) and shadowed
  rules (`shadowing`). Each engine finding maps back to its console rule
  through `raw_refs` (the rule uid).
* INVENTORY checks read rule state the grant model does not carry: expired,
  expiring soon, disabled, and unused (zero hits, or no hit within the window).

Every check carries its evidence. The register is per RULE, because a rule is
what an owner validates and a change package changes.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import logging

from ..analyzers.run_all import _analyzers
from ..graph.build import build_graph
from ..identity import resolve_identities
from .rulebase import ParsedRulebase, RuleMeta

UNUSED_DAYS = int(os.environ.get("NPR_FRR_UNUSED_DAYS", "90"))
EXPIRING_DAYS = int(os.environ.get("NPR_FRR_EXPIRING_DAYS", "30"))

# Inventory check severities (0-100, same scale as engine findings). Fixed and
# documented rather than tuned: they rank cleanup, not exposure.
_SEV = {"expired": 55, "unused": 50, "disabled": 25, "expiring_soon": 30}


def _band(score: int) -> str:
    return "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"


@dataclass
class Check:
    check: str                  # any_any | admin_port_exposed | broad_source | over_permissive |
                                # shadowed | expired | expiring_soon | disabled | unused
    severity: int
    band: str
    title: str
    evidence: dict = field(default_factory=dict)
    finding_id: Optional[str] = None


@dataclass
class RegisterEntry:
    rule_uid: str
    layer: str
    number: Optional[int]
    name: Optional[str]
    section: Optional[str]
    action: str
    enabled: bool
    sources: list[str]
    destinations: list[str]
    services: list[str]
    hit_count: Optional[int]
    last_hit: Optional[str]
    expires_at: Optional[str]
    checks: list[Check] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @property
    def severity(self) -> int:
        return max((c.severity for c in self.checks), default=0)

    @property
    def band(self) -> str:
        """The worst band among the checks. Not derived from `severity`: the
        engine forces some findings critical (internet any/any) whatever their
        score, and that floor must survive into the register."""
        if not self.checks:
            return "low"
        return max((c.band for c in self.checks), key=lambda b: _BAND_RANK[b])


@dataclass
class Review:
    register: list[RegisterEntry]
    limitations: list[str]
    degraded_analyzers: list[dict]
    reviewed_at: str
    reference_time: str
    stats: dict

    def to_jsonable(self) -> dict[str, Any]:
        return {"stats": self.stats, "limitations": self.limitations,
                "degraded_analyzers": self.degraded_analyzers,
                "reviewed_at": self.reviewed_at, "reference_time": self.reference_time,
                "register": [{**asdict(e), "severity": e.severity, "band": e.band}
                             for e in self.register]}


log = logging.getLogger("npr.api.review")

# The engine analyzers a rule review needs. cidr_overlap (pairwise redundancy,
# tens of thousands of findings on a large rulebase), path_trace (cross-tool
# paths) and transport_exposure (QUIC) answer other questions.
REVIEW_ANALYZERS = ("over_permissive", "shadowing")


def _run_review_analyzers(records, graph, alias_map):
    """The review subset, isolated like a snapshot run: one analyzer failing
    costs its own checks, is named in `degraded`, and becomes a limitation."""
    findings, degraded = [], []
    for name, call in _analyzers(records, graph, alias_map):
        if name not in REVIEW_ANALYZERS:
            continue
        try:
            findings += call()
        except Exception as exc:  # noqa: BLE001 — isolation boundary, recorded below
            log.error("review analyzer failed", exc_info=True,
                      extra={"event": "review_analyzer_degraded", "analyzer": name})
            degraded.append({"analyzer": name, "error": type(exc).__name__, "message": str(exc)})
    return findings, degraded


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


_BAND_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
# Sources at least this broad (prefix length) count as a broad source.
BROAD_PREFIXLEN = int(os.environ.get("NPR_FRR_BROAD_PREFIXLEN", "16"))


def _classify_over_permissive(sig: dict) -> str:
    """Name an over_permissive finding by the FRR check it answers, from the
    engine's own signals (analyzers/over_permissive.py)."""
    src_any = "0.0.0.0/0" in (sig.get("source_cidrs") or [])
    dst_any = "0.0.0.0/0" in (sig.get("dest_cidrs") or [])
    if src_any and dst_any and sig.get("protocol") == "any":
        return "any_any"
    if "admin" in str(sig.get("port_class") or ""):
        return "admin_port_exposed"
    plen = sig.get("source_prefixlen")
    if sig.get("src_zone") == "internet" or (isinstance(plen, int) and plen <= BROAD_PREFIXLEN):
        return "broad_source"
    return "over_permissive"


_ALL_TARGETS = {"policy targets", "any", "all"}


def _shadowing_refuted(later: Optional[RuleMeta], earlier: Optional[RuleMeta],
                       ref: datetime) -> Optional[str]:
    """Why the engine's "never matches" must not be reported for this pair, or None.

    The engine compares grants within one rulebase; a firewall applies a rule
    only on the gateways it is installed on. And the firewall's own hit counter
    is direct evidence: a rule hit recently DOES match traffic somewhere."""
    if later is None or earlier is None:
        return None
    e_targets = {t.lower() for t in earlier.install_on}
    l_targets = {t.lower() for t in later.install_on}
    if e_targets and not (e_targets & _ALL_TARGETS) and not (l_targets <= e_targets):
        return (f"not reported as shadowed: rule {earlier.number} covers it but is installed on "
                f"{', '.join(earlier.install_on)}, not on all of this rule's targets")
    if later.hit_count and later.last_hit and later.last_hit >= ref - timedelta(days=UNUSED_DAYS):
        return (f"not reported as shadowed: rule {earlier.number} appears to cover it, but the "
                f"firewall counted {later.hit_count} hits (last {later.last_hit.date()}); check "
                "install targets and inline layers")
    return None


def _inventory_checks(r: RuleMeta, ref: datetime) -> list[Check]:
    out: list[Check] = []
    if r.expires_at and r.expires_at <= ref:
        out.append(Check("expired", _SEV["expired"], _band(_SEV["expired"]),
                         f"expired {r.expires_at.date()}; still in the rulebase",
                         {"expires_at": _iso(r.expires_at)}))
    elif r.expires_at and r.expires_at <= ref + timedelta(days=EXPIRING_DAYS):
        out.append(Check("expiring_soon", _SEV["expiring_soon"], _band(_SEV["expiring_soon"]),
                         f"expires {r.expires_at.date()}", {"expires_at": _iso(r.expires_at)}))
    if not r.enabled:
        out.append(Check("disabled", _SEV["disabled"], _band(_SEV["disabled"]),
                         "disabled; still in the rulebase", {}))
    expired = bool(r.expires_at and r.expires_at <= ref)
    if r.enabled and not expired and r.action == "allow" and r.hit_count is not None:
        stale = r.last_hit is not None and r.last_hit < ref - timedelta(days=UNUSED_DAYS)
        if r.hit_count == 0 or stale:
            why = "never hit" if r.hit_count == 0 else f"last hit {r.last_hit.date()}"
            out.append(Check("unused", _SEV["unused"], _band(_SEV["unused"]),
                             f"{why} (window {UNUSED_DAYS} days)",
                             {"hit_count": r.hit_count, "last_hit": _iso(r.last_hit),
                              "window_days": UNUSED_DAYS}))
    return out


def review(parsed: ParsedRulebase, *, now: Optional[datetime] = None) -> Review:
    now = now or datetime.now(timezone.utc)
    ref = parsed.exported_at or now
    res = parsed.result
    idr = resolve_identities(res.entities, [])
    graph = build_graph(res.records, idr.assets, idr.alias_map)
    findings, degraded = _run_review_analyzers(res.records, graph, idr.alias_map)

    by_uid: dict[str, RegisterEntry] = {}
    for r in parsed.rules:
        e = RegisterEntry(rule_uid=r.uid, layer=r.layer, number=r.number, name=r.name,
                          section=r.section, action=r.action, enabled=r.enabled,
                          sources=r.sources, destinations=r.destinations, services=r.services,
                          hit_count=r.hit_count, last_hit=_iso(r.last_hit),
                          expires_at=_iso(r.expires_at), limitations=list(r.limitations))
        e.checks += _inventory_checks(r, ref)
        by_uid[r.uid] = e

    number = {r.uid: r.number for r in parsed.rules}
    meta = {r.uid: r for r in parsed.rules}
    for f in findings:
        sig = dict(f.signals or {})
        if f.type == "over_permissive":
            entry = by_uid.get(sig.get("raw_ref") or (f.raw_refs or [None])[0])
            kind, title = _classify_over_permissive(sig), f.title
        elif f.type == "shadowed_rule":
            # The finding names both rules; the check belongs to the one that
            # can never match, with the rule that covers it as the evidence.
            entry = by_uid.get(sig.get("shadowed_ref"))
            covering = sig.get("shadowing_ref")
            refuted = _shadowing_refuted(meta.get(sig.get("shadowed_ref")), meta.get(covering), ref)
            if refuted and entry is not None:
                if refuted not in entry.limitations:
                    entry.limitations.append(refuted)
                continue
            kind = "shadowed"
            title = f"never matched: rule {number.get(covering, covering)} above it already covers it"
            sig["covered_by_rule"] = number.get(covering)
        else:
            continue                                   # cross-tool paths etc. are not per-rule checks
        if entry is None or any(c.finding_id == f.id for c in entry.checks):
            continue
        band = "critical" if f.forced_critical else f.severity_band
        entry.checks.append(Check(kind, f.severity, band, title, sig, f.id))

    # Several grants of one rule can raise the same check (one per service in
    # a group); the register keeps the worst of each kind per rule.
    for e in by_uid.values():
        worst: dict[str, Check] = {}
        for c in e.checks:
            prev = worst.get(c.check)
            if prev is None or (_BAND_RANK[c.band], c.severity) > (_BAND_RANK[prev.band], prev.severity):
                worst[c.check] = c
        e.checks = sorted(worst.values(), key=lambda c: (-_BAND_RANK[c.band], -c.severity))

    register = sorted(by_uid.values(),
                      key=lambda e: (-_BAND_RANK[e.band] if e.checks else 1, -e.severity,
                                     e.layer, e.number or 0))
    stats = {
        "rules": len(register),
        "rules_with_findings": sum(1 for e in register if e.checks),
        "by_check": {},
        "by_band": {b: sum(1 for e in register if e.checks and e.band == b)
                    for b in ("critical", "high", "medium", "low")},
        "grants_analysed": len(res.records),
    }
    for e in register:
        for c in e.checks:
            stats["by_check"][c.check] = stats["by_check"].get(c.check, 0) + 1

    limitations = list(parsed.limitations)
    if degraded:
        limitations.append("analysis incomplete: " + ", ".join(d["analyzer"] for d in degraded)
                           + " failed; their checks are missing from this register")
    if len(parsed.layers) > 1:
        limitations.append("shadowing is evaluated across all layers together, not per layer")
    return Review(register=register, limitations=limitations, degraded_analyzers=degraded,
                  reviewed_at=now.isoformat(), reference_time=ref.isoformat(), stats=stats)
