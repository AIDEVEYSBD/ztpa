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
    # NAT rules whose original or translated destination this rule reaches.
    nat: list[dict] = field(default_factory=list)

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
    effective_policy: list = field(default_factory=list)
    nat_findings: list = field(default_factory=list)

    def to_jsonable(self) -> dict[str, Any]:
        return {"stats": self.stats, "limitations": self.limitations,
                "degraded_analyzers": self.degraded_analyzers,
                "reviewed_at": self.reviewed_at, "reference_time": self.reference_time,
                "effective_policy": self.effective_policy,
                "nat_findings": [asdict(f) for f in self.nat_findings],
                "register": [{**asdict(e), "severity": e.severity, "band": e.band}
                             for e in self.register]}


log = logging.getLogger("npr.api.review")

# The engine analyzers a rule review needs. cidr_overlap (pairwise redundancy,
# tens of thousands of findings on a large rulebase), path_trace (cross-tool
# paths) and transport_exposure (QUIC) answer other questions.
REVIEW_ANALYZERS = ("over_permissive",)      # shadowing runs per gateway: see _shadowing_by_gateway


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
    if later.hit_count and later.last_hit and later.last_hit >= ref - timedelta(days=UNUSED_DAYS):
        return (f"not reported as shadowed: rule {earlier.number} appears to cover it, but the "
                f"firewall counted {later.hit_count} hits (last {later.last_hit.date()}); check "
                "install targets and inline layers")
    return None


ALL_GATEWAYS = "(all gateways)"


def _gateways_of(r: RuleMeta) -> set[str]:
    t = {x.lower() for x in r.install_on}
    return {ALL_GATEWAYS} if (not t or t & _ALL_TARGETS) else t


def _shadowing_by_gateway(parsed: ParsedRulebase, graph, alias_map, ref: datetime):
    """Shadowing computed where it actually happens: per (layer, gateway), over
    the rules installed on that gateway, in order. A rule installed on every
    gateway ('Policy Targets') belongs to each partition.

    A rule is shadowed in a partition only when EVERY one of its grants is
    covered there: a rule allowing ssh and https under a rule allowing only ssh
    still carries the https traffic, and calling it "never matched" would
    propose removing live traffic. A rule whose grants were truncated at parse
    time is never claimed shadowed (its unanalysed grants may not be covered).

    Returns ({uid: {partition: (coverer_uids, finding)}}, effective_policy,
    degraded). Partitions with the same rule set share one computation, so a
    hundred gateways running one policy cost the same as one."""
    from ..analyzers import shadowing

    explicit = sorted({g for r in parsed.rules for g in _gateways_of(r)} - {ALL_GATEWAYS})
    gateways = explicit or [ALL_GATEWAYS]
    by_rule_records: dict[str, list] = {}
    for rec in parsed.result.records:
        by_rule_records.setdefault(rec.raw_ref, []).append(rec)
    memo: dict[frozenset, list] = {}
    covered: dict[str, dict] = {}
    effective: list[dict] = []
    degraded: list[dict] = []
    gw_of = {r.uid: _gateways_of(r) for r in parsed.rules}
    truncated = {r.uid for r in parsed.rules if r.grants_truncated}
    for layer in parsed.layers:
        rules = [r for r in parsed.rules if r.layer == layer]
        for g in gateways:
            here = [r for r in rules if g in gw_of[r.uid] or ALL_GATEWAYS in gw_of[r.uid]]
            key = frozenset(r.uid for r in here)
            if key not in memo:
                recs = [x for r in here for x in by_rule_records.get(r.uid, ())]
                try:
                    memo[key] = shadowing.analyze(recs, graph, alias_map)
                except Exception as exc:  # noqa: BLE001 — isolation boundary, recorded
                    log.error("shadowing failed", exc_info=True,
                              extra={"event": "review_analyzer_degraded", "analyzer": "shadowing"})
                    degraded.append({"analyzer": "shadowing", "error": type(exc).__name__,
                                     "message": str(exc)})
                    memo[key] = []
            per_rule: dict[str, dict] = {}
            for f in memo[key]:
                per_rule.setdefault(f.signals.get("shadowed_ref"), {})[f.signals.get("shadowed_record")] = f
            shadowed_here = set()
            for uid, by_grant in per_rule.items():
                if uid in truncated or len(by_grant) < len(by_rule_records.get(uid, ())):
                    continue                           # some grant of this rule still matches here
                fs = list(by_grant.values())
                coverers = tuple(sorted({x.signals.get("shadowing_ref") for x in fs}))
                covered.setdefault(uid, {})[(layer, g)] = (coverers, fs[0])
                shadowed_here.add(uid)
            live = [r for r in here if r.enabled and not (r.expires_at and r.expires_at <= ref)]
            live_uids = {r.uid for r in live}
            effective.append({
                "layer": layer, "gateway": g, "rules_installed": len(here),
                "effective_allow": [r.number for r in live if r.action == "allow" and r.uid not in shadowed_here],
                "shadowed": [r.number for r in live if r.uid in shadowed_here],
                "deny": [r.number for r in live if r.action == "deny" and r.uid not in shadowed_here],
                "inactive": [r.number for r in here if r.uid not in live_uids],
            })
    return covered, effective, degraded


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
    covered, effective, shadow_degraded = _shadowing_by_gateway(parsed, graph, idr.alias_map, ref)
    degraded += shadow_degraded

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
        else:
            continue                                   # cross-tool paths etc. are not per-rule checks
        if entry is None or any(c.finding_id == f.id for c in entry.checks):
            continue
        band = "critical" if f.forced_critical else f.severity_band
        entry.checks.append(Check(kind, f.severity, band, title, sig, f.id))

    # Shadowing: reported only when the rule is covered on EVERY gateway it is
    # installed on, and the firewall's own hit counter does not contradict it.
    for uid, where in covered.items():
        entry, rm = by_uid.get(uid), meta.get(uid)
        if entry is None or rm is None:
            continue
        mine = {(rm.layer, g) for g in (_gateways_of(rm) if ALL_GATEWAYS not in _gateways_of(rm)
                                         else {e["gateway"] for e in effective if e["layer"] == rm.layer})}
        missing = sorted(g for (_l, g) in mine - set(where))
        coverers = sorted({number.get(c, c) for cs, _f in where.values() for c in cs},
                          key=lambda x: (x is None, str(x) if isinstance(x, str) else x))
        if missing:
            entry.limitations.append(
                f"covered by rule {', '.join(map(str, coverers))} on some gateways but effective on "
                f"{', '.join(missing)}")
            continue
        cov_uids, f = next(iter(where.values()))
        cov_numbers = sorted(n for n in (number.get(c) for c in cov_uids) if n is not None)
        first_cov = min(cov_uids, key=lambda c: (number.get(c) is None, number.get(c) or 0))
        refuted = _shadowing_refuted(rm, meta.get(first_cov), ref)
        if refuted:
            if refuted not in entry.limitations:
                entry.limitations.append(refuted)
            continue
        sig = dict(f.signals or {})
        sig.pop("shadowed_record", None)               # one grant's id; the check is about the rule
        # The earliest coverer: a deny moved above it is above all of them.
        sig["covered_by_rule"] = number.get(first_cov)
        sig["covered_by_rules"] = cov_numbers
        sig["gateways"] = sorted(g for (_l, g) in where)
        above = (f"rule {cov_numbers[0]}" if len(cov_numbers) == 1 else
                 "rules " + ", ".join(map(str, cov_numbers)) if cov_numbers else f"rule {first_cov}")
        entry.checks.append(Check("shadowed", f.severity, f.severity_band,
                                  f"never matched: {above} above it already cover"
                                  f"{'s' if len(cov_numbers) <= 1 else ''} it", sig, f.id))

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
    from . import nat as nat_mod
    nat_findings, nat_context = nat_mod.analyse(parsed)
    for e in register:
        e.nat = nat_context.get(e.rule_uid, [])
    stats["nat"] = {"rules": len(parsed.nat),
                    "by_check": {k: sum(1 for f in nat_findings if f.check == k)
                                 for k in sorted({f.check for f in nat_findings})}}
    if parsed.nat:
        limitations.append("NAT is shown as context on access rules and checked for NAT-rule hygiene; "
                           "access grants are evaluated on addresses as written, not rewritten through NAT")
    return Review(register=register, limitations=limitations, degraded_analyzers=degraded,
                  reviewed_at=now.isoformat(), reference_time=ref.isoformat(), stats=stats,
                  effective_policy=effective, nat_findings=nat_findings)
