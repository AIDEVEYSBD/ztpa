"""The change-package drafter: from a rule-risk register to proposed changes,
each with its availability impact, the commands a human would run, and the
exact rollback.

DETERMINISTIC. Which change a check calls for is a rule, not a judgement:

  check              proposal                          availability impact
  -----------------  --------------------------------  ---------------------------------
  shadowed (allow)   remove (covered by rule N)        none   -- the rule never matches
  shadowed (deny)    move above the covering rule      changes behaviour -- owner decides
  shadowed by a rule revisit after rule N changes      none   -- removing it now would break
   being narrowed                                               traffic once rule N is narrowed
  shadowed cleanup   revisit after rule N changes      none   -- never move a deny-all
  expired            remove                            none   -- an expired rule never matches
  disabled           remove                            none   -- a disabled rule never matches
  unused             disable now, remove after review  possible -- hits can be seasonal
  any_any /          time-bound for N days and         likely -- the rule carries traffic;
  admin_port_exposed narrow to owner-supplied sources  the owner supplies what it should allow
  / broad_source /   (the export has no flow data to
  over_permissive    derive a narrower rule from)

NO DEVICE WRITE AND NO ITSM CALL EXISTS IN THIS CODE PATH. The output is text a
network engineer runs after the package is approved (FRR-03). Commands are
Check Point `mgmt_cli`; rollback commands restore the rule exactly as exported
(sources, destinations, services, action, position, enabled, time).
"""

from __future__ import annotations

import os
import shlex
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

TIME_BOUND_DAYS = int(os.environ.get("NPR_FRR_TIME_BOUND_DAYS", "30"))
UNUSED_REMOVE_AFTER_DAYS = int(os.environ.get("NPR_FRR_UNUSED_REMOVE_AFTER_DAYS", "30"))

# Highest-priority check wins when a rule has several.
_PRIORITY = ["any_any", "admin_port_exposed", "broad_source", "over_permissive",
             "shadowed", "expired", "disabled", "unused"]
_NARROW = {"any_any", "admin_port_exposed", "broad_source", "over_permissive"}


@dataclass
class Item:
    item_id: str
    rule_uid: str
    layer: str
    rule_number: Optional[int]
    rule_name: Optional[str]
    check: str
    band: str
    proposal: str                 # remove | disable_then_remove | reorder | time_bound_and_narrow
    rationale: str
    availability_impact: str      # none | possible | likely | changes_behaviour
    requires_owner_input: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    rollback: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


def _q(v: Any) -> str:
    return shlex.quote(str(v))


def _restore(rule: dict, layer: str) -> list[str]:
    """`mgmt_cli add access-rule` recreating the rule as exported."""
    parts = [f"mgmt_cli add access-rule layer {_q(layer)}",
             f"position {rule['number']}" if rule.get("number") is not None else "position bottom",
             f"name {_q(rule.get('name') or rule['uid'])}"]
    for key, cli in (("sources", "source"), ("destinations", "destination"), ("services", "service")):
        for i, v in enumerate(rule.get(key) or ["Any"], 1):
            parts.append(f"{cli}.{i} {_q(v)}")
    parts.append(f"action {_q(rule.get('action_raw') or 'Accept')}")
    parts.append(f"enabled {'true' if rule.get('enabled', True) else 'false'}")
    for flag, cli in (("source_negate", "source-negate"), ("destination_negate", "destination-negate"),
                      ("service_negate", "service-negate")):
        if rule.get(flag):
            parts.append(f"{cli} true")
    return [" ".join(parts) + "   # restores the rule as exported; re-apply its time object if it had one"]


def _publish() -> list[str]:
    return ["mgmt_cli publish", "mgmt_cli install-policy policy-package <package> targets.1 <gateway>"]


def _is_cleanup(rule: dict) -> bool:
    """A deny-everything rule: the rulebase's intended default, never moved."""
    def any_(cell):
        return not cell or all(str(v).lower() == "any" for v in cell)
    return rule.get("action") == "deny" and all(
        any_(rule.get(k)) for k in ("sources", "destinations", "services"))


def _draft_item(n: int, entry: dict, rule: dict, numbers: dict[int, dict],
                narrowed: set[int]) -> Optional[Item]:
    checks = {c["check"]: c for c in entry["checks"]}
    kind = next((k for k in _PRIORITY if k in checks), None)
    if kind is None:
        return None
    c = checks[kind]
    layer, uid = entry["layer"], entry["rule_uid"]
    sel = f"uid {_q(uid)} layer {_q(layer)}"
    base = dict(item_id=f"item-{n}", rule_uid=uid, layer=layer, rule_number=entry["number"],
                rule_name=entry["name"], check=kind, band=c["band"], evidence=c.get("evidence") or {})

    if kind == "shadowed":
        cover = (c.get("evidence") or {}).get("covered_by_rule")
        if cover in narrowed:
            # The covering rule is itself being narrowed or time-bound; once it
            # is, THIS rule carries the traffic. Removing it now is an outage.
            return Item(**base, proposal="revisit_after",
                        rationale=f"covered by rule {cover}, which this package narrows. Leave it in "
                                  f"place; re-review it after rule {cover} changes.",
                        availability_impact="none")
        if entry["action"] == "deny" and _is_cleanup(rule):
            return Item(**base, proposal="revisit_after",
                        rationale=f"the cleanup rule never fires because rule {cover} allows "
                                  f"everything; fixing rule {cover} restores it. Never move a cleanup rule.",
                        availability_impact="none")
        if entry["action"] == "deny":
            return Item(**base, proposal="reorder",
                        rationale=f"this deny never fires: allow rule {cover} above it permits the "
                                  "same traffic. Moving it above that rule makes it take effect.",
                        availability_impact="changes_behaviour",
                        commands=[f"mgmt_cli set access-rule {sel} new-position {cover}", *_publish()],
                        rollback=[f"mgmt_cli set access-rule {sel} new-position {entry['number']}", *_publish()])
        return Item(**base, proposal="remove",
                    rationale=f"never matched: rule {cover} above it already allows everything this "
                              "rule allows. Removing it changes no traffic.",
                    availability_impact="none",
                    commands=[f"mgmt_cli delete access-rule {sel}", *_publish()],
                    rollback=[*_restore(rule, layer), *_publish()])
    if kind in ("expired", "disabled"):
        why = (f"expired {entry['expires_at'][:10]}" if kind == "expired" else "disabled")
        return Item(**base, proposal="remove",
                    rationale=f"{why}: the rule matches no traffic today. Removing it is cleanup.",
                    availability_impact="none",
                    commands=[f"mgmt_cli delete access-rule {sel}", *_publish()],
                    rollback=[*_restore(rule, layer), *_publish()])
    if kind in _NARROW and "unused" in checks:
        # A risky rule nobody uses: no need to narrow what can simply go.
        risky, c = c, checks["unused"]
        kind = "unused"
        base["evidence"] = {**(risky.get("evidence") or {}), **(c.get("evidence") or {})}
        base["check"] = f"{risky['check']}+unused"
    if kind == "unused":
        return Item(**base, proposal="disable_then_remove",
                    rationale=f"{c['title']}. Disable now; remove after {UNUSED_REMOVE_AFTER_DAYS} days "
                              "if nothing breaks. Hit counts can miss seasonal or failover traffic, so "
                              "the owner confirms.",
                    availability_impact="possible",
                    commands=[f"mgmt_cli set access-rule {sel} enabled false", *_publish(),
                              f"# after {UNUSED_REMOVE_AFTER_DAYS} days with no incident:",
                              f"mgmt_cli delete access-rule {sel}", *_publish()],
                    rollback=[f"mgmt_cli set access-rule {sel} enabled true", *_publish(),
                              "# if already deleted:", *_restore(rule, layer)])
    # Narrowing: a live, risky rule.
    tname = f"frr-{uid[:8]}-{TIME_BOUND_DAYS}d"
    return Item(**base, proposal="time_bound_and_narrow",
                rationale=f"{c['title']}. Contain it now by making it expire in {TIME_BOUND_DAYS} days, "
                          "and replace it with a rule limited to the sources and services the owner "
                          "confirms are needed. The export holds no flow data to derive those from.",
                availability_impact="likely",
                requires_owner_input=["allowed_sources", "allowed_services", "business_justification"],
                commands=[f"mgmt_cli add time name {_q(tname)} end-never false "
                          f"end.date \"<today + {TIME_BOUND_DAYS} days, dd-MMM-yyyy>\"",
                          f"mgmt_cli set access-rule {sel} time.1 {_q(tname)}",
                          f"# then: add the narrowed rule above rule {entry['number']} with the "
                          "owner-confirmed sources and services",
                          *_publish()],
                rollback=[f"mgmt_cli set access-rule {sel} time.1 Any",
                          f"mgmt_cli delete time name {_q(tname)}",
                          "# and delete the narrowed rule if it was added", *_publish()])


def draft(review: dict, parsed: dict) -> dict:
    """A change package from a stored review and parsed rulebase (both as served
    by intake). Items are ordered by severity, as the register is."""
    rules = {r["uid"]: r for r in parsed["rules"]}
    numbers = {r["number"]: r for r in parsed["rules"] if r.get("number") is not None}
    items: list[Item] = []
    narrowed = {e["number"] for e in review["register"]
                if e["checks"] and next((k for k in _PRIORITY if k in {c["check"] for c in e["checks"]}),
                                        None) in _NARROW}
    for entry in review["register"]:
        if not entry["checks"] or entry["rule_uid"] not in rules:
            continue
        item = _draft_item(len(items) + 1, entry, rules[entry["rule_uid"]], numbers, narrowed)
        if item:
            items.append(item)
    impact: dict[str, int] = {}
    for it in items:
        impact[it.availability_impact] = impact.get(it.availability_impact, 0) + 1
    return {"items": [asdict(i) for i in items],
            "summary": {"items": len(items), "by_impact": impact,
                        "by_proposal": {p: sum(1 for i in items if i.proposal == p)
                                        for p in sorted({i.proposal for i in items})}},
            "limitations": review.get("limitations", []),
            "notes": ["No change is applied by this product. A network engineer runs the "
                      "commands after approval; every item has its rollback."]}
