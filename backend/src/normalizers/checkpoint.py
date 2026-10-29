"""Check Point policy, read from the Management API's own JSON.

INPUT
-----
The responses of

    show-access-rulebase  name <layer>  details-level full  use-object-dictionary true  show-hits true
    show-nat-rulebase     package <pkg> details-level full  use-object-dictionary true

either as one response, or bundled:

    {"exported_at": "<ISO-8601>",                 # optional; the uploader may declare it instead
     "access_layers": [<show-access-rulebase response>, ...],
     "nat_packages":  [<show-nat-rulebase response>, ...]}

Rules reference objects by uid; `objects-dictionary` holds the objects.
Sections (`access-section`) nest rules; numbering is the console's `rule-number`.

WHAT IS REFUSED (ExportRejected), BECAUSE ACCEPTING IT WOULD MISREPORT
---------------------------------------------------------------------
* no `rulebase` list            -- not a rulebase export; reading it as "no rules"
                                   is the empty-estate failure (audit item B3)
* a paginated, incomplete page  -- `to < total` means rules are missing; a review of
                                   half a rulebase reports the other half as clean
* a rule without uid / source / destination / service / action

WHAT IS APPROXIMATED (recorded as a limitation on the rule, never silently)
--------------------------------------------------------------------------
* a negated cell                -- "anything except X" is read as ANY (broader, so
                                   risk is over- rather than under-stated)
* an application/site service   -- read as any port, any protocol (same direction)
* a reference missing from the objects dictionary -- the endpoint is unresolved
                                   and flagged, so it is never scored as one host
* an inline layer               -- the parent rule is kept; its child layer is not
                                   expanded (limitation names it)
* a rule expanding to more than MAX_GRANTS_PER_RULE grants -- truncated, limited

STATE THAT CHANGES WHAT A RULE MEANS
------------------------------------
* `enabled: false`       -> no grant (a switched-off rule permits nothing); kept in
                            the inventory so the review can recommend removing it
* time object in the past -> no grant (an expired rule never matches); inventory
                            records `expires_at` for the expired-rule check
* `hits` absent          -> hit_count None (unknown), never 0
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from itertools import product
from typing import Any, Iterable, Optional

from ..frr.rulebase import ExportRejected, NatRule, ParsedRulebase, RuleMeta
from .common import (
    NormalizeResult, ObservedEntity, ResolvedObject, merge_entities, parse_service,
    record_from_service,
)

TOOL = "checkpoint"
ANY = "0.0.0.0/0"
MAX_GRANTS_PER_RULE = 512
_MAX_GROUP_DEPTH = 16

_ALLOW_ACTIONS = {"accept", "ask", "inform"}       # ask/inform let the user proceed
_DENY_ACTIONS = {"drop", "reject"}


def _parse_time(value: Any) -> Optional[datetime]:
    """Check Point times arrive as {"iso-8601": ..., "posix": ms} or a bare string."""
    if value is None:
        return None
    if isinstance(value, dict):
        if value.get("posix") is not None:
            return datetime.fromtimestamp(int(value["posix"]) / 1000, tz=timezone.utc)
        value = value.get("iso-8601")
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class _Objects:
    """uid -> object, with address and service dereferencing."""

    def __init__(self, dictionary: Iterable[dict]) -> None:
        self.by_uid: dict[str, dict] = {}
        for o in dictionary or []:
            if isinstance(o, dict) and o.get("uid"):
                self.by_uid[o["uid"]] = o

    def get(self, ref: Any) -> Optional[dict]:
        if isinstance(ref, dict):                     # inline object (details-level full without dictionary)
            if ref.get("uid") and ref["uid"] not in self.by_uid:
                self.by_uid[ref["uid"]] = ref
            return ref
        return self.by_uid.get(str(ref))

    def name(self, ref: Any) -> str:
        o = self.get(ref)
        return (o or {}).get("name") or str(ref if not isinstance(ref, dict) else ref.get("uid"))

    @staticmethod
    def is_any(o: Optional[dict]) -> bool:
        return bool(o) and (o.get("type") == "CpmiAnyObject" or str(o.get("name", "")).lower() == "any")

    def address_cidrs(self, ref: Any, depth: int = 0, seen: frozenset = frozenset()
                      ) -> tuple[list[str], list[str]]:
        """(cidrs, warnings). Empty cidrs + a warning = unresolvable network."""
        o = self.get(ref)
        if o is None:
            return [], [f"object {ref} is not in the export's objects dictionary"]
        if self.is_any(o):
            return [ANY], []
        uid = o.get("uid")
        if uid in seen or depth > _MAX_GROUP_DEPTH:
            return [], [f"group {o.get('name')} is nested cyclically or too deep"]
        t = o.get("type", "")
        try:
            if t == "host":
                ip = o.get("ipv4-address") or o.get("ipv6-address")
                return ([str(ipaddress.ip_network(ip))] if ip else []), ([] if ip else [f"host {o.get('name')} has no address"])
            if t == "network":
                if o.get("subnet4"):
                    return [str(ipaddress.ip_network(f"{o['subnet4']}/{o.get('mask-length4', 32)}", strict=False))], []
                if o.get("subnet6"):
                    return [str(ipaddress.ip_network(f"{o['subnet6']}/{o.get('mask-length6', 128)}", strict=False))], []
                return [], [f"network {o.get('name')} has no subnet"]
            if t == "address-range":
                first = ipaddress.ip_address(o.get("ipv4-address-first") or o.get("ipv6-address-first"))
                last = ipaddress.ip_address(o.get("ipv4-address-last") or o.get("ipv6-address-last"))
                return [str(n) for n in ipaddress.summarize_address_range(first, last)], []
            if t in ("group", "group-with-exclusion"):
                members = o.get("members") or []
                if t == "group-with-exclusion":
                    members = [o.get("include")] if o.get("include") else []
                out, warns = [], []
                for m in members:
                    c, w = self.address_cidrs(m, depth + 1, seen | {uid})
                    out += c
                    warns += w
                if t == "group-with-exclusion":
                    warns.append(f"group {o.get('name')} excludes addresses; read as its include set (broader)")
                return sorted(set(out)), warns
        except (ValueError, TypeError) as e:
            return [], [f"object {o.get('name')}: unreadable address ({e})"]
        # access-role, dns-domain, security-zone, updatable-object, ...: no address space.
        return [], []

    def services(self, ref: Any, depth: int = 0, seen: frozenset = frozenset()
                 ) -> tuple[list[str], list[str]]:
        """Service strings for parse_service, plus warnings."""
        o = self.get(ref)
        if o is None:
            return ["any"], [f"service {ref} is not in the objects dictionary; read as any"]
        if self.is_any(o):
            return ["any"], []
        uid = o.get("uid")
        if uid in seen or depth > _MAX_GROUP_DEPTH:
            return ["any"], [f"service group {o.get('name')} is cyclic or too deep; read as any"]
        t = o.get("type", "")
        if t in ("service-tcp", "service-udp", "service-sctp"):
            proto = t.split("-", 1)[1]
            port = str(o.get("port", "")).strip()
            if port.startswith(">"):
                port = f"{int(port[1:]) + 1}-65535"
            elif port.startswith("<"):
                port = f"1-{int(port[1:]) - 1}"
            return [f"{proto}/{port}" if port else f"{proto}/any"], []
        if t in ("service-icmp", "service-icmp6"):
            return ["icmp"], []
        if t == "service-group":
            out, warns = [], []
            for m in o.get("members") or []:
                s, w = self.services(m, depth + 1, seen | {uid})
                out += s
                warns += w
            return out or ["any"], warns
        if t in ("application-site", "application-site-category", "application-site-group"):
            return ["any"], [f"application {o.get('name')} is matched by Check Point at L7; "
                             "read as any port (broader)"]
        return ["any"], [f"service {o.get('name')} of type {t or 'unknown'} read as any"]


def _required(rule: dict, key: str, where: str) -> Any:
    v = rule.get(key)
    if v is None or (isinstance(v, list) and not v and key != "time"):
        raise ExportRejected(f"{where}: rule has no '{key}'; a rule without it cannot be reviewed")
    return v


def _check_complete(resp: dict, what: str) -> None:
    if not isinstance(resp.get("rulebase"), list):
        raise ExportRejected(f"{what}: no 'rulebase' list; this is not a rulebase export "
                             "(expected show-access-rulebase / show-nat-rulebase JSON)")
    total, to = resp.get("total"), resp.get("to")
    if isinstance(total, int) and isinstance(to, int) and to < total:
        raise ExportRejected(f"{what}: export is one page (rules {resp.get('from', 1)}-{to} of "
                             f"{total}); export with a limit >= total or merge the pages first")


def _walk(rulebase: list, section: Optional[str] = None):
    for item in rulebase or []:
        if not isinstance(item, dict):
            continue
        t = item.get("type", "")
        if t.endswith("-section"):
            yield from _walk(item.get("rulebase") or [], item.get("name") or section)
        else:
            yield item, section


def _endpoint(objs: _Objects, refs: list, negate: bool) -> tuple[list[tuple[str, list[str], bool]], list[str]]:
    """[(name, cidrs, unresolved)] for each reference in a rule cell."""
    if negate:
        names = ", ".join(objs.name(r) for r in refs)
        return [(ANY, [ANY], False)], [f"cell is negated (anything except {names}); read as any"]
    out, warns = [], []
    for r in refs:
        o = objs.get(r)
        cidrs, w = objs.address_cidrs(r)
        warns += w
        if objs.is_any(o) or cidrs == [ANY]:
            out.append((ANY, [ANY], False))
        else:
            out.append((objs.name(r), cidrs, bool(w) and not cidrs))
    return out, warns


def _parse_layer(resp: dict, objs: _Objects, exported_at: Optional[datetime],
                 res: NormalizeResult, entities: dict, parsed: ParsedRulebase) -> None:
    layer = resp.get("name") or resp.get("uid") or "layer"
    _check_complete(resp, f"access layer {layer}")
    parsed.layers.append(layer)
    now = exported_at or datetime.now(timezone.utc)
    for rule, section in _walk(resp["rulebase"]):
        where = f"layer {layer} rule {rule.get('rule-number', rule.get('uid', '?'))}"
        uid = _required(rule, "uid", where)
        src_refs = _required(rule, "source", where)
        dst_refs = _required(rule, "destination", where)
        svc_refs = _required(rule, "service", where)
        action_o = objs.get(_required(rule, "action", where)) or {}
        action_raw = str(action_o.get("name") or rule["action"])
        a = action_raw.lower()
        action = "allow" if a in _ALLOW_ACTIONS else "deny" if a in _DENY_ACTIONS else "other"

        expires = None
        for t in rule.get("time") or []:
            to = objs.get(t) or {}
            if objs.is_any(to) or to.get("end-never", True):
                continue
            end = _parse_time(to.get("end"))
            if end and (expires is None or end < expires):
                expires = end
        hits = rule.get("hits") if isinstance(rule.get("hits"), dict) else None
        meta = RuleMeta(
            source_tool=TOOL, layer=layer, uid=uid, number=rule.get("rule-number"),
            name=rule.get("name"), enabled=bool(rule.get("enabled", True)),
            action=action, action_raw=action_raw,
            sources=[objs.name(r) for r in src_refs], destinations=[objs.name(r) for r in dst_refs],
            services=[objs.name(r) for r in svc_refs],
            source_negate=bool(rule.get("source-negate")),
            destination_negate=bool(rule.get("destination-negate")),
            service_negate=bool(rule.get("service-negate")),
            expires_at=expires,
            hit_count=int(hits["value"]) if hits and hits.get("value") is not None else None,
            last_hit=_parse_time(hits.get("last-date")) if hits else None,
            install_on=[objs.name(r) for r in rule.get("install-on") or []],
            section=section, comments=rule.get("comments") or None,
        )
        parsed.rules.append(meta)

        if rule.get("inline-layer"):
            meta.limitations.append(f"applies inline layer {objs.name(rule['inline-layer'])}, "
                                    "which is not expanded")
        if action == "other":
            meta.limitations.append(f"action '{action_raw}' is not allow/deny; no grant emitted")
            continue
        if not meta.enabled:
            continue
        if expires is not None and expires <= now:
            continue

        srcs, w1 = _endpoint(objs, src_refs, meta.source_negate)
        dsts, w2 = _endpoint(objs, dst_refs, meta.destination_negate)
        svcs, w3 = [], []
        if meta.service_negate:
            svcs, w3 = ["any"], ["service cell is negated; read as any"]
        else:
            for r in svc_refs:
                s, w = objs.services(r)
                svcs += s
                w3 += w
        meta.limitations += sorted(set(w1 + w2 + w3))

        combos = product(srcs, dsts, dict.fromkeys(svcs))
        n_total = len(srcs) * len(dsts) * len(dict.fromkeys(svcs))
        for i, ((sname, scidrs, sunres), (dname, dcidrs, _), svc) in enumerate(combos):
            if i >= MAX_GRANTS_PER_RULE:
                meta.limitations.append(f"expands to {n_total} grants; only the first "
                                        f"{MAX_GRANTS_PER_RULE} are analysed")
                meta.grants_truncated = True
                break
            rid = f"cp:{layer}:{uid}:{i}"
            for name, cidrs in ((sname, scidrs), (dname, dcidrs)):
                if name != ANY:
                    merge_entities(entities, ObservedEntity(
                        name=name, kind="identity", tool=TOOL,
                        cidr=cidrs[0] if len(cidrs) == 1 else None, cidrs=list(cidrs),
                        tags=[], abstract=bool(cidrs)))
            res.records.append(record_from_service(
                record_id=rid, source_tool=TOOL, raw_ref=uid, source=sname, destination=dname,
                svc=parse_service(svc), action=action, order=meta.number,
                note=f"{layer} rule {meta.number}: {meta.name or ''}".strip(),
                source_cidrs=scidrs, dest_cidrs=dcidrs, source_unresolved=sunres))
            meta.record_ids.append(rid)


def _parse_nat(resp: dict, objs: _Objects, parsed: ParsedRulebase) -> None:
    package = resp.get("name") or resp.get("package") or resp.get("uid") or "package"
    _check_complete(resp, f"NAT package {package}")

    def cell(rule: dict, key: str) -> tuple[list[str], list[str]]:
        v = rule.get(key)
        refs = v if isinstance(v, list) else ([v] if v else [])
        names = [objs.name(r) for r in refs]
        cidrs: list[str] = []
        for r in refs:
            cidrs += objs.address_cidrs(r)[0]
        return names, sorted(set(cidrs))

    for rule, _section in _walk(resp["rulebase"]):
        if rule.get("type") not in (None, "nat-rule"):
            continue
        os_, osc = cell(rule, "original-source")
        od, odc = cell(rule, "original-destination")
        ts, tsc = cell(rule, "translated-source")
        td, tdc = cell(rule, "translated-destination")
        osvc = rule.get("original-service")
        specs: list[str] = []
        for r in (osvc if isinstance(osvc, list) else [osvc] if osvc else []):
            specs += objs.services(r)[0]
        parsed.nat.append(NatRule(
            source_tool=TOOL, package=package, uid=rule.get("uid", ""),
            number=rule.get("rule-number"), enabled=bool(rule.get("enabled", True)),
            method=str(rule.get("method") or "static"),
            auto_generated=bool(rule.get("auto-generated")),
            original_source=os_, original_destination=od,
            original_service=cell(rule, "original-service")[0],
            translated_source=ts, translated_destination=td,
            translated_service=cell(rule, "translated-service")[0],
            original_source_cidrs=osc, original_destination_cidrs=odc,
            translated_source_cidrs=tsc, translated_destination_cidrs=tdc,
            original_service_specs=sorted(set(specs)) or ["any"],
            install_on=[objs.name(r) for r in rule.get("install-on") or []],
            comments=rule.get("comments") or None))


def parse(export: Any, *, exported_at: Optional[datetime] = None) -> ParsedRulebase:
    """Parse a Check Point export. Raises ExportRejected when it cannot be
    reviewed as given (see the module docstring)."""
    if not isinstance(export, dict):
        raise ExportRejected("a Check Point export is a JSON object")
    if "access_layers" in export or "nat_packages" in export:
        layers = export.get("access_layers") or []
        nats = export.get("nat_packages") or []
        declared = _parse_time(export.get("exported_at"))
    else:
        layers, nats, declared = [export], [], None
    if not isinstance(layers, list) or not layers:
        raise ExportRejected("the export contains no access layer")
    when = exported_at or declared

    dictionary: list = []
    for resp in [*layers, *nats]:
        if not isinstance(resp, dict):
            raise ExportRejected("each access layer / NAT package must be a JSON object")
        dictionary += resp.get("objects-dictionary") or []
    objs = _Objects(dictionary)

    res = NormalizeResult()
    parsed = ParsedRulebase(source_tool=TOOL, result=res, exported_at=when)
    entities: dict = {}
    for resp in layers:
        _parse_layer(resp, objs, when, res, entities, parsed)
    for resp in nats:
        _parse_nat(resp, objs, parsed)
    res.entities = list(entities.values())

    for uid in sorted(objs.by_uid):
        o = objs.by_uid[uid]
        if o.get("type") in ("host", "network", "address-range", "group", "group-with-exclusion"):
            cidrs, warnings = objs.address_cidrs(uid)
            row = {"uid": uid, "type": o.get("type"), "cidrs": cidrs}
            if warnings:
                row["warnings"] = warnings
            res.resolved.append(ResolvedObject(TOOL, o.get("name") or uid, "address", row, None))

    if not parsed.rules:
        raise ExportRejected("the export's rulebase contains no rules; refusing to report an empty "
                             "policy as reviewed")
    if when is None:
        parsed.limitations.append("export time unknown: expiry was judged against the time of "
                                  "review, and export age could not be checked")
    if parsed.rules and all(r.hit_count is None for r in parsed.rules):
        parsed.limitations.append("hit counts absent (export without show-hits): unused-rule "
                                  "checks cannot run")
    return parsed
