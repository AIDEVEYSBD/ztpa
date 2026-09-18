"""Firewall policy from the vendor consoles: FortiManager, FortiGate, Junos Space.

WHY THIS IS NOT IN `fortinet.py` AND `juniper.py`.

Those two modules read the DEVICE inventory their consoles serve, and each says
in its own docstring that it emits no PolicyRecord -- a statement two test
modules assert, and the thing that makes "this console contributed devices and
interfaces" a checkable claim rather than a hope. Adding policy emission there
would have made those docstrings false and those tests fail for a good reason,
which is the worst kind of test failure to re-baseline. So policy arrives in its
own exports read by its own module, exactly as `algosec` and `algosec_topology`
already split one tool across two files and two readers.

WHAT IT FIXES. Every policy record in the product used to come from AlgoSec,
Guardicore or Wiz. A client with nine consoles onboarded therefore saw findings
attributed to three of them, and reasonably read the other six as having
contributed nothing -- which the Sources screen then confirmed by listing
"firewall policies" under YIELDS above a contributed count of zero records.

THE TWO TRAPS THIS MODULE EXISTS TO AVOID
-----------------------------------------
1. THE WILDCARD NAME. FortiOS spells the internet `all`; Junos spells it `any`.
   Both already dereference to 0.0.0.0/0 -- but under their OWN NAMES, so three
   spellings become three graph nodes that all mean the internet, and therefore
   three separate origins for `cross_tool_paths`, `who_can_reach` and the change
   simulator. `_canon_endpoint` collapses the NAME onto the canonical CIDR and
   keeps the vendor's own word in the audit row, so the provenance survives
   without the graph splitting.

2. THE VENDOR CATALOG SHAPE. `profile.object_cidrs` dereferences a catalog of
   `{name: {"value": ..., "type": ...}}` and recurses into group members through
   `member.get("value")`. FortiOS spells a leaf address as
   `subnet: ["10.20.0.0", "255.255.255.0"]` and a group's members as
   `member: [{"name": ...}]`. Handed that directly it returns `([], [])` --
   EMPTY, WITH NO WARNING -- so `source_unresolved` stays False and
   `exposure_score` falls back to the single-host floor, scoring a /16 group as
   one address. The adapters below convert each vendor's spelling into the
   shared shape BEFORE dereferencing, rather than widening the shared helper to
   know about four vendors' key names.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..netaddr import ANY_TOKENS
from .common import (
    NormalizeResult, ObservedEntity, ResolvedObject,
    merge_entities, normalize_cidr, parse_service, record_from_service,
)
from .profile import (
    object_cidrs, object_is_abstract, require_action, require_rows, require_rule,
    require_token,
)

#: The canonical name every wildcard spelling collapses onto. Deliberately the
#: CIDR and not a word: `graph.build` keys a node on this string, and the engine
#: already has 0.0.0.0/0 nodes from the AlgoSec and Wiz exports.
ANY_NAME = "0.0.0.0/0"


@dataclass
class _Endpoint:
    name: str
    cidrs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    unresolved: bool = False
    #: The vendor's own word for this endpoint, when it differs from `name`.
    #: Kept so the audit trail can show what the export actually said.
    as_written: str | None = None


def _canon_endpoint(token: str, catalog: dict) -> _Endpoint:
    """One src/dst token -> the node name and address space it denotes.

    A wildcard collapses onto `ANY_NAME`; anything else keeps its own name and
    dereferences through the catalog. `cidrs == []` on a named object is a FACT
    ("this object resolves to no address"), not an omission -- `exposure_score`
    reads the distinction, so it must not be papered over here.
    """
    tok = str(token).strip()
    if tok.lower() in ANY_TOKENS:
        return _Endpoint(name=ANY_NAME, cidrs=[ANY_NAME], as_written=tok)
    obj = catalog.get(tok)
    if obj is None:
        # Not in the catalog and not a wildcard: an identity node with no known
        # address space, flagged so the scorer does not treat absence as a /32.
        return _Endpoint(name=tok, unresolved=True)
    cidrs, warnings = object_cidrs(obj.get("value"), objects=catalog,
                                   seen=frozenset({tok}))
    if cidrs == [ANY_NAME]:
        # A NAMED object that dereferences to the whole internet -- FortiOS ships
        # one called `all`. It collapses too: the node is the address space, not
        # the label somebody gave it.
        return _Endpoint(name=ANY_NAME, cidrs=cidrs, tags=list(obj.get("tags") or []),
                         as_written=tok)
    return _Endpoint(name=tok, cidrs=cidrs, tags=list(obj.get("tags") or []),
                     unresolved=bool(warnings) and not cidrs)


def _audit_catalog(res: NormalizeResult, tool: str, catalog: dict, device: str) -> None:
    """One audit row per catalog object, sorted, so the dereferencing trail is
    stable across runs -- it is persisted and rendered."""
    for name in sorted(catalog):
        obj = catalog[name]
        cidrs, warnings = object_cidrs(obj.get("value"), objects=catalog,
                                       seen=frozenset({name}))
        row = {"value": obj.get("value"), "type": obj.get("type"),
               "tags": obj.get("tags") or [], "cidrs": cidrs,
               "abstract": object_is_abstract(obj.get("type"), cidrs, warnings)}
        if warnings:
            row["warnings"] = warnings
        res.resolved.append(ResolvedObject(tool, name, "address", row, device))


def _emit(res: NormalizeResult, *, tool: str, device: str, ref: str, src: _Endpoint,
          dst: _Endpoint, svc, action: str, order: int | None, note: str | None,
          entities: dict) -> None:
    """One PolicyRecord, plus the entity rows its endpoints imply."""
    for ep in (src, dst):
        if ep.name == ANY_NAME:
            continue                      # the internet is not an observed asset
        merge_entities(entities, ObservedEntity(
            name=ep.name, kind="identity", tool=tool,
            cidr=ep.cidrs[0] if len(ep.cidrs) == 1 else None,
            cidrs=list(ep.cidrs), tags=list(ep.tags),
            # A named object denoting a RANGE is abstract: reaching hosts inside
            # it does not let you originate as it, and `_valid_traversal` refuses
            # to pivot through one. Every endpoint these rules name is a segment.
            abstract=bool(ep.cidrs),
        ))
    res.records.append(record_from_service(
        record_id=ref, source_tool=tool, raw_ref=ref,
        source=src.name, destination=dst.name, svc=svc, action=action,
        dest_tags=dst.tags, order=order, note=note,
        source_cidrs=src.cidrs, dest_cidrs=dst.cidrs,
        source_unresolved=src.unresolved,
    ))


# ── FortiManager / FortiGate ───────────────────────────────────────────────

def _forti_catalog(addresses: list, groups: list) -> dict:
    """FortiOS address + addrgrp rows -> the shared catalog shape.

    `subnet: ["10.20.0.0", "255.255.255.0"]` becomes `value: "10.20.0.0/24"`, and
    a group's `member: [{"name": ...}]` becomes `value: [<names>]` -- which is
    the form `object_cidrs` recurses through. Without this the helper silently
    returns nothing; see the module docstring.
    """
    out: dict = {}
    for a in addresses or []:
        name = a.get("name")
        if not name:
            continue
        sub = a.get("subnet")
        if isinstance(sub, list) and len(sub) == 2:
            value = normalize_cidr(f"{sub[0]}/{sub[1]}") or f"{sub[0]}/32"
        else:
            value = sub if isinstance(sub, str) else a.get("ip-address")
        out[name] = {"value": value, "type": a.get("type") or "ipmask",
                     "tags": [], "comment": a.get("comment")}
    for g in groups or []:
        name = g.get("name")
        if not name:
            continue
        out[name] = {"value": [m.get("name") for m in (g.get("member") or [])
                               if isinstance(m, dict) and m.get("name")],
                     "type": "addrgrp", "tags": []}
    return out


def _forti_first(row: dict, key: str) -> str:
    """FortiOS carries src/dst/service as a LIST of `{name: ...}`. The first
    member is taken and a multi-member column is refused rather than quietly
    reduced -- one rule naming three destinations is three grants, and
    collapsing it to one under-reports the other two."""
    vals = row.get(key)
    if isinstance(vals, list) and vals:
        names = [v.get("name") for v in vals if isinstance(v, dict) and v.get("name")]
        if len(names) > 1 and key in ("srcaddr", "dstaddr", "service"):
            raise ValueError(
                f"rule {row.get('policyid')}: {key} names {len(names)} members "
                f"({', '.join(names)}); one rule naming several is several grants "
                "and reducing it to one under-reports the rest")
        if names:
            return names[0]
    return ""


def normalize_fortimanager(export: dict) -> NormalizeResult:
    """The policy package out of FortiManager's JSON-RPC envelope."""
    return _normalize_forti(export, tool="fortimanager", device="fortimanager-01",
                            rows=_fmg_rows(export), catalog=_fmg_catalog(export))


def _fmg_blocks(export: dict) -> dict:
    """`result[].url -> data`, with a failed block refused by name. FortiManager
    answers HTTP 200 on failure and puts the real outcome in
    `result[].status.code`, so an unchecked read ingests an empty result as
    success -- which is the failure this console is notorious for."""
    out: dict = {}
    for blk in export.get("result") or []:
        if not isinstance(blk, dict):
            continue
        code = (blk.get("status") or {}).get("code")
        if code not in (None, 0):
            raise ValueError(
                f"fortimanager: {blk.get('url')!r} returned status code {code} "
                f"({(blk.get('status') or {}).get('message')!r}); a non-zero code with "
                "HTTP 200 is how an empty FortiManager result ingests as success")
        out[str(blk.get("url") or "")] = blk.get("data") or []
    return out


def _fmg_rows(export: dict) -> list:
    blocks = _fmg_blocks(export)
    for url, data in blocks.items():
        if url.endswith("/firewall/policy"):
            return data
    return []


def _fmg_catalog(export: dict) -> dict:
    blocks = _fmg_blocks(export)
    addrs, grps = [], []
    for url, data in blocks.items():
        if url.endswith("/firewall/address"):
            addrs = data
        elif url.endswith("/firewall/addrgrp"):
            grps = data
    return _forti_catalog(addrs, grps)


def normalize_fortigate(export: dict) -> NormalizeResult:
    """The rulebase read straight off one FortiGate. Keyed by hostname, because
    a direct read answers from whichever unit you asked -- the HA secondary's
    config is synced, but this is not a claim about the secondary."""
    res = NormalizeResult()
    entities: dict = {}
    for host in sorted(export):
        body = export[host] or {}
        pol = (body.get("cmdb/firewall/policy") or {}).get("results") or []
        addr = (body.get("cmdb/firewall/address") or {}).get("results") or []
        one = _normalize_forti({}, tool="fortigate", device=host, rows=pol,
                               catalog=_forti_catalog(addr, []), entities=entities)
        res.records.extend(one.records)
        res.resolved.extend(one.resolved)
    res.entities = list(entities.values())
    return res


def _normalize_forti(_export: dict, *, tool: str, device: str, rows: list,
                     catalog: dict, entities: dict | None = None) -> NormalizeResult:
    res = NormalizeResult()
    own = entities is None
    entities = {} if own else entities
    _audit_catalog(res, tool, catalog, device)

    for i, row in enumerate(require_rows(rows, tool=tool, what="'firewall/policy'")):
        rule = require_rule(row, tool=tool, index=i + 1)
        pid = rule.get("policyid")
        ref = f"{device}-{pid}" if pid is not None else f"{device}-#{i + 1}"
        where = f"rule {ref!r}"
        src = _canon_endpoint(_forti_first(rule, "srcaddr") or
                              require_token(rule, "srcaddr", tool=tool, where=where), catalog)
        dst = _canon_endpoint(_forti_first(rule, "dstaddr") or
                              require_token(rule, "dstaddr", tool=tool, where=where), catalog)
        svc = parse_service(_forti_first(rule, "service") or None)
        _emit(res, tool=tool, device=device, ref=ref, src=src, dst=dst, svc=svc,
              action=require_action(rule, "action", tool=tool, where=where),
              order=pid, note=rule.get("comments"), entities=entities)
    if own:
        res.entities = list(entities.values())
    return res


# ── Junos Space / Security Director ────────────────────────────────────────

def normalize_junos_space(export: dict) -> NormalizeResult:
    """Security Director's firewall policies, with its service objects.

    A Space service object carries protocol and port SEPARATELY, and its name
    ("any-tcp", "junos-https") decodes to nothing useful -- so the port and
    protocol are handed to `parse_service` directly. Passing the name would
    reach `P_UNKNOWN` with only a warning, which is how a rule opening every
    port scores as if nobody knew what it opened.
    """
    res = NormalizeResult()
    entities: dict = {}
    tool, device = "junos_space", "junos-space-01"

    addrs = (((export.get("/api/juniper/sd/address-management/addresses") or {})
              .get("addresses") or {}).get("address")) or []
    catalog: dict = {}
    for a in addrs:
        name = a.get("name")
        if not name:
            continue
        ip, mask = a.get("ip-address"), a.get("netmask")
        value = normalize_cidr(f"{ip}/{mask}") if ip and mask else ip
        catalog[name] = {"value": value, "tags": [],
                         "type": "network" if (a.get("address-type") or "").upper() == "NETWORK"
                                 else "host"}
    _audit_catalog(res, tool, catalog, device)

    services: dict = {}
    for s in (((export.get("/api/juniper/sd/service-management/services") or {})
               .get("services") or {}).get("service")) or []:
        protos = ((s.get("protocols") or {}).get("protocol")) or []
        if s.get("name") and protos:
            services[s["name"]] = protos[0]

    policies = (((export.get("/api/juniper/sd/policy-management/firewall/policies") or {})
                 .get("policies") or {}).get("policy")) or []
    for pol in policies:
        for i, row in enumerate(require_rows(((pol.get("rules") or {}).get("rule")) or [],
                                             tool=tool, what="'rules.rule'")):
            rule = require_rule(row, tool=tool, index=i + 1)
            seq = rule.get("sequence-number")
            ref = f"{pol.get('name', 'policy')}-{seq}" if seq is not None else f"{pol.get('name')}-#{i+1}"
            where = f"rule {ref!r}"
            src = _canon_endpoint(_jsp_addr(rule, "source-address"), catalog)
            dst = _canon_endpoint(_jsp_addr(rule, "destination-address"), catalog)
            sname = (((rule.get("service") or {}).get("service")) or [{}])[0].get("name") or ""
            proto = services.get(sname) or {}
            svc = parse_service(None, port=proto.get("dst-port"), protocol=proto.get("name"))
            _emit(res, tool=tool, device=device, ref=ref, src=src, dst=dst, svc=svc,
                  action=require_action(rule, "action", tool=tool, where=where),
                  order=seq, note=rule.get("description"), entities=entities)
    res.entities = list(entities.values())
    return res


def _jsp_addr(rule: dict, key: str) -> str:
    lst = ((rule.get(key) or {}).get("address")) or []
    return (lst[0].get("name") if lst and isinstance(lst[0], dict) else "") or "any"
