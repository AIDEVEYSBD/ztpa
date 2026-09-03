"""AlgoSec normalizer: vendor-abstracted ordered firewall rules -> PolicyRecords.

src/dst tokens are either a raw CIDR or a named object resolved via the export's
object catalog. Named objects keep their NAME as the node key -- that is what the
operator sees in their console and what `raw_ref` ties back to -- while the
address space the catalog dereferences them to now travels with the record on
`source_cidrs` / `dest_cidrs`.

Why that mattered enough to rewrite this module
-----------------------------------------------
Real AlgoSec/Palo/Check Point policies express sources as named objects or the
keyword `any` in the overwhelming majority of rules; raw CIDRs in the src column
are the exception. This module used to compute a named object's CIDR into a
local called `_s_cidr` and then throw it away, so the record carried only the
label. `severity.exposure_score` short-circuits an identity source to E_IDENTITY
(0.1 -- the exposure of a SINGLE HOST), and `cidr_overlap` skips any record whose
source is not a CIDR. The measured consequence (PROD-READINESS-AUDIT,
`algosec.py:31`) was that the identical rule `allow <src> -> db-prod-01 tcp/3389`
scored 100/critical/forced written as `0.0.0.0/0` and produced NO FINDING AT ALL
written as `any`, `ANY-EXTERNAL` or `INTERNET`. On a real export the tool
therefore reports FEWER findings, and "0 findings" reads to a client as "clean".

Two further decisions this module now owns:

  * A named `network`/`group`/`range`/`subnet` object is marked ``abstract``,
    exactly as the same block written as a raw CIDR always was. `Asset.kind`
    folds from it and `graph.reachability._valid_traversal` refuses to PIVOT
    through an abstract node -- so whether a path exists stopped depending on
    whether the export happened to name the network.
  * A token that looks like an address and is not one (``10.0.0.0/33``) is
    recorded as a malformed address rather than quietly becoming a new
    single-host asset in the inventory.

Malformed input is reported through the `resolved` audit rows (the export's own
"name -> value dereferencing" trail, which the Ingest Inspector already renders)
because `NormalizeResult` has no warning channel this phase; a structurally
un-normalizable rule raises `NormalizeError` naming the tool, rule and field,
instead of the bare `KeyError: 'action'` the audit measured. Per-row skipping
with a "38,412 ingested, 6 skipped" report is Phase 3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .common import (
    NormalizeResult, ObservedEntity, ResolvedObject,
    is_cidr, merge_entities, normalize_cidr, parse_service, record_from_service,
    scope_identifiers,
)
from .profile import (
    object_cidrs, object_is_abstract, object_netmask, require_action, require_mapping,
    require_rows, require_rule, require_token, service_audit, token_audit, token_cidrs,
)

TOOL = "algosec"


@dataclass
class _Resolved:
    """What one src/dst token dereferences to. A named record, not a tuple.

    The previous six-element tuple is how the resolved CIDR came to be discarded
    at the call site: `s_val, s_kind, s_ip, _s_cidr, _s_tags, s_ent` -- two of
    the six silently thrown away by an underscore. Naming the fields makes
    dropping one a visible edit.

    The node KIND is deliberately absent: `record_from_service` derives it from
    the token, so one string cannot be a CIDR here and an identity there.
    """

    name: str                       # display name / node key
    ip: Optional[str]               # concrete host ip, when the object is a host
    cidrs: list[str]                # the resolved address space ([] = none exists)
    tags: list[str]
    entity: ObservedEntity
    warnings: list[str]             # token/value defects, for the audit trail
    # Address space was CLAIMED (an address notation, or a catalog object whose
    # value/members claim to be one) and did not resolve. `cidrs == []` alone
    # cannot say that: a user group legitimately denotes no address space, and
    # scoring the two the same way is what let a typo'd broad rule score as a
    # single host. See `PolicyRecord.source_unresolved`.
    unresolved: bool = False


def _resolve(token: str, objects: dict) -> _Resolved:
    """One src/dst token -> its display name and the ADDRESS SPACE it denotes.

    Three cases, in this order:

    1. the token IS address space (a CIDR) -- a cidr node, abstract, as before;
    2. the token names an object in the export's catalog -- an identity node
       keyed on the NAME, carrying the catalog's resolved CIDRs;
    3. neither -- an identity node with no address space. `cidrs == []` here is
       a fact ("this object resolves to no address"), not an omission; see the
       `PolicyRecord.source_cidrs` docstring on why the distinction is
       load-bearing for `exposure_score`.

    Case 3 also covers the wildcard vocabulary: `any` / `all` / `*` resolve to
    ``0.0.0.0/0`` through `token_cidrs`, so four spellings of one rule finally
    score identically -- as do a Check Point range (`0.0.0.0-255.255.255.255`)
    and an ASA address+mask pair (`0.0.0.0 0.0.0.0`), which used to resolve to
    nothing at all. A named `ANY-EXTERNAL` / `INTERNET` object resolves the same
    way through case 2, from its catalog value.

    Case 2 hands the WHOLE CATALOG to `object_cidrs`, which is what makes a
    group whose members are the names of other groups dereference instead of
    reporting every member unresolvable (audit-2 B8). That is the shape real
    AlgoSec / Panorama / FortiManager catalogs are actually organised in, and it
    is the layer the previous round's fix stopped one level above.
    """
    if is_cidr(token):
        cidr = normalize_cidr(token)
        ent = ObservedEntity(name=cidr, kind="cidr", tool=TOOL, cidr=cidr, cidrs=[cidr],
                             abstract=True)
        return _Resolved(cidr, None, [cidr], [], ent, [])

    obj = objects.get(token)
    if not isinstance(obj, dict) or not obj:
        # Not in the catalog. It may still BE address space -- a bare host ip
        # (its own /32, which is how it joins subnet math and merges with the
        # asset that owns that address) or a wildcard word. If it merely LOOKS
        # like an address, that is a data defect, not a new asset.
        cidrs, warnings = token_cidrs(token)
        abstract = object_is_abstract(None, cidrs, warnings)
        ent = ObservedEntity(
            name=token, kind="identity", tool=TOOL, abstract=abstract,
            cidr=cidrs[0] if (abstract and len(cidrs) == 1) else None,
            cidrs=list(cidrs) if abstract else [],
            identifiers={"malformed_address": True} if warnings else {},
        )
        return _Resolved(token, None, cidrs, [], ent, warnings, bool(warnings))

    value, otype = obj.get("value"), obj.get("type")
    tags = obj.get("tags", []) or []
    cidrs, warnings = object_cidrs(value, netmask=object_netmask(obj), objects=objects,
                                   seen=frozenset({token}))
    abstract = object_is_abstract(otype, cidrs, warnings)
    # The namespace the catalog object declares (a VRF, a tenant), when it
    # declares one. An address is only an identity inside the namespace that
    # assigns it, and this is the only place that knowledge exists.
    scope = scope_identifiers(obj)
    if otype == "host" and not abstract:
        identifiers = dict(scope)
        if warnings:
            identifiers["malformed_address"] = True
        ent = ObservedEntity(name=token, kind="identity", tool=TOOL, ip=value, tags=list(tags),
                             identifiers=identifiers)
        return _Resolved(token, value if isinstance(value, str) else None,
                         cidrs, list(tags), ent, warnings, bool(warnings))
    # A group resolves to several blocks; `ObservedEntity.cidr` holds one string
    # (the identity layer does `ips.add(e.cidr)`), so only a single-block object
    # populates it. `cidrs` carries the WHOLE space, and it has to: the record's
    # `source_cidrs` reaches the exposure term but never the zone layer, which is
    # built from assets, so a group whose members include 0.0.0.0/0 used to reach
    # `zone_of` with an empty ip_set and be classified ZONE_INTERNAL -- scoring
    # the identical grant two bands below the same space written as a literal /0.
    ent = ObservedEntity(
        name=token, kind="identity", tool=TOOL, tags=list(tags), abstract=abstract,
        cidr=cidrs[0] if len(cidrs) == 1 else None,
        cidrs=list(cidrs),
        identifiers={**scope, "malformed_address": True} if warnings else dict(scope),
    )
    return _Resolved(token, None, cidrs, list(tags), ent, warnings, bool(warnings))


def normalize(export: dict) -> NormalizeResult:
    res = NormalizeResult()
    device = export.get("device")
    objects = require_mapping(export.get("objects"), tool=TOOL, what="'objects'")
    entities: dict[str, ObservedEntity] = {}

    # Object catalog audit rows. `sorted` because the dereferencing trail is
    # persisted and rendered, and it must not depend on JSON key order.
    for name in sorted(objects):
        obj = objects[name] if isinstance(objects[name], dict) else {}
        value, otype = obj.get("value"), obj.get("type")
        # The same dereference the rule path uses -- catalog and mask column
        # included -- so the Ingest Inspector shows the address space a NESTED
        # group actually denotes rather than a row of unresolvable member names.
        cidrs, warnings = object_cidrs(value, netmask=object_netmask(obj), objects=objects,
                                       seen=frozenset({name}))
        row = {"value": value, "type": otype, "tags": obj.get("tags", []),
               "cidrs": cidrs, "abstract": object_is_abstract(otype, cidrs, warnings)}
        if warnings:
            row["warnings"] = warnings
        res.resolved.append(ResolvedObject(TOOL, name, "address", row, device))

    for i, row in enumerate(require_rows(export.get("rules"), tool=TOOL, what="'rules'")):
        rule = require_rule(row, tool=TOOL, index=i + 1)
        ref = rule.get("rule_id")
        where = f"rule {ref!r}" if ref is not None else f"rule #{i + 1}"
        ref = require_token(rule, "rule_id", tool=TOOL, where=where)
        src = _resolve(require_token(rule, "src", tool=TOOL, where=where), objects)
        dst = _resolve(require_token(rule, "dst", tool=TOOL, where=where), objects)
        merge_entities(entities, src.entity)
        merge_entities(entities, dst.entity)
        # The service column, and the SEPARATE port/protocol columns some
        # exports use instead of it (Panorama CSV, FortiManager). Those were not
        # read at all: a rule carrying `port: 3389, protocol: "tcp"` and no
        # `service` decoded to a bare `tcp` with no port -- P_UNKNOWN (0.5) --
        # and produced no finding, with no warning either. `parse_service`
        # prefers `service` when it is present, so a rule that has both is
        # unaffected; this only fills in the rules that had nothing.
        svc = parse_service(rule.get("service"), port=rule.get("port"),
                            protocol=rule.get("protocol"), app=rule.get("app"))
        res.resolved.extend(service_audit(TOOL, ref, svc, device))
        # A malformed src/dst is recorded against the RULE, not the object, so
        # the audit row points at the line an operator has to go and fix.
        res.resolved.extend(token_audit(TOOL, ref, {"src": src.warnings, "dst": dst.warnings},
                                        device))
        res.records.append(record_from_service(
            record_id=ref, source_tool=TOOL, raw_ref=ref,
            source=src.name, destination=dst.name, svc=svc,
            action=require_action(rule, "action", tool=TOOL, where=where),
            dest_tags=dst.tags, order=rule.get("order"),
            source_ip=src.ip, dest_ip=dst.ip, note=rule.get("comment"),
            source_cidrs=src.cidrs, dest_cidrs=dst.cidrs,
            source_unresolved=src.unresolved,
        ))

    res.entities = list(entities.values())
    return res
