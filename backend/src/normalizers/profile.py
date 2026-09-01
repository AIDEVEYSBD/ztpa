"""Declarative, mapping-driven normalizer -- 'bring your own source' without code.

A SourceProfile is pure config (data) describing where a JSON export keeps its
rules and which fields map to the canonical model. apply_profile() interprets it
DETERMINISTICALLY -- no model at runtime. New source = a new profile, not new
Python. (The genuinely weird vendors -- NAT match semantics, App-ID, wildcard
masks -- still get a code adapter; this covers the common tabular/JSON case.)

This module also hosts the SHARED normalizer vocabulary (the section below):
the action verb table, object-catalog address resolution, the abstract-object
test and the required-field guards that algosec.py / guardicore.py / wiz.py all
call. Those helpers belong beside `cidrs_for_token` in `common.py`; they live
here only because `common.py` is this phase's frozen shared contract. Keeping
ONE copy is the point -- "compute the resolved CIDR and then throw it away" got
into three normalizers independently precisely because each one had its own
private `_resolve`.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel

from ..netaddr import parse_net
from .common import (
    NormalizeResult, ObservedEntity, ResolvedObject, cidrs_for_token, is_cidr,
    merge_entities, normalize_cidr, parse_service, record_from_service,
    scope_identifiers,
)


# ---------------------------------------------------------------------------
# Shared normalizer vocabulary
# ---------------------------------------------------------------------------


class NormalizeError(ValueError):
    """A source export the normalizer cannot honestly interpret.

    Raised INSTEAD of the bare exceptions the audit measured escaping the
    normalizers (`KeyError: 'action'`, `KeyError: 'src'`, `TypeError: argument
    of type 'NoneType' is not iterable`, `TypeError: unhashable type: 'list'`),
    so a failure names the tool, the row and the field rather than a line
    number in someone else's module.

    Partial ingest -- skipping the offending row and carrying a `skipped`
    report through to the UI -- is Phase 3 work and needs a field on
    `NormalizeResult` that this phase's contract does not have. Until then the
    contract is "normalize, or fail diagnosably"; what it is never allowed to
    be is "normalize something else and say nothing".
    """


# Vendor action verbs -> the two-value canonical vocabulary. Check Point writes
# drop/reject, Cisco permit, Junos/pf pass, Palo allow/deny -- and any of them
# may arrive capitalised. `PolicyRecord.action` is a Literal, so an unmapped
# verb used to die inside pydantic naming neither the rule nor the tool.
_ACTION_ALIASES: dict[str, str] = {
    "allow": "allow", "permit": "allow", "accept": "allow", "pass": "allow",
    "deny": "deny", "drop": "deny", "reject": "deny", "block": "deny",
}

# Declared object types that denote a RANGE of addresses rather than one host.
# The four the audit names; `-group` is matched by suffix because every vendor
# spells a group differently (address-group, network-group, dynamic-group).
_RANGE_OBJECT_TYPES = frozenset({"network", "group", "range", "subnet"})


def decode_action(raw: object, *, default: str = "allow", where: str = "") -> str:
    """A vendor action verb -> "allow" | "deny". Never guesses.

    An ABSENT action falls back to `default` (a profile's `default_action`, or
    the export's own convention) -- there is nothing to interpret in a field
    that is not there. A PRESENT but unmapped verb raises, because inventing
    "allow" for a verb we do not understand fabricates a grant, which is the one
    direction a security tool must never fail in. That is exactly what
    `apply_profile` used to do: `action if action in ("allow", "deny") else
    "allow"` turned every Check Point `drop` into an allow, silently.
    """
    if raw is None:
        return default
    token = str(raw).strip().lower()
    if not token:
        return default
    mapped = _ACTION_ALIASES.get(token)
    if mapped is None:
        raise NormalizeError(
            f"{where}unmapped action verb {str(raw).strip()!r} "
            f"(known: {', '.join(sorted(_ACTION_ALIASES))})")
    return mapped


def is_abstract_object_type(otype: object) -> bool:
    """True when an object's DECLARED type denotes a range, not one host."""
    if otype is None:
        return False
    token = str(otype).strip().lower().replace("_", "-")
    return token in _RANGE_OBJECT_TYPES or token.endswith("-group")


def spans_more_than_one_address(cidrs: list[str]) -> bool:
    """True when a resolved address space is wider than a single host.

    `is_abstract_object_type` reads a vendor's vocabulary; this reads the fact.
    An object declared `host` whose value is `10.40.0.0/16` is a subnet whatever
    the export calls it, and a subnet cannot originate traffic -- which is the
    entire reason `graph.reachability._valid_traversal` refuses to pivot through
    an abstract node. Answering this from the address rather than from the type
    name is what makes a named segment behave like the same segment written as a
    raw CIDR, which is the invariant the audit found broken.
    """
    if len(cidrs) > 1:                      # an address GROUP is never one host
        return True
    for raw in cidrs:
        net = parse_net(raw)
        if net is not None and net.prefixlen < net.max_prefixlen:
            return True
    return False


def object_is_abstract(otype: object, cidrs: list[str], warnings: list[str]) -> bool:
    """The one rule for "this node denotes a range, not a machine".

    Three sufficient conditions, and every normalizer applies all three so a
    named segment cannot be abstract in one tool's view and concrete in
    another's -- `identity.resolve_identities` folds the views with
    ``all(e.abstract ...)``, so one dissenting view makes the merged asset
    concrete and `reachability._valid_traversal` will pivot an attack path
    through it.

      declared type   a `network`/`group`/`range`/`subnet` object;
      resolved width  more than one address, whatever the type name claims;
      unresolved      the value did not parse. FAIL CLOSED: we have no evidence
                      it is a host, and calling it one is precisely how a typo'd
                      broad rule came to score as a single host.
    """
    return (is_abstract_object_type(otype) or spans_more_than_one_address(cidrs)
            or bool(warnings))


def object_cidrs(value: object) -> tuple[list[str], list[str]]:
    """An object-catalog `value` -> (canonical CIDRs, warnings). Never raises.

    Accepts the three shapes real catalogs use: one string, a LIST of strings
    (an address group -- which used to be written straight into
    `ObservedEntity.cidr` and blow up later inside the identity layer at
    `ips.add(e.cidr)` with `unhashable type: 'list'`), and a missing value.

    A value that is not address space at all is REPORTED, never dropped and
    never silently reclassified. `10.0.0.0/33` and `300.1.1.1/24` are typos in
    what is usually a BROAD rule, and today they quietly become single-host
    identity assets -- i.e. bad input LOWERS the reported risk, which is the
    worst failure direction available to a security tool.
    """
    values = value if isinstance(value, (list, tuple)) else [value]
    cidrs: list[str] = []
    warnings: list[str] = []
    for item in values:
        if item is None:
            continue
        if not isinstance(item, str):
            warnings.append(f"object value {item!r} is not a string")
            continue
        if not item.strip():
            continue
        resolved = cidrs_for_token(item)
        if resolved:
            cidrs.extend(resolved)
        else:
            warnings.append(f"unresolvable object value {item.strip()!r}")
    return cidrs, warnings


def token_cidrs(token: str) -> tuple[list[str], list[str]]:
    """A src/dst TOKEN -> (canonical CIDRs, warnings), before any catalog lookup.

    Wraps `common.cidrs_for_token` with the one distinction it cannot make on
    its own: `[]` because the token is a NAME (fine -- the caller resolves it
    against the object catalog next) versus `[]` because the token LOOKS like an
    address and is not one. `10.0.0.0/33` falling through to an identity node is
    the silent reclassification the audit filed: the rule then scores as a
    single host (E=0.1) and vanishes from every piece of subnet math.

    Only a token containing "/" is judged malformed. A bare word could be a
    hostname, a label or a user, and there is no honest way to tell a typo'd
    address from a name that happens to look numeric.
    """
    resolved = cidrs_for_token(token)
    if resolved:
        return resolved, []
    if "/" in token:
        return [], [f"malformed address {token.strip()!r}"]
    return [], []


def require_mapping(value: object, *, tool: str, what: str) -> dict:
    """A catalog that must be a {name: {...}} map. Absent/None = empty catalog."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    raise NormalizeError(
        f"{tool}: {what} must be an object map keyed by name, got {type(value).__name__}")


def require_rows(value: object, *, tool: str, what: str) -> list:
    """A rules array that must be a list. Absent/None = an empty export."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise NormalizeError(
        f"{tool}: {what} must be a list of rules, got {type(value).__name__}")


def require_rule(row: object, *, tool: str, index: int) -> dict:
    """One row that must be a mapping (a bare string row indexed as a dict was
    `TypeError: string indices must be integers` from inside the normalizer)."""
    if not isinstance(row, dict):
        raise NormalizeError(
            f"{tool} rule #{index}: expected an object, got {type(row).__name__}")
    return row


def require_field(rule: dict, name: str, *, tool: str, where: str) -> Any:
    """A field the canonical model cannot be built without."""
    value = rule.get(name)
    if value is None:
        raise NormalizeError(f"{tool} {where}: missing required field {name!r}")
    return value


def require_token(rule: dict, name: str, *, tool: str, where: str) -> str:
    """A src/dst field that must be exactly ONE scalar token.

    A LIST here is a multi-source rule -- the normal shape of a real firewall
    rule, and today `TypeError: unhashable type: 'list'` raised deep inside the
    identity layer with no mention of the rule that caused it. Fanning one rule
    out into a record per (src, dst, service) tuple is Phase 3's ingestion work;
    until that lands the honest answer is a named refusal, never a record whose
    source is the string `"['10.1.0.0/16', '10.2.0.0/16']"`.
    """
    value = require_field(rule, name, tool=tool, where=where)
    if isinstance(value, (list, tuple, set, dict)):
        raise NormalizeError(
            f"{tool} {where}: field {name!r} is a {type(value).__name__}; multi-valued "
            "sources/destinations are not supported yet (one token per rule)")
    token = str(value).strip()
    if not token:
        raise NormalizeError(f"{tool} {where}: field {name!r} is empty")
    return token


def require_action(rule: dict, name: str, *, tool: str, where: str,
                   default: Optional[str] = None) -> str:
    """The action field, required and decoded onto the canonical vocabulary.

    A rule with no verb is not a policy statement, so an ABSENT action raises
    unless the caller supplies a `default` (a profile's `default_action`, which
    is an explicit operator decision rather than a guess). Silently reading a
    missing action as "allow" invents a grant out of a truncated export -- and
    `KeyError: 'action'` from a single malformed row taking down a 4,000-rule
    snapshot is the exact failure the audit measured.
    """
    raw = rule.get(name)
    if raw is None and default is None:
        raise NormalizeError(f"{tool} {where}: missing required field {name!r}")
    return decode_action(raw, default=default or "allow", where=f"{tool} {where}: ")


# Rule-level audit rows are namespaced so they can never collide with a catalog
# OBJECT of the same name: `resolved_objects` is UNIQUE on
# (snapshot_id, source_device, object_name, object_kind) and its `object_kind`
# is a CHECK-constrained domain, so a rule row cannot simply invent a new kind.
_RULE_PREFIX = "rule:"


def service_audit(tool: str, ref: str, svc, device: Optional[str] = None
                  ) -> list[ResolvedObject]:
    """An audit row for a service whose decode was not clean; [] when it was.

    `parse_service` never raises -- it returns its problems on
    `DecodedService.warnings` -- so without this the warnings would be decoded
    and then discarded, which is the same class of loss this phase exists to
    remove. `ResolvedObject` is the export's own "name -> value dereferencing"
    audit trail and already carries an `object_kind` of "service", so the
    warning lands somewhere the Ingest Inspector already renders.
    """
    if not svc.warnings:
        return []
    return [ResolvedObject(tool, f"{_RULE_PREFIX}{ref}", "service",
                           {"service": svc.label, "protocol": svc.protocol,
                            "port": svc.port, "port_end": svc.port_end,
                            "warnings": list(svc.warnings)}, device)]


def token_audit(tool: str, ref: str, fields: dict[str, list[str]],
                device: Optional[str] = None) -> list[ResolvedObject]:
    """ONE audit row per rule carrying every src/dst token defect it had.

    One row and not one per field, because `resolved_objects` is UNIQUE on
    (snapshot_id, source_device, object_name, object_kind): a rule with a
    malformed src AND a malformed dst would otherwise write two rows with the
    same key and silently lose one -- losing the record of a loss.

    This is where a malformed address becomes VISIBLE. `NormalizeResult` has no
    warning channel this phase (adding one is Phase 3's partial-ingest work), and
    the alternative -- staying silent -- is precisely the audit finding: bad
    input quietly lowering the reported risk.
    """
    present = {name: list(warnings) for name, warnings in fields.items() if warnings}
    if not present:
        return []
    return [ResolvedObject(tool, f"{_RULE_PREFIX}{ref}", "address",
                           {"malformed": True, "fields": dict(sorted(present.items()))},
                           device)]


# ---------------------------------------------------------------------------
# The declarative profile
# ---------------------------------------------------------------------------


class FieldMap(BaseModel):
    src: str
    dst: str
    action: Optional[str] = None          # field name; else default_action
    default_action: str = "allow"
    service: Optional[str] = None          # field giving "tcp/443" / "any"
    port: Optional[str] = None             # field giving an int port
    protocol: Optional[str] = None         # field giving a protocol
    app: Optional[str] = None              # field giving an explicit App-ID (e.g. "quic")
    order: Optional[str] = None
    ref: Optional[str] = None              # field giving the rule id; else the index


class SourceProfile(BaseModel):
    tool: str
    rules_path: str                        # top-level key holding the list of rules
    fields: FieldMap
    objects_path: Optional[str] = None     # top-level key holding an object catalog {name: {...}}
    object_value_key: str = "value"
    object_tags_key: str = "tags"
    object_type_key: str = "type"
    device: Optional[str] = None


# The canonical `SourceTool` literal a record must carry. A profile naming a
# tool outside it is still relabelled (see apply_profile) because widening the
# Literal is a models.py change; the relabelling is at least recorded now.
_KNOWN_TOOLS = ("algosec", "guardicore", "wiz", "sd_wan", "sd_lan")


def _resolve(token: object, objects: dict, profile: SourceProfile, tool: str
             ) -> tuple[str, list[str], list[str], list[str], Optional[ObservedEntity]]:
    """One src/dst token -> (display, tags, cidrs, warnings, entity).

    The node KIND (cidr vs identity) is deliberately not returned:
    `record_from_service` derives it from the token, which is what stops one
    string being a CIDR at one call site and an identity at the next.

    `display` is what the operator sees and what the graph keys on; `cidrs` is
    the address space it dereferences to, which is what the analyzers do subnet
    math on. Returning both is the whole fix: the label alone made a named /0
    score as a single host.

    An ABSENT field returns `("", [], [], [warning], None)`. The
    empty string is deliberate and load-bearing: `str(None)` used to produce the
    *truthy* string `"None"`, which sailed straight through
    `advisory.authoring.validate_profile`'s falsiness check and put a green
    "validated" badge over a table of `None -> None` rows. An empty source is
    falsy, so the existing validator now correctly reports the profile invalid.
    """
    if token is None:
        return "", [], [], ["field is absent from the sample row"], None
    if isinstance(token, (list, tuple, set, dict)):
        # Same rule as the coded normalizers: refuse, rather than normalize
        # `str([...])` into a node name nothing will ever resolve.
        return ("", [], [],
                [f"multi-valued field ({type(token).__name__}) is not supported yet"], None)

    text = str(token).strip()
    if not text:
        return "", [], [], ["field is empty in the sample row"], None

    if is_cidr(text):
        cidr = normalize_cidr(text)
        ent = ObservedEntity(name=cidr, kind="cidr", tool=tool, cidr=cidr, cidrs=[cidr],
                             abstract=True)
        return cidr, [], [cidr], [], ent

    obj = objects.get(text) if objects else None
    if not isinstance(obj, dict) or not obj:
        # Not an object in the catalog: it may still BE address space (a bare
        # host ip, or the wildcard vocabulary), and if it merely looks like one
        # that is a data defect worth reporting rather than a new asset.
        cidrs, warnings = token_cidrs(text)
        abstract = object_is_abstract(None, cidrs, warnings)
        ent = ObservedEntity(name=text, kind="identity", tool=tool, abstract=abstract,
                             cidr=cidrs[0] if len(cidrs) == 1 and abstract else None,
                             cidrs=list(cidrs) if abstract else [],
                             identifiers={"malformed_address": True} if warnings else {})
        return text, [], cidrs, warnings, ent

    value = obj.get(profile.object_value_key)
    tags = obj.get(profile.object_tags_key, []) or []
    otype = obj.get(profile.object_type_key)
    cidrs, warnings = object_cidrs(value)
    abstract = object_is_abstract(otype, cidrs, warnings)
    single = cidrs[0] if len(cidrs) == 1 else None
    ent = ObservedEntity(
        name=text, kind="identity", tool=tool, tags=list(tags), abstract=abstract,
        ip=value if (otype == "host" and isinstance(value, str) and not abstract) else None,
        cidr=single if abstract else None,
        # `single` is None for a GROUP, which is how a profile-defined address
        # group reached `zone_of` with no address space at all; `cidrs` is the
        # channel that carries every block. Only for a node that DENOTES space
        # (abstract): a concrete host's address travels on `ip`.
        cidrs=list(cidrs) if abstract else [],
        # Plus the namespace the catalog row declares, if any: a declarative
        # profile is the path a CUSTOMER export takes, so it is the one that most
        # needs to be able to say which VPC / account an address belongs to.
        # `scope_identifiers` reads the row's own keys, so no profile field has
        # to be mapped for an export that already spells them a standard way.
        identifiers={**scope_identifiers(obj),
                     **({"malformed_address": True} if warnings else {})},
    )
    return text, list(tags), cidrs, warnings, ent


def apply_profile(raw: dict, profile: SourceProfile) -> NormalizeResult:
    """Interpret a SourceProfile over one raw export. Deterministic, no model."""
    res = NormalizeResult()
    tool = profile.tool
    fm = profile.fields
    objects = require_mapping(raw.get(profile.objects_path) if profile.objects_path else None,
                              tool=tool, what=f"{profile.objects_path!r}")
    entities: dict[str, ObservedEntity] = {}

    for name in sorted(objects):
        obj = objects[name] if isinstance(objects[name], dict) else {}
        value = obj.get(profile.object_value_key)
        cidrs, warnings = object_cidrs(value)
        row = {"value": value, "type": obj.get(profile.object_type_key),
               "tags": obj.get(profile.object_tags_key, []), "cidrs": cidrs,
               "abstract": object_is_abstract(obj.get(profile.object_type_key),
                                              cidrs, warnings)}
        if warnings:
            row["warnings"] = warnings
        res.resolved.append(ResolvedObject(tool, name, "address", row, profile.device))

    rules = require_rows(raw.get(profile.rules_path), tool=tool,
                         what=f"{profile.rules_path!r}")
    for i, row in enumerate(rules):
        rule = require_rule(row, tool=tool, index=i + 1)
        ref = str(rule.get(fm.ref)) if fm.ref and rule.get(fm.ref) is not None else f"{tool.upper()}-{i + 1}"
        s_val, _s_tags, s_cidrs, s_warn, s_ent = _resolve(rule.get(fm.src), objects, profile, tool)
        d_val, d_tags, d_cidrs, d_warn, d_ent = _resolve(rule.get(fm.dst), objects, profile, tool)
        if s_ent is not None:
            merge_entities(entities, s_ent)
        if d_ent is not None:
            merge_entities(entities, d_ent)
        app = rule.get(fm.app) if fm.app else None
        if fm.service:
            svc = parse_service(service=rule.get(fm.service), app=app)
        else:
            svc = parse_service(port=rule.get(fm.port) if fm.port else None,
                                protocol=rule.get(fm.protocol) if fm.protocol else None, app=app)
        res.resolved.extend(service_audit(tool, ref, svc, profile.device))
        res.resolved.extend(token_audit(tool, ref, {"src": s_warn, "dst": d_warn},
                                        profile.device))
        action = decode_action(rule.get(fm.action) if fm.action else None,
                               default=fm.default_action, where=f"{tool} rule {ref}: ")
        res.records.append(record_from_service(
            # A profile naming an unknown tool is still recorded as "algosec"
            # because `models.SourceTool` is a closed Literal; the relabelling is
            # a known claim-overreach (audit: profile.py:90) whose fix lives in
            # models.py, outside this module.
            record_id=ref, source_tool=tool if tool in _KNOWN_TOOLS else "algosec",
            raw_ref=ref, source=s_val, destination=d_val, svc=svc, action=action,
            dest_tags=list(d_tags), order=rule.get(fm.order) if fm.order else (i + 1) * 10,
            source_cidrs=s_cidrs, dest_cidrs=d_cidrs,
        ))

    res.entities = list(entities.values())
    return res


def field_report(raw: dict, profile: SourceProfile) -> dict:
    """Per-field resolution counts for a proposed profile.

    "Is it valid?" was answered by two questions -- are there any rows, and is
    any row's source/destination/service falsy -- and a profile whose field
    names are ALL wrong answered yes to both (`str(None)` -> `"None"`, truthy).
    Counting how many rows each mapped field actually resolved makes "0 of
    40,000 rows resolved a source" impossible to report as green.

    Returned separately from `apply_profile` because `NormalizeResult` has no
    field to carry it; `advisory.authoring.validate_profile` should merge this
    into its result (see the phase report).
    """
    fm = profile.fields
    rows = require_rows(raw.get(profile.rules_path), tool=profile.tool,
                        what=f"{profile.rules_path!r}")
    mapped: list[tuple[str, Optional[str]]] = [
        ("src", fm.src), ("dst", fm.dst), ("action", fm.action), ("service", fm.service),
        ("port", fm.port), ("protocol", fm.protocol), ("app", fm.app),
        ("order", fm.order), ("ref", fm.ref),
    ]
    resolved: dict[str, int] = {}
    for name, field_name in mapped:
        if field_name is None:
            continue
        resolved[name] = sum(
            1 for row in rows
            if isinstance(row, dict) and row.get(field_name) is not None
            and str(row.get(field_name)).strip() != ""
        )
    # src and dst are the two fields no record can be built without; a mapping
    # that resolves neither is a wrong mapping, not a sparse export.
    unresolved = sorted(name for name in ("src", "dst")
                        if name in resolved and resolved[name] == 0)
    return {
        "rows": len(rows),
        "resolved": dict(sorted(resolved.items())),
        "unresolved_fields": unresolved,
        "valid": bool(rows) and not unresolved,
    }
