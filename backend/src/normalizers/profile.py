"""Declarative, mapping-driven normalizer -- 'bring your own source' without code.

A SourceProfile is pure config (data) describing where a JSON export keeps its
rules and which fields map to the canonical model. apply_profile() interprets it
DETERMINISTICALLY -- no model at runtime. New source = a new profile, not new
Python. (The genuinely weird vendors -- NAT match semantics, App-ID, wildcard
masks -- still get a code adapter; this covers the common tabular/JSON case.)
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from ..models import PolicyRecord
from .common import (
    NormalizeResult, ObservedEntity, ResolvedObject, is_cidr, merge_entities, normalize_cidr, parse_service,
)


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


def _resolve(token: str, objects: dict, profile: SourceProfile, tool: str):
    token = str(token)
    if is_cidr(token):
        cidr = normalize_cidr(token)
        return cidr, "cidr", [], ObservedEntity(name=cidr, kind="cidr", tool=tool, cidr=cidr, abstract=True)
    obj = objects.get(token) if objects else None
    if not obj:
        return token, "identity", [], ObservedEntity(name=token, kind="identity", tool=tool)
    value = obj.get(profile.object_value_key)
    tags = obj.get(profile.object_tags_key, []) or []
    otype = obj.get(profile.object_type_key)
    ent = ObservedEntity(name=token, kind="identity", tool=tool, tags=tags,
                         ip=value if otype == "host" else None,
                         cidr=value if otype not in ("host", None) else None)
    return token, "identity", tags, ent


def apply_profile(raw: dict, profile: SourceProfile) -> NormalizeResult:
    res = NormalizeResult()
    tool = profile.tool
    fm = profile.fields
    objects = raw.get(profile.objects_path, {}) if profile.objects_path else {}
    entities: dict[str, ObservedEntity] = {}

    for name, obj in (objects or {}).items():
        res.resolved.append(ResolvedObject(
            tool, name, "address",
            {"value": obj.get(profile.object_value_key), "type": obj.get(profile.object_type_key),
             "tags": obj.get(profile.object_tags_key, [])}, profile.device))

    rules = raw.get(profile.rules_path, []) or []
    for i, rule in enumerate(rules):
        s_val, s_kind, _st, s_ent = _resolve(rule.get(fm.src), objects, profile, tool)
        d_val, d_kind, d_tags, d_ent = _resolve(rule.get(fm.dst), objects, profile, tool)
        merge_entities(entities, s_ent)
        merge_entities(entities, d_ent)
        app = rule.get(fm.app) if fm.app else None
        if fm.service:
            svc = parse_service(service=rule.get(fm.service), app=app)
        else:
            svc = parse_service(port=rule.get(fm.port) if fm.port else None,
                                protocol=rule.get(fm.protocol) if fm.protocol else None, app=app)
        action = rule.get(fm.action) if fm.action else fm.default_action
        ref = str(rule.get(fm.ref)) if fm.ref and rule.get(fm.ref) is not None else f"{tool.upper()}-{i + 1}"
        known = ("algosec", "guardicore", "wiz", "sd_wan", "sd_lan")
        res.records.append(PolicyRecord(
            id=ref, source_tool=tool if tool in known else "algosec",
            raw_ref=ref, source=s_val, source_kind=s_kind, destination=d_val, destination_kind=d_kind,
            dest_tags=d_tags, service=svc.label, port=svc.port, port_end=svc.port_end,
            protocol=svc.protocol, l7_app=svc.l7_app, l7_source=svc.l7_source,
            action=action if action in ("allow", "deny") else "allow",
            order=rule.get(fm.order) if fm.order else (i + 1) * 10,
        ))

    res.entities = list(entities.values())
    return res
