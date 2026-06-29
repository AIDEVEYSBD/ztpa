"""AlgoSec normalizer: vendor-abstracted ordered firewall rules -> PolicyRecords.

src/dst tokens are either a raw CIDR or a named object resolved via the export's
object catalog. Named objects become identity nodes (carrying ip/cidr + tags as
metadata); raw CIDRs become cidr nodes.
"""

from __future__ import annotations

from ..models import PolicyRecord
from .common import (
    NormalizeResult, ObservedEntity, ResolvedObject,
    is_cidr, merge_entities, normalize_cidr, parse_service,
)

TOOL = "algosec"


def _resolve(token: str, objects: dict) -> tuple[str, str, str | None, str | None, list[str], ObservedEntity]:
    if is_cidr(token):
        cidr = normalize_cidr(token)
        ent = ObservedEntity(name=cidr, kind="cidr", tool=TOOL, cidr=cidr, abstract=True)
        return cidr, "cidr", None, cidr, [], ent
    obj = objects.get(token)
    if obj is None:
        return token, "identity", None, None, [], ObservedEntity(name=token, kind="identity", tool=TOOL)
    value, typ, tags = obj.get("value"), obj.get("type"), obj.get("tags", [])
    if typ == "host":
        ent = ObservedEntity(name=token, kind="identity", tool=TOOL, ip=value, tags=tags)
        return token, "identity", value, None, tags, ent
    ent = ObservedEntity(name=token, kind="identity", tool=TOOL, cidr=value, tags=tags)
    return token, "identity", None, value, tags, ent


def normalize(export: dict) -> NormalizeResult:
    res = NormalizeResult()
    device = export.get("device")
    objects = export.get("objects", {})
    entities: dict[str, ObservedEntity] = {}

    for name, obj in objects.items():
        res.resolved.append(ResolvedObject(
            TOOL, name, "address",
            {"value": obj.get("value"), "type": obj.get("type"), "tags": obj.get("tags", [])},
            device,
        ))

    for rule in export.get("rules", []):
        s_val, s_kind, s_ip, _s_cidr, _s_tags, s_ent = _resolve(rule["src"], objects)
        d_val, d_kind, d_ip, _d_cidr, d_tags, d_ent = _resolve(rule["dst"], objects)
        merge_entities(entities, s_ent)
        merge_entities(entities, d_ent)
        svc = parse_service(rule.get("service"), app=rule.get("app"))
        res.records.append(PolicyRecord(
            id=rule["rule_id"], source_tool=TOOL, raw_ref=rule["rule_id"],
            source=s_val, source_kind=s_kind, destination=d_val, destination_kind=d_kind,
            dest_tags=d_tags, service=svc.label, port=svc.port, port_end=svc.port_end,
            protocol=svc.protocol, l7_app=svc.l7_app, l7_source=svc.l7_source,
            action=rule["action"], order=rule.get("order"),
            source_ip=s_ip, dest_ip=d_ip, note=rule.get("comment"),
        ))

    res.entities = list(entities.values())
    return res
