"""Guardicore normalizer: label/identity microsegmentation -> PolicyRecords.

Guardicore is identity-based: sources and destinations are labels, not CIDRs.
Both sides normalize to identity nodes; tags come from the label catalog.
"""

from __future__ import annotations

from ..models import PolicyRecord
from .common import NormalizeResult, ObservedEntity, ResolvedObject, parse_service

TOOL = "guardicore"


def normalize(export: dict) -> NormalizeResult:
    res = NormalizeResult()
    labels = export.get("labels", {})
    entities: dict[str, ObservedEntity] = {}

    for name, meta in labels.items():
        entities[name] = ObservedEntity(
            name=name, kind="identity", tool=TOOL, tags=meta.get("tags", []),
            identifiers={"role": meta.get("role"), "env": meta.get("env")},
        )
        kind = "zone" if meta.get("role") == "segment" else "application"
        res.resolved.append(ResolvedObject(
            TOOL, name, kind,
            {"role": meta.get("role"), "env": meta.get("env"), "tags": meta.get("tags", [])},
        ))

    for i, pol in enumerate(export.get("policies", [])):
        s, d = pol["src_label"], pol["dst_label"]
        proto, port, label = parse_service(None, pol.get("port"), pol.get("protocol"))
        for nm in (s, d):
            if nm not in entities:
                entities[nm] = ObservedEntity(name=nm, kind="identity", tool=TOOL,
                                              tags=labels.get(nm, {}).get("tags", []))
        res.records.append(PolicyRecord(
            id=pol["policy_id"], source_tool=TOOL, raw_ref=pol["policy_id"],
            source=s, source_kind="identity", destination=d, destination_kind="identity",
            dest_tags=labels.get(d, {}).get("tags", []), service=label, port=port, protocol=proto,
            action=pol["action"], order=(i + 1) * 10, note=pol.get("ruleset"),
        ))

    res.entities = list(entities.values())
    return res
