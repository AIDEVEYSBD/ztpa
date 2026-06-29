"""Wiz normalizer: cloud exposure -> PolicyRecords.

  internet_ingress -> a grant from the internet (0.0.0.0/0) to a cloud asset
  lateral          -> asset-to-asset reachability a security group permits
"""

from __future__ import annotations

from ..models import PolicyRecord
from .common import INTERNET_CIDR, NormalizeResult, ObservedEntity, ResolvedObject, parse_service

TOOL = "wiz"


def normalize(export: dict) -> NormalizeResult:
    res = NormalizeResult()
    assets = export.get("assets", {})
    entities: dict[str, ObservedEntity] = {
        INTERNET_CIDR: ObservedEntity(name=INTERNET_CIDR, kind="cidr", tool=TOOL,
                                      cidr=INTERNET_CIDR, abstract=True),
    }

    for name, meta in assets.items():
        entities[name] = ObservedEntity(
            name=name, kind="identity", tool=TOOL, ip=meta.get("ip"), tags=meta.get("tags", []),
            identifiers={"cloud": meta.get("cloud"), "type": meta.get("type"),
                         "internet_facing": meta.get("internet_facing")},
        )
        res.resolved.append(ResolvedObject(
            TOOL, name, "address",
            {"ip": meta.get("ip"), "type": meta.get("type"), "cloud": meta.get("cloud"),
             "tags": meta.get("tags", []), "internet_facing": meta.get("internet_facing")},
            is_dynamic=bool(meta.get("internet_facing")),
        ))

    for exp in export.get("exposures", []):
        svc = parse_service(None, exp.get("port"), exp.get("protocol"), app=exp.get("app"))
        if exp["kind"] == "internet_ingress":
            s, s_kind, d = INTERNET_CIDR, "cidr", exp["dst"]
        else:  # lateral
            s, s_kind, d = exp["src"], "identity", exp["dst"]
        for nm in ([d] if s_kind == "cidr" else [s, d]):
            if nm not in entities:
                entities[nm] = ObservedEntity(name=nm, kind="identity", tool=TOOL,
                                              ip=assets.get(nm, {}).get("ip"),
                                              tags=assets.get(nm, {}).get("tags", []))
        res.records.append(PolicyRecord(
            id=exp["exposure_id"], source_tool=TOOL, raw_ref=exp["exposure_id"],
            source=s, source_kind=s_kind, destination=d, destination_kind="identity",
            dest_tags=assets.get(d, {}).get("tags", []), service=svc.label, port=svc.port,
            port_end=svc.port_end, protocol=svc.protocol, l7_app=svc.l7_app, l7_source=svc.l7_source,
            action="allow", order=None, note=exp.get("kind"),
            source_ip=assets.get(s, {}).get("ip") if s_kind == "identity" else None,
            dest_ip=assets.get(d, {}).get("ip"),
        ))

    res.entities = list(entities.values())
    return res
