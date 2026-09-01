"""Wiz normalizer: cloud exposure -> PolicyRecords.

  internet_ingress -> a grant from the internet (0.0.0.0/0) to a cloud asset
  lateral          -> asset-to-asset reachability a security group permits

Wiz's catalog is `assets`, and each asset carries a concrete `ip`. That address
is the asset's whole address space, so it now travels with the record on
`source_cidrs` / `dest_cidrs` as a host network (10.30.7.7 -> 10.30.7.7/32).
Without it a lateral grant between two cloud hosts was an identity-to-identity
record with no address space at all, which `severity.exposure_score` and
`cidr_overlap` cannot reason about -- the same "carry the resolved value, not
the label" gap the audit filed against the AlgoSec normalizer.

Cloud assets stay CONCRETE: a load balancer with a public address is a host that
faces the internet, not the internet itself (`graph.zones` makes the same
distinction, deliberately, so a DMZ hop is not relabelled as an internet hop).
The one abstract node this tool emits is the internet itself.

`kind` is an exhaustive match, not a fallback: an unrecognised exposure kind
raises rather than being read as `lateral`, which is how `kind='egress'` used to
die as `KeyError: 'src'` -- a message naming neither the exposure nor the tool.
"""

from __future__ import annotations

from typing import Optional

from .common import (
    INTERNET_CIDR, NormalizeResult, ObservedEntity, ResolvedObject, merge_entities,
    parse_service, record_from_service, scope_identifiers,
)
from .profile import (
    NormalizeError, object_cidrs, require_mapping, require_rows, require_rule,
    require_token, service_audit, spans_more_than_one_address,
)

TOOL = "wiz"

# The exposure kinds this normalizer understands. Matched exhaustively: anything
# else refuses by name rather than being read as `lateral` -- see the module
# docstring. `internet_ingress` is the one kind with no `src` asset.
_INTERNET_INGRESS = "internet_ingress"
_LATERAL = "lateral"
_KINDS = (_INTERNET_INGRESS, _LATERAL)


def _asset_cidrs(assets: dict, name: str) -> tuple[list[str], list[str]]:
    """A cloud asset's address space -> (cidrs, warnings).

    A bare ip becomes its own host network via `object_cidrs`, which is what
    lets it participate in subnet math and match the same address seen from
    another tool. An asset absent from the export resolves to [] -- genuinely no
    address, not "nobody looked".
    """
    meta = assets.get(name)
    if not isinstance(meta, dict):
        return [], []
    return object_cidrs(meta.get("ip"))


def _entity(name: str, assets: dict) -> ObservedEntity:
    """One cloud asset -> the tool's view of that node. Always CONCRETE.

    Wiz enumerated it, so it is a machine; a public address on it makes it a DMZ
    host, not the internet (`graph.zones` draws the same line deliberately).

    `ip` is populated only when the export's value resolves to exactly one host
    address. That is the field `identity.resolve_identities` merges names on, and
    an unparseable string there is a merge key that matches nothing but sorts and
    hashes like a real one -- so a bad value is flagged and withheld rather than
    passed along. A value that resolves to a RANGE goes to `cidr` instead, where
    the identity layer reads it as address space rather than as a host.
    """
    meta = assets.get(name) if isinstance(assets.get(name), dict) else {}
    cidrs, warnings = object_cidrs(meta.get("ip"))
    host = cidrs[0] if len(cidrs) == 1 and not spans_more_than_one_address(cidrs) else None
    identifiers = {"cloud": meta.get("cloud"), "type": meta.get("type"),
                   "internet_facing": meta.get("internet_facing")}
    # The NAMESPACE this address is unique inside (subscription / account / VPC),
    # when the export declares one. `cloud` and `type` above are labels the whole
    # estate shares and are NOT a scope; `identity.resolve_identities` will only
    # fuse two names on a shared IP inside a declared namespace, so this is the
    # channel that makes a legitimate cross-tool shared-IP merge possible at all.
    # A Wiz export that declares none yields {}, i.e. "no scope, do not merge".
    identifiers.update(scope_identifiers(meta))
    if warnings:
        identifiers["malformed_address"] = True
    return ObservedEntity(
        name=name, kind="identity", tool=TOOL,
        ip=host.split("/")[0] if host else None,
        cidr=cidrs[0] if (host is None and len(cidrs) == 1) else None,
        # Every block, for the same reason `cidr` carries one: an asset whose
        # `ip` is a LIST of networks denotes all of them, and the zone layer only
        # ever sees what the entity carried.
        cidrs=list(cidrs) if host is None else [],
        tags=list(meta.get("tags", []) or []), identifiers=identifiers,
    )


def _tags(assets: dict, name: str) -> list[str]:
    """An asset's tags, or [] for an exposure naming an asset the export omits."""
    meta = assets.get(name)
    return list(meta.get("tags", []) or []) if isinstance(meta, dict) else []


def _ip(assets: dict, name: str) -> Optional[str]:
    """An asset's concrete ip as the export wrote it (metadata, not subnet math)."""
    meta = assets.get(name)
    ip = meta.get("ip") if isinstance(meta, dict) else None
    return ip if isinstance(ip, str) else None


def normalize(export: dict) -> NormalizeResult:
    res = NormalizeResult()
    assets = require_mapping(export.get("assets"), tool=TOOL, what="'assets'")
    entities: dict[str, ObservedEntity] = {
        INTERNET_CIDR: ObservedEntity(name=INTERNET_CIDR, kind="cidr", tool=TOOL,
                                      cidr=INTERNET_CIDR, abstract=True),
    }

    # `sorted` because the asset catalog is persisted and rendered; its order
    # must not depend on JSON key order.
    for name in sorted(assets):
        meta = assets[name] if isinstance(assets[name], dict) else {}
        merge_entities(entities, _entity(name, assets))
        cidrs, warnings = object_cidrs(meta.get("ip"))
        row = {"ip": meta.get("ip"), "type": meta.get("type"), "cloud": meta.get("cloud"),
               "tags": meta.get("tags", []), "internet_facing": meta.get("internet_facing"),
               "cidrs": cidrs}
        if warnings:
            row["warnings"] = warnings
        res.resolved.append(ResolvedObject(TOOL, name, "address", row,
                                           is_dynamic=bool(meta.get("internet_facing"))))

    for i, row in enumerate(require_rows(export.get("exposures"), tool=TOOL, what="'exposures'")):
        exp = require_rule(row, tool=TOOL, index=i + 1)
        ref = exp.get("exposure_id")
        where = f"exposure {ref!r}" if ref is not None else f"exposure #{i + 1}"
        ref = require_token(exp, "exposure_id", tool=TOOL, where=where)
        kind = require_token(exp, "kind", tool=TOOL, where=where)
        if kind not in _KINDS:
            raise NormalizeError(
                f"{TOOL} {where}: unknown exposure kind {kind!r} (known: {', '.join(_KINDS)})")
        d = require_token(exp, "dst", tool=TOOL, where=where)
        if kind == _INTERNET_INGRESS:
            s, s_cidrs = INTERNET_CIDR, [INTERNET_CIDR]
        else:
            s = require_token(exp, "src", tool=TOOL, where=where)
            s_cidrs, _s_warn = _asset_cidrs(assets, s)
            merge_entities(entities, _entity(s, assets))
        merge_entities(entities, _entity(d, assets))
        d_cidrs, _d_warn = _asset_cidrs(assets, d)
        svc = parse_service(None, exp.get("port"), exp.get("protocol"), app=exp.get("app"))
        res.resolved.extend(service_audit(TOOL, ref, svc))
        res.records.append(record_from_service(
            record_id=ref, source_tool=TOOL, raw_ref=ref, source=s, destination=d, svc=svc,
            # An exposure IS an allow: Wiz reports reachability that exists, so
            # there is no verb to decode and none to default.
            action="allow", dest_tags=list(_tags(assets, d)), order=None, note=kind,
            source_ip=_ip(assets, s) if kind != _INTERNET_INGRESS else None,
            dest_ip=_ip(assets, d),
            source_cidrs=s_cidrs, dest_cidrs=d_cidrs,
        ))

    res.entities = list(entities.values())
    return res

