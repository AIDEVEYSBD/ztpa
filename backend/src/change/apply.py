"""Apply *accepted* changes to the ingested records as a durable overlay.

A change the operator pushed from the staging area is, in this demo, simulated at
the source system -- but to make the loop honest ("apply the fix, recompute, the
critical is gone"), the engine re-applies every pushed change to the normalized
records on each run, exactly like human-confirmed asset merges are re-applied by
the identity layer. The overlay is therefore durable across recomputes and only
cleared by the demo-reset.

Two change kinds flow through here:
  - add_allow   -- a Change-Gate request: append the proposed allow rule.
  - remediation -- a Risk-To-Do fix: transform the targeted rule (remove /
                   scope_source / restrict_service / reorder_before).

Everything is a pure records -> records transform: no model, no randomness, no
persistence. `run()` calls it between normalize and graph-build so the snapshot
fingerprint (and therefore the snapshot id) already reflects the applied state.
"""

from __future__ import annotations

from ..models import PolicyRecord
from ..normalizers.common import ObservedEntity, is_cidr, parse_service


def apply_remediation(records: list[PolicyRecord], change: dict) -> list[PolicyRecord]:
    """Transform the rule named by `change.target_ref` per `change.op`. Returns a
    new list; the input is left untouched. (Shared with the remediation validator
    so the *applied* change is byte-identical to the *validated* one.)"""
    op, ref = change.get("op"), change.get("target_ref")
    order_of = {r.raw_ref: r.order for r in records if r.order is not None}
    shadowing_order = order_of.get(change.get("shadowing_ref"))
    out: list[PolicyRecord] = []
    for rec in records:
        if rec.raw_ref == ref:
            if op == "remove":
                continue
            if op == "scope_source" and change.get("new_source"):
                ns = change["new_source"]
                rec = rec.model_copy(update={"source": ns, "source_kind": "cidr" if is_cidr(ns) else "identity"})
            elif op == "restrict_service" and change.get("new_service"):
                svc = parse_service(change["new_service"])
                rec = rec.model_copy(update={
                    "service": svc.label, "port": svc.port, "port_end": svc.port_end,
                    "protocol": svc.protocol, "l7_app": svc.l7_app, "l7_source": svc.l7_source,
                })
            elif op == "reorder_before" and shadowing_order is not None:
                rec = rec.model_copy(update={"order": shadowing_order - 1})
        out.append(rec)
    return out


def _added_record(payload: dict) -> PolicyRecord | None:
    """Reconstruct the proposed PolicyRecord from a stored add_allow payload
    (which is a PolicyRecord dump). Returns None if it cannot be reconstructed."""
    try:
        fields = {k: v for k, v in payload.items() if k in PolicyRecord.model_fields}
        return PolicyRecord(**fields)
    except Exception:
        return None


def apply_overlay(records: list[PolicyRecord], applied: list[dict]) -> list[PolicyRecord]:
    """Fold every accepted change into `records`, in the caller's (deterministic)
    order. Each item is a {kind, payload} dict (a pushed staged_changes row)."""
    out = list(records)
    for item in applied:
        payload = item.get("payload") or {}
        if item.get("kind") == "add_allow":
            rec = _added_record(payload)
            if rec is not None:
                out = out + [rec]
        else:  # remediation (and any restrictive change shaped like one)
            out = apply_remediation(out, payload)
    return out


def ensure_entities(base_entities: list[ObservedEntity], records: list[PolicyRecord]) -> list[ObservedEntity]:
    """Augment the observed-entity set with any endpoint referenced by `records`
    that normalization didn't already emit -- e.g. an overlay add_allow (or a
    scope_source remediation) that names a new source/destination. Without this,
    an overlay endpoint becomes a graph node with no backing asset, which fails on
    persist as a graph_nodes.asset_id FK violation. Existing entities (richer:
    tags/ip from the tool catalogs, cross-tool merges) are left untouched; we only
    fill genuine gaps. The record's ip is carried so IP-based merges still apply."""
    known = {e.name for e in base_entities}
    extra: list[ObservedEntity] = []
    for rec in records:
        for name, kind, ip, tags in (
            (rec.source, rec.source_kind, rec.source_ip, []),
            (rec.destination, rec.destination_kind, rec.dest_ip, list(rec.dest_tags)),
        ):
            if not name or name in known:
                continue
            known.add(name)
            if kind == "cidr":
                extra.append(ObservedEntity(name=name, kind="cidr", tool=rec.source_tool, cidr=name, abstract=True))
            else:
                extra.append(ObservedEntity(name=name, kind="identity", tool=rec.source_tool, ip=ip, tags=tags))
    return list(base_entities) + extra
