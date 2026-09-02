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

A CHANGE THAT DOES NOT APPLY IS AN INCIDENT, NOT A NO-OP
--------------------------------------------------------
This module is the one place where an operator's *accepted, pushed* decision is
turned back into policy. Two of its paths used to drop that decision without a
sound:

  * `_added_record` answered None on an unreconstructable `add_allow` payload and
    `apply_overlay` skipped it, so a rule the change gate approved simply was not
    in the snapshot -- and the snapshot was then persisted as authoritative;
  * `apply_remediation` matches on `raw_ref`, and a `target_ref` that names no
    record matches nothing, so the fix "applied" while the finding it was proven
    against stayed exactly as it was. The staging screen says applied, the
    dashboard still shows the critical, and nothing connects the two.

Both now log at ERROR with the change's identity. Neither RAISES: the overlay is
folded inside `run()`, and turning a single bad stored payload into an exception
would take the whole snapshot down, which is a strictly worse failure than one
missing change plus a log line naming it. Making `apply_remediation` raise on an
unmatched ref is a Phase 3 workstream (it is listed there with the validator
changes that must land with it); this commit makes it visible, not fatal.
"""

from __future__ import annotations

import logging

from pydantic import ValidationError

from ..models import PolicyRecord
from ..normalizers.common import ObservedEntity, is_cidr, parse_service
from ..normalizers.profile import object_is_abstract

# Child of the API logger; see advisory/client.py for the convention. Named
# "overlay" rather than "apply" because that is what the operator calls it.
log = logging.getLogger("npr.api.overlay")


def apply_remediation(records: list[PolicyRecord], change: dict) -> list[PolicyRecord]:
    """Transform the rule named by `change.target_ref` per `change.op`. Returns a
    new list; the input is left untouched. (Shared with the remediation validator
    so the *applied* change is byte-identical to the *validated* one.)"""
    op, ref = change.get("op"), change.get("target_ref")
    order_of = {r.raw_ref: r.order for r in records if r.order is not None}
    shadowing_order = order_of.get(change.get("shadowing_ref"))
    matched = 0
    out: list[PolicyRecord] = []
    for rec in records:
        if rec.raw_ref == ref:
            matched += 1
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
    if not matched:
        # The transform ran and changed nothing. Silently, this is the shape of
        # "we applied your fix" over a snapshot in which the fix does not exist:
        # the ref may name a rule from an older export, a different source tool,
        # or one an earlier overlay item already removed.
        log.error("remediation matched no rule; the accepted fix did not change the snapshot",
                  extra={"event": "overlay_remediation_unmatched", "op": op, "target_ref": ref,
                         "records": len(records)})
    elif op == "reorder_before" and shadowing_order is None:
        # Matched the rule but had no order to move it before, so the record was
        # appended untouched -- the same "applied, but nothing happened" lie.
        log.error("reorder_before had no shadowing rule to move before; the rule was left in place",
                  extra={"event": "overlay_reorder_unresolved", "target_ref": ref,
                         "shadowing_ref": change.get("shadowing_ref")})
    return out


def _added_record(payload: dict) -> PolicyRecord | None:
    """Reconstruct the proposed PolicyRecord from a stored add_allow payload
    (which is a PolicyRecord dump). Returns None if it cannot be reconstructed.

    `ValidationError` (a ValueError) is what a stored payload that no longer
    matches the model raises -- a field renamed since the row was written, a
    JSONB value that came back the wrong type -- and TypeError covers a payload
    that is not a mapping at all. Both are named rather than caught as
    `Exception`, so a defect in this function is not silently reclassified as
    "that operator's change was malformed".
    """
    try:
        fields = {k: v for k, v in payload.items() if k in PolicyRecord.model_fields}
        return PolicyRecord(**fields)
    except (ValidationError, TypeError, AttributeError) as exc:
        log.error("accepted add_allow could not be reconstructed; the rule is MISSING from "
                  "this snapshot", exc_info=True,
                  extra={"event": "overlay_add_allow_invalid",
                         "raw_ref": payload.get("raw_ref") if isinstance(payload, dict) else None,
                         "error": f"{type(exc).__name__}: {exc}"})
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
    fill genuine gaps. The record's ip is carried so IP-based merges still apply.

    The endpoint is built from the record's RESOLVED address space
    ------------------------------------------------------------
    An overlay endpoint named ``ANY-EXTERNAL`` used to become a bare identity
    entity: no address space, `abstract` False. Both halves of that were wrong,
    and together they made the change gate's own accepted rule score two bands
    below the identical rule written ``0.0.0.0/0``:

      * with no `cidrs`, the asset came out with ``ip_set == []``, so
        `zones.zone_of` had nothing to classify;
      * with `abstract` False the asset was CONCRETE, and `zone_of` short-circuits
        a concrete node to "not the internet" by design (a host holding a public
        address is a DMZ box, not the internet) -- so even a populated ip_set
        would not have helped.

    Both now come from `PolicyRecord.source_cidrs`/`dest_cidrs`, which the change
    gate already resolves (`change.simulate.resolve_cidrs`), through
    `object_is_abstract` -- the SAME rule every normalizer applies, so an endpoint
    that arrives by overlay is classified exactly like the one that arrives by
    export. A token that resolves to no address space is unchanged: still a
    concrete identity, because "we could not resolve it" is not evidence of a
    range. The host `ip` is dropped for an abstract endpoint for the reason
    `identity` refuses to key on a shared address: a /8 that also claims a host
    address would merge the range with the machine living in it.
    """
    known = {e.name for e in base_entities}
    extra: list[ObservedEntity] = []
    for rec in records:
        for name, kind, ip, tags, cidrs in (
            (rec.source, rec.source_kind, rec.source_ip, [], list(rec.source_cidrs)),
            (rec.destination, rec.destination_kind, rec.dest_ip, list(rec.dest_tags),
             list(rec.dest_cidrs)),
        ):
            if not name or name in known:
                continue
            known.add(name)
            if kind == "cidr":
                extra.append(ObservedEntity(name=name, kind="cidr", tool=rec.source_tool,
                                            cidr=name, cidrs=[name], abstract=True))
                continue
            abstract = object_is_abstract(None, cidrs, [])
            extra.append(ObservedEntity(
                name=name, kind="identity", tool=rec.source_tool,
                ip=None if abstract else ip, tags=tags, abstract=abstract,
                cidr=cidrs[0] if (abstract and len(cidrs) == 1) else None,
                cidrs=cidrs if abstract else [],
            ))
    return list(base_entities) + extra
