"""Guardicore normalizer: label/identity microsegmentation -> PolicyRecords.

Guardicore is identity-based: sources and destinations are labels, not CIDRs, so
both sides normalize to identity nodes and tags come from the label catalog.
That makes an EMPTY `source_cidrs` the normal, correct answer here -- a label
like `web-tier` genuinely denotes no address space, which is exactly the case
`PolicyRecord.source_cidrs`'s "[] means unresolvable, not unlooked-up" rule
exists to distinguish from a normalizer that forgot to look.

Two things this module now gets right:

  * A label whose `role` is ``segment`` is marked ``abstract``. `internal-app`
    is a segment in Guardicore and a ``network`` object (10.40.0.0/16) in
    AlgoSec, and `identity.resolve_identities` folds the two views with
    ``abstract = all(e.abstract for e in ents)`` -- so BOTH tools' views have to
    say so or the merged asset comes out concrete and
    `graph.reachability._valid_traversal` will happily pivot an attack path
    through a /16 segment. That pivot is the demo's flagship path and the audit's
    `demo-grade` finding.
  * A label that DOES carry address space (real Guardicore label sets often
    carry a subnet) resolves it onto the record, so a segmentation policy can
    take part in subnet math instead of scoring as a single host.

`order` is still synthesized from array position; honouring Guardicore's real
`priority` is Phase 3's "carry Guardicore's real priority" workstream and is
deliberately not done here (see PROD-READINESS-AUDIT, guardicore.py:43).
"""

from __future__ import annotations

from .common import (
    NormalizeResult, ObservedEntity, ResolvedObject, merge_entities, parse_service,
    record_from_service, scope_identifiers,
)
from .profile import (
    object_cidrs, object_is_abstract, require_action, require_mapping, require_rows,
    require_rule, require_token, service_audit, token_audit, token_cidrs,
)

TOOL = "guardicore"

# Label roles that denote a RANGE of machines rather than one machine. Same
# semantics as an AlgoSec `network` object type; kept as a named constant so the
# rule is reviewable rather than an inline string comparison.
SEGMENT_ROLES = frozenset({"segment", "subnet", "network", "zone"})

# Optional keys a label may use to carry its address space. Ordered, so the
# resolution is deterministic when an export sets more than one.
_ADDRESS_KEYS = ("cidr", "subnet", "network", "ip")


def _label_cidrs(meta: dict) -> tuple[list[str], list[str]]:
    """The address space a label carries, if any -> (cidrs, warnings)."""
    for key in _ADDRESS_KEYS:
        if meta.get(key) is not None:
            return object_cidrs(meta.get(key))
    return [], []


def _entity(name: str, meta: dict, cidrs: list[str], warnings: list[str]) -> ObservedEntity:
    """One label -> the tool's view of that node."""
    # Abstract by ROLE (Guardicore's vocabulary for "this is a range"), by
    # resolved width, or because the declared address did not resolve -- the last
    # two are `object_is_abstract`'s rules, applied here so a segment cannot come
    # out abstract in AlgoSec's view and concrete in Guardicore's.
    role = str(meta.get("role") or "").strip().lower()
    abstract = role in SEGMENT_ROLES or object_is_abstract(None, cidrs, warnings)
    identifiers: dict = {"role": meta.get("role"), "env": meta.get("env")}
    # `env` is a label every account in the estate shares, so it is deliberately
    # NOT a scope (see `common.scope_identifiers`); a VRF / VPC / tenant the
    # label declares is, and it is what lets the identity layer fuse this node
    # with another tool's view of it on a shared address.
    identifiers.update(scope_identifiers(meta))
    if warnings:
        identifiers["malformed_address"] = True
    return ObservedEntity(
        name=name, kind="identity", tool=TOOL, tags=list(meta.get("tags", []) or []),
        identifiers=identifiers, abstract=abstract,
        # `ObservedEntity.cidr` holds ONE string (the identity layer does
        # `ips.add(e.cidr)`), so only a single-block label populates it; `cidrs`
        # carries every block, so a label resolving to several networks still
        # reaches `zones.zone_of` with the space it actually denotes.
        cidr=cidrs[0] if len(cidrs) == 1 and abstract else None,
        cidrs=list(cidrs) if abstract else [],
        ip=cidrs[0].split("/")[0] if len(cidrs) == 1 and not abstract and cidrs else None,
    )


def _resolve(name: str, labels: dict) -> tuple[list[str], list[str], list[str], ObservedEntity]:
    """One src/dst label -> (cidrs, tags, warnings, entity).

    A label absent from the catalog is still a legitimate node -- Guardicore
    policies reference labels the label export did not include -- so it becomes
    an identity with no tags. It is only address space if the token itself is
    (the wildcard vocabulary, or a CIDR someone put in the label column).
    """
    meta = labels.get(name)
    if not isinstance(meta, dict):
        cidrs, warnings = token_cidrs(name)
        return cidrs, [], warnings, _entity(name, {}, cidrs, warnings)
    cidrs, warnings = _label_cidrs(meta)
    if not cidrs:
        cidrs, token_warnings = token_cidrs(name)
        warnings = warnings + token_warnings
    return cidrs, list(meta.get("tags", []) or []), warnings, _entity(name, meta, cidrs, warnings)


def normalize(export: dict) -> NormalizeResult:
    res = NormalizeResult()
    labels = require_mapping(export.get("labels"), tool=TOOL, what="'labels'")
    entities: dict[str, ObservedEntity] = {}

    # `sorted` because the label catalog is persisted and rendered; its order
    # must not depend on JSON key order.
    for name in sorted(labels):
        meta = labels[name] if isinstance(labels[name], dict) else {}
        cidrs, warnings = _label_cidrs(meta)
        ent = _entity(name, meta, cidrs, warnings)
        merge_entities(entities, ent)
        # The audit row reports the entity's own verdict rather than recomputing
        # it, so the trail an operator reads cannot drift from the flag the graph
        # traverses on.
        row = {"role": meta.get("role"), "env": meta.get("env"),
               "tags": meta.get("tags", []), "cidrs": cidrs, "abstract": ent.abstract}
        if warnings:
            row["warnings"] = warnings
        res.resolved.append(ResolvedObject(
            TOOL, name, "zone" if meta.get("role") == "segment" else "application", row))

    for i, row in enumerate(require_rows(export.get("policies"), tool=TOOL, what="'policies'")):
        pol = require_rule(row, tool=TOOL, index=i + 1)
        ref = pol.get("policy_id")
        where = f"policy {ref!r}" if ref is not None else f"policy #{i + 1}"
        ref = require_token(pol, "policy_id", tool=TOOL, where=where)
        s = require_token(pol, "src_label", tool=TOOL, where=where)
        d = require_token(pol, "dst_label", tool=TOOL, where=where)
        s_cidrs, _s_tags, s_warn, s_ent = _resolve(s, labels)
        d_cidrs, d_tags, d_warn, d_ent = _resolve(d, labels)
        merge_entities(entities, s_ent)
        merge_entities(entities, d_ent)
        svc = parse_service(None, pol.get("port"), pol.get("protocol"), app=pol.get("app"))
        res.resolved.extend(service_audit(TOOL, ref, svc))
        res.resolved.extend(token_audit(TOOL, ref, {"src_label": s_warn, "dst_label": d_warn}))
        res.records.append(record_from_service(
            record_id=ref, source_tool=TOOL, raw_ref=ref, source=s, destination=d, svc=svc,
            action=require_action(pol, "action", tool=TOOL, where=where),
            dest_tags=list(d_tags), order=(i + 1) * 10, note=pol.get("ruleset"),
            source_cidrs=s_cidrs, dest_cidrs=d_cidrs,
        ))

    res.entities = list(entities.values())
    return res

