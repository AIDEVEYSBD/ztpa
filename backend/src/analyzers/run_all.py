r"""Run the whole deterministic engine: normalize -> resolve identities -> build
graph -> analyze -> score. Produces an EngineResult that precompute.py persists.

Everything here is deterministic and reproducible: same inputs -> byte-identical
snapshot id, findings, and ordering. No model, no randomness.

Two Phase 1 changes live in this module.

**The snapshot id is now a content hash of everything that determines the
result** (audit gap theme 4a). `_fingerprint` used to hash
`tool|ref|source|destination|service|action|order` -- and nothing else. It
omitted `dest_tags`, `port`, `port_end`, `protocol`, `l7_app`, the entire object
/ entity catalog, the `manual_merges` argument and the applied-changes overlay,
every one of which changes the assets, the graph or the findings. Retagging one
asset as `pci` flipped a rule from no finding at all to forced-critical while the
system of record insisted it was the same snapshot -- and governance rows hang
off that id. It now covers every field of every canonical record, the entity view
the identity layer merges, the dereferenced object catalog, the merge set and the
overlay.

The widening is only worth as much as the ENCODING under it, and the first cut
of it was not injective. Three postures still shared one id: a tag containing a
comma spelled the two tags it looked like (fields were joined with \x1f but list
members with ","), an unreferenced catalog object was persisted and rendered but
never hashed, and a multi-address object's declared `type` was folded in only
through `abstract`, which was already True by width. Every field now encodes as
JSON -- which escapes both separators, so no value can forge the structure above
it -- and the catalog is hashed as its own fifth blob. See `_value` and
`_RESOLVED_FIELDS`.

**One malformed rule can no longer take the snapshot down** (audit Phase 1
workstream 7). The five analyzers used to run as five bare statements, so an
exception in any of them aborted `run()`; because `app.main._ENGINE` caches the
result, that meant a 500 on every route until the process restarted. Each
analyzer is now isolated, and a failure is RECORDED on the result
(`EngineResult.degraded_analyzers`) and logged rather than swallowed -- a
degraded analyzer that silently returned fewer findings would be the same
"failure rendered as clean" pattern the audit is full of.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from time import perf_counter
from typing import Callable, Iterable

import networkx as nx

from ..change.apply import apply_overlay, ensure_entities
from ..graph.build import build_graph
from ..identity import resolve_identities
from ..ids import content_fingerprint, det_id, snapshot_id as make_snapshot_id
from ..models import Asset, AssetCorrelation, Finding, PolicyRecord
from ..normalizers import normalize_all
from ..normalizers.common import ObservedEntity, ResolvedObject
from . import cidr_overlap, over_permissive, path_trace, shadowing, transport_exposure

_BAND_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# A child of the API's logger, so a degraded analyzer comes out as one JSON line
# with the request id already attached (app/main.py configures "npr.api"). When
# the engine runs outside the API -- tasks.py, verify_engine.py -- it falls
# through to the root handler and still prints.
log = logging.getLogger("npr.api.engine")

# Field / record separators for the fingerprint blobs. ASCII unit + record
# separator rather than "|" and "\n" because a rule comment ("note") can contain
# either, and two different postures must never be able to serialize to one
# string.
_FS, _RS = "\x1f", "\x1e"

# Every PolicyRecord field the fingerprint covers -- i.e. all of them. Listed
# explicitly rather than read off the model so that ADDING a field is a decision
# somebody makes here; `test_analyzers.py::test_fingerprint_covers_every_record_field`
# fails if a new field is added to the model and not to this list, which is the
# guard that stops the id silently narrowing again.
_RECORD_FIELDS: tuple[str, ...] = (
    "id", "source_tool", "raw_ref", "order", "action",
    "source", "source_kind", "source_cidrs", "source_ip",
    "destination", "destination_kind", "dest_cidrs", "dest_ip", "dest_tags",
    "service", "protocol", "port", "port_end", "l7_app", "l7_source", "note",
)

# The observed-entity view the identity layer merges into assets -- i.e. every
# field of ObservedEntity, guarded the same way by
# `test_analyzers.py::test_fingerprint_covers_every_entity_field`. Tags drive the
# D sub-score and all three guardrail floors; ip, cidr, cidrs and identifiers
# drive the merge and therefore the graph shape; abstract decides whether a node
# may be a path pivot.
#
# `cidrs` is NOT redundant with the record fields even though a rule's src/dst
# space is hashed there too: a catalog object that no rule references still
# becomes an asset under Wiz (its whole inventory) and Guardicore (its whole
# label set), and that asset's address space decides its ZONE and therefore the
# boundary multiplier of every path through it. Omitting it would let two
# different postures -- a group holding {0.0.0.0/0, 10/8} and the same group
# holding {10/8} -- hash to one id.
_ENTITY_FIELDS: tuple[str, ...] = (
    "tool", "name", "kind", "ip", "cidr", "cidrs", "tags", "identifiers", "abstract",
)

# The dereferenced object CATALOG -- every field of ResolvedObject, guarded by
# `test_snapshot_fingerprint.py::test_fingerprint_covers_every_resolved_field`.
#
# This blob used to be absent, on the claim (made in this very comment) that the
# catalog "is hashed through the entity view, because that is the only part of it
# the engine reads". That was FALSE in two measured ways, and both left engine
# output that is persisted and rendered outside the id:
#
#   * `normalizers/algosec.py` emits a ResolvedObject for EVERY catalog entry but
#     an ObservedEntity only for objects some rule references. So the value, type
#     and tags of an unreferenced object reached `resolved_objects` and
#     `IngestInspector` while changing nothing hashed: four catalogs differing in
#     an unreferenced object's CIDR (192.168/16 vs 0.0.0.0/0), its type and its
#     tags all produced ONE snapshot id and four different persisted payloads.
#   * An object's declared `type` is folded into the entity only via `abstract`,
#     and `object_is_abstract` is already True by resolved width for any value
#     spanning more than one address. So flipping a multi-address object from
#     `network` to `host` moved nothing hashed, yet rewrote the persisted
#     `resolved_objects.resolved` payload under both the same snapshot id AND the
#     same deterministic row id (`persist.py` keys the row on
#     sid|tool|device|name|kind, never on the payload).
#
# The catalog is engine output that governance rows hang off, so it is hashed
# directly. `resolved` is the payload dict itself, so a change anywhere inside it
# -- a new warning, a re-resolved CIDR -- moves the id without anyone extending
# this list.
_RESOLVED_FIELDS: tuple[str, ...] = (
    "source_tool", "object_name", "object_kind", "source_device", "is_dynamic", "resolved",
)


@dataclass
class EngineResult:
    snapshot_id: str
    label: str
    records: list[PolicyRecord] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    correlations: list[AssetCorrelation] = field(default_factory=list)
    resolved: list[ResolvedObject] = field(default_factory=list)
    alias_map: dict[str, str] = field(default_factory=dict)
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    findings: list[Finding] = field(default_factory=list)
    timings: dict = field(default_factory=dict)   # measured per-stage ms
    # One entry per analyzer that raised: {analyzer, error, message}. EMPTY IS
    # THE ONLY CLEAN STATE -- a non-empty list means this result is missing an
    # entire finding class and must not be read as "nothing found there".
    degraded_analyzers: list[dict] = field(default_factory=list)


# --- analyzer isolation ----------------------------------------------------

def _analyzers(records: list[PolicyRecord], graph: nx.DiGraph,
               alias_map: dict[str, str]) -> tuple[tuple[str, Callable[[], list[Finding]]], ...]:
    """The five analyzers in their fixed run order, each as a zero-arg call.

    Naming them here (rather than inline) is what lets one of them fail by name:
    the marker on the result says WHICH finding class is missing, which is the
    difference between a degraded snapshot and a quietly wrong one.
    """
    return (
        ("over_permissive", lambda: over_permissive.analyze(records, graph, alias_map)),
        ("cidr_overlap", lambda: cidr_overlap.analyze(records)),
        ("shadowing", lambda: shadowing.analyze(records, graph, alias_map)),
        ("path_trace", lambda: path_trace.analyze(graph)),
        ("transport_exposure", lambda: transport_exposure.analyze(records, graph, alias_map)),
    )


def _run_analyzers(records: list[PolicyRecord], graph: nx.DiGraph, alias_map: dict[str, str],
                   *, isolate: bool) -> tuple[list[Finding], list[dict]]:
    """Run every analyzer; return (findings, degraded markers).

    `isolate=True` (a snapshot run): one analyzer raising costs its own finding
    class and nothing else -- a single malformed rule out of 40,000 used to abort
    the whole run and, via the cached engine singleton, every subsequent request.

    `isolate=False` (`reanalyze`): the exception propagates. That path exists to
    PROVE a proposed change resolves a finding without introducing a critical, so
    "fewer findings than expected" is exactly the wrong answer to return quietly;
    the caller must fail closed instead.
    """
    findings: list[Finding] = []
    degraded: list[dict] = []
    for name, call in _analyzers(records, graph, alias_map):
        try:
            findings += call()
        except Exception as exc:            # deliberate boundary: see the docstring
            if not isolate:
                raise
            log.error("analyzer failed; snapshot is degraded", exc_info=True, extra={
                "event": "analyzer_degraded", "analyzer": name,
                "error": type(exc).__name__, "records": len(records),
            })
            degraded.append({"analyzer": name, "error": type(exc).__name__, "message": str(exc)})
    return findings, degraded


def reanalyze(records: list[PolicyRecord], assets: list[Asset],
              alias_map: dict[str, str]) -> list[Finding]:
    """Re-run the analyzers on modified records (no persistence, no id finalize).

    Used by the remediation layer to PROVE a proposed fix resolves a finding
    without introducing new criticals -- the deterministic validation step."""
    graph = build_graph(records, assets, alias_map)
    findings, _degraded = _run_analyzers(records, graph, alias_map, isolate=False)
    return findings


# --- content fingerprint ---------------------------------------------------

def _value(value) -> str:
    r"""One field, canonically -- and INJECTIVELY.

    Canonical: lists are SORTED and dicts key-sorted, so a posture cannot hash
    two ways because a catalog listed the same tags (or the same identifiers) in
    a different order.

    Injective is the harder half, and it is why every branch below now goes
    through `json.dumps`. A list used to be joined with "," while `_record_digest`
    joins FIELDS with \x1f, so a value that contained the joiner could forge the
    structure above it: ``tags=['pci','customer-data','prod']`` and
    ``tags=['customer-data,pci','prod']`` both flattened to
    ``'customer-data,pci,prod'`` and fingerprinted BYTE-IDENTICALLY -- two
    postures, one snapshot id, and measurably two different answers, because
    `config.SENSITIVE_TAGS` matches `pci` by MEMBERSHIP and ``'customer-data,pci'``
    is not that member. On the demo export that single retag moved ALGO-030 from
    70/high to 47/medium and ALGO-002 from 100 to 90 under the same id and the
    same finding ids.

    JSON closes it for good rather than by swapping in a rarer delimiter: it
    quotes and escapes, and it escapes control characters too (\x1f -> \u001f,
    \x1e -> \u001e), so NO encoded field can contain either separator and no two
    distinct values can encode to one string. That also separates None (``null``)
    from the empty string (``""``) and from the string "None", all three of which
    are values a field can genuinely hold and all three of which used to collide
    on "".
    """
    if value is None:
        return "null"
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if isinstance(value, (list, tuple, set, frozenset)):
        return json.dumps(sorted(str(v) for v in value), separators=(",", ":"))
    # bool/int/float keep their own JSON spelling (true / 80 / 1.5); anything
    # else is stringified first so this can never raise on an exotic payload.
    if isinstance(value, (bool, int, float)):
        return json.dumps(value)
    return json.dumps(str(value), separators=(",", ":"))


def _record_digest(rec: PolicyRecord) -> str:
    return _FS.join(_value(getattr(rec, f)) for f in _RECORD_FIELDS)


def _entity_digest(ent: ObservedEntity) -> str:
    return _FS.join(_value(getattr(ent, f)) for f in _ENTITY_FIELDS)


def _merge_digest(pair: Iterable[str]) -> str:
    """A confirmed merge, canonically. The pair is sorted because the identity
    layer's union is symmetric (its component root is always `min(name)`), so
    ("a","b") and ("b","a") produce the identical asset set and must not produce
    two snapshot ids. Adding or removing a merge does change the set, and that is
    the property the exit criterion asks for.

    Encoded through `_value` (a sorted JSON array) rather than joined by hand, so
    an asset name that happens to contain the separator cannot spell a different
    pair -- the same injectivity argument as `_value` itself."""
    return _value([str(p) for p in pair])


def _overlay_digest(change: dict) -> str:
    """One applied (pushed) change. Hashed whole rather than by id: two overlay
    items can share a target rule and differ only in their payload, and a
    remediation whose target no longer exists is a no-op on the records yet still
    a different applied state. `default=str` keeps it total -- a payload comes
    from a JSONB column and must never be able to raise here."""
    return json.dumps(change, sort_keys=True, separators=(",", ":"), default=str)


def _resolved_digest(obj: ResolvedObject) -> str:
    return _FS.join(_value(getattr(obj, f)) for f in _RESOLVED_FIELDS)


def _fingerprint(records: list[PolicyRecord], entities: list[ObservedEntity],
                 resolved: list[ResolvedObject],
                 manual_merges: Iterable[tuple[str, str]],
                 applied_changes: Iterable[dict]) -> str:
    """The content hash behind `snapshot_id`: everything that determines the run.

    Five blobs, in a fixed order. Records, entities and resolved rows are sorted
    (their order in the export must not change the id); merges are sorted (the
    set is what matters). The overlay is NOT sorted -- `apply_overlay` folds
    changes in the caller's order and two orders can produce two different record
    sets, so its order is content.
    """
    return content_fingerprint(
        _RS.join(sorted(_record_digest(r) for r in records)),
        _RS.join(sorted(_entity_digest(e) for e in entities)),
        _RS.join(sorted(_resolved_digest(o) for o in resolved)),
        _RS.join(sorted(_merge_digest(m) for m in manual_merges)),
        _RS.join(_overlay_digest(c) for c in applied_changes),
    )


def run(label: str = "seed-demo", manual_merges: list[tuple[str, str]] = (),
        applied_changes: list[dict] = ()) -> EngineResult:
    t0 = perf_counter()
    nr = normalize_all()
    # Fold in any operator-accepted changes (pushed from staging) so a recompute
    # reflects the applied state -- the fingerprint below then yields a NEW
    # snapshot id, exactly as if the source export had changed. Entities are
    # augmented in lockstep so an overlay-introduced endpoint still resolves to an
    # asset (else its graph node would have no backing asset row).
    records, entities = nr.records, nr.entities
    if applied_changes:
        records = apply_overlay(nr.records, applied_changes)
        entities = ensure_entities(nr.entities, records)
    t1 = perf_counter()
    idr = resolve_identities(entities, manual_merges)
    t2 = perf_counter()
    graph = build_graph(records, idr.assets, idr.alias_map)
    t3 = perf_counter()
    # Hashed over the POST-overlay records and the POST-augmentation entities:
    # the id has to describe the state that was actually analyzed.
    sid = make_snapshot_id(label, _fingerprint(records, entities, nr.resolved,
                                              manual_merges, applied_changes))

    findings, degraded = _run_analyzers(records, graph, idr.alias_map, isolate=True)
    t4 = perf_counter()

    # finalize snapshot-scoped deterministic ids from the stable local keys
    for f in findings:
        f.id = det_id("F", sid, f.id)

    findings.sort(key=lambda f: (
        0 if f.forced_critical else 1, -f.severity, _BAND_ORDER[f.severity_band], f.type, f.id
    ))

    timings = {
        "normalize": round((t1 - t0) * 1000),
        "identity": round((t2 - t1) * 1000),
        "graph": round((t3 - t2) * 1000),
        "analyze": round((t4 - t3) * 1000),
        "total": round((t4 - t0) * 1000),
    }
    if degraded:
        log.error("snapshot completed with degraded analyzers", extra={
            "event": "snapshot_degraded", "snapshot_id": sid,
            "analyzers": [d["analyzer"] for d in degraded],
        })
    return EngineResult(
        snapshot_id=sid, label=label, records=records, assets=idr.assets,
        correlations=idr.correlations, resolved=nr.resolved, alias_map=idr.alias_map,
        graph=graph, findings=findings, timings=timings, degraded_analyzers=degraded,
    )
