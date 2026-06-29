"""Run the whole deterministic engine: normalize -> resolve identities -> build
graph -> analyze -> score. Produces an EngineResult that precompute.py persists.

Everything here is deterministic and reproducible: same inputs -> byte-identical
snapshot id, findings, and ordering. No model, no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter

import networkx as nx

from ..change.apply import apply_overlay, ensure_entities
from ..graph.build import build_graph
from ..identity import resolve_identities
from ..ids import content_fingerprint, det_id, snapshot_id as make_snapshot_id
from ..models import Asset, AssetCorrelation, Finding, PolicyRecord
from ..normalizers import normalize_all
from ..normalizers.common import ResolvedObject
from . import cidr_overlap, over_permissive, path_trace, shadowing, transport_exposure

_BAND_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


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


def reanalyze(records: list[PolicyRecord], assets: list[Asset],
              alias_map: dict[str, str]) -> list[Finding]:
    """Re-run the analyzers on modified records (no persistence, no id finalize).

    Used by the remediation layer to PROVE a proposed fix resolves a finding
    without introducing new criticals -- the deterministic validation step."""
    graph = build_graph(records, assets, alias_map)
    findings: list[Finding] = []
    findings += over_permissive.analyze(records, graph, alias_map)
    findings += cidr_overlap.analyze(records)
    findings += shadowing.analyze(records, graph, alias_map)
    findings += path_trace.analyze(graph)
    findings += transport_exposure.analyze(records, graph, alias_map)
    return findings


def _fingerprint(records: list[PolicyRecord]) -> str:
    return content_fingerprint(sorted(
        f"{r.source_tool}|{r.raw_ref}|{r.source}|{r.destination}|{r.service}|{r.action}|{r.order}"
        for r in records
    ))


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
    sid = make_snapshot_id(label, _fingerprint(records))

    findings: list[Finding] = []
    findings += over_permissive.analyze(records, graph, idr.alias_map)
    findings += cidr_overlap.analyze(records)
    findings += shadowing.analyze(records, graph, idr.alias_map)
    findings += path_trace.analyze(graph)
    findings += transport_exposure.analyze(records, graph, idr.alias_map)
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
    return EngineResult(
        snapshot_id=sid, label=label, records=records, assets=idr.assets,
        correlations=idr.correlations, resolved=nr.resolved, alias_map=idr.alias_map,
        graph=graph, findings=findings, timings=timings,
    )
