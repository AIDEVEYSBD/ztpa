r"""Run the whole deterministic engine: normalize -> resolve identities -> build
graph -> analyze -> score. Produces an EngineResult that precompute.py persists.

Everything here is deterministic and reproducible: same inputs -> byte-identical
snapshot id, findings, and ordering. No model, no randomness.

Two Phase 1 changes live in this module, and two Phase D corrections to
them. Each section below names the defect it closes.

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

**THE SNAPSHOT ID NOW COVERS THE COMPLETENESS OF THE ANALYSIS, NOT ONLY ITS
INPUTS** (audit-2 H8 / phase D1). That isolation shipped with the wrong half of
the guarantee: the id was minted from the INPUTS alone and minted BEFORE the
analyzers ran, so a run that lost an entire finding class hashed to the id of
the healthy run over the same export and `persist_engine_result` upserted the
partial rows straight over the complete ones. Measured against real Postgres: a
healthy recompute wrote 30 findings; the same export with two analyzers raising
wrote 7 under the SAME snapshot id, destroying the 30 -- and every endpoint
reported `status: "ok"`, `served_from: "database"`. A loud crash had been
converted into a quiet, durable, authoritative under-report, which is a strictly
worse failure than the one it replaced.

So the id is minted AFTER the analyzers, over the input fingerprint PLUS an
integrity digest (`_integrity_digest`) of everything that made this run less
than a complete analysis. A complete run hashes exactly as before -- the digest
is the empty string and the extra blob is not added at all, so every existing
snapshot id, explanation-cache key and governance row is byte-identical -- while
an incomplete run is a DIFFERENT snapshot that cannot collide with, and
therefore cannot overwrite, the complete one. `app.main` refuses to publish or
persist it on top of that, and `persist.persist_engine_result` refuses at the
lowest layer.

**A BOUNDED SCAN IS ALSO AN INCOMPLETE ANALYSIS** (audit-2 D1, second half).
`graph.reachability` caps path enumeration at `_PATH_SCAN_CAP` candidates per
target and already logs a structured `path_scan_truncated` warning at each cut,
but `cross_tool_paths` and `find_paths` return bare lists, so every truncation
died in the log stream: on a 51-node mesh the reported cross-tool finding count
is literally `cap x sensitive_targets` and carries no information about the
estate, while health said `ok`. `_record_truncations` collects those events for
the duration of the analyzer phase and folds them into the result the same way a
degraded analyzer is folded in. It is a BRIDGE, deliberately: the durable fix is
for `cross_tool_paths`/`find_paths` to return the flag their own docstrings
describe, and `test_degraded_publication.py` fails loudly if the bridge ever
stops firing -- a silent bridge would be this file's own bug class.
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
from dataclasses import dataclass, field
from time import perf_counter
from typing import Callable, Iterable, Iterator

import networkx as nx

from ..change.apply import apply_overlay, ensure_entities
from ..graph.build import build_graph
from ..identity import resolve_identities
from ..ids import content_fingerprint, det_id, snapshot_id as make_snapshot_id
from ..models import Asset, AssetCorrelation, Finding, PolicyRecord
from ..models import Topology
from ..normalizers import normalize_all
from ..topology import reconstruct
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
#
# `source_unresolved` is the newest entry and it is not cosmetic: the normalizer
# sets it when a source token CLAIMED address space and failed to resolve, and
# `severity.exposure_score` reads it to apply a conservative floor. Two records
# identical in every other field -- one whose source is a user group (no address
# space, correctly E_IDENTITY) and one whose source is a typo'd `10.0.0.0/33`
# (broad, and now floored) -- produce different severities and different
# findings. Omitting it would put two postures with different answers under one
# snapshot id, which is the exact defect the widening above exists to close.
_RECORD_FIELDS: tuple[str, ...] = (
    "id", "source_tool", "raw_ref", "order", "action",
    "source", "source_kind", "source_cidrs", "source_ip", "source_unresolved",
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
    # One entry per (function, src, dst) whose path enumeration hit
    # `_PATH_SCAN_CAP`: {fn, src, dst, cap}. Same rule -- empty is the only clean
    # state. A non-empty list means the findings PRESENT are a bounded sample of
    # the findings that exist, so no count taken from this result is a total and
    # no absence in it is a proof.
    truncations: list[dict] = field(default_factory=list)
    # The reconstructed infrastructure view -- devices, interfaces, links, VLANs,
    # subnets, circuits, and the layers we observed nothing in.
    #
    # A SEPARATE GRAPH, deliberately. `graph` above is POLICY: who may reach what.
    # This is cabling and adjacency, and nothing in `src.graph` may read it. A
    # topology link is not a grant, and letting one become the other would let
    # the engine report reachability that no rule permits -- the one error a
    # security tool cannot ship. `verify_engine` asserts `cross_tool_paths` is
    # byte-identical with and without this populated.
    topology: Topology = field(default_factory=Topology)

    # --- what this result is allowed to claim about itself -----------------
    # Two distinct failure grades, because they have two different remedies and
    # collapsing them would either block a large estate from ever persisting a
    # snapshot or let a missing finding class through as "just bounded".

    @property
    def degraded(self) -> bool:
        """An entire finding CLASS is missing: an analyzer raised and its findings
        do not exist in this result at all. Unfixable by reading more of it, so
        this result may never replace or overwrite a complete one."""
        return bool(self.degraded_analyzers)

    @property
    def partial(self) -> bool:
        """The findings present are a bounded SAMPLE: at least one path
        enumeration stopped at the scan cap. The result is still the best
        available answer for these inputs -- it is persisted -- but every count
        in it is a lower bound and every absence is "not found within budget"."""
        return bool(self.truncations)

    @property
    def complete(self) -> bool:
        """The only state in which this result may be published as authoritative."""
        return not self.degraded and not self.partial

    def integrity_reasons(self) -> list[str]:
        """Why this result is not a complete analysis, in words a human reads on
        /api/health. Sorted and deterministic like everything else here."""
        reasons: list[str] = []
        if self.degraded_analyzers:
            names = ", ".join(sorted(d["analyzer"] for d in self.degraded_analyzers))
            reasons.append(
                f"the analysis is incomplete: {names} failed, so this snapshot is missing "
                f"every finding of that class (it is not 'nothing found there')")
        if self.truncations:
            pairs = ", ".join(sorted(f"{t['src']} -> {t['dst']}" for t in self.truncations))
            reasons.append(
                f"path enumeration hit its scan cap for {len(self.truncations)} target(s) "
                f"({pairs}), so cross-tool findings are a bounded sample: counts are lower "
                f"bounds and absences are not proofs")
        return reasons


# --- bounded-scan capture --------------------------------------------------
# `graph/reachability.py` cuts every path enumeration off at `_PATH_SCAN_CAP`
# candidates and logs one structured WARNING per cut -- and that was the end of
# it: `cross_tool_paths` and `find_paths` both return a bare `list[dict]`, so
# `path_trace.analyze` (and therefore this module, and therefore /api/health and
# every payload) could not tell "no cross-tool path exists" from "the scan ran
# out of budget before it found one". On the audit's 51-node mesh the reported
# count is exactly `cap x sensitive_targets` and health said `ok`.
#
# Until those two functions return the flag their own docstrings promise, the
# events themselves are the channel: they are structured (`event`, `fn`, `cap`
# and the pair), they are emitted at every cut site, and they are already
# WARNING. Two guards keep this from over-reporting:
#
#   * only records from THIS thread are taken, so a background agent tool call
#     answering `reachable()` on another thread cannot mark the engine's run
#     truncated (the engine's own analyzer phase is single-threaded);
#   * the graph logger's level is forced to WARNING for the duration, so
#     `NPR_LOG_LEVEL=ERROR` cannot silently switch the signal off -- an
#     environment variable that turns a safety net into a false all-clear is
#     precisely the defect class this file is being fixed for.
_TRUNCATION_LOGGER = "npr.api.graph"
_TRUNCATION_EVENT = "path_scan_truncated"


class _TruncationRecorder(logging.Handler):
    """Collects `path_scan_truncated` events raised on one thread.

    A `logging.Handler` rather than a `caplog`-style hook because it has to work
    in production, not only under pytest. `emit` is total by construction: a
    handler that raised would be swallowed by `logging.Handler.handleError` and
    the truncation would vanish, which is the failure it exists to prevent."""

    def __init__(self, thread_ident: int) -> None:
        super().__init__(level=logging.WARNING)
        self._thread_ident = thread_ident
        self._seen: dict[tuple[str, str, str], dict] = {}

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(record, "event", None) != _TRUNCATION_EVENT:
            return
        if record.thread != self._thread_ident:
            return
        # `cross_tool_paths` names the pair source/target, `reachable` names it
        # src/dst. One shape out, so a consumer never has to know which cut site
        # fired, and `str()`/`int()` so an exotic extra cannot poison the digest.
        fn = str(getattr(record, "fn", "unknown"))
        src = str(getattr(record, "source", None) or getattr(record, "src", "") or "")
        dst = str(getattr(record, "target", None) or getattr(record, "dst", "") or "")
        try:
            cap = int(getattr(record, "cap", 0) or 0)
        except (TypeError, ValueError):
            cap = 0
        self._seen[(fn, src, dst)] = {"fn": fn, "src": src, "dst": dst, "cap": cap}

    def markers(self) -> list[dict]:
        """One entry per truncated (fn, src, dst), sorted -- never set order."""
        return [self._seen[key] for key in sorted(self._seen)]


@contextlib.contextmanager
def _record_truncations() -> Iterator[_TruncationRecorder]:
    """Capture the graph layer's truncation events for the enclosed block."""
    graph_log = logging.getLogger(_TRUNCATION_LOGGER)
    recorder = _TruncationRecorder(threading.get_ident())
    previous_level = graph_log.level
    if not graph_log.isEnabledFor(logging.WARNING):
        graph_log.setLevel(logging.WARNING)
    graph_log.addHandler(recorder)
    try:
        yield recorder
    finally:
        graph_log.removeHandler(recorder)
        graph_log.setLevel(previous_level)


def _integrity_digest(degraded: list[dict], truncations: list[dict]) -> str:
    """A stable digest of everything that made a run less than a complete
    analysis -- or "" when it was complete.

    "" is load-bearing: `run` adds no blob at all in that case, so a complete run
    hashes to exactly the id it hashed to before this existed. Every persisted
    snapshot, explanation-cache key and governance row keeps its identity.

    What is hashed is deliberately narrower than what is REPORTED. The analyzer
    NAME and the exception TYPE go in; the exception MESSAGE does not, because a
    message can carry a repr with an object address in it and the snapshot id
    must be a function of the posture, never of the heap. Two different failures
    of the same class in the same analyzer therefore share an id -- which is
    fine, because the only property this id needs is that no incomplete run can
    ever collide with the COMPLETE one it would otherwise overwrite."""
    if not degraded and not truncations:
        return ""
    return content_fingerprint(
        _RS.join(sorted(f"{d['analyzer']}{_FS}{d['error']}" for d in degraded)),
        _RS.join(sorted(f"{t['fn']}{_FS}{t['src']}{_FS}{t['dst']}{_FS}{t['cap']}"
                        for t in truncations)),
    )


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


class TruncatedAnalysisError(RuntimeError):
    """A validation re-analysis ran on a path scan that hit its cap.

    Separate from the analyzer exceptions `reanalyze` already lets through
    because the cause is different -- nothing failed, the search ran out of
    budget -- and the consequence is identical: the finding set is a lower
    bound, so "this fix introduces no new critical" is unproven rather than
    proven."""


def reanalyze(records: list[PolicyRecord], assets: list[Asset],
              alias_map: dict[str, str]) -> list[Finding]:
    """Re-run the analyzers on modified records (no persistence, no id finalize).

    Used by the remediation layer to PROVE a proposed fix resolves a finding
    without introducing new criticals -- the deterministic validation step.

    FAILS CLOSED ON A TRUNCATED SCAN, for the same reason it fails closed on an
    analyzer exception. The whole output of this function is a comparison of two
    finding sets, and the claim built from it -- `introduces_new_criticals: []`
    -- is a claim about ABSENCE. A bounded scan cannot support one: the new
    internet-to-PCI path this fix opens may be candidate 4,001. `_validate` in
    `advisory/remediation.py` turns the raise into `resolves: False` plus the
    reason, so the fix is simply not certified, which is the correct answer to
    "we could not prove it"; the campaign planner turns it into a
    `needs_review` step. Both are strictly better than quietly certifying a fix
    against a partial view of its own consequences."""
    graph = build_graph(records, assets, alias_map)
    with _record_truncations() as truncated:
        findings, _degraded = _run_analyzers(records, graph, alias_map, isolate=False)
    markers = truncated.markers()
    if markers:
        pairs = ", ".join(f"{m['src']} -> {m['dst']}" for m in markers)
        raise TruncatedAnalysisError(
            f"path enumeration hit its scan cap for {pairs}, so this validation compared two "
            f"BOUNDED finding sets. A fix cannot be certified as introducing no new critical "
            f"against a search that did not finish.")
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
                 applied_changes: Iterable[dict],
                 nr: NormalizeResult | None = None) -> str:
    """The content hash behind `snapshot_id`: everything that determines the run.

    Six blobs, in a fixed order. Records, entities and resolved rows are sorted
    (their order in the export must not change the id); merges are sorted (the
    set is what matters). The overlay is NOT sorted -- `apply_overlay` folds
    changes in the caller's order and two orders can produce two different record
    sets, so its order is content.

    THE INFRASTRUCTURE BLOB IS IN HERE EVEN THOUGH IT CHANGES NO FINDING.
    It is tempting to leave it out: the topology is a separate graph, no analyzer
    reads it, and excluding it would keep the golden snapshot id stable when a
    console is onboarded. That reasoning is exactly backwards. The id keys every
    snapshot-scoped table, `devices`/`topology_links`/`vlans` among them, so two
    ingests that differ ONLY in their topology would share one id -- and the rows
    a reader got back would depend on which run happened to write last. An id
    that does not cover the content it keys is not a content hash.

    So onboarding a console mints a new snapshot, which is the truth: more of the
    estate was read than last time.

    ...and an estate with NO infrastructure keeps the id it always had. The sixth
    blob is appended only when there is something in it, rather than appended as
    an empty string, because an empty blob is not absent content -- it would
    still perturb the hash and re-baseline every existing snapshot for an ingest
    that read nothing new. "No topology" and "the same policy inputs as before"
    are the same content, and must produce the same id.
    """
    blobs = [
        _RS.join(sorted(_record_digest(r) for r in records)),
        _RS.join(sorted(_entity_digest(e) for e in entities)),
        _RS.join(sorted(_resolved_digest(o) for o in resolved)),
        _RS.join(sorted(_merge_digest(m) for m in manual_merges)),
        _RS.join(_overlay_digest(c) for c in applied_changes),
    ]
    infra = sorted(_infra_digest(nr)) if nr is not None else []
    if infra:
        blobs.append(_RS.join(infra))
    return content_fingerprint(*blobs)


def _infra_digest(nr) -> list[str]:
    """One stable line per infrastructure fact.

    Model-dumped rather than hand-built so a field added to `NetDevice` or
    `NetLink` cannot silently fall outside the fingerprint -- which would let two
    materially different topologies share an id. Sorted by the caller.
    """
    out: list[str] = []
    for kind, items in (("dev", nr.devices), ("if", nr.interfaces), ("ln", nr.links),
                        ("vl", nr.vlans), ("sn", nr.subnets), ("ci", nr.circuits)):
        for item in items:
            out.append(f"{kind}{_FS}{item.model_dump_json()}")
    return out


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
    # The SECOND graph, built from the same ingest and kept entirely apart from
    # the first. `reconstruct` derives each device's lane from its position in
    # the link graph rather than from its name, and refuses to place one it
    # cannot justify. Nothing below reads it: the analyzers take `graph`.
    topology = reconstruct(nr.devices, nr.interfaces, nr.links,
                           nr.vlans, nr.subnets, nr.circuits)
    t3 = perf_counter()
    # Hashed over the POST-overlay records and the POST-augmentation entities:
    # the id has to describe the state that was actually analyzed.
    fingerprint = _fingerprint(records, entities, nr.resolved, manual_merges,
                               applied_changes, nr)

    with _record_truncations() as truncated:
        findings, degraded = _run_analyzers(records, graph, idr.alias_map, isolate=True)
    truncations = truncated.markers()
    t4 = perf_counter()

    # The id is minted HERE, after the analyzers, not before them. An incomplete
    # run is a different snapshot from the complete one over the same inputs, so
    # it cannot upsert over it -- see the module docstring. A complete run adds
    # no blob and keeps the id it always had.
    integrity = _integrity_digest(degraded, truncations)
    sid = make_snapshot_id(label, content_fingerprint(fingerprint, integrity) if integrity
                           else fingerprint)

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
    if truncations:
        # ERROR, not warning: from here on every count in this snapshot is a
        # lower bound. The graph layer already logged each individual cut; this
        # line is the one that says the SNAPSHOT is affected, with its id, so the
        # log and /api/health agree about the same run.
        log.error("snapshot completed with a truncated path scan", extra={
            "event": "snapshot_truncated", "snapshot_id": sid,
            "targets": [f"{t['src']} -> {t['dst']}" for t in truncations],
        })
    return EngineResult(
        snapshot_id=sid, label=label, records=records, assets=idr.assets,
        correlations=idr.correlations, resolved=nr.resolved, alias_map=idr.alias_map,
        graph=graph, findings=findings, timings=timings, degraded_analyzers=degraded,
        truncations=truncations, topology=topology,
    )
