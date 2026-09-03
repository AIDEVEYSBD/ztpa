"""Guards for the ten engine mutations that survived the Phase 1 suite.

Why this file exists
--------------------
The audit's root-cause finding (gap theme 10) is that nothing tested the
deterministic core, and that is what let every other defect ship: 6 of 10
injected engine defects passed both `pytest` and `verify_engine.py` green.
Phase 1 closed most of it. A mutation matrix re-run at the end of Phase 1 found
TEN mutations still surviving -- each a one-line change a careless refactor could
make, each with a measurable consequence for the customer, and every one of them
green across 1,107 tests. This module makes each of them fail.

Every mutation here is a *silent* defect. None of them raises, none of them
changes a count anybody was already asserting; they move a finding's reasons, a
snapshot id, a persisted signal's order, or an asset's identity. That is the
whole reason they survived: the suite asserted that findings EXIST, not that they
say the true thing.

The shape of every guard, and why it is a pair
----------------------------------------------
A test that has never been seen to fail is not a guard, so each mutation gets
two tests built around one shared `_guard_mXX()` assertion body:

  test_mXX_<consequence>                  runs the guard against the real code.
  test_mXX_guard_fails_under_the_mutation runs the SAME guard with the mutation
                                          injected, and asserts it raises.

The second half is the evidence, kept in the repo rather than in somebody's
terminal scrollback: if a future refactor makes a guard vacuous (asserting
something that holds under the mutation too), the pair goes red. Every injection
is the matrix's mutant verbatim -- a module attribute swapped for a copy of the
real function with exactly one line changed, or the one collaborator whose
removal IS the mutation. Every one was additionally verified against a genuinely
mutated checkout of `backend/src` before being written down here.

Assertion messages all start with the mutation id, which is what the paired
`pytest.raises(match=...)` anchors on, so a bites-test cannot pass by tripping
some unrelated assertion.

What is NOT here
----------------
M65 (`shadowing._service_covers`, the `later.protocol == "any"` disjunct) is a
PROVEN EQUIVALENT MUTANT and is deliberately unguarded -- see
`test_m65_is_an_equivalent_mutant_and_cannot_be_guarded` at the bottom, which
proves the equivalence instead of pretending to test it.
"""

from __future__ import annotations

import inspect
from typing import get_args

import pytest

from src import models
from src.analyzers import over_permissive, path_trace, run_all
from src.analyzers.severity import is_internet_source, score_over_permissive
from src.change.simulate import resolve_dest_tags
from src.config import ZONE_INTERNAL, ZONE_INTERNET
from src.graph.build import build_graph
from src.identity import context_of, resolve_identities
from src.models import PolicyRecord
from src.normalizers import common
from src.normalizers.common import (
    NormalizeResult, ObservedEntity, parse_service, record_from_service,
)

# --------------------------------------------------------------------------
# Builders. Deliberately thin: every guard below has to be readable as "this
# input, therefore this consequence", so nothing here makes a decision.
# --------------------------------------------------------------------------


def _entity(name: str, tool: str, *, kind: str = "identity", ip: str | None = None,
            cidr: str | None = None, cidrs: tuple[str, ...] = (), tags: tuple[str, ...] = (),
            identifiers: dict | None = None, abstract: bool = False) -> ObservedEntity:
    return ObservedEntity(name=name, kind=kind, tool=tool, ip=ip, cidr=cidr,
                          cidrs=list(cidrs), tags=list(tags),
                          identifiers=dict(identifiers or {}), abstract=abstract)


def _cidr_entity(block: str, tool: str = "algosec") -> ObservedEntity:
    """A raw-CIDR node, exactly as every normalizer emits one."""
    return _entity(block, tool, kind="cidr", cidr=block, cidrs=(block,), abstract=True)


def _rec(ref: str, source: str, destination: str, service: str, *, tool: str = "algosec",
         action: str = "allow", order: int | None = None, dest_tags: tuple[str, ...] = (),
         source_cidrs: list[str] | None = None,
         dest_cidrs: list[str] | None = None) -> PolicyRecord:
    """One canonical record, built through the same helper the normalizers use."""
    return record_from_service(
        record_id=ref, source_tool=tool, raw_ref=ref, source=source, destination=destination,
        svc=parse_service(service), action=action, order=order, dest_tags=list(dest_tags),
        source_cidrs=source_cidrs, dest_cidrs=dest_cidrs,
    )


def _analyze_over_permissive(records: list[PolicyRecord],
                             entities: list[ObservedEntity]) -> list:
    """records + entities -> over-permissive findings, through the real pipeline.

    identity -> graph -> analyzer, the same three stages `run_all.run` uses, so a
    named object classifies from its resolved address space rather than from an
    empty graph's fallback. Several guards below turn on the zone the source node
    lands in, which only the asset-backed graph can answer.
    """
    idr = resolve_identities(entities)
    graph = build_graph(records, idr.assets, idr.alias_map)
    return over_permissive.analyze(records, graph, idr.alias_map)


def _merge(views: list[ObservedEntity]) -> dict[str, ObservedEntity]:
    """Fold one tool's successive views of a node, exactly as a normalizer does.

    Reached through the MODULE (`common.merge_entities`) rather than by an
    imported name so the bites tests can swap in the mutant.
    """
    entities: dict[str, ObservedEntity] = {}
    for view in views:
        common.merge_entities(entities, view)
    return entities


# --------------------------------------------------------------------------
# The mutants, verbatim from the matrix. Each is the real function with exactly
# ONE line replaced; the diff is called out in a comment on that line.
# --------------------------------------------------------------------------


def _mutant_merge_entities(mutation: str):
    """`normalizers.common.merge_entities` with one line mutated.

    All four merge mutations live in one 6-line function, so one parameterized
    copy keeps each mutant a single visible expression instead of four near-
    identical 12-line pastes that would have to be kept in step by hand.
    """

    def merge(entities: dict[str, ObservedEntity], ent: ObservedEntity) -> None:
        cur = entities.get(ent.name)
        if cur is None:
            entities[ent.name] = ent
            return
        # M30: union -> INTERSECTION
        cur.tags = (sorted(set(cur.tags) & set(ent.tags)) if mutation == "M30"
                    else sorted(set(cur.tags) | set(ent.tags)))
        # M49: first-wins -> LAST-WINS
        cur.ip = ent.ip if mutation == "M49" else (cur.ip or ent.ip)
        cur.cidr = cur.cidr or ent.cidr
        cur.cidrs = sorted(set(cur.cidrs) | set(ent.cidrs))
        # M51: cur wins -> ENT WINS
        cur.identifiers = ({**cur.identifiers, **ent.identifiers} if mutation == "M51"
                           else {**ent.identifiers, **cur.identifiers})
        # M50: and -> OR
        cur.abstract = ((cur.abstract or ent.abstract) if mutation == "M50"
                        else (cur.abstract and ent.abstract))

    return merge


def _mutant_reasons_m57(rec: PolicyRecord, E: float, P: float) -> list[str]:
    """`over_permissive._reasons` with the any/any arm DELETED.

    Tracks the real function line for line apart from that one deletion -- the
    internet test here is `is_internet_source`, as it now is in production. A
    mutant that has silently become a copy of an OLDER version of the function
    tests two changes at once and proves neither.
    """
    cfg = over_permissive.OVERPERMISSIVE_CONFIG
    is_internet = over_permissive.is_internet_source(
        rec.source, rec.source_kind, rec.source_cidrs)
    sensitive = bool(set(rec.dest_tags) & over_permissive.SENSITIVE_TAGS)
    out: list[str] = []
    # M57: the `if rec.protocol == "any"` arm is gone.
    if is_internet and (P >= cfg["admin_data_min_P"] or sensitive):
        out.append("exposed directly to the internet")
    if sensitive and E >= cfg["sensitive_dest_min_E"]:
        out.append("regulated destination reachable from more than a single host")
    if P >= cfg["admin_data_min_P"] and E >= cfg["broad_source_E"]:
        out.append("admin/data port open to a broad source range")
    return out


def _mutant_reasons_m56(rec: PolicyRecord, E: float, P: float) -> list[str]:
    """`over_permissive._reasons` with the internet test back on the E proxy.

    RE-TARGETED (PROD-READINESS-AUDIT-2 B2). The mutation this guard injects used
    to be `E >= 1.0` -> `E > 1.0`, a mutation of a line that was itself the bug.
    It is now the bug: the address-space predicate replaced by the exposure-score
    proxy the engine deleted everywhere else. This is the exact code that shipped,
    so the guard below is a regression test for a defect that really happened,
    not a hypothetical.
    """
    cfg = over_permissive.OVERPERMISSIVE_CONFIG
    # M56: `is_internet_source(...)` -> `E >= 1.0`, true only for a /0.
    is_internet = E >= 1.0
    sensitive = bool(set(rec.dest_tags) & over_permissive.SENSITIVE_TAGS)
    out: list[str] = []
    if rec.protocol == "any":
        out.append("allows every protocol and port (any/any)")
    if is_internet and (P >= cfg["admin_data_min_P"] or sensitive):
        out.append("exposed directly to the internet")
    if sensitive and E >= cfg["sensitive_dest_min_E"]:
        out.append("regulated destination reachable from more than a single host")
    if P >= cfg["admin_data_min_P"] and E >= cfg["broad_source_E"]:
        out.append("admin/data port open to a broad source range")
    return out


def _mutant_is_wildcard_source_m59(rec: PolicyRecord) -> bool:
    """`over_permissive._is_wildcard_source` with the resolved-cidrs arm dropped."""
    return over_permissive.is_any(rec.source)      # M59: the `or any(...)` arm is gone


def _mutant_fingerprint_m48(records, entities, resolved, manual_merges, applied_changes) -> str:
    """`run_all._fingerprint` with the applied-changes overlay SORTED."""
    return run_all.content_fingerprint(
        run_all._RS.join(sorted(run_all._record_digest(r) for r in records)),
        run_all._RS.join(sorted(run_all._entity_digest(e) for e in entities)),
        run_all._RS.join(sorted(run_all._resolved_digest(o) for o in resolved)),
        run_all._RS.join(sorted(run_all._merge_digest(m) for m in manual_merges)),
        # M48: the overlay blob is sorted, which its own docstring forbids.
        run_all._RS.join(sorted(run_all._overlay_digest(c) for c in applied_changes)),
    )


# ==========================================================================
# M57 -- deleting the any/any arm of `_reasons` deletes the WHOLE finding.
# ==========================================================================

_ANY_ANY_REASON = "allows every protocol and port (any/any)"


def _guard_m57() -> None:
    """An any/any rule that trips NO other predicate must still be reported.

    The input isolates the arm, which is the only way to see the real damage.
    `10.20.30.0/24 -> app-01 any` scores E=0.3 (the published /24../27 band) --
    below `broad_source_E` (0.5), so the broad-source arm cannot fire; the source
    is RFC 1918, so `is_internet_source` is False and the internet arm cannot
    fire (nor can any guardrail clause, all three of which require the internet);
    and its destination carries no sensitive tag, so neither regulated-destination
    arm fires either. Of the four arms in `_reasons`, only the any/any one is
    left, and `analyze` drops a NON-FORCED record with no reasons before it ever
    builds a Finding. Delete that arm and the customer's most permissive rule is
    not downgraded, it is INVISIBLE.

    On the seeded demo the same rule trips two other arms and so merely loses its
    headline sentence; `test_m57_the_demo_still_calls_its_any_any_rule_an_any_any
    _rule` pins that half.
    """
    records = [_rec("MG-57", "10.20.30.0/24", "app-01", "any",
                    dest_tags=("prod",), dest_cidrs=["10.90.4.4/32"])]
    entities = [_cidr_entity("10.20.30.0/24"),
                _entity("app-01", "algosec", ip="10.90.4.4", tags=("prod",))]
    findings = _analyze_over_permissive(records, entities)

    assert len(findings) == 1, (
        f"M57: the any/any rule produced {len(findings)} findings, expected exactly 1. "
        "No other predicate in _reasons can fire on this input, so an empty reason "
        "list means `analyze` skipped the rule entirely and the finding is gone.")
    finding = findings[0]
    assert finding.signals["reasons"] == [_ANY_ANY_REASON], (
        f"M57: reasons were {finding.signals['reasons']!r}, expected exactly "
        f"[{_ANY_ANY_REASON!r}] -- the any/any arm is the only thing reporting this rule.")
    assert finding.title.startswith("any protocol/port open from"), (
        f"M57: title was {finding.title!r}; an any/any grant must say so in its headline.")


def test_m57_an_any_any_rule_that_trips_nothing_else_is_still_reported() -> None:
    _guard_m57()


def test_m57_guard_fails_under_the_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject the matrix's M57 (delete the any/any arm) and watch the guard bite."""
    monkeypatch.setattr(over_permissive, "_reasons", _mutant_reasons_m57)
    with pytest.raises(AssertionError, match=r"^M57"):
        _guard_m57()


# ==========================================================================
# M52 -- dropping the wildcard arm of `PolicyRecord._canonicalize_cidrs`
#        re-admits the audit's headline defect one layer below the analyzers.
# ==========================================================================

_WILDCARD_SPELLINGS = ("any", "Any", "ANY", "all", "ALL", "*")


def _wildcard_record(cidrs: list[str], source: str = "EXTERNAL-NETS") -> PolicyRecord:
    """A /0 -> PCI-database RDP grant, built straight through the model.

    Constructed with `PolicyRecord(...)` rather than `record_from_service` on
    purpose: the helper derives `source_cidrs` from the token through
    `cidrs_for_token`, which pre-canonicalizes the wildcard vocabulary and so
    would hide the very arm under test. This is the shape a record has when it
    arrives already-formed -- `change.apply._added_record` rebuilding an
    overlay's proposal from stored JSONB, or any deserialized PolicyRecord.
    """
    return PolicyRecord(
        id="MG-52", source_tool="algosec", raw_ref="MG-52",
        source=source, source_kind="cidr" if common.is_cidr(source) else "identity",
        destination="db-prod-01", destination_kind="identity", dest_tags=["pci"],
        source_cidrs=list(cidrs), dest_cidrs=list(cidrs),
        service="tcp/3389", port=3389, protocol="tcp", action="allow",
    )


def _guard_m52() -> None:
    """The wildcard vocabulary must resolve to 0.0.0.0/0 INSIDE the model.

    `_canonicalize_cidrs` is, by `change.simulate`'s own comment, "the single
    place that normal form is defined" for resolved address space -- which is why
    `simulate_change` rebuilds a proposal through `model_validate` rather than
    `model_copy`. Every normalizer happens to pre-canonicalize through
    `cidrs_for_token`, which is exactly why this mutant survived; the arm is
    still live for every PolicyRecord that arrives already-shaped, above all
    `change.apply._added_record`, which reconstructs an overlay's proposed rule
    from a stored JSONB payload on every single engine run.

    Losing it is not a cosmetic normalization miss. `exposure_score` reads
    `source_cidrs` and falls back to E_IDENTITY -- 0.1, the score of ONE HOST --
    only when that list is empty, so dropping the arm turns a /0 into a single
    machine: severity 100/forced-critical becomes 62/high. That is the audit's
    headline defect, re-entering one layer down.
    """
    for spelling in _WILDCARD_SPELLINGS:
        rec = _wildcard_record([spelling])
        assert rec.source_cidrs == ["0.0.0.0/0"], (
            f"M52: source_cidrs=[{spelling!r}] canonicalized to {rec.source_cidrs!r}, "
            "expected ['0.0.0.0/0'] -- the wildcard vocabulary IS the whole address space.")
        assert rec.dest_cidrs == ["0.0.0.0/0"], (
            f"M52: dest_cidrs=[{spelling!r}] canonicalized to {rec.dest_cidrs!r}, "
            "expected ['0.0.0.0/0'].")

    # The consequence: four spellings of one grant, one score. `0.0.0.0/0` and a
    # named object resolving to it already agreed before this mutation; the
    # fourth encoding -- a catalog whose value is the WORD -- is the one the arm
    # carries, and it must not be the odd one out.
    encodings = {
        "literal /0": ("0.0.0.0/0", ["0.0.0.0/0"]),
        "wildcard word as the source": ("any", ["0.0.0.0/0"]),
        "named object -> /0": ("EXTERNAL-NETS", ["0.0.0.0/0"]),
        "named object -> the word": ("EXTERNAL-NETS", ["any"]),
    }
    scored = {}
    for name, (source, cidrs) in encodings.items():
        rec = _wildcard_record(cidrs, source)
        sc = score_over_permissive(
            source=rec.source, source_kind=rec.source_kind, protocol=rec.protocol,
            port=rec.port, dest_tags=rec.dest_tags,
            src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL, source_cidrs=rec.source_cidrs,
        )
        scored[name] = (sc["severity"], sc["forced_critical"], sc["E"])

    baseline = scored["literal /0"]
    for name, value in scored.items():
        assert value == baseline, (
            f"M52: the encoding {name!r} scored {value} but the literal /0 scored {baseline}. "
            "Four spellings of one address space must produce one (severity, forced, E); "
            "an E that collapsed to 0.1 means the resolved space was dropped and the "
            "internet is being reported as a single host.")


def test_m52_the_wildcard_vocabulary_still_resolves_to_the_whole_address_space() -> None:
    _guard_m52()


def test_m52_guard_fails_under_the_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject M52 by removing the arm's only collaborator.

    `if net is None and is_any(raw)` is dead the moment `is_any` stops answering
    True, so a False-returning stand-in is the deleted arm exactly, and it reaches
    the validator because pydantic resolves the name through `src.models`'
    globals at validation time.
    """
    monkeypatch.setattr(models, "is_any", lambda _value: False)
    with pytest.raises(AssertionError, match=r"^M52"):
        _guard_m52()


# ==========================================================================
# M48 -- sorting the applied-changes overlay makes two applied states share
#        one system-of-record id.
# ==========================================================================

# The overlay pair, chosen so that the RECORDS cannot do the distinguishing.
#
# Applied narrow-then-remove, both operator actions land: ALGO-1 is scoped down
# to tcp/443 and then deleted. Applied remove-then-narrow, the first deletes
# ALGO-1 and the second is a NO-OP -- `apply_remediation` finds no rule with that
# raw_ref and returns the list untouched, so the operator's second remediation
# never took effect at all.
#
# Both orders leave the identical rulebook behind. That is the whole point: the
# record blob is byte-identical, so the ONLY blob that can tell these two applied
# states apart is the overlay, and only while it stays ordered. `_overlay_digest`
# says so in as many words -- "a remediation whose target no longer exists is a
# no-op on the records yet still a different applied state".
_M48_REMOVE = {"kind": "remediation", "payload": {"op": "remove", "target_ref": "ALGO-1"}}
_M48_NARROW = {"kind": "remediation",
               "payload": {"op": "restrict_service", "target_ref": "ALGO-1",
                           "new_service": "tcp/443"}}


def _m48_estate() -> NormalizeResult:
    return NormalizeResult(
        records=[_rec("ALGO-1", "0.0.0.0/0", "db-prod-01", "tcp/3389", order=10,
                      dest_tags=("pci", "prod"), dest_cidrs=["10.50.0.10/32"]),
                 _rec("ALGO-2", "10.50.0.0/24", "db-prod-01", "tcp/443", order=20,
                      dest_tags=("pci", "prod"), dest_cidrs=["10.50.0.10/32"])],
        entities=[_cidr_entity("0.0.0.0/0"),
                  _entity("db-prod-01", "algosec", ip="10.50.0.10", tags=("pci", "prod"))],
        resolved=[],
    )


def _guard_m48(monkeypatch: pytest.MonkeyPatch) -> None:
    """The applied-changes overlay is ORDERED, so its order is part of the id.

    `_fingerprint` says it outright: "The overlay is NOT sorted -- `apply_overlay`
    folds changes in the caller's order and two orders can produce two different
    record sets, so its order is content." Sorting it does not merely lose that;
    it loses the only blob that can separate two applied states whose record sets
    coincide, which is exactly the pair below -- one where both remediations
    landed, one where the second was a no-op against a rule that was already
    gone.

    Governance rows hang off the snapshot id, and "was this fix applied?" is a
    question a compliance trail has to be able to answer. Two different answers
    under one id is the system of record asserting something false.

    The guard proves its own premise first -- that the two runs really do produce
    the identical rulebook -- so it cannot pass by accident on a pair the record
    blob was distinguishing all along.
    """
    ids, rulebooks = {}, {}
    for name, overlay in (("narrow-then-remove", [_M48_NARROW, _M48_REMOVE]),
                          ("remove-then-narrow", [_M48_REMOVE, _M48_NARROW])):
        with monkeypatch.context() as mp:
            mp.setattr(run_all, "normalize_all", _m48_estate)
            result = run_all.run(label="mutation-guard", applied_changes=overlay)
        ids[name] = result.snapshot_id
        rulebooks[name] = sorted((r.raw_ref, r.service) for r in result.records)

    assert rulebooks["narrow-then-remove"] == rulebooks["remove-then-narrow"], (
        f"M48: the two overlay orders produced different rulebooks "
        f"({rulebooks['narrow-then-remove']} vs {rulebooks['remove-then-narrow']}), so the "
        "record blob is doing the distinguishing and this input proves nothing about the "
        "overlay. Fix the fixture, not the assertion.")
    assert ids["narrow-then-remove"] != ids["remove-then-narrow"], (
        f"M48: both applied states hashed to snapshot id {ids['narrow-then-remove']!r} even "
        "though one applied two remediations and the other applied one and silently dropped "
        "the second. Their record sets are identical, so the overlay's order was the only "
        "thing left to tell them apart -- sorting it merges two different histories into one "
        "system-of-record id.")


def test_m48_two_overlay_orders_are_two_snapshots(monkeypatch: pytest.MonkeyPatch) -> None:
    _guard_m48(monkeypatch)


def test_m48_guard_fails_under_the_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject the matrix's M48 (sort the overlay blob) and watch the guard bite."""
    monkeypatch.setattr(run_all, "_fingerprint", _mutant_fingerprint_m48)
    with pytest.raises(AssertionError, match=r"^M48"):
        _guard_m48(monkeypatch)


# ==========================================================================
# M30 -- intersecting tags on merge silently drops a `pci` label.
# ==========================================================================

_M30_ASSET = "rds-prod-customers"


def _guard_m30() -> None:
    """Two views of one node UNION their tags; a lost tag disarms the guardrails.

    One tool's inventory row and its policy row describe the same database with
    different label sets -- the inventory knows it is `prod`/`cloud`, the
    compliance view knows it is `pci`/`customer-data`. Intersecting keeps only
    what BOTH happened to mention, and everything that decides "is this a
    regulated destination" reads the surviving set: `dest_score`'s D term, the
    third guardrail clause in `score_over_permissive`, and -- the reason this is
    a security defect rather than a display one -- `change.simulate
    .resolve_dest_tags`, which re-derives a proposal's sensitivity from the ASSET
    layer precisely so a requester cannot understate what they are asking to
    reach. Drop `pci` here and the change gate stops force-escalating.
    """
    merged = _merge([
        _entity(_M30_ASSET, "wiz", ip="10.50.0.20", tags=("prod", "cloud")),
        _entity(_M30_ASSET, "wiz", ip="10.50.0.20", tags=("pci", "customer-data", "prod")),
    ])[_M30_ASSET]

    assert merged.tags == ["cloud", "customer-data", "pci", "prod"], (
        f"M30: merged tags were {merged.tags!r}, expected the sorted UNION "
        "['cloud', 'customer-data', 'pci', 'prod']. Two views of one node contribute "
        "labels; neither one is allowed to veto the other's.")

    asset = next(a for a in resolve_identities([merged]).assets if a.asset_key == _M30_ASSET)
    assert "pci" in asset.tags, (
        f"M30: the asset came out tagged {asset.tags!r} with no 'pci'. The identity layer "
        "sees only the MERGED entity, so a tag dropped in merge_entities is gone from the "
        "system of record.")
    gate_tags = resolve_dest_tags(_M30_ASSET, [asset], {})
    assert {"pci", "customer-data"} <= set(gate_tags), (
        f"M30: the change gate re-derived {gate_tags!r} for this destination. With 'pci' "
        "missing from the asset, a proposed rule reaching a regulated database is no longer "
        "force-escalated -- the requester gets an auto-approve.")


def test_m30_merging_two_views_of_a_node_keeps_every_tag() -> None:
    _guard_m30()


def test_m30_guard_fails_under_the_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject the matrix's M30 (`|` -> `&` on tags) and watch the guard bite."""
    monkeypatch.setattr(common, "merge_entities", _mutant_merge_entities("M30"))
    with pytest.raises(AssertionError, match=r"^M30"):
        _guard_m30()


# ==========================================================================
# M49 -- last-wins on `ip` lets a later row repoint an asset.
# ==========================================================================

_M49_ASSET = "appsrv-07"


def _guard_m49() -> None:
    """The FIRST address observed for a node is its address.

    The ip is the identity: it is what `resolve_identities` keys shared-address
    merges on, what becomes `Asset.ip_set`, what `zones.zone_of` classifies, and
    what `change.simulate.resolve_cidrs` dereferences a hand-typed destination
    against. First-wins is what makes the merge order-independent; last-wins
    means whichever export row the loop happened to reach last silently repoints
    the machine -- and every rule aimed at 10.1.1.5 is then evaluated against a
    host at 10.9.9.9.
    """
    merged = _merge([
        _entity(_M49_ASSET, "guardicore", ip="10.1.1.5", tags=("prod",)),
        _entity(_M49_ASSET, "guardicore", ip="10.9.9.9", tags=("prod",)),
    ])[_M49_ASSET]

    assert merged.ip == "10.1.1.5", (
        f"M49: the merged entity's ip is {merged.ip!r}, expected '10.1.1.5'. A later view "
        "may CONTRIBUTE an address to a node that has none; it may not replace one.")

    asset = next(a for a in resolve_identities([merged]).assets if a.asset_key == _M49_ASSET)
    assert asset.ip_set == ["10.1.1.5/32"], (
        f"M49: the asset's ip_set is {asset.ip_set!r}, expected ['10.1.1.5/32'] -- the "
        "persisted address of this machine, and what every later subnet lookup resolves "
        "this name to, now points somewhere else.")


def test_m49_a_later_row_cannot_repoint_an_asset() -> None:
    _guard_m49()


def test_m49_guard_fails_under_the_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject the matrix's M49 (`cur.ip or ent.ip` -> `ent.ip`)."""
    monkeypatch.setattr(common, "merge_entities", _mutant_merge_entities("M49"))
    with pytest.raises(AssertionError, match=r"^M49"):
        _guard_m49()


# ==========================================================================
# M50 -- OR-ing `abstract` marks a real host as a range and deletes the
#        cross-tool paths that pivot through it.
# ==========================================================================

_M50_PIVOT = "edge-proxy"


def _m50_graph():
    """A cross-tool chain 0.0.0.0/0 -> edge-proxy -> vault-db, built for real.

    Two tools supply the two hops (Wiz the internet ingress, Guardicore the
    lateral one), which is what makes `cross_tool_paths` willing to report it at
    all -- it requires >= 2 distinct tools along the path.

    `edge-proxy` is seen twice by ONE tool, which is the situation merge_entities
    exists for: once as the concrete host it is (the label catalog's asset row),
    once as a label the policy referenced whose address did not resolve, which
    `object_is_abstract` fails safe on by calling abstract. The merge has to
    answer "concrete", because a node that is a HOST in any view is a host.
    """
    entities = list(_merge([
        _entity(_M50_PIVOT, "guardicore", ip="45.33.32.10", tags=("dmz", "prod")),
        _entity(_M50_PIVOT, "guardicore", abstract=True),
    ]).values()) + [
        _cidr_entity("0.0.0.0/0"),
        _entity("vault-db", "algosec", ip="10.90.9.9", tags=("pci", "crown-jewel", "prod")),
    ]
    records = [
        _rec("MG-50-W", "0.0.0.0/0", _M50_PIVOT, "tcp/443", tool="wiz",
             dest_tags=("dmz", "prod"), dest_cidrs=["45.33.32.10/32"]),
        _rec("MG-50-G", _M50_PIVOT, "vault-db", "tcp/5432", tool="guardicore",
             dest_tags=("pci", "crown-jewel", "prod"), source_cidrs=["45.33.32.10/32"],
             dest_cidrs=["10.90.9.9/32"]),
    ]
    idr = resolve_identities(entities)
    return entities, build_graph(records, idr.assets, idr.alias_map)


def _guard_m50() -> None:
    """A node any view calls concrete stays concrete, and stays a path pivot.

    `reachability._valid_traversal` rejects every path that pivots THROUGH an
    abstract node -- reaching hosts inside a range does not let you originate as
    that range. So flipping this one boolean does not downgrade a finding, it
    DELETES the cross-tool chain: the whole differentiator, gone silently.
    """
    entities, graph = _m50_graph()
    merged = next(e for e in entities if e.name == _M50_PIVOT)

    assert merged.abstract is False, (
        "M50: the merged entity came out abstract. `abstract` must be the AND over the "
        "views -- a node is a range only if EVERY view says so -- because 'we could not "
        "resolve this label' is not evidence that a known host is a network.")
    assert graph.nodes[_M50_PIVOT]["kind"] == "concrete", (
        f"M50: the graph node is {graph.nodes[_M50_PIVOT]['kind']!r}; _valid_traversal "
        "refuses to pivot through anything but 'concrete'.")

    findings = path_trace.analyze(graph)
    paths = [f.signals["path"] for f in findings]
    assert ["0.0.0.0/0", _M50_PIVOT, "vault-db"] in paths, (
        f"M50: the cross-tool chain through {_M50_PIVOT} was not reported (paths={paths!r}). "
        "An internet -> proxy -> regulated-database chain spanning two tools is the finding "
        "no single tool can produce, and marking the pivot abstract erases it in silence.")


def test_m50_a_node_seen_as_a_host_stays_a_host_and_stays_a_pivot() -> None:
    _guard_m50()


def test_m50_guard_fails_under_the_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject the matrix's M50 (`and` -> `or` on abstract)."""
    monkeypatch.setattr(common, "merge_entities", _mutant_merge_entities("M50"))
    with pytest.raises(AssertionError, match=r"^M50"):
        _guard_m50()


# ==========================================================================
# M51 -- flipping the identifiers merge lets a later row overwrite a
#        resolved identifier, including the namespace the merge is keyed on.
# ==========================================================================

_M51_ASSET = "appsrv-07"


def _guard_m51() -> None:
    """An identifier already resolved for a node is not overwritten by a later view.

    `{**ent.identifiers, **cur.identifiers}` is first-wins with the same
    justification as `cur.ip or ent.ip`: a later view may FILL a key nobody has
    answered yet, never replace an answer. Flip the two spreads and the last row
    read wins, which moves `identity.context_of` -- the namespace an address is
    unique inside, and the gate on every scoped merge -- onto whichever VPC the
    loop saw last. That is not a display field: `MAX_IP_FANOUT`, the environment
    guard and every `context_ip` correlation are decided by it, and `Asset
    .context` is persisted from it.
    """
    merged = _merge([
        _entity(_M51_ASSET, "wiz", identifiers={"cloud_id": "i-0abc", "vpc": "vpc-prod-a"}),
        _entity(_M51_ASSET, "wiz", identifiers={"cloud_id": "i-9zzz", "vpc": "vpc-dev-b"}),
    ])[_M51_ASSET]

    assert merged.identifiers["cloud_id"] == "i-0abc", (
        f"M51: cloud_id resolved to {merged.identifiers['cloud_id']!r}, expected 'i-0abc'. "
        "A later view may add an identifier; it may not overwrite one.")
    assert context_of(merged) == "vpc-prod-a", (
        f"M51: the entity's namespace is {context_of(merged)!r}, expected 'vpc-prod-a'. "
        "context_of reads these identifiers, so overwriting one moves the scope every "
        "shared-address merge is keyed on -- and merging across namespaces is the false "
        "statement about the customer's network the identity layer exists to prevent.")

    asset = next(a for a in resolve_identities([merged]).assets if a.asset_key == _M51_ASSET)
    assert asset.identifiers["cloud_id"] == "i-0abc" and asset.context == "vpc-prod-a", (
        f"M51: the persisted asset carries identifiers={asset.identifiers!r} "
        f"context={asset.context!r}; the overwrite reached the system of record.")


def test_m51_a_later_row_cannot_overwrite_a_resolved_identifier() -> None:
    _guard_m51()


def test_m51_guard_fails_under_the_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject the matrix's M51 (swap the two dict spreads)."""
    monkeypatch.setattr(common, "merge_entities", _mutant_merge_entities("M51"))
    with pytest.raises(AssertionError, match=r"^M51"):
        _guard_m51()


# ==========================================================================
# M59 -- dropping the resolved-cidrs arm of `_is_wildcard_source` puts a false
#        statement in the most-read line of the finding.
# ==========================================================================


def _guard_m59() -> None:
    """A named object that dereferences to /0 is "the internet" in the headline.

    `_is_wildcard_source` writes the finding's TITLE, which is the line the
    console lists and the one an operator triages from. `ANY-EXTERNAL` and
    `0.0.0.0/0` are the same grant; if only the literal spelling says "open from
    the internet", the named one reads as a grant from some specific named peer,
    and the operator sorting by "what is exposed to the world" never sees it.
    Both records below are scored identically by every other layer -- the ONLY
    difference the guard can be measuring is the title.
    """
    records = [
        _rec("MG-59-LIT", "0.0.0.0/0", "db-prod-01", "tcp/3389",
             dest_tags=("pci", "prod"), dest_cidrs=["10.50.0.10/32"]),
        _rec("MG-59-OBJ", "ANY-EXTERNAL", "db-prod-01", "tcp/3389",
             dest_tags=("pci", "prod"), source_cidrs=["0.0.0.0/0"],
             dest_cidrs=["10.50.0.10/32"]),
    ]
    entities = [
        _cidr_entity("0.0.0.0/0"),
        _entity("ANY-EXTERNAL", "algosec", cidrs=("0.0.0.0/0",), abstract=True),
        _entity("db-prod-01", "algosec", ip="10.50.0.10", tags=("pci", "prod")),
    ]
    by_ref = {f.raw_refs[0]: f for f in _analyze_over_permissive(records, entities)}
    assert set(by_ref) == {"MG-59-LIT", "MG-59-OBJ"}, (
        f"M59: expected both spellings to be reported, got {sorted(by_ref)!r}.")

    obj_title = by_ref["MG-59-OBJ"].title
    assert "open from the internet to" in obj_title, (
        f"M59: the named-object finding is titled {obj_title!r}. Its source resolves to "
        "0.0.0.0/0, so the headline must say 'the internet' -- naming the object instead "
        "describes a world-open grant as a grant from one peer.")
    assert obj_title == by_ref["MG-59-LIT"].title, (
        f"M59: {obj_title!r} != {by_ref['MG-59-LIT'].title!r}. One address space, one "
        "headline: the spelling in the export must not change what the operator reads.")


def test_m59_a_named_object_resolving_to_zero_zero_is_titled_the_internet() -> None:
    _guard_m59()


def test_m59_guard_fails_under_the_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject the matrix's M59 (drop the resolved-cidrs arm)."""
    monkeypatch.setattr(over_permissive, "_is_wildcard_source", _mutant_is_wildcard_source_m59)
    with pytest.raises(AssertionError, match=r"^M59"):
        _guard_m59()


# ==========================================================================
# M56 -- `E >= 1.0` -> `E > 1.0` makes the finding contradict its own guardrail.
# ==========================================================================

_INTERNET_REASON = "exposed directly to the internet"


# Public address space, narrower than a /0. E = 0.3, so the E proxy calls it
# internal; `is_internet_source` calls it what it is.
_PARTNER_PUBLIC_24 = "52.20.10.0/24"


def _guard_m56() -> None:
    """`_reasons` must ask the address space, not the exposure score.

    RE-TARGETED, AND THE OLD RATIONALE WAS WRONG (PROD-READINESS-AUDIT-2 B2)
    -----------------------------------------------------------------------
    The previous version of this guard injected `E >= 1.0` -> `E > 1.0` and
    justified pinning the arm to that boundary like this:

        "The finding survives (the broad-source arm still fires) which is
         exactly why nothing caught this: what is lost is the sentence that says
         why. ... The one that remains here is display-only and must stay pinned
         to its boundary."

    Both halves were false, and the second one certified the live defect as
    correct. The predicate was not display-only: `_reasons` ran BEFORE
    `score_over_permissive` and `analyze` skipped any record it returned nothing
    for, so it gated SCORING. And the finding did not survive -- for any public
    source narrower than a /23 the broad-source arm needs E >= 0.5 and cannot
    fire either, so `allow 52.20.10.0/24 -> app-01 tcp/3389` (a partner's public
    /24, RDP, a prod host) was forced critical at severity 52 by the guardrail
    floor and then emitted by nobody. A mutation guard written to stop a
    regression had become the reason the fix would look like one.

    The rationale is now TRUE, because `analyze` scores first and emits any
    forced rule unconditionally: under the mutant the finding really does
    survive, and what is really lost is the sentence that says why. So the guard
    asserts the contradiction the old text described -- a finding forced critical
    BY the clause "admin/lateral-movement port exposed to the internet" whose
    human-readable reasons never mention the internet -- at the input where the
    proxy and the predicate actually disagree.

    Both spellings are checked. The /0 pins the boundary the old guard covered
    (it passes under the mutant, which is the point: it could never have caught
    this); the partner /24 is where the proxy is wrong, and it is the one that
    bites.
    """
    for ref, source, e_expected in (("MG-56-ZERO", "0.0.0.0/0", 1.0),
                                    ("MG-56-PUB24", _PARTNER_PUBLIC_24, 0.3)):
        records = [_rec(ref, source, "app-01", "tcp/3389",
                        dest_tags=("prod",), dest_cidrs=["10.90.4.4/32"])]
        entities = [_cidr_entity(source),
                    _entity("app-01", "algosec", ip="10.90.4.4", tags=("prod",))]
        findings = _analyze_over_permissive(records, entities)

        assert len(findings) == 1, (
            f"M56: {source} -> app-01 tcp/3389 produced {len(findings)} findings, "
            "expected exactly 1. The guardrail floor forces this critical, so the "
            "analyzer must report it whatever `_reasons` thinks.")
        finding = findings[0]
        assert finding.signals["severity_vector"]["E"] == e_expected, (
            f"M56: {source} scores E={finding.signals['severity_vector']['E']}, expected "
            f"{e_expected}. This guard needs one source ON the E == 1.0 boundary and one "
            "BELOW it; fix the fixture, not the assertion.")
        # The guardrail floor's own verdict, first -- if it stops firing for an
        # internet reason the guard is no longer positioned to catch anything.
        forced = " ".join(finding.signals["forced_reasons"])
        assert finding.forced_critical and "internet" in forced, (
            f"M56: {source} was not forced critical for an internet reason ({forced!r}), "
            "so the contradiction this guard exists to detect cannot arise. Fix the "
            "fixture, not the assertion.")
        # ...and then the prose, which is the same fact rendered for a human.
        assert _INTERNET_REASON in finding.signals["reasons"], (
            f"M56: {source} was forced critical for {forced!r} while its reasons "
            f"{finding.signals['reasons']!r} never say it is internet-facing. The floor "
            "and the prose are two renderings of one fact; a finding that contradicts "
            "its own floor is worse than one that is merely incomplete. `_reasons` is "
            "asking `E >= 1.0` again -- E == 1.0 is only a /0.")


def test_m56_a_public_source_is_reported_as_exposed_to_the_internet() -> None:
    _guard_m56()


def test_m56_guard_fails_under_the_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject M56 as re-targeted: the internet arm back on the `E >= 1.0` proxy."""
    monkeypatch.setattr(over_permissive, "_reasons", _mutant_reasons_m56)
    with pytest.raises(AssertionError, match=r"^M56"):
        _guard_m56()


def test_m56_the_shipped_defect_no_longer_hides_the_finding_entirely() -> None:
    """The A3 half, stated separately so the two failures cannot be confused.

    Under the mutant the finding must still EXIST -- that is what inverting
    `analyze`'s control flow bought, and it is what makes the guard above a test
    about prose rather than about existence. If this ever fails, the reason gate
    has been moved back in front of the scorer and a mutation to a display
    predicate can once again delete a forced-critical finding outright.
    """
    records = [_rec("MG-56-A3", _PARTNER_PUBLIC_24, "app-01", "tcp/3389",
                    dest_tags=("prod",), dest_cidrs=["10.90.4.4/32"])]
    entities = [_cidr_entity(_PARTNER_PUBLIC_24),
                _entity("app-01", "algosec", ip="10.90.4.4", tags=("prod",))]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(over_permissive, "_reasons", _mutant_reasons_m56)
        findings = _analyze_over_permissive(records, entities)
    assert len(findings) == 1 and findings[0].forced_critical, (
        "M56/A3: with the reason gate mutated, the forced-critical finding disappeared. "
        "`_reasons` is gating the scorer again instead of filtering behind it.")


# ==========================================================================
# M61 -- `sorted(rec.dest_tags)` -> `list(...)` makes a persisted signal
#        depend on the order a vendor happened to write its labels in.
# ==========================================================================


def _guard_m61() -> None:
    """The persisted `dest_tags` signal is canonical, not export-ordered.

    Determinism is the engine's selling point and `signals` is persisted whole
    (`persist.py` writes it to `findings.signals`) and rendered in the console.
    Two exports that describe the identical estate and differ only in the order
    they list one asset's labels must produce byte-identical findings; `list()`
    makes the row depend on JSON key order, which means a re-ingest of the same
    posture writes a different payload and no diff of two snapshots can be
    trusted.
    """
    findings = {}
    for name, tags in (("as-exported", ("pci", "crown-jewel", "customer-data")),
                       ("reordered", ("customer-data", "pci", "crown-jewel"))):
        records = [_rec("MG-61", "10.20.30.0/24", "db-prod-01", "tcp/3389", dest_tags=tags,
                        dest_cidrs=["10.50.0.10/32"])]
        entities = [_cidr_entity("10.20.30.0/24"),
                    _entity("db-prod-01", "algosec", ip="10.50.0.10", tags=tags)]
        (finding,) = _analyze_over_permissive(records, entities)
        findings[name] = finding.signals["dest_tags"]

    assert findings["as-exported"] == ["crown-jewel", "customer-data", "pci"], (
        f"M61: dest_tags persisted as {findings['as-exported']!r}, expected the sorted "
        "['crown-jewel', 'customer-data', 'pci'].")
    assert findings["as-exported"] == findings["reordered"], (
        f"M61: the same estate produced {findings['as-exported']!r} and "
        f"{findings['reordered']!r} because the export listed its labels in a different "
        "order. A persisted signal that carries the vendor's key order is not deterministic "
        "output, and two snapshots of one posture stop comparing equal.")


def test_m61_the_persisted_dest_tags_signal_is_sorted() -> None:
    _guard_m61()


def test_m61_guard_fails_under_the_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject the matrix's M61 by shadowing the module's `sorted`.

    `over_permissive` calls `sorted` exactly once -- on `rec.dest_tags` -- so
    binding the name to `list` in the module's globals is that single call
    becoming `list(rec.dest_tags)`, and nothing else in the module moves.
    """
    assert sum(1 for line in _over_permissive_source() if "sorted(" in line) == 1, (
        "M61: over_permissive.py no longer calls sorted() exactly once, so shadowing the "
        "name is no longer a faithful injection of this mutation. Re-target the mutant.")
    monkeypatch.setattr(over_permissive, "sorted", list, raising=False)
    with pytest.raises(AssertionError, match=r"^M61"):
        _guard_m61()


def _over_permissive_source() -> list[str]:
    """The analyzer's own source lines, for the injection-fidelity check above."""
    return inspect.getsource(over_permissive).splitlines()


# ==========================================================================
# The seeded demo pins the three of these that are visible in shipped output.
# ==========================================================================


@pytest.fixture(scope="module")
def demo():
    """The seeded demo snapshot -- the fixture the product actually ships."""
    return run_all.run()


def _demo_over_permissive(demo, needle: str):
    matches = [f for f in demo.findings if f.type == "over_permissive" and needle in f.title]
    assert matches, f"the seeded demo no longer contains an over_permissive finding for {needle!r}"
    return matches[0]


def test_m57_the_demo_still_calls_its_any_any_rule_an_any_any_rule(demo) -> None:
    """M57 on the shipped fixture: the reason vanishes from a finding that survives.

    The constructed guard above proves the whole finding can disappear; this pins
    the same arm on the estate the product demos, where the rule ALSO trips two
    other predicates and so loses only its most important sentence.
    """
    finding = _demo_over_permissive(demo, "any protocol/port open from")
    assert _ANY_ANY_REASON in finding.signals["reasons"], (
        f"M57: the demo's any/any rule reports {finding.signals['reasons']!r} and no longer "
        "says it allows every protocol and port.")


def test_m56_the_demo_still_says_its_internet_findings_are_internet_facing(demo) -> None:
    """M56 on the shipped fixture: every internet-sourced finding keeps its line.

    Selected by `is_internet_source` -- the predicate itself -- rather than by
    `E == 1.0`. Selecting on the proxy is how the old version of this pin agreed
    with the defect: it only ever looked at the findings for which the proxy was
    right, so a demo containing a public /24 would have sailed through it.
    """
    checked = 0
    for finding in demo.findings:
        if finding.type != "over_permissive":
            continue
        signals = finding.signals
        if not is_internet_source(signals.get("source", ""), signals.get("source_kind", ""),
                                  signals.get("source_cidrs") or []):
            continue
        checked += 1
        assert _INTERNET_REASON in signals["reasons"], (
            f"M56: demo finding {finding.title!r} is sourced from public address space "
            f"({signals.get('source')!r} -> {signals.get('source_cidrs')!r}) but reports "
            f"{signals['reasons']!r}, with no internet reason.")
    assert checked, ("M56: the demo no longer contains an over_permissive finding sourced "
                     "from the internet, so this pin is vacuous. Re-point it at a rule "
                     "that is.")


def test_m61_the_demo_persists_sorted_dest_tags(demo) -> None:
    """M61 on the shipped fixture: a multi-labelled destination comes out canonical.

    Only a finding with at least TWO tags can distinguish sorted from unsorted,
    so those are counted separately -- a demo that lost its multi-tag findings
    would otherwise leave this passing on nothing.
    """
    discriminating = 0
    for finding in demo.findings:
        tags = finding.signals.get("dest_tags")
        if tags is None:
            continue
        discriminating += len(tags) > 1
        assert tags == sorted(tags), (
            f"M61: demo finding {finding.title!r} persists dest_tags={tags!r}, which is not "
            "sorted -- the signal is carrying the source export's key order.")
    assert discriminating, ("M61: no demo finding carries more than one dest tag, so sorted "
                            "and unsorted are indistinguishable here and this pin is vacuous.")


# ==========================================================================
# M65 -- reported, not guarded.
# ==========================================================================


def test_m65_is_an_equivalent_mutant_and_cannot_be_guarded() -> None:
    """`shadowing._service_covers`'s `later.protocol == "any"` disjunct is dead.

    The matrix flagged it as a survivor; it is a PROVEN EQUIVALENT MUTANT, so no
    test can distinguish the two versions and writing one would be theatre. This
    test states the proof instead, so the claim is checked rather than asserted
    in a comment, and so the day the surrounding code changes and the disjunct
    stops being dead, somebody is told.

        if earlier.protocol == "any":            # (1) returns before line (2)
            return True
        if later.protocol == "any" or earlier.protocol != later.protocol:   # (2)
            return False

    Reaching (2) means `earlier.protocol != "any"`. So if `later.protocol ==
    "any"` then `earlier.protocol != later.protocol` is already True and the
    second disjunct returns False on its own; and if `later.protocol != "any"`
    the first disjunct is False and contributes nothing. The two forms agree on
    every input, exhaustively over the protocol vocabulary:
    """
    from src.analyzers.shadowing import _service_covers

    protocols = list(get_args(models.Protocol))

    def mutant(earlier: PolicyRecord, later: PolicyRecord) -> bool:
        """`_service_covers` with the dead disjunct removed."""
        from src.analyzers.shadowing import _intervals
        if earlier.protocol == "any":
            return True
        if earlier.protocol != later.protocol:      # M65: `later.protocol == "any" or` gone
            return False
        e_ivs, l_ivs = _intervals(earlier), _intervals(later)
        if e_ivs is None:
            return True
        if l_ivs is None:
            return earlier.service == later.service
        return all(any(elo <= llo and lhi <= ehi for elo, ehi in e_ivs) for llo, lhi in l_ivs)

    services = ("tcp/22", "tcp/1-65535", "tcp/80,443", "udp/53", "icmp", "any", "quic")
    checked = 0
    for e_proto in protocols:
        for l_proto in protocols:
            for e_svc in services:
                for l_svc in services:
                    earlier = _rec("E", "10.0.0.0/8", "d", e_svc, order=1).model_copy(
                        update={"protocol": e_proto})
                    later = _rec("L", "10.0.0.0/8", "d", l_svc, order=2).model_copy(
                        update={"protocol": l_proto})
                    assert _service_covers(earlier, later) == mutant(earlier, later), (
                        f"M65 is NOT equivalent after all: earlier={e_proto}/{e_svc} "
                        f"later={l_proto}/{l_svc} disagree. Write a real guard for it and "
                        "delete this test.")
                    checked += 1
    assert checked == len(protocols) ** 2 * len(services) ** 2


# ==========================================================================
# A cheap tripwire on the guards themselves.
# ==========================================================================


def test_every_mutation_in_the_matrix_has_a_guard_and_a_bites_test() -> None:
    """Ten mutations, ten guards, ten proofs that each guard bites.

    Cheap, and it is the one thing a reviewer of this file actually wants
    checked: that nobody deleted half a pair. M65 is excluded by construction --
    it is equivalent, and has a proof rather than a guard.
    """
    expected = {"M30", "M48", "M49", "M50", "M51", "M52", "M56", "M57", "M59", "M61"}
    here = set(globals())
    guarded = {name for name in expected if f"_guard_{name.lower()}" in here}
    bitten = {name for name in expected
              if f"test_{name.lower()}_guard_fails_under_the_mutation" in here}
    assert guarded == expected, f"missing guard bodies for {sorted(expected - guarded)}"
    assert bitten == expected, f"missing bites tests for {sorted(expected - bitten)}"
