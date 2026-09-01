"""Properties that must hold for ANY input, not values pinned to one fixture.

Why this file exists
--------------------
`backend/scripts/verify_engine.py` is a *golden* check: it asserts that five
deliberately planted problems in one 27-rule file are still found. The audit's
verdict on it (PROD-READINESS-AUDIT, "verify_engine.py is an existence-check
golden test on ONE hardcoded dataset") is that it "says nothing about
correctness on a customer's export, which is the only question a buyer cares
about" -- there was no `0 <= severity <= 100`, no `forced_critical implies band
== critical`, no "every hop in a reported path is a real edge", no "every
raw_ref resolves to a record", and only the `low` band was ever asserted, so
`band_critical` could be moved from 80 to 95 with everything still green.

Every check here is universally quantified over the findings of *whatever*
snapshot it is handed, so it keeps its meaning when the demo fixture is swapped
for a client export.

Two fixtures, deliberately differently shaped
---------------------------------------------
`eng` is the seeded demo. `synth` is a second estate built in this module and
injected by monkeypatching `run_all.normalize_all`, so the whole pipeline
(identity -> graph -> five analyzers -> scoring -> snapshot id) executes over
data the demo does not contain: an IPv6 source network, a full-range
`tcp/1-65535` grant from the internet, a comma port list, a named object that
dereferences to PUBLIC address space, a deny, a broad any/any rule at the top of
the rulebase, and -- crucially -- a cross-tool chain whose intermediate hops are
all CONCRETE hosts.

That last point is why the synthetic estate is not a luxury. Phase 1 marked
range-denoting objects abstract (the audit's option (a) at
`reachability.py:47`), which correctly deleted the seeded demo's only
`cross_tool_path` finding: its 5-hop chain pivoted through `internal-app`, a
/16 that `_valid_traversal`'s own docstring says it rejects. With the demo
alone, `path_trace.analyze`, `score_cross_tool_path` and `describe_path` would
now have ZERO executed coverage in the whole suite. The synthetic estate keeps
them under test on a chain that is honest -- every pivot is a host that can
really originate traffic.

`synthetic_estate()` is public because `test_agents.py` imports it for the same
reason: the remediation agent's `cross_tool_path` branch lost its fixture too.
"""

from __future__ import annotations

import pytest

from src.analyzers import run_all
from src.analyzers.severity import band, severity_from_vector
from src.config import PORT_CLASS_P, SENSITIVE_TAGS, SEVERITY_CONFIG, TRANSPORT_CONFIG
from src.normalizers.common import (
    NormalizeResult, ObservedEntity, parse_service, record_from_service,
)

# --------------------------------------------------------------------------
# The synthetic estate
# --------------------------------------------------------------------------

# Every hop of the synthetic cross-tool chain, in order. Named here so a test
# can assert the chain is REPORTED and, independently, that every hop is a real
# edge whose intermediate nodes are concrete.
SYNTH_CHAIN = ["0.0.0.0/0", "edge-proxy", "mid-tier", "vault-db"]


def _entity(name, tool, *, kind="identity", ip=None, cidr=None, tags=(),
            identifiers=None, abstract=False) -> ObservedEntity:
    return ObservedEntity(name=name, kind=kind, tool=tool, ip=ip, cidr=cidr,
                          tags=list(tags), identifiers=dict(identifiers or {}),
                          abstract=abstract)


def synthetic_estate() -> NormalizeResult:
    """A small three-tool estate with shapes the seeded demo does not contain.

    Deliberate properties, each covering a Phase 1 exit criterion or an analyzer
    branch the demo no longer reaches:

    * `0.0.0.0/0 -> edge-proxy -> mid-tier -> vault-db` spans three tools and
      pivots only through CONCRETE hosts, so `_valid_traversal` accepts it and
      `path_trace` emits a real `cross_tool_path` finding.
    * `SYN-A02` is `0.0.0.0/0 -> open-box tcp/1-65535`: range-aware port scoring
      and the admin-port guardrail must fire on a RANGE, not just on a literal
      `tcp/3389`.
    * `SYN-A03` sources from a PUBLIC IPv6 /32, so a mixed v4/v6 record set has
      to complete `run()` without `cidr_overlap` or `shadowing` raising across
      families -- and the v4 any/any rule at the top must NOT be reported as
      shadowing it, because a v4 /0 covers no v6 address.
    * `partner-net` is a NAMED object resolving to public `141.101.0.0/16` --
      "carry the resolved value, not the label", in the direction where getting
      it wrong under-reports. Its service is a comma list (`tcp/22,3389`), which
      the scalar `(port, port_end)` pair structurally cannot hold, so 3389 only
      reaches the guardrail through `DecodedService.ports`.
    * `edge-proxy` is a concrete host holding a globally-routable address. It
      must classify DMZ, not internet: a host that FACES the internet is not the
      internet (`graph/zones.py`, judgement call A).
    * `SYN-A05` is a deny, `SYN-A06` is the broad any/any rule at order 5 that
      makes everything after it dead, and `SYN-A07`/`SYN-A08` are nested-source
      duplicates so `cidr_overlap` has something to find.

    Every list is built in a fixed order and no set reaches the output, so the
    estate is as deterministic as the real normalizers.
    """
    entities = [
        # The internet, exactly as the normalizers emit it for a raw CIDR token.
        _entity("0.0.0.0/0", "algosec", kind="cidr", cidr="0.0.0.0/0", abstract=True),
        # Three concrete hosts forming the cross-tool chain. `edge-proxy` holds a
        # PUBLIC address and is tagged dmz -- both halves matter (see above).
        _entity("edge-proxy", "wiz", ip="45.33.32.10", tags=["dmz", "prod"],
                identifiers={"cloud": "aws", "type": "ec2"}),
        _entity("mid-tier", "guardicore", ip="10.90.1.5", tags=["prod"],
                identifiers={"role": "app", "env": "prod"}),
        _entity("vault-db", "algosec", ip="10.90.9.9",
                tags=["pci", "crown-jewel", "prod"]),
        # Two more concrete hosts for the non-chain rules.
        _entity("open-box", "algosec", ip="10.90.2.2", tags=["prod"]),
        _entity("v6-web", "algosec", ip="2606:4700::10", tags=["prod"]),
        # A named object whose catalog value is PUBLIC address space holding
        # more than one address -- the case `is_internet_source` must catch and
        # `exposure_score` must not score as a single host.
        _entity("partner-net", "algosec", cidr="141.101.0.0/16",
                tags=["partner"], abstract=True),
        # A named object denoting the internal /16 -- abstract, so it can be a
        # path ENDPOINT but never a pivot.
        _entity("internal-net", "algosec", cidr="10.90.0.0/16", tags=["prod"],
                abstract=True),
        # The public v6 network the v6 rule sources from.
        _entity("2606:4700::/32", "algosec", kind="cidr", cidr="2606:4700::/32",
                abstract=True),
    ]

    def rec(record_id, tool, ref, src, dst, service, *, action="allow", order=None,
            dest_tags=(), source_cidrs=None, dest_cidrs=None):
        return record_from_service(
            record_id=record_id, source_tool=tool, raw_ref=ref, source=src,
            destination=dst, svc=parse_service(service), action=action, order=order,
            dest_tags=list(dest_tags), source_cidrs=source_cidrs, dest_cidrs=dest_cidrs,
        )

    records = [
        # --- the cross-tool chain, one hop per tool -----------------------
        rec("s1", "wiz", "SYN-W01", "0.0.0.0/0", "edge-proxy", "tcp/443",
            dest_tags=["dmz", "prod"], dest_cidrs=["45.33.32.10/32"]),
        rec("s2", "guardicore", "SYN-G01", "edge-proxy", "mid-tier", "tcp/443",
            dest_tags=["prod"], source_cidrs=["45.33.32.10/32"],
            dest_cidrs=["10.90.1.5/32"]),
        rec("s3", "algosec", "SYN-A01", "mid-tier", "vault-db", "tcp/5432", order=10,
            dest_tags=["pci", "crown-jewel", "prod"], source_cidrs=["10.90.1.5/32"],
            dest_cidrs=["10.90.9.9/32"]),
        # --- range-aware scoring + the admin-port guardrail on a RANGE -----
        rec("s4", "algosec", "SYN-A02", "0.0.0.0/0", "open-box", "tcp/1-65535", order=20,
            dest_tags=["prod"], dest_cidrs=["10.90.2.2/32"]),
        # --- IPv6 must not raise anywhere in the pipeline ------------------
        rec("s5", "algosec", "SYN-A03", "2606:4700::/32", "v6-web", "tcp/443", order=30,
            dest_tags=["prod"], dest_cidrs=["2606:4700::10/128"]),
        # --- a named object resolving to PUBLIC space, plus a comma list ---
        rec("s6", "algosec", "SYN-A04", "partner-net", "mid-tier", "tcp/22,3389", order=40,
            dest_tags=["prod"], source_cidrs=["141.101.0.0/16"],
            dest_cidrs=["10.90.1.5/32"]),
        # --- a deny (build_graph must not turn it into an edge) ------------
        rec("s7", "algosec", "SYN-A05", "0.0.0.0/0", "vault-db", "tcp/5432",
            action="deny", order=50, dest_tags=["pci", "crown-jewel", "prod"],
            dest_cidrs=["10.90.9.9/32"]),
        # --- tcp/443 + udp/443 to one dest: tls_fallback_not_blocked -------
        rec("s8", "guardicore", "SYN-G02", "edge-proxy", "mid-tier", "udp/443",
            dest_tags=["prod"], source_cidrs=["45.33.32.10/32"],
            dest_cidrs=["10.90.1.5/32"]),
        # --- the broad allow at the top of the rulebase (order 5) ----------
        rec("s9", "algosec", "SYN-A06", "0.0.0.0/0", "internal-net", "any", order=5,
            dest_tags=["prod"], dest_cidrs=["10.90.0.0/16"]),
        # --- nested sources, same destination + service: cidr_overlap ------
        rec("s10", "algosec", "SYN-A07", "10.90.0.0/16", "open-box", "tcp/8443", order=60,
            dest_tags=["prod"], dest_cidrs=["10.90.2.2/32"]),
        rec("s11", "algosec", "SYN-A08", "10.90.1.0/24", "open-box", "tcp/8443", order=70,
            dest_tags=["prod"], dest_cidrs=["10.90.2.2/32"]),
    ]
    return NormalizeResult(records=records, entities=entities, resolved=[])


@pytest.fixture(scope="module")
def eng():
    """The seeded demo snapshot."""
    return run_all.run()


@pytest.fixture(scope="module")
def synth():
    """The synthetic estate, run through the identical entrypoint.

    `pytest.MonkeyPatch.context()` rather than the `monkeypatch` fixture because
    this fixture is module-scoped; the patch is undone before any test body
    runs, so nothing else in the session sees a patched `normalize_all`.
    """
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(run_all, "normalize_all", synthetic_estate)
        return run_all.run(label="synthetic")


@pytest.fixture(params=["eng", "synth"])
def snapshot(request):
    """Both fixtures, so every invariant below is asserted on two shapes."""
    return request.getfixturevalue(request.param)


# --------------------------------------------------------------------------
# The fixtures themselves are worth pinning: an invariant asserted over an
# empty finding list is vacuously true.
# --------------------------------------------------------------------------

def test_both_fixtures_produce_findings(eng, synth):
    assert eng.findings, "the seeded demo must produce findings"
    assert synth.findings, "the synthetic estate must produce findings"


def test_neither_fixture_degrades_an_analyzer(eng, synth):
    """A degraded analyzer means an entire finding class is MISSING.

    `run_all` isolates each analyzer so one bad rule cannot abort the snapshot,
    which is correct -- but it also means a crash now shows up as quietly fewer
    findings. Empty is the only clean state, and both fixtures must be clean or
    every invariant below is being asserted over a truncated list.
    """
    assert eng.degraded_analyzers == []
    assert synth.degraded_analyzers == []


def test_synthetic_estate_exercises_all_five_detectors(synth):
    """All five `FindingType` detectors emit on the synthetic estate.

    The seeded demo can no longer produce a `cross_tool_path` (see the module
    docstring), so without this fixture one of the five would be untested.
    """
    assert {f.type for f in synth.findings} == {
        "over_permissive", "cidr_overlap", "shadowed_rule",
        "cross_tool_path", "transport_exposure",
    }


def test_synthetic_estate_covers_cross_tool_paths(synth):
    """The chain the demo can no longer supply: three tools, concrete pivots."""
    paths = [f for f in synth.findings if f.type == "cross_tool_path"]
    assert len(paths) == 1
    f = paths[0]
    assert f.signals["path"] == SYNTH_CHAIN
    assert len(f.signals["tools"]) == 3
    assert f.signals["reaches_sensitive"] is True
    assert f.forced_critical is True          # public entry + regulated terminal
    assert f.severity_band == "critical"


def test_a_concrete_host_with_a_public_address_is_dmz_not_internet(synth):
    """`edge-proxy` holds 45.33.32.10, a globally-routable address.

    It is a host that FACES the internet, which `config.ZONE_TAGS` puts in the
    DMZ. Classifying it as the internet would inflate every `dmz->internal` hop
    (B = 1.25) into `internet->internal` (B = 1.5) on paths that never touch the
    internet. Pinned here because the mirror-image error -- a /0 classified as
    internal -- is what Phase 1 fixed, and over-correcting is the obvious way to
    get it wrong next.
    """
    assert synth.graph.nodes["edge-proxy"]["zone"] == "dmz"
    assert synth.graph.nodes["0.0.0.0/0"]["zone"] == "internet"


def test_synthetic_estate_completes_with_mixed_address_families(synth):
    """A v4/v6 mixed record set must analyze without raising.

    Phase 1 exit criterion. `cidr_overlap` and `shadowing` compare networks, and
    CPython's `subnet_of` RAISES across families rather than returning False, so
    one v6 rule used to 500 every route until the process restarted. The
    assertions are that the run completed clean AND that the v6 record survived,
    so this cannot pass by the record having been dropped.
    """
    assert synth.degraded_analyzers == []
    v6 = next(r for r in synth.records if r.raw_ref == "SYN-A03")
    assert v6.source_cidrs == ["2606:4700::/32"]
    assert v6.dest_cidrs == ["2606:4700::10/128"]


def test_a_v4_wildcard_does_not_shadow_a_v6_rule(synth):
    """`SYN-A06` is `0.0.0.0/0 -> 10.90.0.0/16 any` at order 5 and shadows most
    of the AlgoSec rulebase. It must NOT shadow the v6 rule: a v4 /0 contains no
    v6 address, and "covers" across families is the exact comparison that used
    to raise rather than answer False."""
    shadowed = {f.signals["shadowed_ref"] for f in synth.findings
                if f.type == "shadowed_rule"}
    assert "SYN-A02" in shadowed, "the v4 rules after the broad allow are dead"
    assert "SYN-A03" not in shadowed, "a v4 /0 cannot cover a v6 source"


def test_synthetic_full_range_from_the_internet_is_forced_critical(synth):
    """`0.0.0.0/0 -> host tcp/1-65535` must be forced critical.

    Phase 1 exit criterion, and the cleanest statement of the range bug: scored
    from its FIRST port this rule was P = 0.5 "unknown/ephemeral" and produced no
    finding at all, while the identical grant written `tcp/3389` was forced
    critical at 90. The clause it trips is the published clause 2 (an
    admin/lateral-movement port exposed to the internet), reached by interval
    INTERSECTION rather than `port in ...`.
    """
    f = next(x for x in synth.findings
             if x.type == "over_permissive" and x.raw_refs == ["SYN-A02"])
    assert f.forced_critical is True
    assert f.severity_band == "critical"
    assert any("admin/lateral-movement" in r for r in f.signals["forced_reasons"])
    assert f.signals["port_class"] == "any-port"      # span > PORT_SPAN_ANY


def test_synthetic_named_object_resolving_to_public_space_scores_as_public(synth):
    """`partner-net` is a LABEL; its address space is a public /16.

    The audit's headline defect ran the other way -- a named object
    short-circuited to E_IDENTITY (0.1, the score of a single host) whatever it
    dereferenced to -- so this pins that the resolved value, not the label, is
    what gets scored. The service is a comma list, which only reaches the score
    through `DecodedService.ports`.
    """
    f = next(x for x in synth.findings
             if x.type == "over_permissive" and x.raw_refs == ["SYN-A04"])
    assert f.signals["source_cidrs"] == ["141.101.0.0/16"]
    assert f.signals["severity_vector"]["E"] > 0.1
    assert f.signals["exposed_ports"] == [[22, 22], [3389, 3389]]
    assert f.forced_critical is True          # 3389 reachable from public space


def test_a_deny_creates_no_graph_edge(synth):
    """`SYN-A05` denies 0.0.0.0/0 -> vault-db and must not become an allow edge.

    Deny PRECEDENCE is a disclosed simplification (ENGINE.md 10.1) -- a deny does
    not subtract an allow. What must never happen is the opposite: a deny row
    silently ADDING reachability. Pinned so the day deny handling changes, it
    changes on purpose.
    """
    assert not synth.graph.has_edge("0.0.0.0/0", "vault-db")


# --------------------------------------------------------------------------
# The invariants. Each is asserted over both fixtures.
# --------------------------------------------------------------------------

def test_severity_is_in_range(snapshot):
    """0 <= severity <= 100 for every finding."""
    for f in snapshot.findings:
        assert 0 <= f.severity <= 100, f"{f.id} scored {f.severity}"


def test_forced_critical_implies_the_critical_band(snapshot):
    """The guardrail floor exists to make a finding unmissable; a forced finding
    that is not banded critical would be filtered out of the very list it was
    escalated onto."""
    for f in snapshot.findings:
        if f.forced_critical:
            assert f.severity_band == "critical", f"{f.id} forced but {f.severity_band}"


def test_band_agrees_with_the_published_table(snapshot):
    """`severity_band` is `band(severity)` unless the floor overrode it.

    This is what the audit says no check exercised: `verify_engine` only ever
    asserted the `low` band, so `band_critical` could be moved from 80 to 95 and
    everything stayed green.
    """
    for f in snapshot.findings:
        expected = "critical" if f.forced_critical else band(f.severity)
        assert f.severity_band == expected, (
            f"{f.id}: severity {f.severity} forced={f.forced_critical} "
            f"-> banded {f.severity_band}, table says {expected}")


def test_band_thresholds_are_the_published_ones(snapshot):
    """...and the table itself is the one ENGINE.md publishes, checked at every
    boundary. Without this, the test above would happily agree with a `band()`
    that had drifted."""
    c = SEVERITY_CONFIG
    assert (c["band_critical"], c["band_high"], c["band_medium"]) == (80, 60, 35)
    for value, expected in ((0, "low"), (34, "low"), (35, "medium"), (59, "medium"),
                            (60, "high"), (79, "high"), (80, "critical"), (100, "critical")):
        assert band(value) == expected


def test_every_raw_ref_resolves_to_a_real_record(snapshot):
    """A finding cites rule refs an operator is expected to go and edit."""
    known = {r.raw_ref for r in snapshot.records}
    for f in snapshot.findings:
        assert f.raw_refs, f"{f.id} cites no rule"
        for ref in f.raw_refs:
            assert ref in known, f"{f.id} cites unknown rule {ref}"


def test_every_source_tool_is_a_tool_that_supplied_a_cited_rule(snapshot):
    """`source_tools` is what the UI renders as provenance chips."""
    tool_of = {r.raw_ref: r.source_tool for r in snapshot.records}
    for f in snapshot.findings:
        cited = {tool_of[ref] for ref in f.raw_refs}
        assert set(f.source_tools) <= cited, f"{f.id} claims tools it did not cite"


def test_every_involved_node_exists_in_the_graph(snapshot):
    """`involved` drives the map highlight and the agent's node lookups."""
    for f in snapshot.findings:
        for node in f.involved:
            assert node in snapshot.graph, f"{f.id} involves absent node {node}"


def test_every_hop_of_every_reported_path_is_a_real_edge(snapshot):
    """A reported path must be a path.

    The strongest anti-hallucination invariant in the file: a security tool that
    prints a chain the graph does not contain is worse than one that prints
    nothing. It also asserts the traversal rule the chain claims to obey -- no
    intermediate hop may be abstract -- so a future "expand the subnet" change
    cannot quietly reintroduce a pivot through a /16.
    """
    g = snapshot.graph
    for f in snapshot.findings:
        path = f.signals.get("path")
        if not path:
            continue
        for u, v in zip(path, path[1:]):
            assert g.has_edge(u, v), f"{f.id} claims hop {u}->{v}, which is not an edge"
        for hop in path[1:-1]:
            assert g.nodes[hop].get("kind") == "concrete", (
                f"{f.id} pivots through abstract node {hop}")


def test_every_reported_hop_cites_a_grant_that_exists_on_that_edge(snapshot):
    """`hops[i]['ref']` must name a rule that really grants that hop."""
    g = snapshot.graph
    for f in snapshot.findings:
        for hop in f.signals.get("hops") or []:
            data = g[hop["src"]][hop["dst"]]
            assert hop["ref"] in {gr["ref"] for gr in data["grants"]}


def test_finding_ids_are_unique(snapshot):
    """Findings are keyed by id in the DB and in the console's react lists."""
    ids = [f.id for f in snapshot.findings]
    assert len(ids) == len(set(ids))


def test_findings_are_in_the_published_sort_order(snapshot):
    """forced first, then severity desc, then band, type, id -- the order
    `run_all.run` documents and the console renders without re-sorting."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    keys = [(0 if f.forced_critical else 1, -f.severity, order[f.severity_band], f.type, f.id)
            for f in snapshot.findings]
    assert keys == sorted(keys)


# --------------------------------------------------------------------------
# Client auditability: the vector on the finding recomputes to its own severity
# --------------------------------------------------------------------------

def _sensitive(tags) -> bool:
    return bool(set(tags or []) & SENSITIVE_TAGS)


def test_every_severity_vector_recomputes_to_its_own_severity(snapshot):
    """Take the `severity_vector` off any finding, feed it back through the
    published formula, and get that finding's severity back.

    This is the property the whole "defensible math" story rests on: a client
    can audit any number the product prints without access to the source. It is
    asserted per type because three detectors add a PUBLISHED constant on top of
    the smooth score, and that constant is part of the recomputation:

      over_permissive / cross_tool_path / shadowed deny
                                 severity == severity_from_vector(E, P, D, B)
      transport quic_blind_spot  + TRANSPORT_CONFIG['blind_spot_bump'], capped at 100
      transport tls_fallback     a fixed base + a sensitive-destination bump
      shadowed allow             a fixed base; vector deliberately empty
      cidr_overlap               hygiene: a fixed base + one bump; vector empty

    A detector that started inventing a number outside these tables fails here
    even though its severity is still inside 0..100 and correctly banded.
    """
    tc, sc = TRANSPORT_CONFIG, SEVERITY_CONFIG
    for f in snapshot.findings:
        vec = f.signals.get("severity_vector")
        assert vec is not None, f"{f.id} carries no severity_vector"
        sub = f.signals.get("subtype")

        if f.type == "cidr_overlap":
            assert vec == {}, f"{f.id}: overlap is hygiene and publishes no vector"
            assert f.severity in (sc["overlap_base"],
                                  sc["overlap_base"] + sc["overlap_sensitive_bump"])
            continue

        if f.type == "shadowed_rule" and f.signals["shadowed_action"] == "allow":
            assert vec == {}
            assert f.severity == sc["shadowed_allow_base"]
            continue

        if f.type == "transport_exposure" and sub == "tls_fallback_not_blocked":
            bump = tc["fallback_sensitive_bump"] if _sensitive(f.signals["dest_tags"]) else 0
            assert f.severity == tc["fallback_base"] + bump
            continue

        # Everything below publishes the full four-term vector.
        assert sorted(vec) == ["B", "D", "E", "P"], f"{f.id}: vector is {sorted(vec)}"
        recomputed = severity_from_vector(vec["E"], vec["P"], vec["D"], vec["B"])
        if f.type == "transport_exposure":          # quic_blind_spot
            recomputed = min(recomputed + tc["blind_spot_bump"], 100)
        assert f.severity == recomputed, (
            f"{f.id} ({f.type}/{sub}) prints severity {f.severity} but its own "
            f"vector {vec} recomputes to {recomputed}")


def test_every_scored_finding_publishes_a_known_port_class(snapshot):
    """`port_class` names WHICH class of access the rule grants. Until Phase 1
    the label table was keyed by the P VALUE -- and `P_ANY_PORT == P_ADMIN ==
    1.0`, so the any-port row was overwritten at import time and every any/any
    finding shipped a class naming ports the rule does not mention."""
    publishers = {"over_permissive", "transport_exposure", "cross_tool_path"}
    for f in snapshot.findings:
        if f.type not in publishers:
            # cidr_overlap and shadowed_rule score without a port class on
            # purpose: the first is hygiene (no vector at all) and the second is
            # scored on the traffic the DENY failed to block, where the class of
            # the port is not part of the story the finding tells.
            assert "port_class" not in f.signals
            continue
        assert f.signals["port_class"] in PORT_CLASS_P, (
            f"{f.id}: unknown port class {f.signals.get('port_class')!r}")
