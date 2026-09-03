"""The seeded demo's golden output, pinned, attributed, and run by CI.

`backend/scripts/verify_engine.py` has always been the demo regression gate, but
it lived outside pytest -- so CI ran it as a separate shell step and a developer
running `pytest` saw nothing. This module runs every one of its checks, and adds
the thing the script deliberately does not carry: the exact COUNTS.

Why the counts live here and not in the script
-----------------------------------------------
`docs/ENGINE.md` 6.5 tells readers that `verify_engine.py` "asserts the
*properties* (which findings must exist, and which must be forced) rather than a
total -- which is why it survives a change like this one". That is a deliberate
division of labour, and it stays true: the script is the property gate, this
module is the golden. A golden that nobody can explain is how a security tool
starts under-reporting, so every number below carries the reason it is that
number.

HOW TO RE-BASELINE (read before changing a number here)
--------------------------------------------------------
1. Run the engine and diff the FULL output against the values in this file --
   not just the total. `DEMO_FINDINGS` is the per-finding table.
2. For every difference, name the code change that caused it and satisfy
   yourself the new value is more correct than the old one.
3. Write that reason into the comment beside the number you are changing.
4. If you cannot attribute a difference, it is a regression. Do not baseline it.

THE PHASE 1 RE-BASELINE, IN FULL
---------------------------------
Pre-Phase-1 the demo produced `snap_d065e3248774` and 17 findings. It now
produces `snap_e013ae7930ae` and 30. Measured as a controlled A/B: a pristine
`git archive HEAD` tree (Phase 0 applied, Phase 1 not) versus the working tree,
same fixture, same interpreter. Every difference and its cause:

  -1  `cross_tool_path` (severity 100, critical, forced) --
      `0.0.0.0/0 -> lb-public-01 -> app-server-07 -> internal-app -> db-prod-01`.
      TWO independent causes, both verified separately. (a) `internal-app` is an
      AlgoSec `network` object holding 10.40.0.0/16 and is now correctly
      `abstract`, so `_valid_traversal` refuses to pivot through it -- the audit
      filed the old behaviour as a BLOCKER and said fixing it this way "will
      delete the current money-shot until (b) [CIDR-membership expansion]
      lands". (b) Wiz's `appsrv-07` and AlgoSec's `app-server-07` are no longer
      unioned on an unscoped shared IP. Forcing the merge back does NOT restore
      the path (asserted in `verify_engine._check_p5`), so (a) alone is
      sufficient. `path_trace` coverage moved to the synthetic estate in
      `test_engine_invariants.py`.

  -1  `transport_exposure` ALGO-020 + WIZ-021 (severity 40, medium) --
      "app-server-07 is reachable on both tcp/443 and udp/443". The tcp grant is
      AlgoSec's (to `app-server-07`), the udp grant is Wiz's (to `appsrv-07`);
      the pair only ever landed on one destination because the two names were
      fused on a bare shared IP. Verified: forcing the merge restores exactly
      this finding and nothing else.

  +1  `over_permissive` ALGO-030 (severity 70, HIGH, not forced) -- "PostgreSQL
      open from internal-app to db-prod-01". THE AUDIT'S HEADLINE DEFECT, FIXED.
      `exposure_score` used to short-circuit to E_IDENTITY (0.1, the score of a
      single host) whenever `source_kind == "identity"`; it now reads the
      resolved `source_cidrs`, sees 10.40.0.0/16, and scores E = 0.7. That
      crosses `OVERPERMISSIVE_CONFIG["sensitive_dest_min_E"]` (0.3), so a /16
      segment reaching the PCI database is finally reported. This is also the
      first `high` band the demo has ever produced.

  +14 `shadowed_rule` dead-allow findings (severity 10, low). Shadowing now
      compares RESOLVED address space and port INTERVALS instead of destination
      NAMES and exact service STRINGS, so it can finally see that ALGO-001
      (order 1: `0.0.0.0/0 -> 10.0.0.0/8`, service any, comment "temporary broad
      allow (TODO remove)") subsumes every later AlgoSec rule whose destination
      resolves inside 10/8. Each one is independently checkable: same tool, lower
      order, source inside 0.0.0.0/0, destination inside 10.0.0.0/8, service
      inside any -- in a first-match rulebase they cannot fire. 15 of AlgoSec's
      16 rules are shadowed; the 16th is ALGO-001 itself.

  ~   `shadowed_rule` ALGO-021 (the dead deny) is re-attributed: `shadowing_ref`
      ALGO-020 -> ALGO-001, `raw_refs` likewise. Severity 19 / low is unchanged.
      ALGO-001 is the EARLIER covering allow (order 1 vs 20), so this is more
      correct under first-match, and the analyzer keeps the earliest shadower.

  ~   `transport_exposure` WIZ-021 retitled "... to app-server-07" -> "... to
      appsrv-07" (severity 39 / medium / not forced, all unchanged). Same
      withheld merge: the Wiz-named node is no longer aliased onto the AlgoSec
      name.

  ~   `over_permissive` ALGO-001's `port_class` "admin / lateral-movement" ->
      "any-port". `PORT_CLASS_LABEL` was keyed by the P VALUE and
      `P_ANY_PORT == P_ADMIN == 1.0`, so the any-port row was overwritten at
      import time and every any/any finding in the product shipped a port class
      naming ports the rule does not mention. Severity, band and forced_critical
      are unchanged.

  ~   Additive evidence fields on many findings: `source_cidrs`, `dest_cidrs`,
      `exposed_ports`, `exposed_port_end`, `source_cidrs_a`/`_b`. New keys only;
      no existing value changed.

  ~   assets 25 -> 26 and graph nodes 25 -> 26 (`app-server-07` and `appsrv-07`
      are now two assets). `app-segment` and `internal-app` flip concrete ->
      abstract. `alias_map` keeps its 26 entries; `appsrv-07` now maps to itself
      instead of to `app-server-07`. Correlations 4 -> 3, which is three separate
      moves that happen to net to -1: the 0.95-confidence `context_ip` row for
      app-server-07/appsrv-07 is gone (that union no longer happens), one
      0.0-confidence `manual_review` row takes its place, and the `hostname` row
      for `internal-app` is gone because `identity.resolve_identities` has always
      skipped merge-audit rows for abstract nodes ("don't emit identity-merge
      audits for internet/subnet nodes") and `internal-app` is now one.

  ~   snapshot id `snap_d065e3248774` -> `snap_8a921b3f9ffe` -> `snap_9931d1cec28a`
      -> `snap_e013ae7930ae`. Three moves, all of them the SAME mechanism -- the
      content hash widening -- and none of them a change in what the engine
      found. The finding table below is byte-identical across all three.

      FIRST (`d065e3248774` -> `8a921b3f9ffe`). `_fingerprint` used to hash seven
      fields of each rule row and nothing else -- it omitted dest_tags, ports,
      protocol, the entire entity/object catalog, the merge set and the
      applied-changes overlay, so retagging one asset as `pci` flipped a rule from
      no finding to forced-critical while the system of record insisted it was the
      same snapshot. A new id was guaranteed by that widening alone, before any
      behaviour change.

      SECOND (`8a921b3f9ffe` -> `9931d1cec28a`). `ObservedEntity` gained a `cidrs`
      field -- the full address space a node denotes -- and `run_all._ENTITY_FIELDS`
      is the list `test_analyzers.py::test_fingerprint_covers_every_entity_field`
      forces every entity field into. The field had to exist because an address
      GROUP ({0.0.0.0/0, 10.0.0.0/8}) resolves to several blocks and the single
      `ObservedEntity.cidr` could hold only one, so the group's asset came out with
      `ip_set == []`, `zones.zone_of` called it ZONE_INTERNAL, and the boundary
      multiplier collapsed 1.5 -> 1.0: the SAME grant scored 86/critical written
      `0.0.0.0/0` and 57/medium written as the group that resolves to it. The
      demo's AlgoSec catalog contains no multi-member group object (see
      `scripts/seed_demo.py`), so that defect is structurally invisible to the
      demo; it is pinned instead by
      `test_analyzers.py::test_the_four_encodings_of_one_policy_score_identically`.

      THIRD (`9931d1cec28a` -> `snap_e013ae7930ae`). The widened id was still not
      INJECTIVE: three edits to the demo export changed the engine's persisted
      output without changing its id, and one of them changed two severities.
      `run_all._value` joined list members with "," while fields are joined with
      \x1f, so `db-prod-01`'s tags written `['customer-data,pci','prod']`
      fingerprinted byte-identically to `['pci','customer-data','prod']` -- and
      `pci` is no longer a MEMBER, so ALGO-030 dropped 70/high -> 47/medium and
      ALGO-002 100 -> 90 under this exact snapshot id and the same F_ ids. Every
      field now encodes as JSON, which escapes both separators. The other two
      were holes rather than collisions: `normalizers/algosec.py` emits a
      `ResolvedObject` for every catalog entry but an `ObservedEntity` only for
      objects a rule REFERENCES, and an object `type` reaches the entity only via
      `abstract`, which `object_is_abstract` already sets True by width for any
      multi-address value -- so an unreferenced object's CIDR/type/tags, and any
      multi-address object's declared type, were persisted and rendered while
      being outside the id. `nr.resolved` is now a fifth blob (`_RESOLVED_FIELDS`).
      Pinned by `test_snapshot_fingerprint.py`, which drives every one of these
      through the real normalizer rather than through a stubbed NormalizeResult.

      NOTHING ELSE MOVED, at any of the three. Verified each time by re-baselining
      the id alone and re-running this whole module: `test_the_full_finding_table`,
      both count tables, the forced-critical total and every structural count below
      passed untouched, and `verify_engine.py` reported ALL CHECKS PASSED with 30
      findings. Only the id and the F_ ids derived from it (`det_id("F", sid, ...)`)
      differ.

  =   NOT CHANGED, and worth saying: 27 canonical records, 20 resolved-object
      audit rows, 23 graph edges, and every severity, band and forced_critical
      value of every finding that exists in both runs.
"""

from __future__ import annotations

import importlib.util
from collections import Counter
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_engine.py"


def _load_verify_engine():
    """Import the standalone script by path.

    `backend/scripts` is not a package (the scripts are run as programs, and
    `pyproject.toml` puts only `backend/` on the path), so this is loaded by
    file location rather than by name. Deliberately NOT copied into this module:
    `make verify` / `python tasks.py verify` / the CI step all run the script,
    and a second copy of the checks would be free to drift from the one those
    three actually execute.
    """
    spec = importlib.util.spec_from_file_location("verify_engine", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def verify():
    return _load_verify_engine()


@pytest.fixture(scope="module")
def verified(verify):
    """(checks, EngineResult) from one run of the script's own check set."""
    return verify.checks()


# --------------------------------------------------------------------------
# 1. Everything `verify_engine.py` asserts, now also under pytest
# --------------------------------------------------------------------------

def test_every_verify_engine_check_passes(verified):
    checks, _result = verified
    failed = [f"{c.name}" + (f" ({c.detail})" if c.detail else "") for c in checks if not c.ok]
    assert not failed, "verify_engine checks failed:\n  " + "\n  ".join(failed)


# The names, pinned. Without this a check could be deleted (the easiest possible
# way to make a golden green) and `test_every_verify_engine_check_passes` would
# happily keep passing over the smaller set.
EXPECTED_CHECKS = [
    "P1 any/any present",
    "P1 forced_critical",
    "P1 port_class names the grant, not a port it never mentions",
    "P2 RDP->PCI present",
    "P2 forced_critical",
    "P3 overlap present + low",
    "P4 shadowed-deny present + low",
    "P4 the shadower is the broad rule at the top of the rulebase",
    "P5 no cross-tool path is reported (the only chain pivots through a /16)",
    "P5 every grant of the 5-hop chain still exists (data regression check)",
    "P5 internal-app is abstract (a /16 is an endpoint, never a pivot)",
    "P5 the withheld app-server-07/appsrv-07 merge is recorded, not silent",
    "P5 with the merge forced, the chain is a real edge sequence",
    "P5 ...and _valid_traversal still rejects it (the /16 pivot, not the merge)",
    "P5 ...so no cross-tool path returns from the merge alone",
    "P6 QUIC blind spot present (internet)",
    "P6 QUIC blind spot forced_critical",
    "P6 QUIC decoded l7_app",
    "P7 TLS fallback-not-blocked present",
    "P8 named object resolving to a /16 reaching the PCI database is reported",
    "P8 the resolved address space is what was scored, not the label",
    "L7 decode: declared App-ID resolved to QUIC transport",
    "every finding has a severity_vector",
    "no analyzer degraded (a degraded run is missing a whole finding class)",
    "determinism (byte-identical re-run, all fields)",
    "determinism (cross-process, PYTHONHASHSEED 0 vs random)",
    "cross-process dump agrees with the in-process snapshot id",
]


def test_no_verify_engine_check_was_quietly_removed(verified):
    checks, _result = verified
    assert [c.name for c in checks] == EXPECTED_CHECKS


def test_the_standalone_script_still_exits_zero(verify, capsys):
    """`make verify`, `python tasks.py verify` and the CI step all invoke
    `main()`; its exit code is the contract they read."""
    assert verify.main() == 0
    assert "ALL CHECKS PASSED" in capsys.readouterr().out


# --------------------------------------------------------------------------
# 2. The golden itself
# --------------------------------------------------------------------------

# The content hash of the seeded demo. See the module docstring for why it moved
# (three times: the Phase 1 fingerprint widening, then `ObservedEntity.cidrs`
# joining it, then the fingerprint becoming injective -- JSON field encoding plus
# the resolved-catalog blob). No finding, count, band or structural number below
# moved with any of them.
DEMO_SNAPSHOT_ID = "snap_10eac3f23a5a"

# 17 before Phase 1. -1 cross_tool_path, -1 transport_exposure, +1 over_permissive,
# +14 shadowed_rule. Every one of the four is attributed in the module docstring.
# Then +1 transport_exposure (round-2 audit quick win 3: the any-protocol filter
# was excluding ALGO-001, a rule in the shipped fixture) -> 31.
DEMO_FINDING_COUNT = 31

DEMO_BY_TYPE = {
    "cidr_overlap": 2,          # unchanged
    "over_permissive": 5,       # 4 + ALGO-030 (resolved-CIDR exposure scoring)
    "shadowed_rule": 15,        # 1 + 14 (containment shadowing sees ALGO-001)
    "transport_exposure": 9,    # 9 - 1 (withheld merge) + 1 (ALGO-001, any-protocol filter dropped)
    # "cross_tool_path": 0      # 1 -> 0 (the /16 pivot is no longer a pivot)
}

DEMO_BY_BAND = {
    "critical": 3,   # 4 - 1 (the cross-tool path was the fourth)
    "high": 1,       # 0 + 1 (ALGO-030 -- the demo's first-ever high)
    "medium": 9,     # 9 - 1 (withheld-merge pair) + 1 (ALGO-001 transport_exposure)
    "low": 18,       # 4 + 14 (the dead-allow findings)
}

DEMO_FORCED_CRITICAL = 3        # 4 - 1, same cause as the critical band

# The full per-finding table: (type, sorted raw_refs, severity, band, forced).
# This is what a re-baseline must be diffed against -- a total alone would hide a
# severity that moved while another moved the opposite way.
DEMO_FINDINGS = [
    ("cidr_overlap", ("ALGO-010", "ALGO-011"), 30, "low", False),
    ("cidr_overlap", ("ALGO-060", "ALGO-061"), 10, "low", False),
    ("over_permissive", ("ALGO-001",), 60, "critical", True),
    ("over_permissive", ("ALGO-002",), 100, "critical", True),
    # NEW: the audit's headline blocker, fixed. E went 0.1 -> 0.7.
    ("over_permissive", ("ALGO-030",), 70, "high", False),
    ("over_permissive", ("ALGO-046",), 49, "medium", False),
    ("over_permissive", ("ALGO-050",), 56, "medium", False),
    # 14 NEW dead-allow findings + the pre-existing dead deny, all now attributed
    # to ALGO-001, the "temporary broad allow (TODO remove)" at order 1.
    ("shadowed_rule", ("ALGO-001", "ALGO-002"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-010"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-011"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-020"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-021"), 19, "low", False),   # the dead deny
    ("shadowed_rule", ("ALGO-001", "ALGO-030"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-046"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-050"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-060"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-061"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-070"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-071"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-072"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-080"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-082"), 10, "low", False),
    # NEW (round-2 audit, quick win 3): transport_exposure.py filtered on
    # `r.port is not None`, which excluded every any-protocol rule -- including
    # ALGO-001, which ships in data/mock/algosec_export.json itself. `_opens`
    # already handled protocol == "any", so the filter was removing the widest
    # grant in the fixture from the analyzer whose docs claimed to cover it.
    ("transport_exposure", ("ALGO-001",), 40, "medium", False),
    ("transport_exposure", ("ALGO-060", "ALGO-061", "ALGO-082", "WIZ-011"), 40, "medium", False),
    ("transport_exposure", ("ALGO-070", "ALGO-080"), 40, "medium", False),
    ("transport_exposure", ("ALGO-080",), 78, "critical", True),
    ("transport_exposure", ("ALGO-082",), 54, "medium", False),
    ("transport_exposure", ("GC-020",), 34, "low", False),
    ("transport_exposure", ("WIZ-001", "WIZ-020"), 40, "medium", False),
    ("transport_exposure", ("WIZ-020",), 57, "medium", False),
    # Retitled "to app-server-07" -> "to appsrv-07"; the numbers are unchanged.
    ("transport_exposure", ("WIZ-021",), 39, "medium", False),
]

# Structural counts. records / resolved / edges are UNCHANGED by Phase 1, which
# is itself the point: no rule and no dereference was lost, only how they score.
DEMO_RECORD_COUNT = 27
DEMO_RESOLVED_COUNT = 20
DEMO_ASSET_COUNT = 26       # 25 + 1: app-server-07 and appsrv-07 are two assets
DEMO_ALIAS_COUNT = 26       # unchanged in size; appsrv-07 now maps to itself
DEMO_CORRELATION_COUNT = 3  # 4 - 1: one context_ip row became one manual_review row
DEMO_NODE_COUNT = 26        # tracks the asset count
DEMO_EDGE_COUNT = 23        # unchanged


@pytest.fixture(scope="module")
def demo(verified):
    _checks, result = verified
    return result


def test_snapshot_id_is_the_baselined_one(demo):
    """The id governance rows hang off. It moved once, on purpose (see the module
    docstring); it must not move again without an explanation beside it."""
    assert demo.snapshot_id == DEMO_SNAPSHOT_ID


def test_finding_count(demo):
    assert len(demo.findings) == DEMO_FINDING_COUNT


def test_findings_by_type(demo):
    assert dict(Counter(f.type for f in demo.findings)) == DEMO_BY_TYPE


def test_findings_by_band(demo):
    assert dict(Counter(f.severity_band for f in demo.findings)) == DEMO_BY_BAND


def test_forced_critical_count(demo):
    assert sum(1 for f in demo.findings if f.forced_critical) == DEMO_FORCED_CRITICAL


def test_the_full_finding_table(demo):
    """Every finding's type, cited rules, severity, band and forced flag.

    The check the audit says was missing: `verify_engine` asserted the existence
    of six findings and the `low` band twice, so `band_critical` could be moved
    from 80 to 95 and every score could shift, with everything still green.
    """
    actual = sorted((f.type, tuple(sorted(f.raw_refs)), f.severity,
                     f.severity_band, f.forced_critical) for f in demo.findings)
    assert actual == sorted(DEMO_FINDINGS)


def test_no_cross_tool_path_and_the_reason_is_recorded(demo):
    """Called out on its own because it is the single most consequential change
    in the re-baseline: the product's differentiator produces nothing on the
    shipped demo, and anyone reading a green suite deserves to trip over that
    fact rather than infer it from a count."""
    assert [f for f in demo.findings if f.type == "cross_tool_path"] == []
    assert demo.graph.nodes["internal-app"]["kind"] == "abstract"


def test_structural_counts(demo):
    assert len(demo.records) == DEMO_RECORD_COUNT
    assert len(demo.resolved) == DEMO_RESOLVED_COUNT
    assert len(demo.assets) == DEMO_ASSET_COUNT
    assert len(demo.alias_map) == DEMO_ALIAS_COUNT
    assert len(demo.correlations) == DEMO_CORRELATION_COUNT
    assert demo.graph.number_of_nodes() == DEMO_NODE_COUNT
    assert demo.graph.number_of_edges() == DEMO_EDGE_COUNT


def test_the_withheld_merge_is_the_only_manual_review_row(demo):
    """The withheld merge is a user-visible output of this phase ("1 merge
    withheld pending review"), not an internal detail -- so it is pinned."""
    rows = [c for c in demo.correlations if c.match_key == "manual_review"]
    assert len(rows) == 1
    assert rows[0].asset_key == "app-server-07"
    assert rows[0].confidence == 0.0
    assert rows[0].evidence["reason"] == "unscoped_ip"
    assert sorted(rows[0].evidence["names"]) == ["app-server-07", "appsrv-07"]
