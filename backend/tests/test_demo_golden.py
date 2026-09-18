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

THE CROSS-TOOL PATH RE-BASELINE (31 -> 35, snap_10eac3f23a5a -> snap_7aa6db6c2ddb)
---------------------------------------------------------------------------------
Phase 1 correctly deleted the demo's flagship `cross_tool_path`, because it was
not true: it pivoted through `internal-app`, a /16 ADDRESS RANGE, and it rested
on fusing `appsrv-07` with `app-server-07` on a bare shared IP with no namespace
on either side. Both deletions were right and BOTH RULES ARE STILL IN FORCE. The
finding is back because the FIXTURE changed, not because the engine did.

NO ENGINE PREDICATE WAS TOUCHED. `_valid_traversal`, `object_is_abstract`, the
`abstract` flag, `identity.resolve_identities`' four guards, the `(context, ip)`
union key and every severity function are byte-identical. The changes are three
data edits in `scripts/seed_demo.py`:

  (a) All three exports now declare `vpcId` on their cloud-resident nodes -- the
      namespace an RFC 1918 address is unique inside, which all three tools
      genuinely record for a cloud workload. `normalizers.common.scope_identifiers`
      already lifted this field and `identity.context_of` already read it back;
      no export carried one, so the scoped arm of the merge had never once been
      satisfiable. With it declared, `appsrv-07` and `app-server-07` fuse on
      MATCHING declared tenancy. Strip the field and the merge is withheld again
      as `unscoped_ip` -- pinned in both directions by
      `verify_engine._check_p5` and `test_reachability`.
  (b) A CONCRETE host inside the app segment: `internal-app-01` (10.40.0.5),
      which Guardicore observes (GC-002) and AlgoSec grants from (ALGO-029).
      This is the audit's option (b) -- "the path is rebuilt through the concrete
      hosts inside the range" -- supplied as data. The /16 `internal-app` is
      still abstract and `_valid_traversal` still refuses to pivot through it;
      the legacy chain still exists as edges and is still rejected, asserted.
  (c) ALGO-029 sits at order 29, BEFORE the broad ALGO-030, so it reads as the
      original least-privilege grant that ALGO-030 later widened.

Every one of the four new findings, and the one retitle:

  +1  `cross_tool_path` (severity 100, critical, FORCED) --
      `0.0.0.0/0 --wiz--> lb-public-01 --wiz--> app-server-07
       --guardicore--> internal-app-01 --algosec--> db-prod-01`.
      Three distinct source tools, four grants (WIZ-001, WIZ-002, GC-002,
      ALGO-029), and no abstract node except the internet endpoint. Scored by
      the ordinary `score_cross_tool_path` path -- nothing special-cased.

  +1  `cidr_overlap` ALGO-029 + ALGO-030 (severity 30, low). ALGO-029's source
      (10.40.0.5/32) lies inside ALGO-030's (10.40.0.0/16) and both grant
      tcp/5432 to db-prod-01. That IS a redundancy and the analyzer is right to
      say so; it is the direct consequence of keeping both the host rule and the
      segment rule, which is what makes ALGO-030's over-permissiveness legible.

  +1  `shadowed_rule` ALGO-001 + ALGO-029 (severity 10, low). The 16th of
      AlgoSec's 17 rules to fall under ALGO-001 (order 1, `0.0.0.0/0 ->
      10.0.0.0/8`, service any), on exactly the same terms as the other 14:
      same tool, lower order, source inside 0.0.0.0/0, destination inside
      10.0.0.0/8, service inside any.

  +1  `transport_exposure` ALGO-020 + WIZ-021 (severity 40, medium) --
      "app-server-07 is reachable on both tcp/443 and udp/443". This is the
      finding the Phase 1 entry above records LOSING to the withheld merge, with
      the note "forcing the merge restores exactly this finding and nothing
      else". The merge is back on evidence, so the finding is back, at the same
      severity and band it had before Phase 1.

  ~   `transport_exposure` WIZ-021 retitled "... to appsrv-07" -> "... to
      app-server-07" (severity 39 / medium / not forced, all unchanged). The
      exact reverse of the Phase 1 retitle, same mechanism: the canonical asset
      key is the name the most tools use, and that is `app-server-07` (AlgoSec +
      Guardicore) over `appsrv-07` (Wiz).

  ~   `over_permissive` is UNCHANGED at 5, and ALGO-030 keeps 70 / high /
      `source_cidrs == ["10.40.0.0/16"]` / E == 0.7. ALGO-029 does not join it:
      its source is a single host, E == 0.1, below `sensitive_dest_min_E` (0.3).
      P8 -- the audit's headline fix -- is therefore untouched by all of this.

  ~   records 27 -> 29 (ALGO-029, GC-002). resolved 20 -> 22 (the
      `internal-app-01` catalog row, once from each tool that names it). assets
      26 -> 26 (+internal-app-01, -appsrv-07 folding back into app-server-07).
      alias_map 26 -> 27. correlations 3 -> 4 (-1 manual_review, +1 context_ip,
      +1 hostname for internal-app-01). nodes 26 -> 26. edges 23 -> 25 (the two
      new grants; the Wiz edge into that host is RENAMED by the merge, not
      added). snapshot id follows the changed input, as it must.

  =   NOT CHANGED: every severity, band and forced_critical of all 31 findings
      that exist in both runs, `degraded_analyzers == []`, and both determinism
      checks (same-process full dump, and cross-process under PYTHONHASHSEED 0
      vs random).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import seed_topology  # noqa: E402

from src import estate  # noqa: E402
from src.graph.reachability import _valid_traversal

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
def _mock_dir_holds_the_demo_dataset():
    """Fail with the CAUSE, not with a hash mismatch.

    Every golden below is built from `backend/data/mock`, which is not a fixture
    -- it is the engine's live input, and `scenarios.write_scenario` overwrites
    it whenever an admin picks a different dataset in the console. Switch to
    "Partial onboarding" and leave it there, and this module reports
    `assert 'a1b2...' == 'c3d4...'`: a baselined snapshot id that moved, which
    reads as an engine regression and sends the reader into the analyzers.

    Compared byte-for-byte against a freshly built demo dataset rather than by
    counting files, because `clean` and `scale` write the same ten filenames
    with different contents.
    """
    import src.scenarios as scenarios          # local: costs nothing when unused
    expected = dict(scenarios._policy())
    expected.update(seed_topology.build_exports(estate.build()))
    wrong = sorted(
        name for name, doc in expected.items()
        if not (scenarios.MOCK_DIR / name).exists()
        or (scenarios.MOCK_DIR / name).read_text() != json.dumps(doc, indent=2) + "\n")
    missing = sorted(set(scenarios.INFRA) - set(expected))
    assert not wrong and not missing, (
        "backend/data/mock is not the demo dataset, so every golden in this "
        "module is being measured against the wrong estate.\n"
        f"  differs: {', '.join(wrong) or 'none'}\n"
        "  restore it with:  python -c \"import sys; sys.path.insert(0, 'scripts'); "
        "import src.scenarios as s; s.write_scenario('demo')\"\n"
        "If you MEANT to change the demo dataset, re-baseline per the module "
        "docstring -- do not silence this.")


@pytest.fixture(scope="module")
def verify(_mock_dir_holds_the_demo_dataset):
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
    # P5 grew from 15 checks to 19. The flagship carries TWO cross-tool paths now
    # (the retired `multi_path` scenario advertised two and reported one), so the
    # walk runs over both -- and three checks are genuinely new rather than
    # doubled: the two paths must share no grant, every cited grant must be the
    # SOLE grant for its hop, and the scope-strip counterfactual now asserts in
    # BOTH directions (path A dies without the declared tenancy, path B does not,
    # because its merges are hostname agreements).
    "P5 exactly two cross-tool paths are reported",
    "P5 path A (db-prod-01) is the expected internet -> LB -> app -> pivot -> PCI-db chain",
    "P5 path B (db-prod-02) is the expected internet -> LB -> app -> pivot -> PCI-db chain",
    "P5 every hop on both is a real edge in the graph",
    "P5 each hop is granted by the expected rule from the expected tool",
    "P5 no node on either is abstract -- every pivot is a concrete host",
    "P5 _valid_traversal accepts both",
    "P5 each traverses at least 3 distinct source tools",
    "P5 each reaches a regulated asset and is scored critical",
    "P5 the two paths share no grant, so cutting one leaves the other",
    "P5 cutting a cited grant cuts the ACCESS, not just the finding",
    "P5 the app-server-07/appsrv-07 merge happened on a SHARED DECLARED scope",
    "P5 ...so nothing is withheld for review any more",
    "P5 strip the declared scopes and the path that needs the merge DISAPPEARS",
    "P5 ...while the path built on hostname agreement survives it",
    "P5 the legacy chain through the /16 is still a real edge sequence",
    "P5 ...and _valid_traversal STILL rejects it (a /16 is never a pivot)",
    "P5 internal-app is still abstract (a /16 is an endpoint, never a pivot)",
    "P5 every grant of both chains still exists (data regression check)",
    "P6 QUIC blind spot present (internet)",
    "P6 QUIC blind spot forced_critical",
    "P6 QUIC decoded l7_app",
    "P7 TLS fallback-not-blocked present",
    # P9-P11: the three vendor consoles reach the finding table, every spelling
    # of the internet is one node, and the Fortinet shadowed deny is named.
    "P9 fortimanager contributes at least one finding",
    "P9 fortigate contributes at least one finding",
    "P9 junos_space contributes at least one finding",
    "P10 every spelling of the internet is one node",
    "P11 the FortiManager deny is reported as shadowed by the accept above it",
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

# The content hash of the seeded demo. Unlike the three Phase 1 moves (which were
# all fingerprint-widening and changed no finding), this one follows a real change
# to the INPUT: the three exports now declare the `vpcId` their cloud workloads
# live in, and AlgoSec/Guardicore carry a new concrete host plus the two rules
# that reach it. See "THE CROSS-TOOL PATH RE-BASELINE" in the module docstring.
# THE INFRASTRUCTURE RE-BASELINE (this change), in two steps.
#
#   snap_7aa6db6c2ddb -> snap_f95d00f824ab   the six infrastructure exports
#   snap_f95d00f824ab -> snap_830fc44e6089   Catalyst Center's IP pool endpoint
#
# The second step is a SECOND ingest of the same estate, not a second change to
# the engine. `/dna/intent/api/v1/global-pool` was added to the Catalyst
# projection because `vlan-names` returns ids and nothing else, so without it a
# VLAN had no subnet and no name -- and "which VLAN is this host in", which the
# inventory and the address drill-down both answer by containment, was empty for
# every row in the estate. The pool now supplies VLAN 30 = 10.30.0.0/16 =
# "app-tier", and 10.30.7.7 resolves into it.
#
# It is NOT back-formed from the SVI mask, which is the available shortcut and
# would place app-server-07 outside its own VLAN (the SVI reads 10.30.0.1/24
# while the VLAN carries a /16). `test_a_vlan_subnet_comes_from_the_pool_and_
# never_from_the_gateway_mask` pins that.
#
# In both steps: the snapshot id, and NOTHING ELSE.
#
# Diffed in full against the previous baseline, per the procedure at the top of
# this file. Every other assertion in this file passes UNCHANGED: 35 findings,
# the same 3/1/5/16/10 by type, the same 4/1/10/20 by band, 4 forced critical,
# the byte-identical per-finding table below, 26 graph nodes and 25 edges, 26
# assets, and the five-hop cross-tool path intact.
#
# THE CAUSE, attributed: `run_all._fingerprint` grew a sixth blob covering the
# infrastructure layer, and seven console exports are now present in data/mock,
# so the hash has more content to cover. It is not that the analysis changed --
# the seven topology normalizers emit ZERO PolicyRecords and zero
# ObservedEntities by construction, asserted at runtime in
# test_two_graphs_stay_separate.py and by grep in the verify pass.
#
# WHY THE ID SHOULD MOVE HERE rather than be excluded from the hash: the id keys
# every snapshot-scoped table, `devices`/`topology_links`/`vlans` among them. Two
# ingests differing only in topology sharing one id would mean the rows a reader
# gets back depend on which run wrote last. An id that does not cover the content
# it keys is not a content hash. An estate with NO infrastructure exports still
# produces the old id -- the sixth blob is appended only when non-empty, and
# `test_an_estate_with_no_topology_keeps_the_id_it_always_had` pins that.
# THE VLAN 45 STEP  (snap_5b671e7fc071 -> snap_173ab466881a)
#
# A THIRD ingest of the same estate, and the id and NOTHING ELSE moved: 38
# findings, the same 2/5/10/3/18 by type, the same 5/1/10/22 by band, 5 forced
# critical, the byte-identical per-finding table below, and every structural
# count unchanged. Re-run and diffed in full per the procedure at the top of this
# file before the number here was touched.
#
# THE CAUSE: `estate.py` gained VLAN 45 `data-svc` (10.45.0.0/24), so the
# infrastructure blob inside `run_all._fingerprint` has one more VLAN and three
# more SVIs in it. Path B's pivot `data-node-01` lives at 10.45.0.9, and without
# a VLAN containing that address the second cross-tool path's middle hop was a
# host floating in the endpoint lane with no subnet, no gateway and no access
# switch under it -- so "where does this finding live", which the Inventory and
# the address drill-down both answer by containment, had no answer for it. The
# two halves of a scenario have to be ONE estate; this is that rule applied to
# the path the flagship was just given.
#
# It cannot move a policy finding, and did not: the seven topology normalizers
# emit zero PolicyRecords and zero ObservedEntities by construction
# (test_two_graphs_stay_separate.py).
DEMO_SNAPSHOT_ID = "snap_fdabe95f9480"

# ---------------------------------------------------------------------------
# THE PATH-B RE-BASELINE, IN FULL  (35 -> 38)
#
# Cause: `scripts/seed_demo.py` gained planted problem 6 -- a SECOND cross-tool
# path to a second regulated database -- and re-sourced ALGO-030 to close an
# anti-cheat. No engine code changed. Measured by diffing the full per-finding
# table below, not the total. Every difference, and why the new value is the
# more correct one:
#
#   -1  cidr_overlap (ALGO-029, ALGO-030) 30/low. GONE, AND THAT IS THE POINT.
#       ALGO-030 used to source from `internal-app` (10.40.0.0/16), which
#       CONTAINS ALGO-029's source 10.40.0.5 -- so the two overlapped, and
#       ALGO-030 was a covering twin for the last hop of path A. The engine does
#       not model CIDR-membership expansion (docs/ENGINE.md 10.2), so "remove
#       ALGO-029" resolved the cross-tool finding while leaving the flow open
#       through ALGO-030. ALGO-030 now sources from `app-segment`
#       (10.30.0.0/16), which does not contain 10.40.0.5. Losing this overlap is
#       the anti-cheat landing: `verify_engine`'s "P5 cutting a cited grant cuts
#       the ACCESS, not just the finding" is the check that now passes because
#       of it.
#
#   -1/+1  transport_exposure (ALGO-070, ALGO-080) -> (ALGO-062, ALGO-070,
#       ALGO-080), 40/medium either way. Not a finding lost and another gained:
#       the SAME finding, with a third rule joining the group. ALGO-062 grants
#       the same service to the same destination, so it belongs in it.
#
#   +1  cidr_overlap (ALGO-062, ALGO-070) 10/low. ALGO-062 (10.30.0.0/16 ->
#       app-server-09, tcp/443) was added to keep a third overlap in the fixture
#       after the ALGO-029/ALGO-030 one correctly disappeared. 10/low rather
#       than the 30/low it replaces because app-server-09 carries no regulated
#       tag, where db-prod-01 does -- the score followed the destination, which
#       is what it is supposed to do. Aimed at a LEAF host that grants nothing
#       onward, so it opens no third path.
#
#   +1  cross_tool_path (ALGO-031, GC-030, WIZ-010, WIZ-011) 100/critical,
#       forced. PATH B. internet -> lb-public-02 -> app-server-08 ->
#       data-node-01 -> db-prod-02, three tools, four grants, every pivot a
#       concrete host, and DISJOINT from path A -- no shared hop and no shared
#       endpoint, asserted by `verify_engine`. Both of its middle grants are
#       sole grants by construction, so it carries no covering twin.
#
#   +2  shadowed_rule (ALGO-001, ALGO-031) and (ALGO-001, ALGO-062), 10/low
#       each. The two new AlgoSec rules fall under the order-1 "temporary broad
#       allow (TODO remove)" on exactly the same terms as the sixteen already
#       here: same tool, lower order, source inside 0.0.0.0/0, destination
#       inside 10.0.0.0/8, service inside any. A new AlgoSec rule that did NOT
#       produce one of these would be the anomaly.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# THE VENDOR-POLICY RE-BASELINE  (38 -> 47)
#
# Cause: FortiManager, FortiGate and Junos Space now emit PolicyRecords from
# their own rulebases (scripts/seed_demo.py planted problems 7-10, read by
# normalizers/vendor_policy.py). Before this, every policy record came from
# AlgoSec, Guardicore or Wiz, so nine onboarded consoles produced findings
# attributed to three. No engine code changed; no analyzer changed.
#
# NOTHING WAS LOST. The diff is +9 and -0: every pre-existing row is present
# with the same refs, severity, band and forced flag. That is the property worth
# checking first, because seven new records could have become covering twins and
# silently unmade an existing finding.
#
#   +1  over_permissive (fortimanager-01-1) 60/critical FORCED. `all` ->
#       MGMT-NET on tcp/22: SSH to the out-of-band management segment from the
#       internet, commented as temporary vendor access dated 2019. Forced by the
#       published guardrail floor -- an admin/lateral-movement port reachable
#       from 0.0.0.0/0.
#   +1  over_permissive (edge-inbound-10) 60/critical FORCED. The Junos edge
#       policy permits `any` -> DMZ-NET on a custom service object covering
#       tcp/1-65535. The RANGE is the point: it is not a named service, so the
#       rule does not say what it opens, and what it opens is every admin port.
#   +1  over_permissive (fortimanager-01-3) 23/low. INTERNAL-NETS -> DB-TIER on
#       any protocol. Low because the source is three /24s rather than the
#       internet; it is here for the shadowing pair below, not for its own score.
#   +1  shadowed_rule (fortimanager-01-3, fortimanager-01-4) 23/low, with
#       shadowed_action 'deny'. THE FINDING THIS INGEST EXISTS FOR: policy 4
#       denies DEV-NET -> DB-TIER, and DEV-NET is a MEMBER of the INTERNAL-NETS
#       group that policy 3 already accepts. Under first-match the deny can
#       never fire, so the intent an operator wrote down is the one not
#       enforced. Asserted by verify_engine P11.
#   +1  shadowed_rule (fortimanager-01-1, fortimanager-01-2) 10/low. Policy 2
#       grants USERS-NET -> MGMT-NET on tcp/22, which policy 1 already grants
#       from 0.0.0.0/0 on the same port. Dead config, correctly reported.
#   +1  cidr_overlap (fortimanager-01-1, fortimanager-01-2) 30/low. The same
#       pair seen by the redundancy analyzer rather than the ordering one:
#       10.60.0.0/24 sits inside 0.0.0.0/0 for one destination and service.
#   +1  transport_exposure (fw-perim-01-2) 57/critical FORCED. QUIC (udp/443)
#       from the internet to the DMZ, published beside the tcp/443 service as
#       "HTTP/3 edge acceleration". Encrypted end to end inside UDP, so the
#       inspection stack sees an opaque flow rather than the web traffic it is.
#   +1  transport_exposure (edge-inbound-10, fw-perim-01-1, fw-perim-01-2)
#       40/medium. THE FIRST NON-PATH FINDING WHOSE REFS SPAN TWO VENDORS'
#       CONSOLES: the DMZ edge is reachable on both tcp/443 and udp/443, and the
#       evidence is a Junos rule plus two FortiGate rules. Nothing in the
#       product could produce this before, because all policy came from one
#       vendor family.
#   +1  transport_exposure (fortimanager-01-3) 40/medium. The any-protocol grant
#       to the database tier reaches it on an uninspectable transport too.
#
# WHAT DID NOT MOVE, and each is asserted rather than assumed:
#   * cross_tool_path stays 2, with byte-identical chains. No new rule touches
#     db-prod-01, db-prod-02, internal-app-01, data-node-01, app-server-07 or
#     app-server-08 -- which is what keeps both paths and all four sole grants
#     intact (verify_engine P5).
#   * every spelling of the internet is still ONE node. FortiOS says `all` and
#     Junos says `any`; left uncollapsed the graph would hold three internets,
#     each its own path origin (verify_engine P10).
# ---------------------------------------------------------------------------
DEMO_FINDING_COUNT = 47

DEMO_BY_TYPE = {
    "cidr_overlap": 4,          # 3 + 1 (fortimanager-01-1/02)          # 3 - 1 (ALGO-029/030 stopped overlapping) + 1 (ALGO-062/070)
    "over_permissive": 8,       # 5 + 3 (fortimanager-01-1, -3, edge-inbound-10)
                                # now resolves to; ALGO-031's source is one host (E 0.1),
                                # below sensitive_dest_min_E 0.3, so it is not reported
    "shadowed_rule": 20,        # 18 + 2 (the Fortinet dead grant and the shadowed deny)
    "transport_exposure": 13,   # 10 + 3 (the QUIC pair, the cross-vendor row, the any-protocol grant)
    "cross_tool_path": 2,       # 1 + 1: path B
}

DEMO_BY_BAND = {
    "critical": 8,   # 5 + 3 (fortimanager-01-1, edge-inbound-10, fw-perim-01-2)   # 4 + 1 (path B, forced)
    "high": 1,       # unchanged (ALGO-030, still 70/high on its resolved /16)
    "medium": 12,    # 10 + 2 (the cross-vendor row and fortimanager-01-3)
    "low": 26,       # 22 + 4 (two shadowed, one overlap, one over-permissive)       # 20 - 1 (the ALGO-029/030 overlap) + 3 (ALGO-062/070 overlap
                     # and the two new shadowed rules)
}

DEMO_FORCED_CRITICAL = 8        # 4 + 1, same cause as the critical band

# The full per-finding table: (type, sorted raw_refs, severity, band, forced).
# This is what a re-baseline must be diffed against -- a total alone would hide a
# severity that moved while another moved the opposite way.
DEMO_FINDINGS = [
    ("cidr_overlap", ("ALGO-010", "ALGO-011"), 30, "low", False),
    # There is deliberately NO ("cidr_overlap", ("ALGO-029", "ALGO-030")) row any
    # more. It was the covering twin that made "remove ALGO-029" resolve the
    # cross-tool finding without closing the flow; ALGO-030 now sources from
    # app-segment, which does not contain 10.40.0.5. See the re-baseline note.
    ("cidr_overlap", ("ALGO-060", "ALGO-061"), 10, "low", False),
    # Its replacement, so the fixture keeps three overlaps. Aimed at a LEAF host
    # (app-server-09 grants nothing onward) so it opens no path, and 10/low
    # rather than 30/low because that destination carries no regulated tag.
    ("cidr_overlap", ("ALGO-062", "ALGO-070"), 10, "low", False),
    # THE DIFFERENTIATOR, back and REAL this time:
    #   0.0.0.0/0 --wiz--> lb-public-01 --wiz--> app-server-07
    #             --guardicore--> internal-app-01 --algosec--> db-prod-01
    # Three tools, four grants, every pivot a concrete host. It exists because
    # the fixtures now declare the `vpcId` that lets appsrv-07 and app-server-07
    # merge on evidence, and because the pivot is the host internal-app-01 rather
    # than the /16 internal-app -- NOT because any engine rule was relaxed.
    # `verify_engine._check_p5` walks it hop by hop and proves both dependencies.
    ("cross_tool_path", ("ALGO-029", "GC-002", "WIZ-001", "WIZ-002"), 100, "critical", True),
    # PATH B, and the reason the demo has a remediation QUEUE rather than a
    # single trick: 0.0.0.0/0 -> lb-public-02 -> app-server-08 -> data-node-01
    # -> db-prod-02. It shares no hop and no endpoint with path A, so cutting
    # one leaves the other standing -- asserted in `verify_engine._check_p5`,
    # which also proves neither cited grant has a broader twin.
    ("cross_tool_path", ("ALGO-031", "GC-030", "WIZ-010", "WIZ-011"), 100, "critical", True),
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
    # NEW: the 16th AlgoSec rule to fall under ALGO-001, on the same terms as the
    # other 14 -- same tool, lower order, source inside 0.0.0.0/0, destination
    # inside 10.0.0.0/8, service inside any.
    ("shadowed_rule", ("ALGO-001", "ALGO-029"), 10, "low", False),
    # ALGO-031 and ALGO-062, the two rules planted problem 6 added. They fall
    # under the order-1 broad allow on the same terms as every other AlgoSec
    # rule here; a new rule that did NOT produce one of these would be the
    # anomaly worth investigating.
    ("shadowed_rule", ("ALGO-001", "ALGO-031"), 10, "low", False),
    ("shadowed_rule", ("ALGO-001", "ALGO-062"), 10, "low", False),
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
    # RESTORED by the merge. app-server-07 is reachable on tcp/443 (ALGO-020,
    # AlgoSec) and udp/443 (WIZ-021, Wiz); the pair can only land on ONE
    # destination once the two tools' names for that host are one asset. Phase 1
    # recorded losing exactly this finding to the withheld merge ("forcing the
    # merge restores exactly this finding and nothing else") -- and it is back.
    ("transport_exposure", ("ALGO-020", "WIZ-021"), 40, "medium", False),
    ("transport_exposure", ("ALGO-060", "ALGO-061", "ALGO-082", "WIZ-011"), 40, "medium", False),
    # ALGO-062 joined this group: same destination, same service, so it is the
    # same finding with a third rule in it rather than a new one.
    ("transport_exposure", ("ALGO-062", "ALGO-070", "ALGO-080"), 40, "medium", False),

    # ── The vendor consoles' own policy (planted problems 7-10) ────────────
    # Nine rows, and the reason each is here is in the re-baseline note above.
    # Grouped at the end rather than interleaved so the AlgoSec/Guardicore/Wiz
    # table above stays byte-comparable against the previous baseline.
    ("cidr_overlap", ("fortimanager-01-1", "fortimanager-01-2"), 30, "low", False),
    ("over_permissive", ("edge-inbound-10",), 60, "critical", True),
    ("over_permissive", ("fortimanager-01-1",), 60, "critical", True),
    ("over_permissive", ("fortimanager-01-3",), 23, "low", False),
    ("shadowed_rule", ("fortimanager-01-1", "fortimanager-01-2"), 10, "low", False),
    # THE SHADOWED DENY. `fortimanager-01-4` denies DEV-NET -> DB-TIER, and
    # DEV-NET is a member of the INTERNAL-NETS group that `-3` already accepts,
    # so the deny can never fire. verify_engine P11 asserts the shadower.
    ("shadowed_rule", ("fortimanager-01-3", "fortimanager-01-4"), 23, "low", False),
    # THE CROSS-VENDOR ROW: a Junos rule and two FortiGate rules, one finding.
    ("transport_exposure", ("edge-inbound-10", "fw-perim-01-1", "fw-perim-01-2"), 40, "medium", False),
    ("transport_exposure", ("fortimanager-01-3",), 40, "medium", False),
    ("transport_exposure", ("fw-perim-01-2",), 57, "critical", True),
    ("transport_exposure", ("ALGO-080",), 78, "critical", True),
    ("transport_exposure", ("ALGO-082",), 54, "medium", False),
    ("transport_exposure", ("GC-020",), 34, "low", False),
    ("transport_exposure", ("WIZ-001", "WIZ-020"), 40, "medium", False),
    ("transport_exposure", ("WIZ-020",), 57, "medium", False),
    # Retitled back "to appsrv-07" -> "to app-server-07" (the canonical key is the
    # name two tools use); the numbers are unchanged, as they were in Phase 1.
    ("transport_exposure", ("WIZ-021",), 39, "medium", False),
]

# Structural counts. Every move below is path B's three new rules and two new
# objects arriving -- no rule and no dereference was LOST, which is the thing
# these numbers exist to catch.
DEMO_RECORD_COUNT = 39      # 32 + 7: 4 FortiManager, 2 FortiGate, 1 Junos Space      # 29 + 3: ALGO-031, ALGO-062, GC-030
DEMO_RESOLVED_COUNT = 33    # 25 + 8: one audit row per vendor catalog object    # 22 + 3: db-prod-02 (algosec) and data-node-01, once
                            # from each of the two tools that name it
DEMO_ASSET_COUNT = 34       # 28 + 6: the five FortiOS address objects and the group       # 26 + 2: data-node-01 and db-prod-02. ALGO-062's source
                            # is written as a raw 10.30.0.0/16, which is the address
                            # space `app-segment` already denotes, so it adds no node
DEMO_ALIAS_COUNT = 35       # tracks the asset count       # tracks the asset count
DEMO_CORRELATION_COUNT = 5  # 4 + 1: a `hostname` row for data-node-01, which AlgoSec
                            # and Guardicore name identically. Path B needs NO
                            # context_ip merge -- that asymmetry with path A is
                            # asserted by verify_engine's scope-strip counterfactual
DEMO_NODE_COUNT = 34        # tracks the asset count        # tracks the asset count
DEMO_EDGE_COUNT = 32        # 28 + 4: MGMT-NET x2, DB-TIER, DMZ-NET (the internet
                            # spellings collapse, so the three internet-sourced
                            # vendor rules add edges from ONE node, not three)        # 25 + 3: app-server-08->data-node-01 (GC-030),
                            # data-node-01->db-prod-02 (ALGO-031) and
                            # 10.30.0.0/16->app-server-09 (ALGO-062). Note what is
                            # NOT here: internal-app->db-prod-01 is GONE, because
                            # ALGO-030 was re-sourced -- and app-segment->db-prod-01
                            # takes its place, so the count nets out level


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


#: The two chains, the grants that make each hop, and which kind of identity
#: evidence each one rests on. Kept here rather than inlined so the asymmetry is
#: readable at a glance: A needs a SCOPED merge (Wiz calls the host `appsrv-07`),
#: B needs only that three tools spell the same hostname the same way.
DEMO_PATHS = [
    (["0.0.0.0/0", "lb-public-01", "app-server-07", "internal-app-01", "db-prod-01"],
     [("wiz", "WIZ-001"), ("wiz", "WIZ-002"),
      ("guardicore", "GC-002"), ("algosec", "ALGO-029")]),
    (["0.0.0.0/0", "lb-public-02", "app-server-08", "data-node-01", "db-prod-02"],
     [("wiz", "WIZ-010"), ("wiz", "WIZ-011"),
      ("guardicore", "GC-030"), ("algosec", "ALGO-031")]),
]


def test_both_cross_tool_paths_are_real(demo):
    """Called out on its own because these are the single most consequential
    entries in the table: the product's differentiator, and the findings a reader
    of a green suite should be able to check without trusting a count.

    So this does not assert the findings EXIST -- it walks them. Every hop is a
    real edge, no pivot is abstract, and each spans three tools. A path the
    engine merely prints is not evidence of anything.
    """
    paths = [f for f in demo.findings if f.type == "cross_tool_path"]
    assert len(paths) == 2
    by_chain = {tuple(f.signals["path"]): f for f in paths}
    assert sorted(by_chain) == sorted(tuple(chain) for chain, _hops in DEMO_PATHS)

    g = demo.graph
    for chain, hops in DEMO_PATHS:
        f = by_chain[tuple(chain)]
        assert all(g.has_edge(a, b) for a, b in zip(chain, chain[1:])), chain
        # No pivot may be a range. The endpoints may be (the internet is one).
        assert [g.nodes[n]["kind"] for n in chain[1:-1]] == ["concrete"] * 3, chain
        assert _valid_traversal(g, chain), chain
        assert sorted(f.signals["tools"]) == ["algosec", "guardicore", "wiz"], chain
        assert [(h["tool"], h["ref"]) for h in f.signals["hops"]] == hops, chain

    # ...and the rule that deleted the OLD path is untouched: `internal-app` is
    # still a /16, still abstract, and still refused as a pivot. It is refused on
    # the chain that still exists, too -- ALGO-030 was re-sourced, so the old last
    # hop `internal-app -> db-prod-01` is gone, and what remains is a complete
    # internet-to-PCI chain in which EVERY pivot is a range.
    assert g.nodes["internal-app"]["kind"] == "abstract"
    legacy = ["0.0.0.0/0", "10.0.0.0/8", "app-segment", "db-prod-01"]
    assert all(g.has_edge(a, b) for a, b in zip(legacy, legacy[1:]))
    assert not _valid_traversal(g, legacy)


def test_the_two_paths_are_disjoint_so_cutting_one_leaves_the_other(demo):
    """Two entries are only worth two entries if they are genuinely separate.

    The retired `multi_path` scenario is the cautionary tale: it advertised two
    paths and reported one, because its second pivot was a /16 that
    `_valid_traversal` correctly refused, and nothing asserted otherwise. If a
    future fixture edit let these two share a grant or a terminal, "you cut the
    first one and the second is still there" -- the beat the pair exists for --
    would quietly stop being true.
    """
    paths = [f for f in demo.findings if f.type == "cross_tool_path"]
    grants = [{h["ref"] for h in f.signals["hops"]} for f in paths]
    assert not grants[0] & grants[1]
    assert len({tuple(f.signals["path"])[-1] for f in paths}) == 2


def test_no_cited_grant_has_a_broader_twin_that_keeps_the_access_open(demo):
    """The anti-cheat, asserted where a reader of this file will find it.

    `advisory/remediation` proposes "remove <rule>" and the gate re-simulates --
    but the engine does not model CIDR-membership expansion (docs/ENGINE.md
    10.2), so a rule granting `10.40.0.0/16 -> db-prod-01` covers a rule granting
    `10.40.0.5 -> db-prod-01` without the engine knowing. Both of path A's inner
    hops used to have exactly such a twin (GC-001 on 8443, ALGO-030 from the
    /16), so the demo's own remediation beat would have deleted the FINDING and
    left the FLOW -- on the one screen whose entire pitch is that it does not.

    Cut each cited grant out of the record set and re-derive the graph: the hop's
    edge has to go with it. `verify_engine` runs the same check; it is repeated
    here because it is the one a re-baseline is most likely to break silently.
    """
    from src.graph.build import build_graph

    cosmetic = []
    for f in (p for p in demo.findings if p.type == "cross_tool_path"):
        # The two INNER hops: the ones a fix would target. The internet ingress
        # is deliberately excluded -- WIZ-001 has a udp/443 twin (WIZ-020) and
        # that is a real alternative grant the engine reports on its own, not an
        # expansion it cannot see.
        for hop in f.signals["hops"][2:]:
            kept = [r for r in demo.records if r.raw_ref != hop["ref"]]
            if build_graph(kept, demo.assets, demo.alias_map).has_edge(hop["src"], hop["dst"]):
                cosmetic.append((hop["ref"], hop["src"], hop["dst"]))
    assert not cosmetic, (
        "removing these rules would resolve the finding and leave the access: "
        f"{cosmetic}")


def test_structural_counts(demo):
    assert len(demo.records) == DEMO_RECORD_COUNT
    assert len(demo.resolved) == DEMO_RESOLVED_COUNT
    assert len(demo.assets) == DEMO_ASSET_COUNT
    assert len(demo.alias_map) == DEMO_ALIAS_COUNT
    assert len(demo.correlations) == DEMO_CORRELATION_COUNT
    assert demo.graph.number_of_nodes() == DEMO_NODE_COUNT
    assert demo.graph.number_of_edges() == DEMO_EDGE_COUNT


def test_the_merge_happened_on_declared_tenancy_and_nothing_is_withheld(demo):
    """The identity decision is a user-visible output, not an internal detail.

    Phase 1 pinned the WITHHELD state ("1 merge withheld pending review") because
    the fixtures declared no namespace and the `(context, ip)` union key could
    never be satisfied. The fixtures declare one now, so the merge happens -- and
    what is pinned is that it happened FOR THE RIGHT REASON: a `context_ip` row
    whose evidence names the address AND the scope it was keyed on. A merge that
    reappeared with a null context would mean the fail-safe had been weakened,
    and would fail here.
    """
    merged = [c for c in demo.correlations if c.match_key == "context_ip"]
    assert len(merged) == 1
    assert merged[0].asset_key == "app-server-07"
    assert merged[0].confidence == 0.95
    assert merged[0].evidence["ip"] == "10.30.7.7"
    assert merged[0].evidence["context"] == "vpc-0a7d3e91c4b28f56"   # NOT None
    assert sorted(merged[0].evidence["names"]) == ["app-server-07", "appsrv-07"]

    # Nothing is ambiguous any more, so nothing is queued for a human.
    assert [c for c in demo.correlations if c.match_key == "manual_review"] == []
