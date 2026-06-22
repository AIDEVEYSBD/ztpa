# Core Engine — Logic, Calculations & Math

This document describes the **deterministic engine**: every fact and number the
ZeroTrust Policy Advisor computes, how it computes them, and the exact formulas
and calibration constants involved.

> **The one governing rule.** The deterministic engine owns *all facts and math*
> (normalization, identity resolution, CIDR/subnet math, reachability, shadowing,
> effective policy, severity, change-delta). The AI/agent layer owns only
> *language and judgment* (explaining, ranking, classifying, drafting). The model
> never computes reachability or subnet math — it calls deterministic tools and
> reasons over their structured results.

Everything here is **reproducible**: identical inputs → byte-identical snapshot
id, findings, scores, and ordering. No randomness, no timestamps, no model.

Source map (all paths under `backend/src/`):

| Concern | File |
|---|---|
| Calibration knobs + categorical lookups | `config.py` |
| Identity resolution (union-find) | `identity.py` |
| Graph construction | `graph/build.py` |
| Zones + boundary multipliers | `graph/zones.py` |
| Reachability + path tracing | `graph/reachability.py` |
| Severity model | `analyzers/severity.py` |
| The 4 analyzers | `analyzers/{over_permissive,cidr_overlap,shadowing,path_trace}.py` |
| Change simulation + delta | `change/simulate.py` |
| Deterministic ids | `ids.py` |
| Orchestration | `analyzers/run_all.py` |

---

## 1. Pipeline

`run_all.run()` executes five ordered, deterministic stages:

```
normalize → resolve identities → build graph → analyze (4 detectors) → score + sort
```

1. **Normalize** — each tool's raw export (AlgoSec, Guardicore, Wiz) is adapted
   into a common `PolicyRecord` set + `ObservedEntity` set. Source connectors are
   simulated; the canonical model they produce is real.
2. **Resolve identities** — merge each tool's view of a host into one canonical
   asset (§2).
3. **Build graph** — a directed policy graph of allowed connections (§3).
4. **Analyze** — four independent detectors emit `Finding`s (§5).
5. **Score + finalize** — assign deterministic ids, sort by a fixed key.

The snapshot id is a content hash of the normalized records, so the same inputs
always yield the same `snap_…` id (§7).

Findings are sorted by a **stable total order** (`run_all.py:83`):

```
key = (forced_critical first, −severity, band_order, type, id)
```

so a guardrail-forced finding always sorts above an equally-severe non-forced
one, and ties break deterministically by type then id.

---

## 2. Identity resolution — the duplicate-IP solution

**Problem:** `appsrv-07` (Wiz) and `app-server-07` (AlgoSec/Guardicore) are the
same machine. IP is an *attribute*, not a key. A wrong merge would corrupt a
fact (reachability), so merging uses **deterministic signals only**.

**Algorithm:** union-find (disjoint set) over all observed names
(`identity.py:36-142`).

Names are unioned when:

| Signal | Rule |
|---|---|
| **Shared host IP** | different names observed with the same concrete IP are unioned (`match_key = context_ip`, confidence **0.95**) |
| **Exact name across tools** | one name seen by >1 tool (`match_key = hostname`, confidence **1.0**) |
| **Human-confirmed merge** | reviewed entity-suggestions (`match_key = manual_review`, confidence **1.0**) |

Determinism rules:
- **Union root:** `parent[max(ra, rb)] = min(ra, rb)` — the lexicographically
  smaller name always becomes the root.
- **Canonical key** for a merged component = the name used by the **most tools**;
  ties break to the lexicographically smallest (`identity.py:85`).

The **`alias_map`** (every observed name → canonical key) is what lets the graph
connect a Wiz node to an AlgoSec node. The fuzzy/embedding-based suggester
(`advisory.entity_suggest`) only *proposes* merges for human review — it never
auto-merges.

> Confidence values (1.0 / 0.95) are fixed audit labels on exact-match merges,
> not computed probabilities.

---

## 3. Policy graph

`build_graph()` (`graph/build.py`) produces a `networkx.DiGraph`.

**Nodes** — one per canonical asset, carrying `kind` (concrete/abstract),
`tags`, `ip_set`, `display`, `zone`, and `tools`. Source/destination names not
matching a known asset (e.g. `0.0.0.0/0`, a bare subnet) are added as
`kind="abstract"` nodes.

**Edges** — one directed edge per allowed (source → destination) pair. Each edge
holds **every** grant between those two nodes as a list (`grants`), plus the
union of contributing `tools` and `services`. Parallel grants are **kept, not
collapsed**, preserving provenance (which tool, which rule ref).

```python
grant = {service, port, protocol, tool, ref}
# multiple grants between the same (s, d) accumulate on one edge
```

### Effective policy (important caveat)

Only **`allow`** records become edges; `deny` records are skipped
(`build.py:46`). For the demo this is exact because the single `deny` is already
shadowed, so `effective policy = union of allow edges`. A **non-shadowed deny
that removed an allow path is not yet subtracted** — deny-precedence (first-match
subtraction) is the documented production extension. The shadowing analyzer still
*surfaces* the dead deny.

---

## 4. Zones & the trust-boundary multiplier (B)

`graph/zones.py` + `config.py`. A node's **zone** is a deterministic lookup:

- Only the literal internet node `0.0.0.0/0` → `internet`.
- Tags map to zones (`dmz`/`internet-facing`/`public` → **dmz**;
  `dev`/`sandbox`/`test` → **dev**). Most-exposed tag wins (`ZONE_PRIORITY`).
- Everything else → `internal` (prod/internal default).

The **boundary multiplier B** scales severity by *direction of crossing*:

| src zone → dst zone | B |
|---|---|
| internet → internal | **1.5** |
| dmz → internal | **1.25** |
| dev → internal (dev→prod) | **1.25** |
| any other pair | **1.0** |

> `internet → dmz` is intentionally **1.0** — a DMZ asset is *meant* to face the
> internet, so that direction is expected, not a boundary violation.

---

## 5. The severity model

Severity is `risk = likelihood × impact`, with impact **capped by destination
value** so a dev-sandbox finding can never out-rank a crown-jewel one. It is
built from four sub-scores, each a **categorical lookup** (per BUILD_SPEC §6 —
these are *policy facts*, not computed), combined by one multiplicative formula.

### 5.1 The four sub-scores

**E — exposure breadth** (`severity.py:exposure_score`). From the source prefix
length; an identity/label source → 0.1.

| Source prefix | E |
|---|---|
| `/0` (also "any") | 1.0 |
| `/1`–`/8` | 0.9 |
| `/9`–`/16` | 0.7 |
| `/17`–`/23` | 0.5 |
| `/24`–`/27` | 0.3 |
| `/28`–`/32` | 0.1 |
| identity / label | 0.1 |

**P — port/service sensitivity** (`severity.py:port_score`). The *kind* of access
granted.

| Class | Ports | P |
|---|---|---|
| any protocol | `protocol == "any"` | 1.0 |
| admin / lateral-movement | 22, 23, 135, 445, 3389, 5985, 5986 | 1.0 |
| data store | 5432, 3306, 1433, 27017, 6379 | 0.9 |
| infra control plane | 6443, 2379 | 0.85 |
| general app / web | 80, 443, 8080, 8443, 53, 123 | 0.4 |
| unknown / ephemeral | anything else | 0.5 |

**D — destination sensitivity** (`severity.py:dest_score`). The **max** over the
destination's tags; untagged → 0.4.

| Tag | D |
|---|---|
| crown-jewel | 1.0 |
| pci / customer-data / phi | 0.9 |
| prod | 0.6 |
| dev / sandbox / test | 0.2 |
| untagged | 0.4 |

**B — boundary multiplier** — see §4.

### 5.2 The combination formula

`severity.py:severity_from_vector`:

```
impact          = D × (impact_base + impact_p_weight × P)   = D × (0.5 + 0.5·P)
exposure_factor = exposure_floor   + exposure_span    × E   = 0.4 + 0.6·E
raw             = impact × exposure_factor × B
severity        = round( 100 × min(raw, 1.0) )              # 0..100
```

Properties:
- **impact ∈ [0, D]** — destination value is a hard ceiling on impact.
- **exposure_factor ∈ [0.4, 1.0]** — even a single-host source keeps 40% weight;
  it never zeroes a sensitive finding.
- **B** only ever *raises* score (≥ 1.0), and only across a real trust boundary.

### 5.3 Bands

`severity.py:band` (lower-inclusive thresholds):

| severity | band |
|---|---|
| ≥ 80 | critical |
| ≥ 60 | high |
| ≥ 35 | medium |
| else | low |

### 5.4 The guardrail floor (force-critical)

Separate from the smooth score, **categorically-unacceptable patterns are
force-flagged critical** regardless of the computed number, so no downstream
model error can bury a true emergency. For over-permissive rules
(`severity.py:score_over_permissive`), any of:

- internet source **and** `protocol == "any"` (`E ≥ 1.0` ∧ any/any)
- internet source **and** an admin/lateral port (22/23/135/445/3389/5985/5986)
- a **sensitive** destination (crown-jewel/pci/customer-data/phi) reachable from
  the internet

A forced finding gets `severity_band = "critical"` even if `severity < 80`.

### 5.5 Worked example — RDP from the internet to a PCI database

Rule: `allow 0.0.0.0/0 → db-prod-01 tcp/3389`, db tagged `pci`,
internet → internal.

```
E = 1.0   (/0)
P = 1.0   (3389 ∈ admin/lateral)
D = 0.9   (pci)
B = 1.5   (internet → internal)

impact          = 0.9 × (0.5 + 0.5·1.0) = 0.9 × 1.0  = 0.90
exposure_factor = 0.4 + 0.6·1.0                       = 1.00
raw             = 0.90 × 1.00 × 1.5                   = 1.35
severity        = round(100 × min(1.35, 1.0))         = 100
```

Also force-critical (admin port from the internet **and** sensitive dest from the
internet). Band = critical.

---

## 6. The four analyzers

Each emits `Finding`s with a stable local id (later hashed into an `F_…` id, §7).

### 6.1 Over-permissive (`over_permissive.py`)
Iterates `allow` records and flags a rule if **any** predicate holds
(`_reasons`):

- `protocol == "any"` (any/any)
- internet source (`E ≥ 1.0`) with `P ≥ 0.85` *or* a sensitive dest
- sensitive dest reachable from wider than a single host (`E ≥ 0.3`, i.e. ⊇ /27)
- admin/data port (`P ≥ 0.85`) open to a broad source (`E ≥ 0.5`, i.e. ⊇ /23)

Flagged rules are scored by the **full formula** (§5.2) plus the guardrail floor.

### 6.2 CIDR overlap / redundancy (`cidr_overlap.py`)
Groups `allow` rules by `(tool, destination, service)`; for each pair compares
source networks with `ipaddress` (`subnet_of` / `overlaps`). Reports `contains`
or `overlaps`. **Hygiene, not exposure** — fixed scoring
(`severity.py:score_overlap`):

```
severity = overlap_base (10)
         + overlap_sensitive_bump (20)   if either dest is sensitive
                                          OR either source is broad (≤ /8)
```

So a CIDR-overlap finding is always **10 or 30** and stays in the low band.

### 6.3 Rule shadowing (`shadowing.py`)
Within a tool's **ordered** rules, a later rule is shadowed if an earlier rule
has a broader-or-equal source (`later ⊆ earlier`), same destination, and
overlapping service. Only the **earliest** shadower is reported.

- **Shadowed `deny`** = dangerous (traffic you meant to block is actually
  allowed) → scored on the **full formula** over that effective exposure.
- **Shadowed `allow`** = dead config → **fixed 10** (`shadowed_allow_base`).

### 6.4 Cross-tool path tracing (`path_trace.py` + `reachability.py`)
**The differentiator.** Finds every simple path from the internet to a
sensitive-tagged asset that **spans ≥ 2 distinct source tools** — an exposure no
single console can see. Scored with the full formula
(`severity.py:score_cross_tool_path`): entry as source (E), terminal tags as D,
last-hop service as P, the path's boundary multiplier as B. **Force-critical**
when the path crosses `internet → internal` *and* reaches a sensitive asset.

---

## 7. Reachability & path tracing (the graph math)

`graph/reachability.py`. All path logic is real `networkx.all_simple_paths` over
the directed allow graph — never re-derived by a model.

- **`cross_tool_paths(g, sensitive_tags)`** — for each sensitive target reachable
  from `0.0.0.0/0`, enumerate simple paths (cutoff = 8 hops), keep those spanning
  ≥ 2 tools, dedupe, sort by `(length, path)`.
- **`reachable(src, dst, port)`** — yes/no + the path(s); optional port filter.
- **`who_can_reach(target)`** — effective-policy view: which nodes can reach a
  target, and whether the internet can.

Two bounds / simplifications worth knowing:

- **Scan cap** `_PATH_SCAN_CAP = 4000` candidate paths per (source, target) —
  `all_simple_paths` is worst-case exponential; this keeps the engine bounded at
  thousands of assets/edges.
- **`_valid_traversal`** rejects paths that **pivot *through* an abstract node**
  (a subnet/internet node may be an endpoint but never an intermediate hop):
  reaching hosts inside a range doesn't let you *originate* as that range.
  CIDR-membership expansion (treating concrete hosts inside an allowed range as
  real pivots) is the documented production extension; without it, multi-hop
  paths transiting a subnet can be **under-counted**.

---

## 8. Change simulation & delta

`change/simulate.py`. A proposed rule is **never classified in isolation** — the
engine first computes what newly becomes reachable, *then* the model judges that.

```
base_graph = build_graph(records)
new_graph  = build_graph(records + [proposed])

new_paths     = internet→sensitive paths in new_graph that weren't in base_graph
new_exposed   = the terminal assets of those new paths
boundaries    = trust boundaries the new paths (and the rule itself) cross
new_over_perm = over-permissive predicates the rule itself trips
```

The delta sets **`forced_escalate = True`** when any of:
- it opens ≥ 1 new internet path to a sensitive asset,
- it trips an over-permissive guardrail reason (§5.4),
- it introduces an any/any rule,
- it creates new `internet → internal` exposure.

The advisory layer's `classify_change` then applies **three layers**: (1) a
guardrail that force-escalates the catastrophic patterns up front
(confidence 0.99), (2) the LLM judge over the computed delta, (3) a deterministic
engine override — and **fails closed to `escalate`** if the model output is
missing/invalid. The decision is computed from the delta every run, never stored
as a canned verdict.

The same `reanalyze()` primitive (`run_all.py:40`) lets the remediation layer
**prove** a proposed fix resolves a finding without introducing new criticals —
the deterministic validation step behind "fix-as-code."

---

## 9. Determinism & ids

`ids.py`. Every id is a **stable function of content** (SHA-1 over the defining
fields, sorted-JSON serialized), so a cold re-run UPSERTs byte-identical rows.

```
det_id("F", snapshot_id, local_finding_key)   → F_<sha1[:16]>
snapshot_id(label, content_fingerprint)        → snap_<sha1[:12]>
content_fingerprint(*blobs)                     → <sha1[:40]>
```

- **`F_a0de5194c1cac6f8`** is a finding's content-addressed primary key — the
  same finding from the same data always yields the same id. It is a database
  key, *not* a user-facing label (the assistant is instructed never to print it).
- The snapshot fingerprint hashes each normalized record's
  `tool|ref|source|destination|service|action|order` (`run_all.py:_fingerprint`),
  so any change to the inputs yields a new snapshot id.

No `random`, no timestamps anywhere in the fact path.

---

## 10. Known simplifications (claim vs. reality)

These are the deliberate shortcuts where the engine is narrower than the general
claim. None affect the demo's correctness, but they matter for real data:

1. **Deny precedence not implemented** (`graph/build.py`) — effective policy =
   union of allow edges; a non-shadowed deny that should subtract an allow path
   is invisible to reachability and the change-delta.
2. **No CIDR-membership expansion** (`reachability.py`) — a host inside a broad
   allowed range isn't treated as a reachable pivot, so paths transiting a subnet
   can be under-counted.
3. **Port match is substring, not numeric** (`reachability.py:124`) — the
   optional port filter in `reachable()` matches `f"/{port}"` as a substring of
   the service string, which can false-positive (e.g. `port=3` matches
   `tcp/3389`).
4. **Sub-scores are categorical lookups, by design** — E/P/D and the
   overlap/shadowed-allow constants are table lookups, not formulas; only the
   *combination* in §5.2 is a computed formula. This is intentional (BUILD_SPEC
   §6): the numbers are tunable policy knobs, the shape is the engineering.

---

## 11. Calibration knobs (quick reference)

All in `config.py` — change scoring without touching logic; re-runs stay
byte-identical.

| Knob | Value | Used in |
|---|---|---|
| `impact_base` | 0.5 | impact term |
| `impact_p_weight` | 0.5 | impact term |
| `exposure_floor` | 0.4 | exposure factor |
| `exposure_span` | 0.6 | exposure factor |
| `band_critical / high / medium` | 80 / 60 / 35 | bands |
| `overlap_base` | 10 | cidr_overlap |
| `overlap_sensitive_bump` | 20 | cidr_overlap |
| `overlap_broad_prefixlen` | 8 (≤ /8 = broad) | cidr_overlap bump |
| `shadowed_allow_base` | 10 | shadowing |
| `broad_source_E` | 0.5 (⊇ /23) | over-permissive predicate |
| `sensitive_dest_min_E` | 0.3 (⊇ /27) | over-permissive predicate |
| `admin_data_min_P` | 0.85 | over-permissive predicate |
| boundary multipliers | 1.5 / 1.25 | zones |
| path cutoff / scan cap | 8 hops / 4000 | reachability |
