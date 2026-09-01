# Core Engine — Logic, Calculations & Math

This document describes the **deterministic engine**: every fact and number the
Network Policy Reviewer computes, how it computes them, and the exact formulas
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
| Address-space classification (`is_public` / `is_any` / `parse_net`) | `netaddr.py` |
| Identity resolution (union-find) | `identity.py` |
| Graph construction | `graph/build.py` |
| Zones + boundary multipliers | `graph/zones.py` |
| Reachability + path tracing | `graph/reachability.py` |
| Severity model | `analyzers/severity.py` |
| The 5 analyzers | `analyzers/{over_permissive,cidr_overlap,shadowing,path_trace,transport_exposure}.py` |
| Change simulation + delta | `change/simulate.py` |
| Deterministic ids | `ids.py` |
| Orchestration | `analyzers/run_all.py` |

---

## 1. Pipeline

`run_all.run()` executes five ordered, deterministic stages:

```
normalize → resolve identities → build graph → analyze (5 detectors) → score + sort
```

1. **Normalize** — each tool's raw export (AlgoSec, Guardicore, Wiz) is adapted
   into a common `PolicyRecord` set + `ObservedEntity` set. Source connectors are
   simulated; the canonical model they produce is real.
2. **Resolve identities** — merge each tool's view of a host into one canonical
   asset (§2).
3. **Build graph** — a directed policy graph of allowed connections (§3).
4. **Analyze** — five independent detectors emit `Finding`s (§6), in the fixed
   order `over_permissive → cidr_overlap → shadowing → path_trace →
   transport_exposure` (`run_all.py:_analyzers`). Each runs **isolated**: an
   exception costs that detector's finding class and nothing else, and is
   recorded by name on `EngineResult.degraded_analyzers` (and logged) rather
   than swallowed. **An empty `degraded_analyzers` list is the only clean
   state** — a non-empty one means the snapshot is missing an entire finding
   class and must not be read as "nothing found there". `reanalyze()`
   deliberately does *not* isolate: it exists to prove a proposed fix introduces
   no new critical, so it must fail closed rather than return a quietly smaller
   answer.
5. **Score + finalize** — assign deterministic ids, sort by a fixed key.

The snapshot id is a content hash of **everything the run reads** — every
canonical record, the entity/object catalog, the confirmed manual merges and the
applied-changes overlay — so the same inputs always yield the same `snap_…` id,
and any change that could move a finding moves the id too (§9).

Findings are sorted by a **stable total order** (`run_all.py:run`):

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
(`identity.py:resolve_identities`).

Names are unioned when:

| Signal | Rule |
|---|---|
| **Exact name across tools** | one name seen by >1 tool (`match_key = hostname`, confidence **1.0**) |
| **Shared host IP, *within one declared scope*** | different names carrying the same canonical IP **and the same declared context** (`match_key = context_ip`, confidence **0.95**) |
| **Human-confirmed merge** | reviewed entity-suggestions (`match_key = manual_review`, confidence **1.0**) — bypasses every guard below, which is the point of the review path |

### Why the shared-IP arm is scoped, capped and guarded

An IP only identifies a host inside the namespace that assigns it. RFC 1918
reuse across VPCs, accounts and VRFs is universal in any estate large enough to
need this product, and union-find is transitive — so an unscoped merge on the
raw IP string fuses unrelated hosts, `build_graph` collapses both nodes' edges
onto one, and the tool **reports reachability that does not exist**. `dest_score`
takes the max over the unioned tags, so a dev box inherits `pci` and every allow
into it becomes a critical finding about regulated data. Fabricated reachability
in a security tool is worse than no tool, so **every rule fails the same way:
when in doubt, do not merge.** A missed merge is a review candidate; a wrong
merge is a false statement nobody can see.

Four independent guards (`identity.py`):

| Guard | Rule |
|---|---|
| **Scope** | the union key is `(context, canonical_ip)`. Context is the first non-empty of `vrf`, `vpc`, `account`, `subscription`, `project`, `tenant` (`CONTEXT_IDENTIFIER_KEYS` — `env` and `cloud` are deliberately excluded, being estate-wide labels). If either side declares no context, or the two differ, **there is no union** — it becomes a `manual_review` candidate. The context is not inferred: `normalizers.common.scope_identifiers` lifts it off the export row (`vpcId`, `vpc_id`, `accountId`, `subscriptionId`, `projectId`, `tenant`, `routing_instance`, … case- and separator-insensitive) into those canonical keys, so an export that names no namespace can never take this arm |
| **Sentinel** | addresses in `SENTINEL_BLOCKS` never union in any scope: `0.0.0.0/32`, `127.0.0.0/8`, `169.254.0.0/16`, `::/128`, `::1/128`, `fe80::/10`. They are placeholders, not identities. Membership is tested on the **canonical** address, which folds the IPv4-mapped v6 spelling onto its embedded v4 (`::ffff:127.0.0.1` *is* `127.0.0.1`) — the family is a spelling, never a second identity |
| **Fan-out** | more than `MAX_IP_FANOUT` (**3**) distinct *names* on one address inside one scope means the address is shared infrastructure (a cluster VIP, a NAT pool, an unresolved-DNS default), and the whole group is withheld. Three is the widest fan-out one genuine host can generate — one name per host-describing tool (AlgoSec, Guardicore, Wiz) |
| **Environment** | two components with *known and different* environment classes (`ENV_TAG_CLASSES` folds `production`/`prod`/`prd` into one) are never unioned automatically |

A withheld merge is not silently dropped: it is counted in `suppressed_merges`
and broken out by `suppressed_by_reason` over the published `SUPPRESSION_REASONS`
(`context_mismatch`, `env_conflict`, `ip_fanout`, `sentinel_ip`, `unscoped_ip`),
so the review queue can say *why* rather than just "suppressed".

**On the seeded demo this rule bites, and it is meant to.** None of the three
bundled exports declares a VPC / account / VRF, so the `10.30.7.7` collision
between `app-server-07` (AlgoSec, Guardicore) and `appsrv-07` (Wiz) is
**unscoped**: the engine withholds the merge and emits one `unscoped_ip`
`manual_review` row instead of fusing them. They become one asset when an
operator confirms it (`manual_merges`), which restores the merged-estate
reachability set exactly — `test_reachability.py` pins both states. Any prose
elsewhere that describes the demo as merging those two names *by IP* is
describing the pre-Phase-1 behaviour.

Determinism rules:
- **Union root:** `parent[max(ra, rb)] = min(ra, rb)` — the lexicographically
  smaller name always becomes the root.
- **Canonical key** for a merged component = the name used by the **most tools**;
  ties break to the lexicographically smallest (`identity.py`).

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
grant = {service, port, port_end, protocol, l7_app, l7_source, tool, ref}
# multiple grants between the same (s, d) accumulate on one edge
# the edge also carries unions: tools, services, apps
```

A node's `kind` and `zone` are **copied** from the asset layer, never re-derived
here: `kind` comes from `Asset.kind` (folded by the identity layer from each
normalizer's `ObservedEntity.abstract`) and decides which paths exist via
`_valid_traversal` (§7); `zone` comes from `zones.zone_of`, which is handed the
node's resolved `ip_set` and `kind` so a named object resolving to `0.0.0.0/0`
lands in the same zone, with the same B, as the literal string (§4). A second
opinion in either place would let the graph and the traversal filter disagree
about the same node.

### Effective policy (important caveat)

Only **`allow`** records become edges; `deny` records are skipped
(`build.py:build_graph`). For the demo this is exact because the single `deny` is already
shadowed, so `effective policy = union of allow edges`. A **non-shadowed deny
that removed an allow path is not yet subtracted** — deny-precedence (first-match
subtraction) is the documented production extension. The shadowing analyzer still
*surfaces* the dead deny.

---

## 4. Zones & the trust-boundary multiplier (B)

`graph/zones.py` + `config.py` + `netaddr.py`. A node's **zone** is a
deterministic lookup, applied in this order:

- **A node that *denotes* globally-routable address space → `internet`.** This is
  a property of the address space, decided by `netaddr.is_public`, not a string
  comparison — so `0.0.0.0/0`, `0.0.0.0/1`, `1.0.0.0/8`, `::/0`, the wildcard
  words `any`/`all`/`*`, and a named object whose catalog value resolves to
  public space all land in the same zone. Two arms: the node key itself is
  address space, or the node is an abstract object whose resolved `ip_set` is.
- **A *concrete asset* is never `internet`, even with a public IP.**
  `lb-public-01` (52.20.10.10) is a host that *faces* the internet; it is not the
  internet. It sits in the DMZ by tag, which is why `internet → dmz` is
  deliberately 1.0 below. Classifying every public-IP'd host as `internet` would
  inflate every `dmz → internal` hop (1.25) into `internet → internal` (1.5).
- Tags map to zones (`dmz`/`internet-facing`/`public` → **dmz**;
  `dev`/`sandbox`/`test` → **dev**). Most-exposed tag wins (`ZONE_PRIORITY`).
- Everything else → `internal` (prod/internal default).

The address-space test wins over tags, so a `/0` labelled `dev` is still the
internet. `severity.is_internet_source` calls the **same** `netaddr.is_public`,
so the zone label and the guardrail floor cannot drift into disagreeing about
what "the internet" means.

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

**E — exposure breadth** (`severity.py:exposure_score`). The prefix length of the
**broadest network the source actually denotes** — read from
`PolicyRecord.source_cidrs`, the resolved address space the normalizer filled from
the export's own object catalog, *not* from the source label. A named object,
an address group and a raw CIDR describing the same space therefore score the
same. The label is consulted only when `source_cidrs` is genuinely empty (the
token names no address space at all — a user, a tag, an application group), and
then falls back to `E_IDENTITY` = 0.1.

An address group resolves to several networks; the **widest** one wins, because a
grant is as exposed as the widest address it admits.

| IPv4 prefix | IPv6 prefix | E |
|---|---|---|
| `/0` (also `any`/`all`/`*`) | `::/0` | 1.0 |
| `/1`–`/8` | `/1`–`/16` | 0.9 |
| `/9`–`/16` | `/17`–`/32` | 0.7 |
| `/17`–`/23` | `/33`–`/48` | 0.5 |
| `/24`–`/27` | `/49`–`/64` | 0.3 |
| `/28`–`/32` | `/65`–`/128` | 0.1 |
| unresolvable identity / label | — | 0.1 |

> **IPv6 has its own band table** (`config.EXPOSURE_BANDS_V6`), chosen from the
> network's own `.version`. A prefix length means a completely different amount
> of space in the two families: `2001:db8::/32` holds 2⁹⁶ addresses and the IPv4
> table would score it 0.1, the score of a single host.

**P — port/service sensitivity** (`severity.py:port_score`). The *kind* of access
granted — the **max class over every port the service opens**, not the class of
its first port. All three encodings (`tcp/3389`, `tcp/1-65535`, `tcp/80,443`)
become one interval set and are scored the same way.

`config.PORT_CLASS_P` is declared strictly most-severe-first and walked in
order, so the first class that applies wins and the 1.0 tie between *any-port*
and *admin* is pinned to one answer for all time:

| Class | Applies when | P |
|---|---|---|
| any-port | `protocol == "any"`, **or** the service spans more than `PORT_SPAN_ANY` (1024) ports in total | 1.0 |
| admin / lateral-movement | the interval set contains 22, 23, 135, 445, 3389, 5985 or 5986 | 1.0 |
| data store | contains 5432, 3306, 1433, 27017 or 6379 | 0.9 |
| infra control plane | contains 6443 or 2379 | 0.85 |
| unknown / ephemeral | contains any port in no named class (also: no readable port) | 0.5 |
| general app / web | every port is one of 80, 443, 8080, 8443, 53, 123 | 0.4 |

Two consequences of the ordering, both deliberate:

- **Widening a service can never lower P.** `tcp/80` is 0.4; `tcp/80-81` is 0.5,
  because port 81 is unclassified and *unknown* (0.5) deliberately outranks
  *general app* (0.4) — a range that opens 443 plus 8000 unclassified ports is
  not a "web" grant.
- **`tcp/1-65535` is any-port (1.0), and reported as such.** It also contains
  3389, so it matches *admin* too; the table order fixes the reported label.
  1024 is the size of the IANA System port range (RFC 6335 §6): a single grant
  wider than the entire registry of privileged ports is unrestricted access, and
  the threshold is externally citable rather than tuned.

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
(`severity.py:score_over_permissive`) there are exactly **three** clauses, any
of which forces:

1. internet source **and** `protocol == "any"` (any/any)
2. internet source **and** the service's port interval set **intersects** the
   admin/lateral set (22/23/135/445/3389/5985/5986)
3. a **sensitive** destination (crown-jewel/pci/customer-data/phi) reachable from
   the internet — port-independent by design

A forced finding gets `severity_band = "critical"` even if `severity < 80`.

Two things decide how often these fire, and both are address/interval facts
rather than string facts:

- **"Internet source" is `severity.is_internet_source`**, which asks
  `netaddr.is_public` over the resolved `source_cidrs` (falling back to the
  label). It is **not** `E ≥ 1.0`. That old test was a proxy that only a `/0`
  satisfied, so `0.0.0.0/1`, `1.0.0.0/8` and `::/0` slipped past the floor
  entirely. **Any** public member of an address group makes the grant
  internet-facing: a group holding both `10.0.0.0/8` and `1.0.0.0/8` admits the
  internet.
- **Clause 2 tests interval intersection**, not `port in ADMIN_LATERAL_PORTS`.
  `tcp/1-65535` exposes 3389 just as surely as `tcp/3389` does, and a guardrail
  an ordinary port range walks straight through is not a floor.

The clause *list* is the same three it has always been — they simply fire on
strictly more inputs now, which is the only direction a floor is allowed to move.

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

## 6. The five analyzers

Each emits `Finding`s with a stable local id (later hashed into an `F_…` id, §9).
The five detector names are exactly `FindingType` in `models.py`:
`over_permissive`, `cidr_overlap`, `shadowed_rule`, `cross_tool_path`,
`transport_exposure`.

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

### 6.5 Transport-/application-layer exposure (`transport_exposure.py`)
The fifth detector, and the one the formula reference used to omit. It reasons
about the **decoded L7 application** (`PolicyRecord.l7_app`, populated by
`normalizers/common.py:parse_service` either from a declared App-ID or by the
deterministic `config.APP_BY_PORT` lookup), not just the port number. Its
constants live in one place, `config.TRANSPORT_CONFIG`.

**(a) `quic_blind_spot`** — one finding per `allow` record whose decoded
`l7_app` is in `config.INSPECTION_BLIND_APPS`
(`quic`, `http3`, `doq`, `dns-over-quic`, `http3-discovery`). These ride UDP
and/or encrypt their handshake, so a legacy enforcement point cannot inspect
them: a reachable allow is an inspection blind spot. Scored on the **full
formula** (§5.2) plus a flat bump:

```
severity = min( severity_from_vector(E, P, D, B) + blind_spot_bump (15), 100 )
```

**Guardrail.** Force-critical when the source is the internet (`E ≥ 1.0`)
**and** either the record crosses a trust boundary (`B > 1.0`) or the
destination carries a sensitive tag — i.e. an uninspectable application
reachable from the internet into an internal or regulated asset.

**(b) `tls_fallback_not_blocked`** — one finding per destination allowed on
**both** halves of a pair in `TRANSPORT_CONFIG["fallback_pairs"]` (currently the
single pair `tcp/443` + `udp/443`). An inspectable TLS path exists, but QUIC can
silently win it, so inspection cannot be *forced*. "Allowed on" is **interval
containment over the whole service**, not scalar equality: `tcp/443`,
`tcp/443-8443` and `tcp/80,443` all open tcp/443 and all trip the pair, and a
rule whose protocol is `any` opens the port on every transport. This is a
control gap rather than an exposure, so it uses **fixed** scoring and is
**never** force-critical:

```
severity = fallback_base (40)
         + fallback_sensitive_bump (20)   if the destination is sensitive
```

— always 40 or 60, so it lands in the medium or high band and can never
out-rank a real internet exposure.

> **Read the finding count with this in mind.** `quic_blind_spot` emits **per
> allow rule**, not per distinct problem: one uninspectable application allowed
> by four rules yields four findings, and on the seeded demo dataset this
> detector is consistently one of the largest contributors to the raw total.
> That is intended — each finding ties back to a specific `raw_ref` an operator
> can act on — but it does mean **a finding count is not an estimate of distinct
> issues**. `tls_fallback_not_blocked` is the opposite shape: one finding per
> destination, however many rules opened the pair.
>
> For the current per-type breakdown of the seeded demo, run the engine rather
> than trusting a number written here: `python tasks.py verify` prints the
> snapshot id and total, and `backend/scripts/verify_engine.py` asserts the
> *properties* (which findings must exist, and which must be forced) rather than
> a total — which is why it survives a change like this one.

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
  thousands of assets/edges. It bounds candidates **yielded**, not the DFS work
  behind them (§10.3). Because a bounded scan changes what a *negative* answer
  means — "no path in the first 4000 candidates" is not "no path exists" —
  `reachable()` returns a **`truncated`** flag alongside its verdict and logs a
  warning naming the pair, so the change gate can tell a proven "no" from an
  exhausted budget. The yes/no itself comes from `_bfs_witnesses`, which is
  O(V+E) and never enumerates.
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

The same `reanalyze()` primitive (`run_all.py:reanalyze`) lets the remediation layer
**prove** a proposed fix resolves a finding without introducing new criticals —
the deterministic validation step behind "fix-as-code."

> **Read that proof precisely.** It asserts two things and only two: the target
> finding is gone, and no *new* **critical**-band finding appeared. New
> high/medium/low findings are not checked, and the proof is evaluated against
> the snapshot as it stood when the fix was drafted — it is not re-run when the
> change is later staged or pushed. Unlike the snapshot path, `reanalyze()` does
> **not** isolate a failing analyzer (§1): a proof must fail closed rather than
> certify against a quietly smaller finding set.

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

### The snapshot fingerprint — what it covers

`run_all.py:_fingerprint` hashes **four blobs**, in this fixed order, and
`snapshot_id(label, fingerprint)` folds the run's `label` in on top:

| # | Blob | Contents |
|---|---|---|
| 1 | **Every canonical record**, sorted | all 21 `PolicyRecord` fields — `_RECORD_FIELDS` — including `dest_tags`, the resolved `source_cidrs` / `dest_cidrs`, and the decoded `protocol` / `port` / `port_end` / `l7_app` / `l7_source`, not just the service string |
| 2 | **The observed-entity view**, sorted | `tool`, `name`, `kind`, `ip`, `cidr`, `tags`, `abstract` per entity — i.e. the object/asset catalog the identity layer merges |
| 3 | **The applied `manual_merges`**, sorted | each pair itself sorted, because the union is symmetric: `("a","b")` and `("b","a")` produce one asset set and must produce one id |
| 4 | **The applied-changes overlay**, **in caller order** | each change serialized whole (`json.dumps(sort_keys=True)`), because `apply_overlay` folds changes in order and two orders can yield two different record sets |

Records and entities are hashed **post-overlay and post-augmentation**, so the id
describes the state that was actually analyzed. Fields are joined with ASCII
`US`/`RS` separators rather than `|` and `\n`, because a rule's free-text `note`
can contain either and two different postures must never serialize to one string.
List-valued fields are sorted inside `_value`, so a catalog that lists the same
tags in a different order cannot hash two ways.

**What this means for the id.** Changing *anything the engine reads* — an asset
tag, an object's CIDR, an object's type, the `abstract` flag, a decoded port
range, an L7 app, the confirmed merge list, or the applied-changes overlay —
now yields a **different** `snap_…` id. That closes the failure mode this
section previously had to confess: a snapshot could be re-persisted in place,
under the same id, with different assets and different findings, while
governance rows hung off that id.

`_RECORD_FIELDS` is written out explicitly rather than read off the model, so
adding a field to `PolicyRecord` without adding it here is a deliberate decision
rather than a silent narrowing — and `test_analyzers.py::test_fingerprint_covers_every_record_field`
fails if the two drift apart.

> **Still true, and worth knowing:** the id is a hash of *inputs*, not of
> findings. It tells you the same inputs were analyzed; it does not by itself
> prove the same analyzer code produced them. That is what the byte-identical
> re-run check in `verify_engine.py` and the cross-process determinism test are
> for.

No `random`, no timestamps anywhere in the fact path.

---

## 10. Known simplifications (claim vs. reality)

These are the deliberate shortcuts and open gaps where the engine is narrower
than the general claim. None affect the demo's correctness, but they matter for
real data — so they are listed here rather than left for you to find.

1. **Deny precedence not implemented** (`graph/build.py:build_graph`) — effective
   policy = union of allow edges; a non-shadowed deny that should subtract an
   allow path is invisible to reachability and the change-delta.
2. **No CIDR-membership expansion** (`reachability.py:_valid_traversal`) — a
   host inside a broad allowed range isn't treated as a reachable pivot, so
   paths transiting a subnet can be under-counted.
3. **The path scan cap bounds paths *yielded*, not search *performed*.**
   `_PATH_SCAN_CAP = 4000` is applied as `islice(nx.all_simple_paths(...), cap)`.
   `all_simple_paths` is a DFS generator: the cap stops us *consuming*
   candidates, but the backtracking between two yields is still worst-case
   exponential, so a dense mesh can spend a long time producing the 4000th path
   (measured at ~117 s on a 34-node mesh). Two mitigations, neither of which is
   a fix: the yes/no answer comes from `_bfs_witnesses`, which is O(V+E) and
   never enumerates; and `reachable()` now reports **`truncated`** alongside its
   verdict and logs a warning naming the pair, so a caller can tell a proven
   "no path" from an exhausted scan budget instead of silently trusting the
   smaller answer.
4. **Sub-scores are categorical lookups, by design** — E/P/D and the
   overlap/shadowed-allow constants are table lookups, not formulas; only the
   *combination* in §5.2 is a computed formula. This is intentional (BUILD_SPEC
   §6): the numbers are tunable policy knobs, the shape is the engineering.

> **Fixed, and no longer gaps.** This section previously confessed five defects
> that no longer exist, and §9 confessed a sixth (the narrow snapshot
> fingerprint). They are listed here so that a reader who greps a cited line,
> finds working code, and reasonably starts doubting everything else on this
> page has the answer in front of them:
>
> - *"Port match is substring, not numeric"* — `reachable()`'s filter used to
>   match `f"/{port}"` inside the service string, so `port=3` matched `tcp/3389`.
>   `reachability.py:_grant_matches` / `_edge_matches` now do structured
>   protocol / port-range / L7-app matching per grant, with `start <= port <= end`.
> - *"A port range is scored from its start port"* — `port_score` now takes the
>   whole interval set and returns the max class over it (§5.1).
> - *"'The internet' is the literal string `0.0.0.0/0`"* — both `zone_of` and the
>   guardrail floor now classify address space through `netaddr.is_public`
>   (§4, §5.4).
> - *"A named network object is a concrete node and can pivot"* — a
>   `network`/`group`/`range`/`subnet` object is now marked `abstract` by the
>   normalizer (and any object spanning more than one address), so
>   `_valid_traversal` treats `DC-SUBNETS` and the literal `10.0.0.0/8` alike.
> - *"A mixed IPv4/IPv6 record set raises TypeError"* — `cidr_overlap._covers` /
>   `_overlaps` and `shadowing`'s coverage tests guard on `same_family` and
>   report incomparable families as disjoint rather than crashing.

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
| `PORT_SPAN_ANY` | 1024 (IANA System port range, RFC 6335 §6) | port_score → any-port (§5.1) |
| `MAX_IP_FANOUT` | 3 | identity: shared-IP fan-out guard (§2) |
| `SENTINEL_BLOCKS` | 0.0.0.0/32, 127/8, 169.254/16, ::/128, ::1/128, fe80::/10 | identity: never union (§2) |
| `CONTEXT_IDENTIFIER_KEYS` | vrf, vpc, account, subscription, project, tenant | identity: merge scope (§2) |
| `TRANSPORT_CONFIG["blind_spot_bump"]` | 15 | transport_exposure (§6.5a) |
| `TRANSPORT_CONFIG["fallback_base"]` | 40 | transport_exposure (§6.5b) |
| `TRANSPORT_CONFIG["fallback_sensitive_bump"]` | 20 | transport_exposure (§6.5b) |
| `TRANSPORT_CONFIG["fallback_pairs"]` | `[(tcp/443, udp/443)]` | transport_exposure (§6.5b) |
| `INSPECTION_BLIND_APPS` | quic, http3, doq, dns-over-quic, http3-discovery | transport_exposure (§6.5a) |
| boundary multipliers | 1.5 / 1.25 | zones |
| path cutoff / scan cap | 8 hops / 4000 | reachability |
