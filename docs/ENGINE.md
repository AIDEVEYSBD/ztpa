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
   than swallowed. A non-empty list means the snapshot is missing an entire
   finding class and must not be read as "nothing found there". The phase also
   captures every `path_scan_truncated` event the graph layer emits into
   `EngineResult.truncations`, so a bounded scan stops dying in the log stream.
5. **Score + finalize** — assign deterministic ids, sort by a fixed key.

**Two grades of "this run is not the whole answer", and they are not the same
thing.** `EngineResult` exposes both as properties, and `complete` is
`not degraded and not partial`:

| Grade | Set by | Means | Consequence |
|---|---|---|---|
| `degraded` | `degraded_analyzers` non-empty | an analyzer raised — an entire finding **class** is absent | may never overwrite or be published over a complete run; `persist_engine_result` refuses it |
| `partial` | `truncations` non-empty | at least one path enumeration stopped at `_PATH_SCAN_CAP` — the findings present are a bounded **sample** | still the best available answer, so it is persisted — but every count is a lower bound and every absence is "not found within budget", and the snapshot row is written `failed` with the reason in `notes` rather than `complete` |

`integrity_reasons()` renders either state in a sentence a human reads on
`/api/health`. **Empty is the only clean state for both lists.** `reanalyze()`
deliberately does *not* isolate: it exists to prove a proposed fix introduces no
new critical, so it must fail closed rather than return a quietly smaller answer.

The snapshot id is a content hash of **everything the run reads** — every
canonical record, the entity/object catalog, the confirmed manual merges and the
applied-changes overlay — **plus an integrity digest of anything that made the
run less than a complete analysis**, so the same inputs always yield the same
`snap_…` id, and any change that could move a finding moves the id too (§9).

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
>
> **IPv4-mapped v6 is unwrapped before banding**, by the same rule `netaddr`
> publishes for `is_public`: `::ffff:10.0.0.0/104` *is* `10.0.0.0/8`, and
> `::ffff:0.0.0.0/96` *is* `0.0.0.0/0`. Every mapped block is /96 or longer, so
> without unwrapping the v6 table put the whole internet in its bottom row at
> E = 0.1 while `is_public` called the same token public — two halves of one
> published rule disagreeing. `severity._net_of` parses *and* unwraps, and both
> `exposure_score` and `prefixlen_of` read through it, so a mapped `/96` prints
> prefix length **0** beside E = 1.0 rather than 96 beside 0.1.

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

> **The wildcard vocabulary applies per comma element, not only to the whole
> token.** `tcp/any`, `tcp/all`, `tcp/*` and the Azure NSG `port: "*"` shape are
> how Palo Alto, Check Point, AlgoSec and Azure spell "every port of this
> protocol"; each such element decodes to the full `(1, 65535)` interval via the
> same `netaddr.is_any` the whole-service token and the src/dst tokens already
> use. They used to fall through to `int("any")`, be rejected, and leave the
> record with **no interval set at all** — so `tcp/any`, the widest TCP grant it
> is possible to write, scored P_UNKNOWN (0.5) and produced no finding, while the
> byte-equivalent `tcp/1-65535` scored 90/critical and guardrail clause 2 fired.
> Narrowing a grant from "every protocol" to "every port of one protocol" must not
> be able to silence the engine. `tcp/443,any` is the union, i.e. every port.

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

> **A floor is only as strong as what runs in front of it.** `over_permissive`
> used to consult a *cheaper* internet test (`_reasons`, `E >= 1.0`) **before**
> scoring, and skip the record when it produced no reason — so a rule this floor
> forces critical could be discarded before the floor ran. That gate now calls
> `is_internet_source` itself, and forced findings are emitted whatever it thinks
> (§6.1). One concept, one predicate: `netaddr.is_public` over resolved address
> space, shared by `zone_of`, this floor, that gate, `reachability.internet_entries`
> and the change gate.
>
> **Where the floor is still escapable, and it is clause 3.** `dest_tags` is read
> off the destination *label*, so aiming the same rule at a subnet that *contains*
> the regulated asset drops D to the untagged default and clause 3 never fires.
> This is a real, measured gap, not a theoretical one — see §10.5.

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
**Score first, filter second.** Every `allow` record is scored by the full formula
(§5.2) *and* the guardrail floor (§5.4) before anything decides whether to report
it. A rule the floor forces critical is emitted **unconditionally**. `_reasons` is
consulted only for the rest, and answers only the question a cheap heuristic is
qualified to answer — is this non-forced rule worth an operator's attention:

- `protocol == "any"` (any/any)
- **internet source** — `severity.is_internet_source`, the *same* predicate the
  floor uses, over the same resolved address space — with `P ≥ 0.85` *or* a
  sensitive dest
- sensitive dest reachable from wider than a single host (`E ≥ 0.3`, i.e. ⊇ /27)
- admin/data port (`P ≥ 0.85`) open to a broad source (`E ≥ 0.5`, i.e. ⊇ /23)

The three remaining `E` thresholds stay thresholds on purpose: they are genuinely
questions about *breadth* ("wider than a single host", "a broad source range"), and
a band cut is the honest way to ask those. Only the internet arm was a
classification question wearing a threshold's clothes.

> **Why the order is load-bearing.** `_reasons` used to run *before* the scorer,
> with the loop `continue`ing when it returned `[]` — so it was a **gate on
> scoring**, not a filter on reporting — and its internet arm was `E ≥ 1.0`, true
> only for a `/0`. `allow 52.20.10.0/24 → app-01 tcp/3389`, a partner's public /24
> with RDP to a prod host, was scored 52 **and forced critical** by the published
> floor, and then thrown away by the cheaper test standing in front of it. Not
> down-ranked: never emitted, by this analyzer or any other. A floor a gate can
> silence is not a floor, and §5.4's promise that "no downstream model error can
> bury a true emergency" was untrue of the layer directly above it. Both halves are
> closed: the control flow is inverted, and the two private definitions of "the
> internet" became one function call.
>
> `_is_wildcard_source` is deliberately **not** unified with it. That one drives the
> finding's display label, and writing "open from the internet" above a rule sourced
> from a single partner's public /24 would be a false statement in the most-read
> line of the finding. Narrow is right there; narrow in the gate was the defect.

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

**Where the search starts is a graph fact, not a string.** The entry set is
`reachability.internet_entries(g)` — *every* node `graph.build` stamped
`ZONE_INTERNET`, which `zones.zone_of` decides from the node's resolved address
space. So `0.0.0.0/0`, `any`, `ANY-EXTERNAL` and a named group dereferencing to
public space are all entry points, paths from every entry are unioned and deduped
by node tuple, and the whole set is sorted. This is not a nicety: the entry used
to be the literal key `0.0.0.0/0`, guarded by `if source not in g: return []`, and
real AlgoSec / Palo / Check Point exports write the internet source as `any` or as
a named object in what `normalizers/algosec.py` calls "the overwhelming majority
of rules". Those estates got an **empty list** from the analyzer this product is
sold on — and an empty list renders as *"no internet-to-crown-jewel path exists."*
`change/simulate.py` calls the same function (§8), so the finding a buyer is shown
and the ruling an operator is given cannot disagree about where the internet is.

**The entry is scored on its resolved space too.** `describe_path` emits
`entry_cidrs` (the entry node's `ip_set`, sorted), and `score_cross_tool_path`
reads it before falling back to the label. Until that key was produced, a chain
entered through a named object scored `E_IDENTITY` = 0.1 — the exposure of a single
host — for a path beginning at the whole internet.

Its two hard limits are §10.2 (a chain that pivots *through* a subnet or group
object is not reported) and §10.3 plus the scale table in §10 (enumeration is
worst-case exponential and the cap bounds yields, not work).

> **On the shipped fixture this detector reports two findings**, and §10.2 is
> still in force: the chains it reports pivot through concrete hosts that a
> second tool independently observes, while the all-ranges chain
> `0.0.0.0/0 → 10.0.0.0/8 → app-segment → db-prod-01` exists as real edges and is
> declined in full. The count moved because the FIXTURE gained those hosts, not
> because the traversal rule was loosened — `verify_engine` asserts both
> directions. See §10.2 for the limitation that remains, and `docs/DEMO.md`
> beat 6 for how the two are presented together.

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
them: a reachable allow is an inspection blind spot. **Read §10.8 before you rely
on this check**: `l7_app` is inferred from the *first* port interval's start port,
so `udp/1-65535` — which opens 443 — infers no app and produces no blind-spot
finding, i.e. widening the rule removes the finding. Scored on the **full
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
rule whose protocol is `any` opens the port on every transport.

> **That last clause is now true of the code, and was not.** The analyzer filtered
> its input to `r.port is not None`, so an `any` service — protocol `any`, no port,
> the widest grant an export can express — was excluded from the very check whose
> sentence above promises to cover it. `data/mock/algosec_export.json` ships such a
> rule (`ALGO-001`, `0.0.0.0/0 → 10.0.0.0/8 any`), so the detector was skipping the
> broadest rule in the product's own demo. `_opens` is now the single place that
> decides what a rule grants: a rule naming no port opens every port exactly when
> it names no protocol either — the same reading `severity.port_score` gives it. A
> *protocol-bearing* rule whose service failed to decode still opens nothing:
> "port unknown" is not evidence that 443 is reachable, and inventing a grant is
> the mirror-image error. This is a
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

- **`internet_entries(g)`** — every node whose zone is `ZONE_INTERNET`, sorted.
  The module's single definition of *where the internet is*, derived from resolved
  address space rather than from a node key, and the one all three consumers below
  (plus `change.simulate`) call so they cannot drift apart.
- **`cross_tool_paths(g, sensitive_tags)`** — for each internet entry, and each
  sensitive target reachable from it, enumerate simple paths (cutoff = 8 hops),
  keep those spanning ≥ 2 tools, dedupe by node tuple across entries, sort by
  `(length, path)`. A `sources` argument exists as a probe hatch; production passes
  nothing and gets the full entry set.
- **`reachable(src, dst, port)`** — yes/no + the path(s); optional port filter.
- **`who_can_reach(target)`** — effective-policy view: which nodes can reach a
  target, and whether *any* internet node can. It returns `internet_entries` —
  the entries that actually reach this target, named — beside the boolean, so the
  claim ships the evidence for itself; `internet_path` is the shortest of them,
  ties broken by the path, so it stays deterministic when several entries qualify.

Two bounds / simplifications worth knowing:

- **Scan cap** `_PATH_SCAN_CAP = 4000` candidate paths per (source, target) —
  `all_simple_paths` is worst-case exponential; this keeps the engine bounded at
  thousands of assets/edges. It bounds candidates **yielded**, not the DFS work
  behind them (§10.3). Because a bounded scan changes what a *negative* answer
  means — "no path in the first 4000 candidates" is not "no path exists" —
  `reachable()` returns a **`truncated`** flag alongside its verdict and logs a
  warning naming the pair, so the change gate can tell a proven "no" from an
  exhausted budget. The yes/no itself comes from `_bfs_witnesses`, which is
  O(V+E) and never enumerates. `cross_tool_paths` and `find_paths` still return
  bare lists, so `run_all` captures their `path_scan_truncated` events instead
  and marks the whole run **`partial`** (§1): counts from a partial snapshot are
  lower bounds and absences in it are not proofs.
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

> **The first clause is a diff, so what counts as "the internet" decides it.**
> `_internet_sensitive_paths` takes its entry set from
> `reachability.internet_entries` — the same zone-derived answer §6.4 shows the
> buyer. It used to be `find_paths(g, "0.0.0.0/0", t)`, which meant an estate whose
> pre-existing internet ingress is spelled `any` or `ANY-EXTERNAL` had an empty map
> on **both sides of the diff**: a proposed *internal* rule completing a chain from
> the internet to a PCI database flipped `forced_escalate` from `True` to `False`
> purely on the spelling of a rule the operator did not write. And because
> `classify_change` short-circuits to `escalate` on `forced_escalate` **before any
> model call**, a `False` there sent the decision to the LLM under a delta that
> read "no new internet paths". Entries and targets are both iterated sorted, so
> `new_paths` order on the wire is stable.

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

**The id also covers the *completeness* of the run, not only its inputs.** It is
minted **after** the analyzers, over the input fingerprint plus
`run_all._integrity_digest(degraded, truncations)` — the analyzer names, the
exception *types*, and the truncated (fn, src, dst, cap) tuples. A **complete**
run's digest is the empty string and no extra blob is added at all, so every
existing snapshot id, explanation-cache key and governance row is byte-identical
to what it was before this existed. An **incomplete** run is therefore a
*different* snapshot from the complete one over the same export, and cannot
collide with it — which is what stops it upserting partial findings over
complete ones under a shared id. (The exception *message* is deliberately left
out of the hash: a repr can carry a heap address, and the id must be a function
of the posture, never of the process.)

> **Still true, and worth knowing:** the id is a hash of *inputs plus integrity*,
> not of findings. It tells you the same inputs were analyzed to the same degree
> of completeness; it does not by itself prove the same analyzer code produced
> them. That is what the byte-identical re-run check in `verify_engine.py` and
> the cross-process determinism test are for.

No `random`, no timestamps anywhere in the fact path.

---

## 10. Known simplifications (claim vs. reality)

These are the deliberate shortcuts and open gaps where the engine is narrower
than the general claim. **All but one of them are invisible on the seeded demo**,
and that is not luck: 27 rules is three orders of magnitude below where the scale
limits bite, `seed_demo.py` writes the internet literally `0.0.0.0/0`, and the one
rule that *does* aim at a subnet containing a regulated asset
(`ALGO-001: 0.0.0.0/0 → 10.0.0.0/8 any`, which contains `db-prod-01`) is forced
critical by the any/any clause before the containment gap in §10.5 can matter. A
fixture that demonstrates a product is not a fixture that stresses it — so the gaps
are written down here rather than left for you to meet on real data.

The exception is **§10.2**, which is visible as a zero: the demo's flagship
cross-tool path is not reported at all. It is called out there rather than buried,
because a headline count of 0 with no explanation beside it is exactly the kind of
silence this section exists to break.

Where a gap has been measured, the measurement is printed instead of an adjective,
and the input shape that produced it is named so you can reproduce it.

Item numbers are stable: §10.1 … §10.4 are the original four and are referenced
from `REQUIREMENTS.md` and §7. New disclosures are appended, never renumbered.

1. **Deny precedence not implemented** (`graph/build.py:build_graph`) — effective
   policy = union of allow edges; a non-shadowed deny that should subtract an
   allow path is invisible to reachability and the change-delta.
2. **No CIDR-membership expansion in traversal** (`reachability.py:_valid_traversal`)
   — a host inside a broad allowed range isn't treated as a reachable pivot, so
   paths transiting a subnet can be under-counted. This is only the *path* half
   of the containment gap; the *scoring* half is §10.5, and the two are
   independent — fixing traversal would not fix D.

   **This one is not invisible on the demo — it *is* the demo's zero.** The seeded
   3-tool chain `Internet → lb-public-01 → app-server-07 → internal-app →
   db-prod-01` pivots through `internal-app`, an AlgoSec network object
   `10.40.0.0/16`. Marking network objects abstract (correctly) removed the only
   legal pivot, so `cross_tool_paths` returns `[]` on the shipped fixture and the
   product's flagship finding count is **0**. `scripts/verify_engine.py` asserts
   that state deliberately (`P5`), and `REMEDIATION-LOG.md` records when and why it
   changed. Two things are true at once and both belong in the same sentence:
   refusing to route an attack path through an address range is correct, and the
   headline number is currently zero because of it. The chain returns when
   membership expansion makes the concrete hosts inside `10.40.0.0/16` the real
   pivots — Phase 3. (A second, independent cause also holds it down: the
   `appsrv-07` ↔ `app-server-07` merge is withheld as an unscoped IP collision,
   §2. Forcing that merge does *not* bring the path back; this item is the
   dominant cause.)
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
   smaller answer. **What this costs at the scale the product is sold on is
   measured below** — and the mitigation does not cover the worst case, because
   a target that never yields a path never trips a cap that counts yields.
4. **Sub-scores are categorical lookups, by design** — E/P/D and the
   overlap/shadowed-allow constants are table lookups, not formulas; only the
   *combination* in §5.2 is a computed formula. This is intentional (BUILD_SPEC
   §6): the numbers are tunable policy knobs, the shape is the engineering.
5. **Destination sensitivity (D) reads the destination *label's* tags — the
   engine is containment-blind on the destination side.** `severity.dest_score`
   is fed `PolicyRecord.dest_tags`, and nothing expands a destination object into
   the assets it contains. Phase 1 made the **source** side address-aware (E reads
   the resolved `source_cidrs`, and the guardrail's internet test reads
   `netaddr.is_public`); the destination side was not converted. The consequence
   is a monotonicity violation **in the under-reporting direction**: writing the
   destination as the object that *contains* a regulated asset scores lower than
   naming the asset.

   ```
   db-prod-01 = 10.10.5.9, tags [pci, crown-jewel]
   DC-SUBNETS = 10.10.0.0/16, untagged network object — and it contains db-prod-01

   allow 0.0.0.0/0 -> db-prod-01 tcp/1433   E=1.0 P=0.9 D=1.0 B=1.5 -> 100 critical, FORCED
   allow 0.0.0.0/0 -> DC-SUBNETS tcp/1433   E=1.0 P=0.9 D=0.4 B=1.5 ->  57 medium,  not forced
   ```

   The second rule opens MSSQL from the whole internet to 65,534 addresses
   *including the crown jewel*, and scores two bands below the strictly narrower
   rule. Because D falls back to the untagged default it also walks straight past
   **guardrail clause 3** (§5.4) — the port-independent "regulated asset reachable
   from the internet" floor, which is the clause a compliance reader leans on
   hardest. It propagates: `advisory/report.py:build_summary` computes
   `internet_reaches_regulated_data` from `forced_critical AND dest_tags ∩
   SENSITIVE_TAGS` (or a cross-tool path), so with the subnet spelling the
   posture report answers **no** while still listing `db-prod-01` under
   `sensitive_assets`.

   **It is already in the shipped demo, masked.** `ALGO-001`
   (`allow 0.0.0.0/0 -> 10.0.0.0/8 any`) aims at a /8 that contains `db-prod-01`
   (10.50.0.10, `pci` + `customer-data`). It scores D = 0.4, and it is
   force-critical anyway — by clause **1** (internet + any/any), not clause 3.
   Narrow the service to `tcp/1433` and the same rule, still opening the crown
   jewel to the whole internet, drops out of the floor entirely.

   Three edges of the same gap worth knowing separately:

   - **`dest_tags` is the *emitting tool's* tag list, not the merged asset's.** An
     AlgoSec rule naming `db-prod-01` directly still scores D = 0.4 when only Wiz
     tagged that host — no subnet involved. The graph node carries the merged tags
     (`build.py` unions them); `over_permissive` scores from `rec.dest_tags`.
   - **The engine proves the containment and then ignores it.** With the broad rule
     ordered first, `shadowing` fires on the narrow one — `cidr_overlap.covers`
     establishes destination-CIDR containment from `dest_cidrs` — and reports it as
     dead config. The machinery for the fix already exists one module over, and the
     finding it currently produces reads as *reassurance* about the host now exposed.
   - **The property is enforced for proposed rules and not for ingested ones.**
     `change/simulate.resolve_dest_tags` aggregates tags by containment, and
     `test_change_simulate.py::test_a_wider_cidr_never_narrows_the_tag_set` pins the
     exact inverse invariant ("a caller cannot dilute a regulated destination by
     aiming at its whole subnet"). That invariant holds at the change gate and
     nowhere else in the engine.
6. **Rule state the canonical model does not carry — `enabled` / `disabled` and
   negated address fields — is now REFUSED rather than honoured.** `PolicyRecord`
   still has no enable flag and no negation flag, and honouring the semantics is
   scheduled work (`REQUIREMENTS.md` `FUT-P3-2` / `FUT-P3-4`, the same phase as the
   ingest path). What changed is the failure mode: both were **silently dropped**,
   and the two wrong answers that produced point in opposite directions —

   - a **disabled** rule was scored as if it were live: a measured **100/critical**
     on a rule that is switched off, *plus* a fabricated `shadowed_rule` beneath it
     reading "dead deny: blocked traffic is actually allowed" (over-reporting a
     grant that does not exist);
   - a **negated** source was read as its own complement. `allow NOT 10.0.0.0/8 →
     db-prod-01 tcp/3389` — a rule whose source *is* the internet — was read as
     `10.0.0.0/8` and reported **85/critical, "RDP open from INTERNAL"**: the exact
     inverse of the truth, and the under-reporting direction.

   `profile.require_rule` now raises `NormalizeError` naming the rule when a row
   carries a truthy `disabled`/`inactive`, a falsy `enabled`/`active`, or any key
   whose canonical spelling contains `negate` (so `srcNegate`, `negate_source` and
   `dst-negate` are one rule); `require_token` refuses the inline spelling
   `!10.0.0.0/8` that pf / iptables / some Palo exports write in the column itself.
   All four normalizers route their rows through it. This is the module's own
   published contract — "what it is never allowed to be is *normalize something
   else and say nothing*" — finally applied to rule state.

   **So the gap that remains is a modelling gap, not a silence:** a real export
   using either construct now fails loudly at ingest instead of producing a
   confident wrong number. Nothing bundled today reaches it — there is no upload
   path and no API client, `normalize_all()` reads three fixed files from
   `data/mock/`, `app.main` rewrites those from `scenarios.py` before every lazy
   engine build and every `/api/recompute`, and no generated fixture carries either
   key.

7. **A malformed address object lowers the reported risk instead of raising it.**
   `profile.object_cidrs` returns `cidrs == []` for an unparseable value
   (`10.0.0.0/33`, `300.1.1.1/24` — typos that are almost always in a *broad*
   rule), the record carries `source_cidrs == []`, and `exposure_score` falls back
   to `E_IDENTITY` = **0.1**, the exposure of a single host. Measured:
   `allow BAD-OBJ -> db-prod-01 tcp/22` with the db tagged `pci`+`prod` scores
   **41, not forced**, and clears none of `sensitive_dest_min_E` (0.3) or
   `broad_source_E` (0.5) — so **SSH to a PCI database produces no finding at
   all.** Two mitigations exist and neither changes the number: the object is
   marked `abstract` (fail-closed for *traversal*, so it cannot become a path
   pivot), and `profile.token_audit` writes one `malformed: true` audit row per
   affected rule so the defect is at least visible in `resolved_objects`. The
   scoring outcome is unchanged, and that is the direction that matters.

   *Check it rather than trusting this paragraph:*
   `score_over_permissive(source="BAD-OBJ", source_kind="identity", protocol="tcp",
   port=22, dest_tags=["pci","prod"], src_zone="internal", dst_zone="internal",
   source_cidrs=[])` → `severity 41, forced_critical False`. If that returns a
   forced critical when you run it, this item is closed and should be moved into
   the "Fixed" block below with its call sites named.

8. **L7 application identity is inferred from the FIRST port interval's start
   port** (`normalizers/common._infer_l7`, called with `pstart`) — the same
   "scored as its start port" shape `port_score` eliminated for P, still live for
   `l7_app`. Widening a service can therefore *remove* a finding:

   ```
   udp/443       -> l7='quic'              quic_blind_spot fires
   udp/443-8443  -> l7='quic'              fires, but only because 443 is first
   udp/400-500   -> l7=None                *** the QUIC blind spot disappears ***
   udp/1-65535   -> l7=None                *** disappears, and this opens 443 ***
   udp/80,443    -> l7='http3-discovery'   fires, titled after port 80
   any           -> l7=None                no L7 at all
   ```

   It propagates: `reachability._grant_matches` answers an app-scoped query by
   `grant["l7_app"] == app`, so *"what can reach X over QUIC?"* also misses a
   `udp/1-65535` grant, and `l7_app` is written in exactly one place and never
   enriched afterwards. The `tls_fallback_not_blocked` half of §6.5 is **not**
   affected — it works on decoded intervals, not on `l7_app`.


### Scale — measured, not estimated

The product is sold on "a real 5,000-rule AlgoSec export" (`db.py:206` says so in
as many words). On a **realistic multi-tool export at that size**, `run()` does not
finish in a usable time, and the analyzer that costs the most returns nothing:

| rules | nodes / edges | over_perm | cidr_overlap | shadowing | **path_trace** | total | peak RSS |
|---|---|---|---|---|---|---|---|
| 1,000 | 224 / 886 | 0.007 | 0.006 | 0.127 | 0.094 | **0.26 s** | 51 MB |
| 2,000 | 401 / 1,813 | 0.016 | 0.014 | 0.538 | 7.83 | **8.5 s** | 58 MB |
| 3,000 | 573 / 2,747 | 0.024 | 0.020 | 1.234 | 40.9 | **42.3 s** | 64 MB |
| 5,000 | 926 / 4,645 | 0.038 | 0.030 | 3.13 | **1,265.7** | **1,269 s (21 min)** | 78 MB |
| 10,000 | 1,821 / 9,322 | 0.085 | 0.085 | 14.08 | *aborted at 900 s* | — | 112 MB |

`path_trace` consumed **99.7%** of the runtime at 5,000 rules and returned **0
findings** at every size in that table. It runs **synchronously on the request
path** with no timeout, no progress and no partial result. Of the 18
internet-reachable sensitive targets at 5,000 rules, nine hit the 4,000-path cap in
0.2–2.5 s each and nine yielded *zero* paths within a 20 s budget while never
tripping the cap (§10.3: the cap counts yields, so a target that never yields is
unbounded); one of those, given 600 s, took **142.9 s to produce its first path**.
The BFS reachability closure over the same graph answers in **0.000 s**.

Two further limits on the same curve:

- **`cidr_overlap` emits O(n²) *findings*, not merely O(n²) work.** On the ordinary
  "every branch office to the DC on 443" shape — nested sources, one destination
  group, one service — 5,000 rules produced **12,497,500 findings and 12 GB peak
  RSS** (1,000 rules: 499,500 findings / 1.3 GB). Nothing caps the output.
- **`shadowing` is clean O(n²)**: 0.40 s at 1,000 rules, 6.8 s at 4,000, **27.0 s
  at 8,000**, extrapolating to ≈11 minutes at 40,000. This is the *correct*
  analyzer being expensive — it simply does not bucket by destination and service
  before the ordered-pair scan.

**The bundled scale fixture does not exercise any of this.** `scenarios._scale` /
`scripts/seed_scale.py` completes 5,000 rules in **0.51 s** where the realistic
export takes **1,269 s** — 2,480× apart at identical rule count, because the
generated shape produces few candidate paths. The 27-rule demo fixture is two to
three orders of magnitude below the cliff, and `scripts/verify_engine.py` passes in
0.34 s while asserting nothing about scale. **Do not read a green
`verify_engine.py` as evidence that the engine holds at the advertised size.**

> **Fixed, and no longer gaps.** This section previously confessed five defects
> that no longer exist, and §9 confessed a sixth (the narrow snapshot
> fingerprint). They are listed here so that a reader who greps a cited line,
> finds working code, and reasonably starts doubting everything else on this page
> has the answer in front of them. **Every bullet names all of its call sites,
> and each is a grep you can run.** The previous edition of the third bullet named
> two of five and read as a closure; that is precisely the failure this block
> exists to prevent, so the correction is written into the bullet itself.
>
> - *"Port match is substring, not numeric"* — `reachable()`'s filter used to
>   match `f"/{port}"` inside the service string, so `port=3` matched `tcp/3389`.
>   `reachability.py:_grant_matches` / `_edge_matches` now do structured
>   protocol / port-range / L7-app matching per grant, with `start <= port <= end`,
>   and every filtered call in the module routes through them.
>   *Grep:* `grep -rn 'f"/{port}"' backend/src` → nothing.
> - *"A port range is scored from its start port"* — `severity.port_score` takes
>   the whole interval set (`ports: list[tuple[int, int]]`), returns the max class
>   over it by walking `PORT_CLASS_P` most-severe-first, and treats a span wider
>   than `PORT_SPAN_ANY` as any-port (§5.1). `port_score_from_service` hands it
>   every interval `parse_service` decoded, so the string and structured paths
>   agree. *Grep:* `grep -n "def port_score" backend/src/analyzers/severity.py`.
> - *"'The internet' is the literal string `0.0.0.0/0`"* — **closed in all five
>   places that ask the question**, each now delegating to the one address-space
>   classifier instead of holding a private answer:
>   1. `graph.zones.zone_of` → `netaddr.is_public` (§4);
>   2. the guardrail floor, `severity.is_internet_source` → `netaddr.is_public` (§5.4);
>   3. the reporting gate standing in front of that floor —
>      `over_permissive._reasons` now calls the same `is_internet_source`. It was
>      still `E >= 1.0`, so a rule the floor forced critical could be discarded
>      *before* the floor ever ran (§6.1);
>   4. the entry point of path tracing — `reachability.cross_tool_paths` and
>      `who_can_reach` take their entry set from `reachability.internet_entries(g)`,
>      every node the graph stamped `ZONE_INTERNET`, instead of keying on
>      `INTERNET_CIDR` (§6.4, §7);
>   5. the change gate's force-escalation arm —
>      `change.simulate._internet_sensitive_paths` calls that same
>      `internet_entries` (§8).
>
>   *Grep:* `grep -rn 'INTERNET_CIDR\|"0\.0\.0\.0/0"' backend/src` — the surviving
>   hits are the constant's definition (`netaddr.ANY_V4`,
>   `normalizers.common.INTERNET_CIDR`), the Wiz normalizer *writing* an internet
>   entity, a fixture, prose, and **one display-only test that is not a decision**:
>   `advisory/explain.py:32` labels a finding "the internet (0.0.0.0/0)" only on
>   the literal spelling, so the deterministic fallback sentence for a rule sourced
>   from `ANY-EXTERNAL` prints the object name instead. The score, the band, the
>   force-critical flag and the gate ruling are unaffected — but it is the same
>   class, so it is named here rather than left to be found.
>
>   The earlier edition of this bullet cited only (1) and (2), and was true about
>   both. It was still an over-claim, because (3), (4) and (5) are the sites that
>   decide what a buyer is shown and what an operator may approve — and a reader
>   who greps a cited line, finds `is_public`, and reasonably stops checking would
>   have been misled by a sentence in which every individual word was accurate.
> - *"A named network object is a concrete node and can pivot"* — a
>   `network`/`group`/`range`/`subnet` object (and any object resolving to more
>   than one address) is marked abstract by `normalizers.profile.object_is_abstract`,
>   `graph.build` stamps `kind="abstract"` on the node, and
>   `reachability._valid_traversal` therefore treats `DC-SUBNETS` and the literal
>   `10.0.0.0/8` alike: a legitimate path endpoint, never an intermediate hop.
>   *Grep:* `grep -n "_valid_traversal" -A8 backend/src/graph/reachability.py`.
> - *"A mixed IPv4/IPv6 record set raises TypeError"* — `cidr_overlap.covers` and
>   `cidr_overlap._overlaps` guard every comparison with `netaddr.same_family` and
>   report incomparable families as disjoint rather than crashing; `shadowing` does
>   not do its own arithmetic — it imports that same `covers`
>   (`from .cidr_overlap import covers`), so one guard covers both analyzers.
>   *Grep:* `grep -n "same_family" backend/src/analyzers/cidr_overlap.py`.

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
