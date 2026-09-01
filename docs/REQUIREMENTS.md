# Software Requirements Specification — Network Policy Reviewer (NPR)

> **What this document is.** A reverse-engineered, as-built specification of the Network
> Policy Reviewer. It is written so that a team handed *only* this document would build
> the product **exactly as it stands today** — same architecture, same contracts, same
> scope, same deliberate simulations. Every requirement below is implemented in the
> current tree and traced to the file that implements it.
>
> **What it is not.** An aspirational spec. Requirements that are *not yet* built live in
> §14 (Future Features), derived from `docs/PROD-READINESS-AUDIT.md`, and are marked
> `FUT-*`. Nothing in §1–§13 is a plan; it is a description.

| | |
|---|---|
| **Product** | Network Policy Reviewer (NPR) — cross-tool network-policy risk consolidation |
| **Baseline** | Current `main` (post QUIC/L7 decoding, post change-pipeline) |
| **Document version** | 1.0 — as-built baseline, 2026-08-10 |
| **Companion docs** | `README.md` (overview) · `docs/ENGINE.md` (math) · `docs/AGENTS.md` (agentic layer) · `docs/FEATURES.md` (USP catalog) · `docs/SSO.md` · `docs/DEPLOY.md` · `docs/PROD-READINESS-AUDIT.md` (independent audit) |

---

## Contents

1. [Purpose, scope and conventions](#1-purpose-scope-and-conventions)
2. [Product overview and goals](#2-product-overview-and-goals)
3. [Users, roles and permissions](#3-users-roles-and-permissions)
4. [System context and architecture constraints](#4-system-context-and-architecture-constraints)
5. [Ingestion and normalization](#5-ingestion-and-normalization-ing)
6. [Identity resolution](#6-identity-resolution-idn)
7. [Policy graph and reachability](#7-policy-graph-and-reachability-grp)
8. [Risk analysis and the severity model](#8-risk-analysis-and-the-severity-model-anlsev)
9. [Change pipeline](#9-change-pipeline-chg)
10. [AI advisory and agentic layer](#10-ai-advisory-and-agentic-layer-ai)
11. [API, dashboard and administration](#11-api-dashboard-and-administration-apiuiadm)
12. [Persistence, security and non-functional requirements](#12-persistence-security-and-non-functional-requirements-datsecnfr)
13. [Acceptance criteria and known limitations](#13-acceptance-criteria-and-known-limitations-acclim)
14. [Future features — roadmap from the production-readiness audit](#14-future-features--roadmap-from-the-production-readiness-audit-fut)

---

## 1. Purpose, scope and conventions

### 1.1 Purpose

`PR-1` The system **shall** consolidate network-policy exports from multiple security
tools into one canonical policy model and one reachability graph, detect policy risk
deterministically, explain and prioritise that risk in natural language, and gate
proposed policy changes against the computed impact of those changes.

`PR-2` The system **shall** be demonstrable end-to-end on a laptop with no internet
connection and no hosted AI key, using seeded, simulated tool exports.

### 1.2 Scope of this release

**In scope (built):** canonical policy model; deterministic identity resolution; policy
graph and reachability; five risk analyzers; an auditable severity model with guardrail
floors; change simulation, an AI change gate, a staging area and a *simulated* push;
eleven AI advisory/agentic capabilities over six deterministic engine tools; a
thirteen-screen dashboard; a Postgres system of record; OIDC SSO with three application
roles; a cross-platform task runner.

**Explicitly out of scope (deliberate, not oversight):**

| ID | Non-goal | Rationale as built |
|---|---|---|
| `PR-3` | Live connectors to AlgoSec / Guardicore / Wiz | Exports are simulated fixtures; the canonical model downstream is real, so swapping adapters for API clients is the only change needed. |
| `PR-4` | Writing changes back to a source system | The push is simulated and must be labelled as such; the conflict math it animates is genuine engine math. |
| `PR-5` | Customer-data upload / ingestion path | The engine reads three fixed files under `backend/data/mock`. See `LIM-4`. |
| `PR-6` | Deny-precedence in effective policy | Effective policy is the union of `allow` edges; a non-shadowed deny does not subtract. Documented in `ENGINE.md` §10.1. |
| `PR-7` | Any model-computed fact | Reachability, subnet math and severity are Python-only. See `PR-8`. |

### 1.3 The governing rule

`PR-8` **The deterministic engine shall own all facts and math** — normalization, identity
resolution, CIDR/subnet math, reachability, shadowing, effective policy, change deltas,
conflict math, severity. **The AI layer shall own only language and judgment** —
explaining, ranking, classifying, drafting. A model **shall never** compute reachability
or subnet math; it **shall** call deterministic tools and reason over their structured
results. Every requirement in §10 is subordinate to this one.

### 1.4 Conventions

- **shall** = mandatory. **should** = strongly expected, one implementation exists.
- Each requirement carries an ID (`AREA-n`) and a *Where* trace to the implementing file.
- Paths are relative to the repository root; backend paths omit the `backend/src/` prefix
  where stated.
- Numeric constants quoted in this document are **normative**: `ENGINE.md` publishes them
  and clients are invited to recompute scores by hand from them.

---

## 2. Product overview and goals

### 2.1 The problem

`PR-9` An estate is governed by several disjoint policy tools — a firewall manager
(AlgoSec), a microsegmentation product (Guardicore) and a cloud exposure scanner (Wiz).
Each console is authoritative for its own slice and blind to the others. The highest-value
risk — a multi-hop path into sensitive data whose hops are enforced by *different* tools —
is therefore invisible to every individual console.

### 2.2 The product goal

`PR-10` The system **shall** surface exactly that class of risk. The canonical
demonstration is the path

```
Internet → lb-public-01 → app-server-07 → internal-app → db-prod-01
```

which crosses **three** tools into PCI/customer data and **shall** be force-flagged
critical. This path **shall** emerge from generic predicates over the canonical model —
it **shall not** be hardcoded, name-matched, or otherwise special-cased anywhere in
`graph/` or `analyzers/`.

### 2.3 Product principles (binding on all sections)

| ID | Principle |
|---|---|
| `PR-11` | **Determinism.** Identical inputs **shall** yield byte-identical snapshot ids, findings, scores and ordering. No randomness, no timestamps, no model output in the fact path. |
| `PR-12` | **Auditability.** Every score **shall** ship its own input vector so a client can recompute it by hand from published tables. |
| `PR-13` | **Provenance.** Every canonical record **shall** carry the source tool and the vendor rule id it came from. Parallel grants **shall** be preserved, not collapsed. |
| `PR-14` | **Fail-closed judgment.** Where a model's output governs a decision, an unusable output **shall** resolve to the conservative outcome (escalate / needs-review / deterministic fallback), never to a crash and never to the permissive outcome. |
| `PR-15` | **The engine is the judge.** A model proposal **shall** be honoured only after the deterministic engine has proven it. |

---

## 3. Users, roles and permissions

`RL-1` The system **shall** support three application roles, resolved from the identity
provider and, where multiple are held, resolved to the **highest**: `admin > analyst > viewer`.

| Role | SSO app role | Intended grants |
|---|---|---|
| `admin` | `npr_admin` | Everything, plus the admin console: users, snapshots, per-role capability toggles, usage metrics, dataset switching, demo reset |
| `analyst` | `npr_analyst` | Full read + AI advisory; submit **and** approve/reject change requests; run remediation campaigns |
| `viewer` | `npr_viewer` | Read-only: findings, graph, reports, evidence |

`RL-2` A user holding **no** recognised role **shall** be authenticated but not entitled,
and **shall** be routed to a `/no-access` screen with a real retry that issues a fresh
authorization request. There **shall be no** implicit `viewer` fallback.

`RL-3` The bare names `admin` / `analyst` / `viewer` **shall** also be accepted, and the
mapping from IdP role name to application role **shall** be overridable by configuration
(`SSO_ROLE_MAP`) without a code change.

`RL-4` The directory-wide role claim (`autox:roles`) **shall** be read for display and
audit only and **shall never** be an authorization input.

- *Where:* `frontend/auth.ts`, `frontend/auth.autox.ts`, `docs/SSO.md`, `backend/src/request_ctx.py`

> **As-built enforcement gap.** `RL-1`'s viewer restriction is enforced on some routes and
> not others; see `LIM-6` and `FUT-P0-3`. This document records the intent *and* the gap.

---

## 4. System context and architecture constraints

### 4.1 Component decomposition

`ARC-1` The system **shall** be composed of three deployable parts and one database:

```
 Simulated exports          Deterministic engine (Python)          AI advisory (pluggable)      Dashboard
 AlgoSec  ─┐                 normalize → resolve identity              explain · rank · classify     Next.js
 Guardicore├─▶ normalizers ─▶ → graph → analyzers → severity ─▶ findings ─▶ remediate · report · ask ─▶ (EY-branded,
 Wiz      ─┘   (+ profiles)   reachability · change-delta            agent = tools, never math       React Flow)
                                       │                                        │
                                       ▼                                        ▼
                             Postgres (Neon, ztpa schema) ◀── system of record ─┘   audit_log
```

| ID | Component | Requirement | Stack as built |
|---|---|---|---|
| `ARC-2` | Backend | FastAPI application exposing the engine and the advisory layer over HTTP | FastAPI, pydantic v2, `networkx`, `ipaddress`, psycopg 3 |
| `ARC-3` | Engine | A pure-Python library with no HTTP, no model and no I/O in its fact path | `backend/src/` |
| `ARC-4` | Frontend | Next.js App Router dashboard, EY-branded, dark + light | Next 14, Tailwind, Framer Motion, React Flow (`@xyflow/react`), Auth.js v5 |
| `ARC-5` | Database | Neon Postgres, all objects in the `ztpa` schema | `db/schema.sql`, `db/auth_schema.sql`, `db/sso_schema.sql` |

`ARC-6` The canonical data contracts **shall** be defined once, as pydantic v2 models, and
**shall** be the single vocabulary spoken by normalizers, graph, analyzers, advisory,
change pipeline and API alike.
- *Where:* `models.py` — `PolicyRecord`, `Finding`, `ChangeRequest`, `ChangeDecision`, `RankedAction(s)`, `Asset`, `AssetCorrelation`, `Snapshot`

`ARC-7` The advisory layer **shall never** mutate a model instance. It **shall** read facts
and return separate language.

### 4.2 Runtime constraints

| ID | Requirement |
|---|---|
| `ARC-8` | Every FastAPI route handler **shall** be a synchronous `def`, never `async def`, so slow model calls run on the threadpool and cannot block the event loop. This applies to all 46 endpoints. |
| `ARC-9` | The engine **shall** be built once into a process-level singleton and warmed in a background thread at startup, so the first request does not pay the build cost. |
| `ARC-10` | Actor identity (role, email, subject) **shall** be propagated per request via a `ContextVar` set by pure-ASGI middleware, and any client-supplied `x-npr-*` header **shall** be stripped before the middleware sets its own. |
| `ARC-11` | The database layer **shall** be written for a serverless Postgres: connection-health check on checkout, `max_lifetime`/`max_idle` cycling, `search_path` set once per connection and committed, every table also schema-qualified, and graceful degradation when the pool library is absent. |

- *Where:* `app/main.py` (`_ActorMiddleware`, `_ENGINE`, `_warm`), `src/request_ctx.py`, `src/db.py`

---

## 5. Ingestion and normalization (`ING`)

### 5.1 Sources

`ING-1` The system **shall** ingest three tool exports, each with its own adapter, and
**shall** treat them as *simulated but structurally representative* of the real product's
export format:

| Source tool | Character of the export | Adapter |
|---|---|---|
| `algosec` | Firewall rulebase: ordered rules, named address objects, service strings | `normalizers/algosec.py` |
| `guardicore` | Microsegmentation policy: label-based source/destination, App-IDs | `normalizers/guardicore.py` |
| `wiz` | Cloud exposure findings: public exposure of cloud resources | `normalizers/wiz.py` |

`ING-2` The canonical `SourceTool` vocabulary **shall** additionally reserve `sd_wan` and
`sd_lan` for profile-authored connectors.

`ING-3` Reading the three exports **shall** be a fixed, deterministic step over three known
filenames under `backend/data/mock/`.
- *Where:* `normalizers/__init__.py:normalize_all`

### 5.2 The canonical policy record

`ING-4` Every rule from every tool **shall** normalize to one `PolicyRecord` meaning
exactly *"source X may (or may not) reach destination Y on service Z"*, independent of
origin console.

`ING-5` `PolicyRecord` **shall** carry, at minimum:

| Field | Type | Purpose |
|---|---|---|
| `id` | str | Deterministic content id |
| `source_tool`, `raw_ref` | str | Provenance back to the vendor rule id (`PR-13`) |
| `source`, `source_kind` | str, `cidr\|identity` | Who |
| `destination`, `destination_kind` | str, `cidr\|identity` | To what |
| `dest_tags` | list[str] | Destination sensitivity tags, resolved from the identity layer |
| `service`, `port`, `port_end`, `protocol` | str, int?, int?, `tcp\|udp\|icmp\|sctp\|any` | L4 |
| `l7_app`, `l7_source` | str?, `declared\|inferred` | L7 App-ID **and how it was determined** |
| `action` | `allow\|deny` | |
| `order` | int? | Position within the source rulebase, for shadowing |
| `source_ip`, `dest_ip`, `note` | str? | UI metadata; **never** used by subnet math |

- *Where:* `models.py:PolicyRecord`

### 5.3 Service decoding — L4 and L7

`ING-6` Service decoding **shall** return a single structured `DecodedService` carrying
protocol, port, port range end, display label, L7 app and L7 provenance. It **shall not**
return a bare tuple.
- *Where:* `normalizers/common.py:parse_service`

`ING-7` The decoder **shall** recognise explicit application identity tokens in a source
export (`quic`, `http3`, `tls`, `dns`, `ssh`, …) and mark them `l7_source="declared"`.

`ING-8` Where no App-ID is declared, the decoder **shall** *infer* the likely application
from `(protocol, port)` through a fixed lookup table (`udp/443 → quic`, `udp/53 → dns`,
`tcp/443 → tls`, …) and mark it `l7_source="inferred"`.

`ING-9` L7 inference **shall** be a deterministic table lookup. It **shall not** be a model
call. The declared/inferred distinction **shall** be auditable on every record.

`ING-10` The decoder **shall** parse port ranges into `port`/`port_end`.
- *Where:* `config.py` — `L7_APPS`, `APP_BY_PORT`, `APP_TRANSPORT`, `INSPECTION_BLIND_APPS`

### 5.4 Named-object resolution

`ING-11` Where a source export references named address objects, the adapter **shall**
build an object catalog and record it as `resolved_objects` for audit.

`ING-12` A record whose source or destination is a name rather than an address **shall**
be marked `source_kind="identity"` / `destination_kind="identity"`.

> **As-built constraint (`LIM-1`).** The AlgoSec adapter resolves a named object to its
> CIDR and then discards the resolved value, keeping only the label. Downstream scoring
> therefore reasons over a *string that names* an address space rather than the address
> space itself. This is the single highest-impact defect in the audit and is fixed by
> `FUT-P1-1`.

### 5.5 Declarative connector profiles (bring-your-own source)

`ING-13` The system **shall** support a declarative `SourceProfile` — configuration, not
code — describing where rules live in an unknown export and which fields map to source,
destination, service, action, ref and app.

`ING-14` A profile **shall** be applied by a generic deterministic normalizer producing
ordinary `PolicyRecord`s, so a new source requires no new Python.
- *Where:* `normalizers/profile.py:apply_profile`

`ING-15` Profile validation **shall** be performed by *actually normalizing the supplied
sample* — not by schema inspection alone — and **shall** report which fields were unmapped.

> **As-built constraint (`LIM-2`).** `apply_profile` has exactly one caller: the authoring
> validator. There is no profile registry and no ingestion through an approved profile;
> the feature is a **design-time preview**. See `FUT-P3-1`.

---

## 6. Identity resolution (`IDN`)

### 6.1 Requirement

`IDN-1` The system **shall** merge each tool's view of the same host into one canonical
asset, so that `appsrv-07` (Wiz) and `app-server-07` (AlgoSec/Guardicore) resolve to one
identity. **IP is an attribute, not a key.**

`IDN-2` This merge **shall** be the mechanism that makes cross-tool paths visible at all —
without it the graph has two disconnected components and the money-shot path does not
exist.

### 6.2 Algorithm

`IDN-3` Resolution **shall** be a union-find (disjoint set) over all observed names, using
**deterministic signals only**. A wrong merge corrupts a fact, so no fuzzy signal may
drive it.

`IDN-4` Names **shall** be unioned on exactly these signals:

| Signal | `match_key` | Confidence label |
|---|---|---|
| Different names observed at the same concrete IP | `context_ip` | 0.95 |
| The same name observed by more than one tool | `hostname` | 1.0 |
| A human-confirmed merge of a reviewed suggestion | `manual_review` | 1.0 |

`IDN-5` Confidence values **shall** be fixed audit labels on exact-match merges, **not**
computed probabilities, and **shall** be documented as such.

`IDN-6` The union root **shall** be `parent[max(ra, rb)] = min(ra, rb)` — the
lexicographically smaller name always wins — so the result is independent of input order.

`IDN-7` The canonical key for a merged component **shall** be the name used by the most
tools, breaking ties to the lexicographically smallest name.

`IDN-8` Resolution **shall** emit an `alias_map` (every observed name → canonical key) and
an `AssetCorrelation` audit row per merge, carrying the match key, the confidence label and
the evidence.

`IDN-9` Every iteration point in the resolver **shall** be explicitly sorted (nine sites as
built), so no set/dict iteration order can leak into output.

- *Where:* `identity.py`

### 6.3 Suggestions vs. merges

`IDN-10` The embedding-based duplicate-asset suggester **shall only propose** merges for
human review. It **shall never** auto-merge.

`IDN-11` A confirmed merge **shall** be persisted and **shall** be re-applied on subsequent
engine runs; an unmerge **shall** revoke it.
- *Where:* `advisory/entity_suggest.py`, `app/main.py:/api/assets/merge`, `/api/assets/unmerge`

> **As-built constraint (`LIM-3`).** The IP union is keyed on the bare IP string with no
> VRF/VPC/tenant scope, and `ObservedEntity` has no context field — so duplicate RFC1918
> addressing across segments, shared VIPs and placeholder addresses can fuse unrelated
> hosts transitively. Fixed by `FUT-P1-4`.

---

## 7. Policy graph and reachability (`GRP`)

### 7.1 Graph construction

`GRP-1` The system **shall** build a directed graph (`networkx.DiGraph`) of *allowed*
connections from the canonical records.

`GRP-2` Nodes **shall** be one per canonical asset, carrying `kind` (`concrete`/`abstract`),
`tags`, `ip_set`, `display`, `zone` and `tools`. A source or destination not matching a
known asset (`0.0.0.0/0`, a bare subnet) **shall** be added as an `abstract` node.

`GRP-3` Edges **shall** be one per allowed `(source → destination)` pair, and **shall**
carry **every** grant between those two nodes as a list, plus the union of contributing
tools, services and L7 apps. Parallel grants **shall be kept, not collapsed** (`PR-13`).

`GRP-4` Only `allow` records **shall** become edges (`PR-6`).

- *Where:* `graph/build.py`

### 7.2 Zones and the trust-boundary multiplier

`GRP-5` A node's zone **shall** be a deterministic lookup: the internet node → `internet`;
tags → `dmz` (`dmz`/`internet-facing`/`public`) or `dev` (`dev`/`sandbox`/`test`), most
exposed tag winning; everything else → `internal`.

`GRP-6` The boundary multiplier **B** **shall** scale severity by direction of crossing:

| src → dst | B |
|---|---|
| internet → internal | **1.5** |
| dmz → internal | **1.25** |
| dev → internal | **1.25** |
| any other pair | **1.0** |

`GRP-7` `internet → dmz` **shall** be 1.0 by design — a DMZ asset is *meant* to face the
internet, so that direction is expected, not a violation.
- *Where:* `graph/zones.py`, `config.py:BOUNDARY_MULTIPLIERS`

### 7.3 Reachability

`GRP-8` All path logic **shall** be real graph traversal over the directed allow graph. It
**shall never** be re-derived, summarised or approximated by a model.

`GRP-9` The engine **shall** expose three reachability primitives:

| Primitive | Contract |
|---|---|
| `cross_tool_paths(g, sensitive_tags)` | For each sensitive target reachable from `0.0.0.0/0`, enumerate simple paths (cutoff 8 hops), keep those spanning ≥ 2 distinct source tools, dedupe, sort by `(length, path)` |
| `reachable(src, dst, port, protocol, app)` | Yes/no plus the path(s), with **structured** protocol / port-range / app matching |
| `who_can_reach(target)` | Effective-policy view: which nodes reach a target, and whether the internet does |

`GRP-10` Port/app matching **shall** be structural (protocol equality-or-`any`, port
interval containment, app match). Substring matching on a service label **shall not** be
used.

`GRP-11` Path enumeration **shall** be bounded by a scan cap (`_PATH_SCAN_CAP = 4000`
candidate paths per source/target pair) so the engine stays bounded at thousands of nodes.

`GRP-12` A path that **pivots through** an abstract node **shall** be rejected
(`_valid_traversal`): a subnet or internet node may be an endpoint but never an
intermediate hop — reaching hosts inside a range does not let an attacker *originate* as
that range.

- *Where:* `graph/reachability.py`

> **As-built constraints.** (`LIM-7`) `who_can_reach` uses a bare path existence check
> without the `_valid_traversal` filter, so it can disagree with `reachable` on the same
> snapshot — fixed by `FUT-P0-2`. (`LIM-8`) The scan cap truncates silently, with no
> `truncated` signal on the finding or the API — fixed by `FUT-P3-3`.

---

## 8. Risk analysis and the severity model (`ANL`/`SEV`)

### 8.1 Pipeline

`ANL-1` Analysis **shall** run as five ordered, deterministic stages:

```
normalize → resolve identities → build graph → analyze (5 detectors) → score + finalize
```

`ANL-2` Findings **shall** be sorted by one stable total order:
`(forced_critical first, −severity, band_order, type, id)` — so a guardrail-forced finding
always outranks an equally-severe unforced one and ties break deterministically.
- *Where:* `analyzers/run_all.py`

### 8.2 The five detectors

`ANL-3` The system **shall** implement five independent detectors, each emitting `Finding`s
with a stable local key:

| # | Detector | Predicate | Scoring |
|---|---|---|---|
| `ANL-4` | **Over-permissive** | any of: `protocol == "any"`; internet source with `P ≥ 0.85` or a sensitive dest; sensitive dest reachable from wider than a single host (`E ≥ 0.3`); admin/data port open to a broad source (`E ≥ 0.5`) | Full formula + guardrail floor |
| `ANL-5` | **CIDR overlap / redundancy** | Group allows by `(tool, destination, service)`; compare source networks with `subnet_of` / `overlaps`; report `contains` or `overlaps` | Fixed: `10`, `+20` if either dest is sensitive or either source is broad (≤ /8) — always low band |
| `ANL-6` | **Rule shadowing** | Within a tool's ordered rules, a later rule whose source ⊆ an earlier rule's source, same destination, overlapping service. Only the **earliest** shadower is reported | Shadowed **deny** = dangerous → full formula. Shadowed **allow** = dead config → fixed `10` |
| `ANL-7` | **Cross-tool path tracing** | Every simple path from the internet to a sensitive-tagged asset that spans **≥ 2 distinct source tools** | Full formula: entry as E, terminal tags as D, last-hop service as P, path boundary as B |
| `ANL-8` | **Transport exposure (L7)** | `quic_blind_spot`: `udp/443` (or another inspection-blind app) reachable from a lower-trust zone to a sensitive dest. `tls_fallback_not_blocked`: both `tcp/443` and `udp/443` open, so the inspectable path cannot be forced | `severity.score_transport_exposure` |

`ANL-9` `ANL-8` **shall** exist because QUIC/HTTP-3 rides UDP/443 and most legacy firewalls
cannot inspect it — a `udp/443` allow is an **inspection blind spot**, a class of risk a
single-console tool does not distinguish from plain UDP.

- *Where:* `analyzers/{over_permissive,cidr_overlap,shadowing,path_trace,transport_exposure}.py`

### 8.3 The severity model

`SEV-1` Severity **shall** be `risk = likelihood × impact`, with impact **capped by
destination value**, so a dev-sandbox finding can never outrank a crown-jewel one.

`SEV-2` Severity **shall** be built from four sub-scores, each a **categorical lookup**
(policy facts, deliberately not formulas), combined by one multiplicative formula.

**E — exposure breadth** (from the source prefix length):

| `/0` (also "any") | `/1–/8` | `/9–/16` | `/17–/23` | `/24–/27` | `/28–/32` | identity/label |
|---|---|---|---|---|---|---|
| 1.0 | 0.9 | 0.7 | 0.5 | 0.3 | 0.1 | 0.1 |

**P — port/service sensitivity:**

| Class | Members | P |
|---|---|---|
| any protocol | `protocol == "any"` | 1.0 |
| admin / lateral movement | 22, 23, 135, 445, 3389, 5985, 5986 | 1.0 |
| data store | 5432, 3306, 1433, 27017, 6379 | 0.9 |
| infra control plane | 6443, 2379 | 0.85 |
| general app / web | 80, 443, 8080, 8443, 53, 123 | 0.4 |
| unknown / ephemeral | anything else | 0.5 |

**D — destination sensitivity** (max over the destination's tags):

| crown-jewel | pci / customer-data / phi | prod | dev / sandbox / test | untagged |
|---|---|---|---|---|
| 1.0 | 0.9 | 0.6 | 0.2 | 0.4 |

**B — boundary multiplier:** per `GRP-6`.

`SEV-3` The combination **shall** be exactly:

```
impact          = D × (0.5 + 0.5·P)          # impact_base + impact_p_weight·P
exposure_factor = 0.4 + 0.6·E                # exposure_floor + exposure_span·E
raw             = impact × exposure_factor × B
severity        = round(100 × min(raw, 1.0)) # 0..100
```

with the invariants: `impact ∈ [0, D]`; `exposure_factor ∈ [0.4, 1.0]` so a single-host
source still keeps 40% weight; `B ≥ 1.0` so a boundary can only ever raise a score.

`SEV-4` Bands **shall** be lower-inclusive: `≥ 80` critical, `≥ 60` high, `≥ 35` medium,
else low.

`SEV-5` Every finding **shall** ship its own `signals["severity_vector"]`, so any published
score is reproducible by hand from §8.3 (`PR-12`).

- *Where:* `analyzers/severity.py`, `config.py`

### 8.4 Guardrail floors (force-critical)

`SEV-6` Separately from the smooth score, categorically unacceptable patterns **shall** be
force-flagged critical regardless of the computed number, so that no downstream model error
can bury a true emergency. For over-permissive rules, any of:

- internet source **and** `protocol == "any"`;
- internet source **and** an admin/lateral port (22/23/135/445/3389/5985/5986);
- a **sensitive** destination (crown-jewel/pci/customer-data/phi) reachable from the internet.

`SEV-7` A cross-tool path **shall** be force-critical when it crosses `internet → internal`
**and** reaches a sensitive asset.

`SEV-8` A forced finding **shall** carry `severity_band = "critical"` even when
`severity < 80`, and `forced_critical = true`.

`SEV-9` **Worked example (normative).** `allow 0.0.0.0/0 → db-prod-01 tcp/3389`, db tagged
`pci`, internet → internal:

```
E = 1.0 · P = 1.0 · D = 0.9 · B = 1.5
impact          = 0.9 × (0.5 + 0.5·1.0) = 0.90
exposure_factor = 0.4 + 0.6·1.0         = 1.00
raw             = 0.90 × 1.00 × 1.5     = 1.35
severity        = round(100 × min(1.35, 1.0)) = 100      → critical, also forced
```

This example **shall** reproduce to exactly 100.

### 8.5 Calibration

`SEV-10` All calibration constants **shall** live in one module so scoring can be retuned
without touching logic, and re-runs **shall** stay byte-identical: `impact_base` 0.5,
`impact_p_weight` 0.5, `exposure_floor` 0.4, `exposure_span` 0.6, bands 80/60/35,
`overlap_base` 10, `overlap_sensitive_bump` 20, `overlap_broad_prefixlen` 8,
`shadowed_allow_base` 10, `broad_source_E` 0.5, `sensitive_dest_min_E` 0.3,
`admin_data_min_P` 0.85, boundary multipliers 1.5/1.25, path cutoff 8, scan cap 4000.
- *Where:* `config.py`

### 8.6 Determinism and identifiers

`SEV-11` Every identifier **shall** be a stable function of content — SHA-1 over
sorted-JSON of the defining fields — so a cold re-run UPSERTs byte-identical rows:

```
det_id("F", snapshot_id, local_finding_key) → F_<sha1[:16]>
snapshot_id(label, content_fingerprint)     → snap_<sha1[:12]>
content_fingerprint(*blobs)                 → <sha1[:40]>
```

`SEV-12` A finding id **shall** be a database key, **not** a user-facing label; the
assistant **shall** be instructed never to print one.

`SEV-13` There **shall be** no `random`, no timestamp and no model output anywhere in the
fact path.
- *Where:* `ids.py`, `analyzers/run_all.py:_fingerprint`

> **As-built constraint (`LIM-5`).** The snapshot fingerprint hashes only
> `tool|ref|source|destination|service|action|order`. Asset tags, the object catalog,
> protocol/port/L7 decoding and the applied manual merges do **not** change the snapshot
> id, so the id identifies the *rule set*, not the *analysis*. Fixed by `FUT-P1-5`.

---

## 9. Change pipeline (`CHG`)

### 9.1 Simulation and delta

`CHG-1` A proposed rule **shall never** be classified in isolation. The engine **shall**
first compute what newly becomes reachable, and only then may a model judge that delta.

`CHG-2` The delta **shall** be computed as:

```
base_graph = build_graph(records)
new_graph  = build_graph(records + [proposed])

new_paths     = internet→sensitive paths in new_graph absent from base_graph
new_exposed   = terminal assets of those new paths
boundaries    = trust boundaries the new paths (and the rule itself) cross
new_over_perm = over-permissive predicates the rule itself trips
```

`CHG-3` The delta **shall** set `forced_escalate = true` when the change opens ≥ 1 new
internet path to a sensitive asset, trips an over-permissive guardrail reason, introduces
an any/any rule, or creates new `internet → internal` exposure.

`CHG-4` Simulation **shall** be side-effect free: a fresh graph per call, copied records,
and **no** module-level cached graph.
- *Where:* `change/simulate.py`

### 9.2 The change gate (three layers)

`CHG-5` The gate **shall** apply exactly three layers, in this order:

| Layer | Requirement |
|---|---|
| **1 — Deterministic guardrail** | Catastrophic patterns **shall** force-escalate **before any model call is made**. Confidence 0.99. |
| **2 — Model judge, fail-closed** | The model rules on the *computed delta plus gathered evidence*. Missing, unparseable or invalid output **shall** resolve to `escalate`. |
| **3 — Engine override** | Even where the model says `auto_approve`, a non-clean delta **shall** force `escalate`. |

`CHG-6` The model **shall** be able to *narrow* the approval envelope and **shall never** be
able to widen it. Prompt injection in the requester's justification **shall not** be able to
raise the risk tolerance; the justification **shall** be passed to the model explicitly
labelled **UNTRUSTED**.

`CHG-7` The decision **shall** be computed from the delta on every run and **shall never**
be stored as a canned verdict. There **shall be no** request field through which a client
can supply its own verdict.

`CHG-8` The final auto-approve/escalate determination **shall** be recorded as made by the
engine (`model: "engine"`), not by the model.
- *Where:* `advisory/classify_change.py`, `app/main.py:/api/change/classify`

### 9.3 Staging and push

`CHG-9` An approved or overridden change **shall** be sendable to a **Staging Area**, where
it is held with its originating request, decision and target tool.

`CHG-10` Staging **shall** run deterministic **conflict detection** against the current
canonical rules *and* against sibling staged changes for the same tool, surfacing
duplicates, CIDR overlaps, shadowing denies, contradictions and stale targets — each with a
deterministic resolution.

`CHG-11` For a restrictive (remediation) change, the only conflict class **shall** be a
**stale target**: the rule it edits no longer exists in this snapshot.

`CHG-12` The push **shall** be a *simulated*, stepped operation returning an ordered plan
the UI animates, so an operator watches conflicts resolve. The conflict math **shall** be
genuine engine math (`PR-4`).

`CHG-13` A pushed change **shall** be recorded as a durable overlay re-applied on
subsequent recomputes.
- *Where:* `change/staging.py`, `change/apply.py`, `app/main.py:/api/staging*`

> **As-built constraint (`LIM-9`).** The push UI narrates "Connected to the AlgoSec policy
> data source" and "Applied to AlgoSec — data source updated" for an operation that
> contacts nothing, and a conflict resolved as "Skip: no-op" is still appended. Truth-in-
> labelling is `FUT-P0-6`.

### 9.4 Unified pipeline

`CHG-14` The three change surfaces **shall** compose into one pipeline:

```
Risk To-Do (draft + iterate a fix, with reviewer comments)
    → Change Gate (evaluate the computed delta, rule on it)
        → Staging Area (conflict math)
            → Push (simulated)
```

---

## 10. AI advisory and agentic layer (`AI`)

### 10.1 Provider model

`AI-1` Every capability **shall** talk to one provider-pluggable client, resolved per call:

| `ADVISORY_PROVIDER` | Resolution |
|---|---|
| `auto` (default for a fresh clone) | Local Ollama if reachable with a model pulled; else OpenAI if keyed; else Anthropic if keyed |
| `ollama` | Always local |
| `openai` | Always OpenAI (`OPENAI_MODEL`, default `gpt-4o`) |
| `anthropic` | Always Anthropic (`ADVISORY_MODEL`) |

`AI-2` The system **shall** run end-to-end **with no AI key at all**: every capability
**shall** have a deterministic fallback (`PR-14`).

`AI-3` Local-first inference **shall** be the default posture, because network topology and
policy are the estate's attack map — the most sensitive data it owns. Running locally means
that data never leaves the host, at zero per-call cost, with an offline, rate-limit-free
demo.

`AI-4` Model calls **shall** be bounded by timeouts with retry, so a cold local model
degrades to the fallback rather than hanging the HTTP request.

`AI-5` Every model and tool call **shall** be metered to `ai_metrics` with provider, model,
capability, tokens, latency, role and an estimated USD cost (local Ollama = $0).
- *Where:* `advisory/client.py`, `settings.py:active_provider`, `metrics.py`, `config.py:est_cost_usd`

> **As-built constraint (`LIM-10`).** The shipped Render blueprint pins
> `ADVISORY_PROVIDER=openai`, and tool-calling is implemented **only** on the Ollama path —
> so on the documented hosted deployment the assistant answers from a precomputed
> finding-title blob rather than from tool results. Fixed by `FUT-P0-8` (disclosure) and
> `FUT-P4-1` (parity).

### 10.2 The deterministic engine tools

`AI-6` The engine **shall** expose exactly six deterministic tools to the model layer, all
pure Python requiring no key:

| Tool | Returns |
|---|---|
| `resolve` | A name or CIDR → its canonical asset (tags, IPs, source tools, zone) |
| `reachable` | Can source reach destination (optionally on a port)? yes/no + the path(s) |
| `find_paths` | All paths source → destination, with the tools each hop crosses |
| `effective_policy` | What can actually reach an asset, and whether it is internet-exposed |
| `risk_findings` | The deterministic findings, filterable by type / minimum severity |
| `simulate_change` | The delta a proposed allow rule would create |

- *Where:* `agent/tools.py`

### 10.3 The capabilities

`AI-7` The system **shall** provide these advisory capabilities, each registered in one
capability registry with a description, an example output and a per-role enable flag:

| # | Capability | Kind | Endpoint |
|---|---|---|---|
| 1 | Change-request triage (auto-approve vs escalate) | agentic, guardrailed, fail-closed | `POST /api/change/classify` |
| 2 | "Ask your network" assistant | agentic tool-calling over the engine | `POST /api/agent/ask` |
| 3 | Plain-English explanation of a finding | language | `POST /api/findings/{id}/explain` |
| 4 | Root-cause grouping + worst-first ranking | judgment | `GET /api/actions` |
| 5 | Remediation fix-as-code, re-simulated to prove it resolves | language + judgment | `POST /api/findings/{id}/remediate` |
| 6 | Remediation **campaign** across all findings | agentic, cumulative | `GET/POST /api/campaign/plan`, `POST /api/campaign/submit` |
| 7 | Executive / PCI-DSS / Zero-Trust posture report | language | `GET /api/report/narrative` |
| 8 | Change-intake extraction (free text → structured rule) | language → structure | `POST /api/intake` |
| 9 | Connector authoring from a sample export | agentic, engine-validated | `POST /api/connectors/propose` |
| 10 | Entity-resolution **suggestions** for human review | embeddings | `GET /api/assets/merge-suggestions` |
| 11 | Embeddings (backing #10) | embeddings | internal |

### 10.4 Agent loop requirements

`AI-8` **Remediation loop.** The model **shall** propose a structured change
(`remove` / `scope_source` / `restrict_service` / `reorder_before`) against a rule ref from
the finding's facts; the engine **shall** apply it to a copy of the records and **re-run
all analyzers**; the model **shall** see that verdict and revise, up to `MAX_ATTEMPTS = 3`.
A fix **shall** be accepted only when the engine certifies it resolves the target finding
and introduces no new critical. If no clean model fix is found, a deterministic fallback
**shall** be used and re-validated.

`AI-9` The remediation output **shall** include `fix_text`, the structured `change`, the
engine `validation`, `by` (provenance) and a `trace` of every attempt with its engine
verdict, so a human can read *"scope R-14 → still reachable → remove R-14 → resolved."*

`AI-10` A reviewer's comment **shall** be feedable into the same loop as the first round's
feedback, so human iteration reuses the agent rather than bypassing it.

`AI-11` **Campaign.** The campaign **shall** plan worst-first across all findings and drive
the critical count toward zero, re-simulating after every step so each fix is judged against
the **cumulative** record set, not the original snapshot. A candidate **shall** be applied
only if it removes its target and opens no new critical; otherwise it **shall** be marked
`needs_review` and skipped. **The campaign shall be structurally incapable of making the
posture worse.**

`AI-12` The campaign **shall** output the `criticals_trajectory` (e.g. `[4,3,2,1,0]`),
ordered steps with each sub-loop's trace, `residual_findings` and `cleared_all_criticals`;
**shall** be persisted per snapshot so navigating away and back re-uses the plan; and
**shall be advisory only** — submission routes each proven step through the Change Gate as
its own request.

`AI-13` **Triage investigator.** Before ruling, the model **shall** be allowed to gather
evidence in a bounded ReAct loop (`MAX_TOOL_CALLS = 4`), each turn returning either
`{tool, args}` or `{done: true}`. Tool results **shall** be real engine computations; a
hallucinated tool name or bad args **shall** be recorded as evidence, never raised as a
crash. This loop **shall** be provider-portable (plain JSON completions) and fail-open — no
model means empty evidence and a decision on the delta alone.

`AI-14` **Connector authoring.** The model **shall** propose a profile; the engine **shall**
validate it by normalizing the real sample; the concrete failure reason ("zero records →
`rules_path` is wrong", "rows missing source → that field name is wrong") **shall** be fed
back for up to 3 rounds; a never-validating profile **shall** be returned as the best
partial, flagged `needs_review`. At runtime the model is gone — only the deterministic
profile normalizer runs.

`AI-15` **Every agent shall** be bounded (hard round/tool-call caps + per-call timeout),
**shall** have a deterministic fallback, **shall** return a `trace` for human audit, and
**shall** be judged by the engine (`PR-15`).

- *Where:* `advisory/{remediation,campaign,classify_change,authoring,explain,rank,report,intake,entity_suggest,orchestrator}.py`, `agent/{tools,assistant}.py`

### 10.5 Capability gating

`AI-16` Each capability **shall** be enable-able per role from an admin screen, backed by a
`tool_settings` table, and a disabled capability **shall** 403 for that role.

> **As-built constraint (`LIM-11`).** An absent `tool_settings` row defaults to *all roles*,
> and a DB error with a cold cache also yields the default-on map. This is a **feature-flag
> layer, not an authorization boundary**, and must not be relied on to restrict write paths.

---

## 11. API, dashboard and administration (`API`/`UI`/`ADM`)

### 11.1 HTTP API

`API-1` The backend **shall** expose the following 46 endpoints. All are synchronous `def`
(`ARC-8`).

| Group | Endpoints |
|---|---|
| **Health & snapshot** | `GET /api/health` · `POST /api/recompute` · `GET /api/scenarios` · `GET /api/snapshots` · `DELETE /api/snapshots/{id}` · `GET /api/snapshot` |
| **Engine reads** | `GET /api/graph` · `GET /api/findings` · `GET /api/findings/{fid}` · `GET /api/assets` · `GET /api/rule/{ref}` · `GET /api/ingest` · `GET /api/actions` · `POST /api/actions/recompute` |
| **Advisory** | `POST /api/findings/{fid}/explain` · `POST /api/findings/{fid}/remediate` · `POST /api/findings/{fid}/remediate/refine` · `GET /api/findings/{fid}/remediation-thread` · `GET /api/report` · `GET /api/report/narrative` · `POST /api/intake` · `POST /api/connectors/propose` |
| **Agentic** | `POST /api/agent/ask` · `GET /api/agent/suggestions` · `GET /api/campaign/plan` · `POST /api/campaign/plan` · `POST /api/campaign/submit` |
| **Identity** | `GET /api/assets/merge-suggestions` · `POST /api/assets/merge` · `POST /api/assets/unmerge` · `GET /api/assets/merges` |
| **Change** | `GET /api/change-requests` · `POST /api/change/classify` · `GET /api/change-decisions` · `POST /api/change/submit` · `POST /api/change/reject` |
| **Staging** | `POST /api/staging` · `GET /api/staging` · `POST /api/staging/{id}/push` · `DELETE /api/staging/{id}` |
| **Admin** | `POST /api/admin/dataset` · `POST /api/admin/reset-demo` · `GET /api/admin/tools` · `POST /api/admin/tools/{key}` · `GET /api/admin/metrics` · `GET /api/audit` |

`API-2` Read endpoints **shall** accept an optional `snapshot` parameter so a historical
snapshot can be viewed read-only.

`API-3` CORS **shall** be restricted to the configured frontend origin; the normal request
path **shall** be server-to-server through the Next.js proxy.

- *Where:* `app/main.py`

### 11.2 Dashboard

`UI-1` The dashboard **shall** present thirteen screens behind one console shell, with a
role-aware sidebar:

| Screen | Requirement |
|---|---|
| **Network Map** | One graph assembled from all three tools; a stat row (tools → one model, canonical rules, unified assets, findings, criticals, cross-tool paths); protocol/app filtering; a **Trace cross-tool path** action that animates the money-shot chain with each hop labelled by the enforcing tool; a scale banner when the graph is large |
| **Risk To-Do** | Findings collapsed into worst-first ranked actions; per-finding plain-English "why this matters"; **Draft & validate a fix** showing the engine's re-simulation verdict and the agent's trace; reviewer comments; L7 chips; send-to-gate |
| **Change Gate** | Pick a demo request or type a custom change → evaluate → auto-approve/escalate with all criteria shown, the triggering reason, and the investigation evidence trail |
| **Staging Area** | Staged changes, detected conflicts with their deterministic resolutions, and the stepped push animation |
| **Ask the Network** | Free-text Q&A with the tool trace rendered |
| **Posture Report** | Executive / PCI-DSS / Zero-Trust narrative written from the deterministic findings, plus the deterministic breakdown |
| **Connectors** | Paste a sample export → propose connector → the profile, the validation and the authoring trace |
| **Assets & Identity** | One identity per asset with its merge evidence, plus duplicate-asset suggestions for review |
| **Ingested data** | The raw-to-canonical inspector |
| **Snapshots** *(admin)* | List, view historically, delete |
| **Tools & Usage** *(admin)* | Per-role capability enable/disable |
| **Metrics & Cost** *(admin)* | KPI/cost dashboard over `ai_metrics` |
| **Manage users** *(admin)* | User administration |

`UI-2` The topbar **shall** carry the active snapshot, a recompute action with a stepped
progress overlay, and the provider/residency indication.

`UI-3` Historical snapshot views **shall** be read-only.

`UI-4` The product **shall** be EY-branded and **shall** support dark and light themes.

- *Where:* `frontend/app/console/page.tsx`, `frontend/components/*`

> **As-built constraint (`LIM-12`).** 20 frontend call sites swallow errors with
> `.catch(() => {})` and the error banner is fed only by `/api/health`, which reports `ok`
> even when the database is down — so a dead backend renders as "0 findings, 0 prioritized
> actions" rather than as an error. This is the single most damaging UX defect in the audit;
> fixed by `FUT-P0-5`.

### 11.3 Administration and operations tooling

`ADM-1` An admin **shall** be able to switch the active dataset between the seeded demo and
a generated scale scenario of size *n*.

`ADM-2` An admin **shall** be able to reset the demo to its seeded state.

`ADM-3` All orchestration **shall** go through one cross-platform task runner requiring only
a system Python on PATH — no `make`, no bash, no `psql` — supporting: `setup`, `db`, `seed`,
`seed-scale`, `precompute`, `precompute-ai`, `demo`, `backend`, `frontend`, `dev`, `verify`,
`admin`, `set-password`, `send-reset`, `stop`, `help`.

`ADM-4` A cold run **shall** reproduce the demo identically: deterministic ids yield
byte-identical rows, the dashboard reads the precomputed snapshot from Postgres, and only
the AI calls run live.

- *Where:* `tasks.py`, `backend/scripts/{seed_demo,seed_scale,precompute,precompute_ai,verify_engine}.py`

---

## 12. Persistence, security and non-functional requirements (`DAT`/`SEC`/`NFR`)

### 12.1 System of record

`DAT-1` Postgres **shall** be the system of record, with every object in a dedicated `ztpa`
schema.

`DAT-2` The schema **shall** carry these tables: `snapshots`, `sources`, `resolved_objects`,
`assets`, `asset_correlations`, `canonical_rules`, `graph_nodes`, `graph_edges`, `findings`,
`ranked_actions`, `change_requests`, `change_decisions`, `audit_log`, `ai_metrics`,
`tool_settings`, `remediation_revisions`, `staged_changes`, `campaign_plans`; plus
`app_users` and `auth_tokens` for local authentication.

`DAT-3` Ids **shall** be deterministic TEXT, so re-running a snapshot UPSERTs identical rows
(`SEV-11`).

`DAT-4` Persistence **shall** write the full engine result: assets, correlations, canonical
rules (including `l7_app` and port ranges), graph nodes and edges, findings with their
signals, and ranked actions.

`DAT-5` Governance actions **shall** be written to `audit_log`.

`DAT-6` AI usage **shall** be written to `ai_metrics` (`AI-5`).

- *Where:* `db/schema.sql`, `src/persist.py`, `src/db.py`

> **As-built constraint (`LIM-13`).** Clearing a snapshot's children is implemented by
> deleting the parent `snapshots` row, and `change_requests.snapshot_id` is
> `ON DELETE CASCADE` — so a recompute destroys the change-request and decision history for
> that snapshot. Fixed by `FUT-P0-4`.

### 12.2 Authentication and authorization

`SEC-1` The frontend **shall** authenticate against an OIDC provider using authorization
code + **PKCE (S256)**, with `state` and `nonce`, and **shall** verify the ID token
(ES256) against the provider's JWKS, taking endpoints from discovery.

`SEC-2` Authorization **shall** be driven by the application-role claim, resolved per `RL-1`.

`SEC-3` `offline_access` **shall not** be requested — no refresh tokens, therefore no
rotation/reuse-detection races. Role freshness **shall** instead be handled by an
**absolute** (not rolling) session deadline, default 3600 s, so a role revocation takes
effect within that window.

`SEC-4` Setting the SSO client id **shall** turn SSO on **and** unregister the password and
magic-link providers, so they cannot be used as an SSO bypass, unless a cutover flag is
explicitly set.

`SEC-5` Logout **shall** be RP-initiated with `id_token_hint` and a registered
post-logout redirect URI.

`SEC-6` User rows **shall** be keyed on the IdP `sub`, never email; an existing unlinked
local row **shall** be claimed by email **only** when the email is verified, and its local
password cleared. Provisioning **shall** be a side effect of successful authentication —
a failed upsert logs and sign-in continues; local state **shall never** deny sign-in.

`SEC-7` The sign-in screen **shall** probe the IdP's health endpoint and poll until it
returns its own JSON `{"status":"ok"}` before redirecting, because a status code alone does
not distinguish a cold start from readiness.

`SEC-8` The proxy **shall** forward `x-npr-role` / `x-npr-email` / `x-npr-sub` to the
backend for per-role capability gating and usage attribution, and the backend **shall**
strip any client-supplied `x-npr-*` header before setting its own.

`SEC-9` Every backend query **shall** use parameter binding; secrets **shall** live only in
a git-ignored `.env` (locally) or an encrypted platform variable (deployed); there
**shall be** no `NEXT_PUBLIC_*` variables.

- *Where:* `frontend/auth*.ts`, `frontend/middleware.ts`, `src/request_ctx.py`, `docs/SSO.md`

> **As-built constraint (`LIM-6`).** `SEC-8`'s trust model requires the backend to be
> reachable only through the proxy, but the shipped blueprint deploys it as a public
> service with no shared secret; and nine mutating endpoints carry no role guard at all
> (`/api/recompute`, `/api/campaign/plan`, `/api/campaign/submit`, `/api/actions/recompute`,
> `/api/assets/merge`, `/api/assets/unmerge`, `POST /api/staging`, `POST /api/staging/{id}/push`,
> `DELETE /api/staging/{id}`). Fixed by `FUT-P0-3`.

### 12.3 Non-functional requirements

| ID | Requirement | As built |
|---|---|---|
| `NFR-1` | **Determinism.** Full engine output — snapshot id, assets, alias map, correlations, all finding fields including signals, sorted nodes and edges — **shall** hash identically across separate processes and across hash seeds. | Verified across 5 processes × 5 `PYTHONHASHSEED` values |
| `NFR-2` | **No demo hardcoding.** No seeded asset name, rule id or path **shall** appear in `graph/` or `analyzers/` outside prose docstrings. | Verified: zero matches |
| `NFR-3` | **Offline operation.** The full demo **shall** run with no internet, no hosted key, and a local model. | `PR-2`, `AI-2` |
| `NFR-4` | **Portability.** Setup and orchestration **shall** work on Windows, macOS, Linux and WSL from one runner. | `ADM-3` |
| `NFR-5` | **Cost observability.** Every AI call **shall** be priced and attributable by capability, provider, model and role. | `AI-5` |
| `NFR-6` | **Graceful AI degradation.** A model that is unreachable, slow or emitting garbage **shall** produce a deterministic outcome, never a crash. | `PR-14`, `AI-15` |
| `NFR-7` | **Bounded engine work.** Path enumeration **shall** be capped; model loops **shall** be capped in rounds and wall-clock. | `GRP-11`, `AI-15` |
| `NFR-8` | **Honest disclosure.** Documentation **shall** volunteer the engine's known simplifications rather than let a reader discover them. | `ENGINE.md` §10 |

> **As-built performance profile (measured in the audit; see `FUT-P3-3`).** Shadowing and
> CIDR-overlap are O(n²) per group — ~11.5 s at 2,000 rules, ~25 s at 10,000, ~5 min at
> 40,000. Identity resolution is ~3.3 s at 2,000 merged assets. Path enumeration on a
> 34-node mesh takes ~117 s; the shipped scale fixture is a star topology and therefore does
> not exercise it. `NFR-7` bounds *yielded paths*, not DFS backtracking.

---

## 13. Acceptance criteria and known limitations (`ACC`/`LIM`)

### 13.1 Engine acceptance checks

`ACC-1` A single command (`python tasks.py verify`) **shall** re-run the engine on the
seeded dataset and assert these golden acceptance predicates:

| Check | Assertion |
|---|---|
| P1 | An any/any finding is present **and** `forced_critical` |
| P2 | An RDP→PCI finding is present **and** `forced_critical` |
| P3 | A CIDR-overlap finding is present **and** in the low band |
| P4 | A shadowed-deny finding is present **and** in the low band |
| P5 | A cross-tool path finding is present, critical, is exactly the 5-hop chain, `reaches_sensitive`, and spans **3 tools** |
| P6 | A QUIC blind-spot finding from the internet is present, `forced_critical`, with `l7_app == "quic"` |
| P7 | A TLS-fallback-not-blocked finding is present |

- *Where:* `backend/scripts/verify_engine.py`

`ACC-2` A test suite **shall** cover the agentic layer's guarantees, including: that the
engine's rejection verdict physically reached the next prompt; that the guardrail path made
**zero** model calls; that an LLM `auto_approve` on an unsafe delta is overridden; and that
campaign criticals are monotonically non-increasing. It **shall** pass fully offline with a
dead database and a dead model socket.
- *Where:* `backend/tests/test_agents.py` (16 tests)

`ACC-3` The product **shall** support a ~7-minute demo script covering: consolidation → the
money-shot path → prioritised risk with a proven fix → the change gate refusing an
injected "URGENT, pre-approved" request → tool-grounded Q&A → bring-your-own-source →
posture report and identity.
- *Where:* `DEMO.md`

### 13.2 Known limitations of this build

These are the deliberate or accepted gaps in the as-built product. They are the input to
§14 and are stated here so the requirements above are not read as claims they do not
support.

| ID | Limitation | Fixed by |
|---|---|---|
| `LIM-1` | The canonical model keeps a named object's **label** and discards its resolved CIDR, so a real export using named objects scores `E=0.1` and produces **fewer** findings than the demo | `FUT-P1-1` |
| `LIM-2` | Connector authoring is design-time preview only; there is no profile registry and no ingestion through an approved profile | `FUT-P3-1` |
| `LIM-3` | Identity merges on a bare IP with no tenancy/VRF scope, transitively, with no sentinel-address guard | `FUT-P1-4` |
| `LIM-4` | There is no ingestion path, and the engine regenerates the three input files on each build — so a file placed in the input directory is overwritten | `FUT-P3-1` |
| `LIM-5` | `snapshot_id` is a fingerprint of the rule rows only, not of the analysis | `FUT-P1-5` |
| `LIM-6` | Nine mutating endpoints have no role guard; the actor boundary is a proxy-injected header with no shared secret | `FUT-P0-3` |
| `LIM-7` | `who_can_reach` and `reachable` can disagree on the same snapshot | `FUT-P0-2` |
| `LIM-8` | Path-scan truncation is silent | `FUT-P3-3` |
| `LIM-9` | Staging narrates a live push that does not happen, and a "skip" resolution still appends | `FUT-P0-6` |
| `LIM-10` | Tool-calling is Ollama-only; the shipped hosted deployment degrades silently | `FUT-P0-8`, `FUT-P4-1` |
| `LIM-11` | Per-role capability toggles are default-on feature flags, not an authorization boundary | `FUT-P0-3` |
| `LIM-12` | Failures render as empty state; there is no application logging | `FUT-P0-5`, `FUT-P2-2` |
| `LIM-13` | A recompute cascade-deletes the change-request and decision audit trail | `FUT-P0-4` |
| `LIM-14` | The severity model is blind to port ranges, treats "the internet" as the literal string `0.0.0.0/0`, and mixed IPv4/IPv6 input raises | `FUT-P1-2`, `FUT-P1-3` |
| `LIM-15` | The custom-change path of the Change Gate has never executed successfully (a 6-field dataclass is unpacked into 3 names) | `FUT-P0-1` |
| `LIM-16` | Nothing tests the deterministic core: 6 of 10 injected engine defects pass both `pytest` and `verify` green | `FUT-P1-6` |
| `LIM-17` | Analyzers are O(n²) and unbounded in wall-clock; the scale fixture cannot exercise path enumeration | `FUT-P3-3` |
| `LIM-18` | `README.md` and `FEATURES.md` overreach where `ENGINE.md` §10 is honest | `FUT-DOC-*` |

---

## 14. Future features — roadmap from the production-readiness audit (`FUT`)

> Source: `docs/PROD-READINESS-AUDIT.md` — 9 independent auditors over the full source,
> every finding handed to an adversarial verifier instructed to refute it, plus a
> completeness critic. **159 findings raised, 4 refuted, 155 survived.** Empirical probes
> (mutation testing, input perturbation, cross-process determinism, scale timing) were run
> against the real engine.
>
> **Audit verdict.** The determinism, provenance and guardrail architecture are genuinely
> well built. The math is correct for the one data encoding the demo fixture happens to use;
> it has no tests on its own arithmetic; and the layers wrapped around it (authz,
> persistence, error handling) turn every failure into a confident, silent, wrong-looking-
> fine screen. **Effort sizes below: (S)** ≤ 1 day · **(M)** days · **(L)** 1–2 weeks.

### 14.0 Priority-zero quick wins (< 1 day each)

| ID | Change | Payoff |
|---|---|---|
| `FUT-QW-1` | Use `svc = parse_service(...)` at `main.py:584` instead of tuple-unpacking `DecodedService` | Un-breaks "Simulate a custom change", dead since the initial commit. **Ship with `FUT-QW-2` — alone it opens an auto-approve hole** |
| `FUT-QW-2` | Resolve `dest_tags` from the engine inside `simulate_change` | No caller can strip the tags that drive the guardrail |
| `FUT-QW-3` | Version-check before `subnet_of` in `cidr_overlap._relation` and `shadowing._covers` | Two lines stop one IPv6 rule permanently 500-ing every route |
| `FUT-QW-4` | Align `_ACTIVE_SCENARIO` with the precompute label | Makes the whole precompute-AI step actually take effect — today zero cached explanations are ever served |
| `FUT-QW-5` | Branch the Topbar overlay on `busy.result.error` | Removes the most misleading pixel in the product: a green tick and "Snapshot recomputed" on a 500 |
| `FUT-QW-6` | Add a provider/residency chip bound to the existing `health.ai` payload | Backend already computes `data_residency` and the type is already declared — no component reads it |
| `FUT-QW-7` | Gate the dev magic-link on `NODE_ENV !== 'production'` | Closes a ten-second unauthenticated takeover of any known email on pre-SSO deployments |
| `FUT-QW-8` | Remove `rejectUnauthorized: false` and stop stripping `channel_binding` in `frontend/lib/db.ts` | Restores both defences on the connection carrying password hashes and role assignments |
| `FUT-QW-9` | Add `cmd_test` + `.github/workflows/ci.yml` + `pyproject.toml` with `pythonpath=['backend']` | 16 good tests are installed but orphaned; the suite already passes offline |
| `FUT-QW-10` | Populate `backend/conftest.py` (currently 0 bytes) with an autouse fixture stubbing `record_metric`/`ollama_probe` and blanking `DATABASE_URL` | Stops local `pytest` writing junk rows into the live `ai_metrics` table; cuts the offline suite 61 s → ~5 s |
| `FUT-QW-11` | Have `db.audit()` read `request_ctx.current()` itself | Turns an event log into an audit trail in one function; no call site can forget the identity |
| `FUT-QW-12` | Bound `DatasetBody.n` and every `limit` with `Field(ge=…, le=…)` | Removes a 500 on `?limit=-1` and an unbounded synchronous engine rebuild |
| `FUT-QW-13` | Record and read back real `ranked_by` provenance instead of hardcoding `'llm'` | Stops the Report tab attributing deterministic buckets to the LLM in front of a client |
| `FUT-QW-14` | Delete the unconditional `taskkill /F /IM node.exe` in `tasks.py` | Stops a documented command killing every Node process on the developer's machine |

### 14.1 Phase 0 — Stop the bleeding *(1 week, 2–3 engineers)*

**Goal:** every screen is either correct or **visibly** failed. No engine math changes.

| ID | Requirement | Size |
|---|---|---|
| `FUT-P0-1` | Fix the custom-change crash **and** the `dest_tags` hole in one commit (`FUT-QW-1` + `FUT-QW-2`) | S |
| `FUT-P0-2` | Reimplement `who_can_reach` on the same primitive as `reachable` — a reverse BFS that refuses to expand through abstract nodes — and return the witness path, so the two tools are provably consistent | M |
| `FUT-P0-3` | Add `require_approver` (admin\|analyst) and `require_operator` (admin) dependencies to the nine unguarded mutating routes; make staging check role unconditionally; add a proxy shared secret compared with `hmac.compare_digest`, rejecting any `x-npr-*` request without it | M |
| `FUT-P0-4` | Stop deleting the parent `snapshots` row to clear children — delete engine-owned tables explicitly and make `change_requests.snapshot_id` a plain column (or `ON DELETE SET NULL`); add `campaign_plans` to the cache-clear list | M |
| `FUT-P0-5` | Give the console a per-resource `{status: loading\|ok\|error}` state machine; replace every `.catch(() => {})`; **never render a zero count while a dependent fetch is errored**; make the fetch wrapper throw a typed `ApiError` carrying status + detail so a 403 reads as a permissions message | M |
| `FUT-P0-6` | Truth-in-labelling on Staging and the recompute overlay: prefix simulated steps with "Simulated", return `simulated: true` in the push plan, and never render a green check on failure | S |
| `FUT-P0-7` | Stand up CI: `tasks.py test`, `pyproject.toml`, `conftest.py`, `.github/workflows/ci.yml` (pytest + verify + typecheck), ESLint config | S |
| `FUT-P0-8` | Surface the residency signal already on the wire — a Topbar chip reading "Hosted — data leaves this host" whenever the active provider is not Ollama | S |

**Exit criteria.** `POST /api/change/classify` with a custom body returns 200 with a decision
(proven by a TestClient test) · `effective_policy(a).internet_exposed == reachable('0.0.0.0/0', a).reachable`
for every asset, asserted as a property test · a viewer receives 403 from all nine routes,
asserted by a parametrised test · two recomputes leave the decision row count unchanged ·
killing the backend renders an explicit error panel and `grep` for `.catch(() => {})` returns
zero hits · CI runs green on push.

### 14.2 Phase 1 — Make the engine's math defensible *(3 weeks)*

**Goal:** fix arithmetic that is wrong on valid input, and pin all of it with tests.
**Test-first: write the failing table-driven test, then fix.**

| ID | Requirement | Size |
|---|---|---|
| `FUT-P1-1` | **Carry the resolved value, not the label.** Add `source_cidrs`/`dest_cidrs` to `PolicyRecord`, populate from the object catalog in every normalizer, and drive exposure scoring, CIDR overlap and shadowing off the resolved list — falling back to `E_IDENTITY` only when an object genuinely has no address. Recognise `any`/`Any`/`ANY`/`all` as `0.0.0.0/0`. Mark network/group/range/subnet object types abstract | M |
| `FUT-P1-2` | **Make scoring range-aware and protocol-honest.** `port_score` takes `port_end` and returns the max class over the interval; thread `port_end` through over-permissive, both port guardrails, transport exposure and staging conflict math; map `ip`/`all` to protocol `any`; add `gre`/`esp`/`ah`; parse comma-separated port lists; validate `0 ≤ port ≤ 65535` and `lo ≤ hi`; return explicit `unparsed`/`warnings` instead of coercing | M |
| `FUT-P1-3` | **Classify address space instead of comparing strings.** Replace `node_key == '0.0.0.0/0'` and `E >= 1.0` with a shared `is_public(net)` built on `ipaddress`, handling `::/0` and any zero-prefix network; make the cross-tool force-critical guardrail independent of the destination zone label | M |
| `FUT-P1-4` | **Scope the identity merge.** Add `context` (VPC/account/VRF/tenant) to `ObservedEntity`, key the union on `(context, ip)`, and **do not union when context is unknown** — emit an `entity_suggest` candidate instead. Maintain a sentinel-address ignore set (`0.0.0.0`, `127/8`, `169.254/16`, `::`, `::1`), cap merge fan-out, refuse to union entities with mutually exclusive env tags, return a suppressed-merge counter, and fix `_host_cidr` to use `max_prefixlen` | M |
| `FUT-P1-5` | **Make the snapshot id a real content hash:** fold protocol, port, `port_end`, `l7_app` and sorted `dest_tags` into the per-record string, plus a sorted digest of the entity/object view, the applied manual merges and the applied-change overlay ids | S |
| `FUT-P1-6` | **Write the tests that pin all of the above:** `test_severity.py` (table-driven exact values across the 34/35/59/60/79/80 band boundaries, one case per sensitivity tag, one per guardrail clause independently), `test_engine_invariants.py`, `test_determinism.py` (cross-process, full dump), `test_normalizers.py`, `test_reachability.py`, and `verify_engine` split into a pytest golden test | M |
| `FUT-P1-7` | Guard the analyzer suite so one bad input cannot take down a snapshot: version checks, per-analyzer try/except recording a degraded-analyzer marker, and a guard around the engine build so a bad dataset yields a diagnosable 4xx rather than a poisoned singleton | S |

**Exit criteria.** The same policy expressed four ways (`0.0.0.0/0`, `any`, a named object
resolving to `0.0.0.0/0`, an address group) yields **identical** severity, band and
`forced_critical` · `0.0.0.0/0 → host tcp/1-65535` produces a forced-critical finding ·
a mixed IPv4/IPv6 record set completes without raising · `0.0.0.0/1` and `1.0.0.0/8`
classify as internet and score within one band of `0.0.0.0/0` · **all 10 injected engine
defects now fail pytest (6 of 10 currently pass green)** · a cross-process determinism test
asserts SHA-256 equality of the full dump · unscoped IP collisions emit `manual_review`
instead of unioning · changing only a tag, an object CIDR or the merge list yields a
different snapshot id.

### 14.3 Phase 2 — Make the system of record trustworthy *(2 weeks)*

**Goal:** governance records survive, carry identity, and are observable. Migrations become
real. This is what turns a dashboard into something a compliance function can accept.

| ID | Requirement | Size |
|---|---|---|
| `FUT-P2-1` | Stop silent degradation on inputs that change the **answer**: merge/overlay load failures raise a specific `EngineInputError` so recompute returns 503 and leaves the previous snapshot intact; mark the result `persisted=False` on write failure and return 503 rather than an empty 200; add a global exception handler returning `{error, request_id}` | M |
| `FUT-P2-2` | Add structured logging, mint an `X-Request-Id` in middleware and bind it to every line, replace all 29 `except Exception: pass` with a logged warning, and wire error reporting on both backend and frontend | M |
| `FUT-P2-3` | Give the audit trail a **who** and a **reader**: `actor_email`/`actor_sub`/`actor_role` columns populated inside `audit()` itself; `staged_changes.created_by` populated; a required, persisted reason on manual escalate-override; `audit_log.snapshot_id` as a plain column so the correlation survives; and a role-gated admin Audit screen with pagination | M |
| `FUT-P2-4` | Adopt a real migration system (Alembic or numbered forward-only files applied one per transaction); move every runtime `ensure_*` DDL helper into a migration and delete it; add the migration step to the deploy pipeline; fix the known drift (`asset_merges` missing from `schema.sql`, `match_key` CHECK missing `manual_review`) | L |
| `FUT-P2-5` | Correct the transaction boundaries: no LLM call inside an open pooled transaction; make `/api/actions` a pure read; wrap merge-confirm and reset-demo in one transaction each; add a single-flight guard on ranking; chunk `upsert_many` at `65535 // len(cols)` | M |
| `FUT-P2-6` | Add a lock with double-checked locking around the engine build and every rebind; make scenario writes atomic via tmp + `os.replace`; persist `{scenario, n}` so a restart does not silently revert everyone to demo | S |

**Exit criteria.** A recompute, a dataset switch, an asset merge and a reset each leave
`change_requests`, `change_decisions` and `audit_log` intact · `audit_log` carries the actor,
populated inside `audit()` so no call site can forget · a structured log line with a request
id exists for every currently-silent degradation, and `X-Request-Id` round-trips into the
error envelope · `/api/health` returns 503/`degraded` when the schema or active snapshot is
missing, with a separate `/api/live` for the platform probe · `alembic upgrade head` is the
only way schema changes apply · **no LLM call executes inside an open DB transaction**,
asserted by a test.

### 14.4 Phase 3 — Pilot-ready: survive a real client's data *(4 weeks)*

**Goal:** accept a customer export, ingest it partially and honestly, and finish in bounded
time. **Nothing before this phase lets the product be pointed at a client file at all.**

| ID | Requirement | Size |
|---|---|---|
| `FUT-P3-1` | **Build the ingestion path that does not exist.** Remove scenario regeneration from the engine/recompute paths (it becomes an explicit admin action); add `POST /api/ingest/upload` storing the raw blob in a **table**, not a shared file on ephemeral disk; have `normalize_all` read from that store with the demo fixtures as a seeded default. Register approved `SourceProfile`s so BYO-source becomes real ingestion, not a preview | L |
| `FUT-P3-2` | **Make normalization survive real data.** Wrap each rule in try/except accumulating `skipped:[{index, reason}]` and surface the count in the UI; normalize the action vocabulary (`allow/permit/accept`, `deny/drop/reject/block`, case-insensitive) and raise on unmapped rather than crashing in pydantic; accept list-valued src/dst/service and fan out one record per tuple keeping the parent ref; honour `enabled`/`disabled`; carry `device` and the source's real priority | L |
| `FUT-P3-3` | **Bound the expensive algorithms.** Replace unbounded `all_simple_paths` with a traversal capping **visited edges** and pruning abstract pivots at expansion time; propagate `truncated: true`; replace the per-target loop with one reverse BFS from all sensitive targets; bucket shadowing by canonical destination and pre-parse source networks once; replace CIDR-overlap's pairwise combinations with a sort-and-sweep; add a per-snapshot wall-clock budget; build a **meshed** scale fixture that actually exercises path enumeration | L |
| `FUT-P3-4` | **Fix analyzer coverage** now that resolved CIDRs and port ranges exist: extend shadowing to a full 5-tuple test (source, destination via `ip_set` containment, protocol, port interval); replace service string equality with interval intersection resolving declared apps; branch on the `(earlier.action, later.action)` pair so deny-after-deny is a `redundant_deny`, not a fabricated "traffic is actually allowed"; gate transport exposure on source overlap and zone; score cross-tool paths on the **max** over terminal grants rather than the alphabetically first | M |
| `FUT-P3-5` | **Tighten the model-output → state-mutation path.** Reject any `target_ref` not in the finding's own `raw_refs`; match on `(source_tool, raw_ref)`; validate `new_source` parses as a CIDR and `new_service` as proto/port; widen validation to report new findings across **all** bands and fail on new critical **or high**; raise on an unmatched ref instead of silently no-op'ing; return per-item apply outcomes; make conflict resolutions executable (a "skip" must not append); **re-prove at push time against the live engine** | M |
| `FUT-P3-6` | **Broaden the change-gate delta** to the primitive the remediation path already trusts: `reanalyze(records + [proposed])` diffed against the current findings by signature, force-escalating on any new critical or high, keeping the internet→sensitive path diff as an additional named signal. Skip over-permissive scoring when the proposal is a `deny`, and drop `deny` from the simulate tool schema until the graph subtracts it | L |

**Exit criteria.** A realistically-shaped 5,000-rule multi-device export ingests end-to-end
and produces findings, with a visible "N rules ingested, M skipped" report naming each
skipped row and reason · no code path regenerates the input files during engine or
recompute, and a file placed in the store survives a restart · a 10,000-rule snapshot
completes under a pinned wall-clock budget asserted by a perf test, on a meshed fixture ·
truncation is reported, never silent · shadowing detects the canonical broad-rule-at-the-top
case · a rule marked disabled produces no allow edge, and synthesized ordering is labelled
as such · every mutating remediation validates its target ref and returns a per-item outcome.

### 14.5 Phase 4 — Production hardening *(6 weeks)*

**Goal:** operate it for someone else — bounded cost, bounded latency, real provider parity,
real coverage, reproducible builds.

| ID | Requirement | Size |
|---|---|---|
| `FUT-P4-1` | **Provider-portable tool calling** (OpenAI `tools`/`tool_choice`, Anthropic `tools`/`tool_use`) behind one interface — or route the assistant through the already-portable JSON ReAct loop. Make `max_tokens` a per-call parameter sized by role and check `stop_reason` so a truncated response sets `ok=False`. Route every tool call through the registry dispatch so the admin kill switch actually applies | L |
| `FUT-P4-2` | **Cost and latency control:** per-actor token-bucket rate limiting on the six LLM endpoints, max length on every model-bound body plus a byte cap on samples, a daily cost ceiling from `ai_metrics` that trips capabilities closed, `price_for` returning `(price, known)` with a `price_known` column so unpriced calls are reported rather than shown as $0.00, an explicit timeout on every completion, and a defensible local-model timeout default | M |
| `FUT-P4-3` | **Convert long-running capabilities to jobs:** POST returns `{job_id}`, work runs on a bounded worker writing progress, the UI polls — following the two-phase pattern the report orchestrator already uses correctly. Reconcile the explain polling budget with the server timeout by returning a server-derived deadline | L |
| `FUT-P4-4` | **Close the 0%-coverage gap:** TestClient tests for every endpoint (2xx shape, 4xx on bad input, 403 for viewer on each mutating route, custom classify body, decisions surviving a recompute); recording-fake-cursor tests for persistence asserting every column exists in the schema; pure-function tests for conflict detection and overlay apply; stubbed-model tests for rank/report/explain/intake; a Playwright smoke spec | L |
| `FUT-P4-5` | **Reproducibility and hygiene:** commit and install from `requirements.lock`; replace deprecated startup events with a lifespan that joins background threads and closes the pool; propagate contextvars into background threads so metrics are attributed correctly; add the missing indexes (`audit_log(ts DESC)`, `staged_changes(request_id)`, `change_requests(snapshot_id)`, `findings(snapshot_id, type)`) plus a retention policy | M |
| `FUT-P4-6` | **Make compliance and injection handling defensible:** build a deterministic `requirement id → predicate over findings` table so the model **narrates engine verdicts instead of inventing control numbers**; wrap all ingested strings in explicit `<untrusted_data>` delimiters across every prompt; add an adversarial regression test | M |

**Exit criteria.** Tool-calling works identically on Ollama, OpenAI and Anthropic, verified
per provider against a stubbed SDK client, and **the assistant never answers a path question
without a tool result** · rate limits and a daily cost ceiling trip capabilities closed ·
campaign and report run as background jobs with a status endpoint · every endpoint has
TestClient coverage and the persistence + API layers leave 0% coverage · the lockfile is
committed and installed from · a deterministic PCI control map exists · an adversarial test
proves a finding whose title contains an injected instruction leaves severity, band,
ordering and the chosen target ref unchanged.

### 14.6 Documentation corrections (`FUT-DOC`)

The cheapest confidence available: make the claims match the code. `ENGINE.md` §10 and
`HOW-IT-WORKS.md` §14 are already unusually honest — **bring `README.md` and `FEATURES.md`
up to that standard rather than removing the caveats.**

| ID | Correction |
|---|---|
| `FUT-DOC-1` | **Local-first residency** (`README.md`, `DEMO.md`): say inference runs locally *in that configuration*, note that `auto` falls back to a hosted provider and that the shipped blueprint pins OpenAI, and point at the provider chip for the active residency |
| `FUT-DOC-2` | **Bring-your-own source** (`README.md`, `FEATURES.md` §1.7): describe it as a **design-time connector-authoring assist**; registering a profile and ingesting through it is not implemented |
| `FUT-DOC-3` | **Ingestion** (`FEATURES.md` §1.1): state that the build reads three fixed simulated exports, that there is no upload path, that the engine regenerates those files on a cold build, and that adapters assume well-formed rows |
| `FUT-DOC-4` | **`verify`** (`README.md`): call it a golden regression check on the one seeded fixture, not a correctness proof on arbitrary input; add the unit-test command |
| `FUT-DOC-5` | **Provider parity** (`AGENTS.md`): same contracts and guardrails for structured judgment, but tool-calling is Ollama-only today and the Anthropic path is capped at 1500 output tokens |
| `FUT-DOC-6` | **Analyzer count** (`ENGINE.md` §1, §6, source map): four → **five**, and add a §6.5 for `transport_exposure`, which produces 8 of the 17 demo findings and is currently absent from the formula reference |
| `FUT-DOC-7` | **`ENGINE.md` §10.3:** delete the substring-port bug (fixed) and replace it with the live gaps — port ranges scored from the range start, "the internet" as a literal string, named network objects acting as path pivots, mixed IPv4/IPv6 raising, and the scan cap bounding yielded paths rather than DFS work |
| `FUT-DOC-8` | **`ENGINE.md` §9:** state that the fingerprint hashes only the rule rows, so tags, the object catalog, L4/L7 decoding and confirmed merges do **not** change the snapshot id — treat it as identifying the rule set, not the analysis |
| `FUT-DOC-9` | **"Proven" remediation** (`AGENTS.md`, `FEATURES.md`): the proof is *target finding disappears and no new **critical***; new high/medium/low are not checked, the proof is against the draft-time snapshot and is not re-run at push, and the fallback is **conservative (removal-based)**, not "surgical" |
| `FUT-DOC-10` | **Staging copy** (`FEATURES.md`, `Staging.tsx`): the FEATURES wording is already honest; the on-screen copy is not. "Connect to algosec (simulated)", "staged — simulated push, no live connector", and stop reporting a resolution the overlay does not perform |
| `FUT-DOC-11` | **`SSO.md` role table:** either implement the viewer restriction or state that it is not enforced on the nine listed routes. **Fix the code rather than the doc** — but until it ships, the doc must not promise an enforcement that does not exist |
| `FUT-DOC-12` | **Model routing** (`README.md`): one model serves judge and prose; give exact pull tags, and warn that the availability probe only checks that *some* model is present, so a mismatched tag silently puts every capability on deterministic fallback |
| `FUT-DOC-13` | **Capability toggles:** describe as default-on and best-effort — a feature-flag layer, **not** an authorization boundary |
| `FUT-DOC-14` | **Capability count:** four docs give four different numbers. Pick one canonical count in `FEATURES.md`, reference it from the others, and add a CI check asserting the doc counts agree with the code |

### 14.7 Sequencing

```
Phase 0 ──▶ Phase 1 ──▶ Phase 2 ──▶ Phase 3 ──▶ Phase 4
1 week      3 weeks      2 weeks      4 weeks     6 weeks
demo can    math is      record is    survives    operable
not lie     defensible   trustworthy  real data   for others
```

`FUT-SEQ-1` Phase 1's test workstream (`FUT-P1-6`) **shall not** be deferred: until the
engine has tests, every other fix in this plan is unprotected and will regress. It is also
the cheapest item on the list — the suite already runs green fully offline.

`FUT-SEQ-2` No client data **shall** be ingested before Phase 3 completes. Phases 0–2 make
the *demo* defensible; Phase 3 is the first point at which the product can be pointed at a
customer export at all.

---

## Appendix A — Requirement index by area

| Prefix | Area | Section |
|---|---|---|
| `PR` | Product scope and principles | §1–§2 |
| `RL` | Roles | §3 |
| `ARC` | Architecture | §4 |
| `ING` | Ingestion and normalization | §5 |
| `IDN` | Identity resolution | §6 |
| `GRP` | Graph and reachability | §7 |
| `ANL` / `SEV` | Analyzers and severity | §8 |
| `CHG` | Change pipeline | §9 |
| `AI` | Advisory and agentic layer | §10 |
| `API` / `UI` / `ADM` | Interfaces and administration | §11 |
| `DAT` / `SEC` / `NFR` | Persistence, security, non-functional | §12 |
| `ACC` / `LIM` | Acceptance and known limitations | §13 |
| `FUT` | Future features | §14 |

## Appendix B — Source map

| Concern | Path |
|---|---|
| Canonical contracts | `backend/src/models.py` |
| Calibration constants | `backend/src/config.py` |
| Normalizers + declarative profiles | `backend/src/normalizers/` |
| Identity resolution | `backend/src/identity.py` |
| Graph, zones, reachability | `backend/src/graph/` |
| Analyzers + severity + orchestration | `backend/src/analyzers/` |
| Change simulation, staging, apply | `backend/src/change/` |
| Advisory + agents | `backend/src/advisory/`, `backend/src/agent/` |
| Persistence and DB | `backend/src/persist.py`, `backend/src/db.py`, `db/schema.sql` |
| API | `backend/app/main.py` |
| Dashboard | `frontend/app/`, `frontend/components/` |
| Auth + SSO | `frontend/auth*.ts`, `frontend/middleware.ts`, `db/sso_schema.sql` |
| Orchestration | `tasks.py`, `backend/scripts/` |
| Deployment | `render.yaml`, `docs/DEPLOY.md` |

---

## Changelog

- **2026-08-10** — v1.0. As-built baseline reverse-engineered from the current tree and the
  companion docs; future-features roadmap (§14) derived from `docs/PROD-READINESS-AUDIT.md`
  (155 surviving findings, 5 phases, 14 quick wins, 14 documentation corrections).
