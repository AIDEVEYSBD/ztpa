# Remediation Log

Running record of work against `docs/PROD-READINESS-AUDIT.md` (155 surviving findings, 19 blockers).
One entry per phase. Updated as each phase completes.

**Started:** 2026-09-01 · **Branch:** `remediation/prod-readiness`, merged to `main` 2026-09-15 · **Baseline commit:** `c0789d6`

Every number below was verified by running the command, not taken from an agent's report.
Claims that could **not** be verified in this environment are called out explicitly as such.

---

## Status at a glance

| Phase | Scope | Status |
|---|---|---|
| **0** — Stop the bleeding | Crash, authz, audit-trail wipe, silent failures, CI | ✅ Complete |
| **1** — Engine math defensible | Resolved CIDRs, port ranges, internet classification, identity scoping, content-hash snapshot id | ✅ Complete |
| **2** — System of record | Governance survival, audit identity, migrations, logging, transaction boundaries | ✅ Complete (2 gaps carried) |
| **3** — Pilot-ready | Real ingestion path, bounded algorithms, analyzer coverage | ⬜ Next |
| **Network Analyser** | Sources → Inventory → Topology → Resilience; multi-console reconstruction | ✅ Complete |
| **Demo scenario set** | One estate per scenario: all ten exports written, a second cross-tool path, an anti-cheat, `partial` added, `multi_path` deleted | ✅ Complete |
| **4** — Production hardening | Provider parity, cost/latency limits, full coverage, reproducible builds | 🟡 Platform half complete (branch `feat/frr-platform`) — see below |

| Metric | Baseline | Now |
|---|---|---|
| Tests passing | 16 | **2,083** (real Postgres, as the least-privilege role) |
| Test suite runtime | 60.2s | **5.2s** |
| Silent frontend catches (`.catch(() => {})`) | 11 | **0** |
| Bare `except Exception:` (backend) | 29 | **9** |
| CI | none | pytest (offline + real Postgres) + verify_engine + typecheck + lint + next build + image builds + Terraform validate |
| Engine output | `snap_9909fd547587`, 17 findings | `snap_6f12b7b48a9c`, **30 findings** (see Phase 1 caveat) |

---

## Phase 0 — Stop the bleeding ✅

**Goal:** every screen is either correct or visibly failed. No engine math changed.
**Ran:** 17 agents — 1 harness, 6 file-disjoint implementers, 8 adversarial verifiers, 1 repair, 1 gate.
**Result:** 42 files changed (+2,465 / −466) plus 11 new files (~2,338 lines). Uncommitted.

### What was fixed

| # | Defect | Fix |
|---|---|---|
| 1 | **"Simulate a custom change" 500'd on every call since the initial commit** — `main.py:584` unpacked a 6-field dataclass into 3 names | Use `svc = parse_service(...)`; L7 app now decoded on the custom path too |
| 2 | **Change gate could auto-approve SQL access to a PCI database** — callers passed `dest_tags=[]`, disabling the sensitivity guardrail | Tags resolved from engine assets inside `simulate_change`; a caller may only ever *add* sensitivity |
| 3 | **The product contradicted itself** — `effective_policy` said internet-exposed, `reachable` said no, for the same asset | `who_can_reach` rebuilt on the same primitive (reverse BFS, abstract-node pruning), returns a witness path |
| 4 | **9 mutating routes had no role guard** — a viewer could push a rule into the durable overlay | 15 routes guarded by `require_approver` / `require_operator`; a reflective test reads the live route table |
| 5 | **Backend trusted a forgeable `x-npr-role` header on a public service** | `NPR_PROXY_SECRET` compared with `hmac.compare_digest`; 401 on a claimed identity without it |
| 6 | **Every recompute cascade-deleted the change-request and decision audit trail** | `delete_snapshot_children` clears only engine-owned tables; governance FKs no longer cascade |
| 7 | **A dead database and a clean estate were pixel-identical** — "0 findings, 0 prioritized actions" | Typed `ApiError` (status + detail), per-resource state machine, explicit error panels; never renders a zero while a dependent fetch is errored |
| 8 | **Recompute failure rendered a green check and "Snapshot recomputed"** | Topbar branches on the error and renders a distinct failure state |
| 9 | **Staging claimed "Applied to AlgoSec — data source updated"** for a push that contacts nothing | Relabelled as simulated; `simulated: true` in the payload; a "skip" step now actually skips |
| 10 | **Zero logging in ~6,500 LOC; `/api/health` hardcoded `status:'ok'` when db was down** | Structured JSON logging with request ids; health returns 503 + `degraded`; `/api/live` for the platform probe |
| 11 | **A ten-second account takeover** — `devLink` returned a live sign-in token to an unauthenticated browser | Removed from the server-action return type; user-enumeration oracle closed |
| 12 | **TLS verification disabled** on the Postgres connection holding bcrypt hashes and auth tokens | `rejectUnauthorized` restored, `channel_binding` no longer stripped |
| 13 | **16 good tests existed but no runner exposed them; no CI** | `pyproject.toml`, `conftest.py` offline stubs, `tasks.py test`, `make test`, GitHub Actions |
| 14 | **`tasks.py stop` force-killed every Node process** on a developer's Windows machine | Removed; replaced with a targeted, printed fallback |

### Exit criteria: 7/8 met on first pass, 8/8 after repair
The refuted one — silent catches surviving in three admin components no agent owned — was found by an adversarial verifier and repaired.

### Verified independently (not taken on trust)
- Engine output **byte-identical to baseline**: same snapshot id, same 17 findings, with exactly one intended behaviour change (`app-segment` internet-exposure — the contradiction in defect 3). A 42-file refactor that moves nothing else.
- Suite timing: the entire 60s baseline was two 30s psycopg connect timeouts fired by `record_metric` against the placeholder Neon URL — i.e. **every local test run was writing junk rows into the live `ai_metrics` table**. Now stubbed.
- A viewer **does** reach `/api/change/classify` un-guarded, and it writes governance rows. Carried into Phase 1.

### ⚠️ Caveats

**~~The governance fix rests on a migration that has never run.~~ RESOLVED 2026-09-01 — see below.**

**The authz boundary ships fail-open.**
`NPR_PROXY_SECRET` is `sync: false`, so it is unset on deploy and the backend trusts `x-npr-role` exactly as before until an operator sets the same value in both the Render and Vercel dashboards. The 403 work is real and well-tested; the boundary it depends on is off by default.

### Corrected an incorrect agent finding
The final gate reported a cycle bug — "a node reports reaching itself" — as the riskiest change. I built a 3-node cycle and ran it: `who_can_reach` and `reachable` agree exactly and no node reports reaching itself. **Refuted.** The *test* it flagged is genuinely weak, though (it asserts the demo graph is acyclic before testing the property), and that is being fixed in Phase 1.

### Carried into Phase 1
- `/api/change/classify` + both `/remediate` routes unguarded; the test exempting them says "writes no governance state", which is false
- `eslint` in neither `package.json` nor `package-lock.json` — the lint gate cannot run on a clean checkout
- `-q` in pytest `addopts` suppresses the summary line entirely (you cannot tell 169 from 3)
- Health 503 + `ApiError` together make a *degraded* backend render as *dead*
- 16 bare `except Exception:` remain in `backend/src` (Phase 2 scope)

---

## Interlude — the governance fix, proven against a real database ✅

**2026-09-01.** Phase 0's biggest caveat is closed. A throwaway Postgres 16 was brought up in Docker
(`localhost:55433`, container `npr-pg`) and the DDL was executed for the first time anywhere:
`db/schema.sql`, `db/auth_schema.sql`, `db/sso_schema.sql`, then `db/migrations/0001_governance_fk.sql`.
All applied cleanly. **Nothing touched the Neon instance**, and `.env` was not modified.

### Foreign-key rules after migration — verified from `information_schema`

| Table | On snapshot delete | Correct? |
|---|---|---|
| `assets`, `canonical_rules`, `findings`, `graph_nodes`, `graph_edges`, `resolved_objects`, `asset_correlations`, `ranked_actions` | CASCADE | ✅ engine-owned, regenerated |
| `change_requests` | **SET NULL** | ✅ governance survives |
| `audit_log` | **SET NULL** | ✅ governance survives |

### The audit's worst finding, reproduced and closed

| Schema + code | Recompute presses | `change_decisions` rows |
|---|---|---|
| **Baseline** (`c0789d6`) | 1 | **1 → 0** — entire governance trail destroyed |
| **Current** (Phase 0 + migration) | 2 | **1 → 1** — intact, `snapshot_id` preserved |

The exit criterion *"pressing Recompute twice leaves the change-decisions row count unchanged"* is now
**demonstrated**, not argued through a recording fake cursor.

**One correction to Phase 0's account:** the **FK migration is the load-bearing fix**, not the
`delete_snapshot_children` rewrite. With the new FK in place, running the *old* destructive
`DELETE FROM ztpa.snapshots` verbatim still leaves governance rows intact. Two independent defences
now exist, and the schema-level one is the one that actually holds.

---

## Phase 1 — Make the engine's math defensible ✅

**Goal:** fix arithmetic that is wrong on valid input, and pin it so it cannot silently regress.
**Ran:** 25 agents — 1 contract, 8 file-disjoint implementers, 2 crosscut (golden re-baseline + a mutation
matrix in an isolated worktree), 9 adversarial verifiers, 4 sequential repairs, 1 gate.
**Committed:** `90877f0` on `remediation/prod-readiness` (95 files, +23,891 / −3,163).

### The audit's headline test — passed

Same policy, four encodings, against `db-prod-01` (`pci`, `customer-data`) on tcp/3389:

| Encoding | Before | After |
|---|---|---|
| literal `0.0.0.0/0` | 100 critical | **100 critical forced** |
| keyword `any` | **no finding** | **100 critical forced** |
| named `ANY-EXTERNAL` | **no finding** | **100 critical forced** |
| named `INTERNET` | **no finding** | **100 critical forced** |
| address group `{0/0, 10/8}` | — | **100 critical forced** |

Verified by running the real engine, not by reading the test that claims it.

### What was fixed

| Defect | Fix |
|---|---|
| Normalizers resolved a named object's CIDR then **discarded it** (`_s_cidr`) | `PolicyRecord.source_cidrs` / `dest_cidrs`; scoring, overlap and shadowing all read the resolved value |
| `0.0.0.0/0 -> host tcp/1-65535` produced **zero findings** (scored from the range *start* port) | Range-aware `port_score` returning the max class over the interval; both guardrails fire on ranges |
| "The internet" meant the literal string `0.0.0.0/0`; `0.0.0.0/1` scored 90→56 | New `src/netaddr.py` classifies by address-space math (`is_global`/`is_private`), v4 + v6 |
| One IPv6 rule raised TypeError and **permanently poisoned** the cached engine | `.version` guards in `cidr_overlap` and `shadowing` |
| Identity merged on a bare IP with no tenancy scope | Union keyed on `(context, ip)`; sentinels, fan-out cap, prod/dev exclusion; unscoped collisions emit `manual_review` |
| `snapshot_id` omitted tags, ports, objects and merges — same id, different findings | Real content hash over all of them |
| One malformed rule aborted the whole snapshot | Per-analyzer isolation with a visible degraded marker |
| Comma port lists silently lost their ports; `ip`/`all` decoded as `tcp` | Interval list on `DecodedService`; protocol vocabulary widened; explicit `warnings` |

### Four criteria were refuted by adversarial verifiers, then repaired — all re-verified independently

| Refuted claim | Root cause found | Now |
|---|---|---|
| four-encodings | A multi-block address group set `ObservedEntity.cidr=None` → empty `ip_set` → `zone_of` returned INTERNAL → boundary multiplier collapsed. Two bands apart. | ✅ 100/critical/forced |
| p0-residual | `/api/findings`, `/api/graph`, `/api/snapshot`, `/api/actions` 500'd without a DB **despite the engine holding the data in memory** | ✅ 200 with `served_from=engine_memory`; `/api/snapshots` honestly `unavailable` |
| snapshot-content-hash | Lists joined with `,` while fields joined with `\x1f` — a comma-bearing tag collided with the tag pair it spells | ✅ hashes differ |
| identity-scoped | `is_sentinel_ip` gated on `version` equality, so `::ffff:127.0.0.1` bypassed the guard and collapsed the estate onto the PCI database | ✅ every sentinel spelling caught |

### ⚠️ The demo's flagship finding disappeared — and the headline count is misleading

Findings went **17 → 30**, but that number oversells it. The breakdown:

| Type | Before | After |
|---|---|---|
| `shadowed_rule` | 1 | **15** (containment test now works) |
| `over_permissive` | 4 | 5 |
| `transport_exposure` | 9 | 8 |
| `cross_tool_path` | **1** | **0** ← |
| **critical band** | **4** | **3** |
| **forced-critical** | **4** | **3** |

The lost finding is the demo's money shot: **"Cross-tool path: Internet can reach db-prod-01 through 3 tools"**, severity 100, forced critical.

**Root cause — TWO independent causes, not one.** My first analysis blamed only the identity merge and
was incomplete; the Phase 1 gate proved independence by forcing the merge back with
`run(manual_merges=[("app-server-07","appsrv-07")])` — **the path does not return.**

| # | Cause | Effect |
|---|---|---|
| **(a)** *dominant* | `internal-app` is an AlgoSec **network object** `10.40.0.0/16`, now correctly marked `abstract`. `_valid_traversal` refuses to pivot through an abstract node. | The 3-tool path has no legal pivot |
| **(b)** | The `appsrv-07` ↔ `app-server-07` union is withheld — an unscoped IP collision now emits `manual_review`. Assets 25→26, correlations 4→3, `suppressed_merges=1`. | Also removes one `transport_exposure` finding |

**The audit anticipated exactly this** (line ~699): marking network objects abstract *"will delete the
current money-shot until CIDR-membership expansion lands"*. **That expansion is not built** — it is
Phase 3 scope. Both behaviours are correct: you cannot "pivot through" a /16, which is an address range,
not a device. The path legitimately returns only once the engine knows *which concrete hosts live inside
`10.40.0.0/16`*, so the route reads internet → host-in-segment → db rather than internet → segment → db.

**Correction to an earlier recommendation:** enriching the fixtures with tenancy fields would fix (b)
only. It would **not** bring the money shot back, because (a) is the dominant cause. The real fix is
CIDR-membership expansion (Phase 3). Fixture enrichment remains worth doing on its own merits — no
export carries a tenancy field, so the fail-safe fires on every merge — but it is not the fix for this.

### The audit's most damaging claim — closed, and proven on constructed input

The gate built a client-shaped AlgoSec export where **no rule uses a raw CIDR and no service is a bare
single port** (9 named catalog objects; services `tcp/1-65535`, `tcp/3000-3400`, `tcp/1433,5432`,
`tcp/8000-9000`, `any`) and ran it through the real pipeline on both trees:

| | Findings | Worst |
|---|---|---|
| Pre-Phase-1 | **1** | 52 / medium, not forced |
| Post-Phase-1 | **4** | **100 / critical / forced**, plus a second at 90 forced |

That is the "a real client's file reads as clean" failure mode, closed and demonstrated.

### Determinism re-verified
Full engine dump (snapshot id, every finding field, assets, correlations, canonical records, resolved
objects, alias_map, sorted nodes **and** edges) hashed across 5 fixed `PYTHONHASHSEED` values plus 8
further random-seed processes: **one hash, byte-identical, 13/13**.

### ⚠️ 10 mutations still survive the suite
The mutation matrix re-ran after repairs. Ten injected defects still pass green — a concrete test backlog,
each with a named fix. Worst: deleting the `protocol == "any"` reason in `over_permissive._reasons` makes
**an entire finding disappear with the suite still green**; and dropping the `is_any` arm in
`PolicyRecord._canonicalize_cidrs` re-introduces the audit's headline defect one layer down.

### Verified state
`pytest` **1107 passed in 2.21s** · `verify_engine.py` ALL CHECKS PASSED · `npx tsc --noEmit` clean.

---

## Interlude — frontend proven, and a critical CVE found ✅

**2026-09-01.** 29 agents: 1 frontend proof, 5 security-review lenses, 22 adversarial judges, 1 report.

### The frontend actually runs — verified in headless Chrome, not inferred

`npm run build` passed **first attempt, zero code edits**. Backend run against the live Postgres, Next app
under `next start`, signed in as admin / analyst / viewer through the real Auth.js flow, driven over CDP.
**All 14 console screens render**, zero page exceptions, zero console errors across 201 CDP events.
Eight screenshots in [`docs/screenshots/`](screenshots/).

| Check | Result |
|---|---|
| Console renders | ✅ 30 findings (3 critical / 1 high / 8 medium / 18 low), 26-asset graph |
| Flagship "Simulate a custom change" as analyst | ✅ **HTTP 200** with a decision — the card that 500'd on every call since the initial commit |
| Same call as viewer | ✅ **403** `approver role required`, rendered as a permissions message, not an outage |
| Baseline crash confirmed real | ✅ `TypeError: cannot unpack non-iterable DecodedService object` reproduced at `c0789d6` |
| **Backend killed → error states** | ✅ six explicit panels + *"6 of 6 console feeds failed. Treat every number on this screen as unknown until they load."* Risk To-Do badge **blank**, not `0`. No `0 findings` anywhere in the DOM |
| **Backend up, no database → degraded** | ✅ yellow banner, real numbers attributed to the running engine, timeline named *"unknown, not empty"* |

### 🔴 CVE-2025-29927 — Next.js middleware bypass. Found and fixed.

`next` was pinned to **14.2.15** at baseline *and* HEAD, and the vulnerable handler was physically present
in the installed tree (`sandbox.js` reads `x-middleware-subrequest` and skips middleware).

This matters more here than in a typical app: **`frontend/middleware.ts` IS the auth model.** Its matcher
covers every path, it gates every page, and it strips client-supplied `x-npr-*` headers before setting its
own from the session. One header skips it entirely — so gated pages render with no session *and* forged
`x-npr-*` headers pass through the rewrite straight to FastAPI. With `render.yaml` shipping the backend
public and `NPR_PROXY_SECRET` unset, **the default shipped configuration was an unauthenticated admin
takeover of the API.**

Pre-existing, not introduced by the remediation — but it undermined the entire premise of the Phase 0
authz work. Fixed in `507a5fb`: `next` → **14.2.35**, pinned exactly. Handler confirmed gone from the
installed tree; build, typecheck, lint and 1107 tests all green.

### Security theatre the review named
- **`NPR_PROXY_SECRET` authenticates the identity *claim*, not the *request*.** With the secret configured, a header-less anonymous request from the open internet still reaches the backend as the default viewer.
- **`test_no_mutating_route_is_unguarded`** subtracts `{GET,HEAD,OPTIONS}` *before* inspecting routes — structurally incapable of catching what it claims to.
- **`_require_capability`**, documented "fail-closed", **fails open** on a cold start with the DB unreachable; disabling `rank` provably does not stop the spend.

### Still outstanding — not fixed here, deliberately
- **`next-auth` / `@auth/core` critical advisory** — config errors can make existence-based auth checks *fail open*. The fix is a beta-to-beta bump on the auth path and needs the login/SSO flows re-verified, so it is queued rather than slipped in.
- `next >= 16` advisories (Image Optimizer DoS, RSC deserialization) require a major upgrade.
- Three frontend honesty defects: `classify` 500s with no DB (unguarded `get_conn()`); the degraded banner claims *"Every panel below loaded"* above two 500 panels; a dead backend is misreported as an API error because the Next rewrite turns ECONNREFUSED into a 500.

---

## Phase 2 — System of record ✅ (with two gaps carried forward)

**2026-09-01/02.** The Phase 2 workflow **crashed**: one repair agent stalled after 6 retries, so its last
fix and the gate never ran. Both were completed by hand. 5 implementers and 9 verifiers had finished;
2 of 3 repairs had landed. The tree stayed healthy throughout.

**Committed:** `473609c` — 44 files, +8,080 / −609. Tests **1,107 → 1,297** (1,258 offline + 39 real-DB).

### What was delivered

| Area | Change |
|---|---|
| Audit trail | `audit()` reads the actor from `request_ctx` **itself** and writes `actor_email`/`actor_sub`/`actor_role`. Every one of 15 call sites previously passed the literal `'user'` — it was an event log, not an audit trail |
| Migrations | Versioned runner replaces runtime `ensure_*` DDL and its READY flags; 3 migrations |
| Persistence | `upsert_many` chunked at the 65,535 bind-parameter limit, so a snapshot over ~2,620 rules actually persists |
| Transactions | No LLM call executes inside an open DB transaction; ranking no longer holds a pooled connection across a model call |
| Security | Proxy boundary authenticates the **request**, not merely the identity claim; `_require_capability` genuinely fails closed; the authz test no longer subtracts `{GET,HEAD,OPTIONS}` before inspecting; `next-auth` critical advisory closed; host-header injection closed |
| Observability | Last bare `except Exception` handlers logged; callers can distinguish "genuinely empty" from "failed to load" |
| Testing | **39 real-database governance tests** — the first in this repo — plus 10 mutation guards |

### The stalled repair was the most interesting finding of the phase
A verifier refuted *"callers can distinguish empty from failed"* with a precise catch: `EmbeddingResult`
was built, documented against this exact scenario — and **wired to nothing**. `embed_texts` had zero
callers; `entity_suggest` still used the legacy `embed()`, which returns `[]` for both "nothing asked" and
"every provider down".

So a dead embedding server rendered as the positive claim **"these two PCI assets do not resemble each
other"** — `name_similarity: 0.0`, payload byte-identical to a real measurement. Fixed: degraded rows carry
`name_similarity: null`, `similarity_available: false` and a reason; confidence rests on tag evidence
instead of being halved by a fabricated zero. **All 6 new guards verified to fail against the pre-fix code.**

### Governance survival — proven under six independent attacks
The gate ignored the shipped tests and drove the **real HTTP routes** against real Postgres:

| Attack | Result |
|---|---|
| All four paths (recompute, dataset switch, merge/unmerge, reset ×2) through real routes | **0 rows lost** across 12 operations |
| 3,006 rows incl. 1,500 pre-archived, whole-row byte comparison | 0 lost; survivors byte-identical; `audit_log` append-only; original retirement dates preserved |
| Fresh install from `schema.sql` | correct without migrations |
| **An actual pre-remediation database**, migrated | FK flipped to SET NULL, columns added, all paths pass |
| **A deploy that forgot the migration** | fails **loudly** in one transaction, destroys nothing — no DELETE fallback |
| Repo-wide sweep for any other destruction path | none; no triggers, no rules; every write funnels through two functions |

Also confirmed the tests genuinely run rather than skipping into a false green: 39 pass with a database,
39 skip without, and a **RuntimeError if `NPR_TEST_DATABASE_URL` is set but unreachable** — so a CI that
asks for a database and is denied one goes red.

### ⚠️ Two criteria still FAIL after repair — carried into the next phase

**1. `degraded_analyzers` has no consumers — a silent under-report presented as complete. (blocker-class)**
`run_all.py` populates and logs it; `grep -rn degraded_analyzers backend/app frontend db` returns nothing.
Reproduced against real Postgres: with `shadowing` and `transport_exposure` raising, `POST /api/recompute`
returns `200 {"ok": true, "findings": 7}` (was 30), persists **only 2 of 4 finding types under the same
snapshot_id — overwriting the good 30-finding rows** — writes `snapshots.status='complete'`, and then
`/api/health` reports `status:"ok"` with empty `degraded_reasons`, `/api/findings` says
`served_from:"database"`, and `/api/report` publishes the truncated severity breakdown.
**No caller can distinguish "no shadowing findings exist" from "shadowing crashed."**

**2. `_require_capability` — docstring vs code, and kill-switch coverage.**
The three behavioural clauses hold under real attack. But the docstring asserts the operator keeps
`GET /api/admin/tools` during a `tool_settings` outage; in fact that route and `POST /api/admin/tools/{key}`
both 500 — so the operator loses the Tools screen and the ability to re-enable a capability at exactly the
moment fail-closed has taken everything away.

**3. The archived compliance record has no reader.** `GET /api/change-decisions` hard-codes
`WHERE archived_at IS NULL` with no `include_archived` parameter, so reset-demo's archived governance rows
are retained but unreadable.

---

## Network Analyser revamp ✅

**Branch:** `feature/network-analyser` · **Plan:** `docs/NETWORK-ANALYSER-PLAN.md`

The console could describe policy and could not describe the network the policy
runs on. `grep -rn vlan backend/` returned nothing, so "which VLAN is this host
in", "how many subnets do we have" and "what does the edge look like" were
unanswerable rather than merely unrendered — and the console opened on the
reachability graph, step 3 of a five-step review with the first two missing.

### What was delivered

| Area | Change |
|---|---|
| Infrastructure model | `NetDevice`, `NetInterface`, `NetLink`, `Vlan`, `Subnet`, `Circuit`, each carrying `Provenance` with the source's **tier**. `l2_switch`/`l3_switch` are distinct roles |
| Reconstruction | Layers derived from **observed connections**, never names. The smoke case names its devices `alpha`/`bravo`/`delta`/`echo` and still lands modem → edge → core → access |
| Multi-console merge | Nine sources, overlapping views folded on one rule: **a stated fact is never overwritten by an absent one**. Conflicts recorded, not resolved away |
| Source registry | One copy replacing five that could not disagree loudly. Records what each console is **blind to** |
| Vendor connectors | FortiManager, FortiGate, carrier portal, Catalyst Center, Meraki, AlgoSec topology, Junos Space — each a projection of one canonical estate, each emitting **zero** PolicyRecords |
| Resilience | Articulation points, bridges, shared-carrier and single-homed findings, per-device blast radius |
| API | 5 reads with the provenance envelope; both required filters (IP containment, source) |
| UI | Sources, Inventory, Topology (fullscreen + finding walkthrough), all honouring the no-fabrication rules |
| Scale | `estate.build(branches=N)` + `bench_topology.py` |

**1,899 tests pass** (from 1,674), `verify_engine` green including its fifteen
checks on the cross-tool path, `tsc` clean, production build clean.

### Real defects found and fixed

1. **The console reported a different trust zone than the engine scored with.**
   `/api/graph` re-derived zones with the 2-argument `zone_of` while the engine
   used the 4-argument form. Measured: `ANY-EXTERNAL` rendered `internal` where
   the engine scored `internet` — severity used a 1.5 boundary multiplier, the
   screen implied 1.0. Named objects are how real AlgoSec and Palo Alto policies
   express `any`, so this was the common case.

2. **The provenance relabel.** `profile.py` recorded any unlisted tool's records
   as `source_tool="algosec"`. Bring-your-own-connector — a shipped feature —
   ingested cleanly under a different vendor's name, and every downstream
   provenance claim was wrong with nothing to notice it by.

3. **`MAX_IP_FANOUT = 3` was a stale constant.** Correct for exactly the three
   host-describing tools that existed when written. A fourth would have withheld
   a legitimate merge, split an asset, and made a cross-tool path vanish with no
   error. Now computed per address from the tools that actually named it —
   stricter where it counts, looser only in the case that was a bug.

4. **The management VLAN was a near-complete mesh.** Containment linked every
   pair sharing a block; every device holds a management address in
   `10.255.0.0/24`. 34 fabricated links on a network with 18 real ones — and a
   mesh has no articulation points, so the resilience analyzer returned a
   flawless network for an estate with four designed single points of failure.
   A drawing heuristic was silently cancelling the analysis.

5. **Duplicate devices across consoles.** 19 devices for a 13-device estate. The
   naive fix was worse: last-write-wins would let the device-tier FortiGate read
   overwrite `model` and `ha_role` with `None`, so onboarding MORE sources would
   produce a THINNER inventory.

6. **Every address in the world was internet-reachable.** `/api/ip` matched an
   any→internal rule's `0.0.0.0/0` **source** and read it as reachability AT the
   address. Reachability is a claim about traffic arriving.

7. **`source_rows` excluded every topology-only console**, so six of nine sources
   would have been absent from the Sources screen while visibly supplying the
   devices on the Topology screen.

8. **An accidental quadratic**, found by the benchmark within a minute of it
   existing: `Estate.interfaces_of` was a linear scan called once per device by
   five connectors. 592 ms → 100 ms at 1,013 devices; ~15 s at 5,000.

### Two decisions worth recording

**The fingerprint covers the topology even though no analyzer reads it.** The
tempting answer is to leave it out and keep the golden id stable. But the id
keys `devices`/`topology_links`/`vlans`, so two ingests differing only in
topology would share one id and the rows a reader gets back would depend on
which run wrote last. An id that does not cover the content it keys is not a
content hash. The sixth blob is appended only when non-empty, so an estate with
no infrastructure keeps the id it always had.

**Redundancy grouping is directional and cannot live on the model.** Derived
onto `NetLink.redundant_group` it immediately deleted real findings — every
access→core uplink landed in one group, so `asw-acc-03`'s single uplink looked
redundant. The deeper reason: `rtr-edge-01` has two modems, which is redundancy
*for the router* and a single point of failure *for each modem*. One field
cannot hold both. It is now computed in the response, for display only.

### What was NOT done, and why

- **Stale rules.** Requires rule hit counts. AlgoSec
  `POST /api/v1/rules/hit-count`, Palo Alto Policy Optimizer and FortiManager
  `_last_hit` are the three real sources; none is connected. Named as unknown
  with the API that would close it, never computed from absence.
- **Live connectors.** Every export is seeded, and every surface says
  `simulated` — `sources.config.mode` was already being written and read by
  nothing.
- **Gaps + evidence register.** The OSCAL-shaped register is designed in the
  plan and not built. Carried forward.
- **`ap-wifi-01` has no observed uplink.** Meraki reports no neighbour table and
  the Catalyst switch it plugs into belongs to a console that correctly refuses
  to borrow the answer. Reported as a coverage gap with its remedy, not drawn.

### ⚠️ Carried forward

**1. No DATABASE_URL starves the API.** With no Postgres the six DB-backed
console feeds each block for the 30 s pool timeout and saturate uvicorn's
threadpool, so unrelated requests fail. Surfaced while driving a real browser
against the app. The five new reads deliberately do not probe the database, but
the underlying behaviour is untouched and will bite any demo run without a
database.

**2. Remediation has no path for a non-policy finding.** `RiskTodo`'s accept
button is `disabled unless validation.resolves`, which re-simulates a
`PolicyRecord` delta. A resilience finding has no policy change, so step 4 of the
five-step process has no route for the findings this work introduces.

**3. `advisory/explain.py` has no branch for the new finding classes**, and
`rank_deterministic` has no type weighting — hygiene findings would swamp the
Risk To-Do.

---

## Demo scenario set — one estate per scenario ✅

**Branch:** `remediation/prod-readiness`

The picker offered four datasets and `scenarios._write` rewrote **three of the
estate's ten console exports**. The seven infrastructure ones survived a switch
and belonged to whichever scenario had written them last, so two of the four
entries contradicted their own names on screen:

* **"Clean estate"** reported zero policy findings beside an Explorer showing 13
  devices and a resilience analyzer reporting **six** single points of failure,
  four of them designed in.
* **"At scale"** added 500 synthetic policy assets and left the topology at 13
  devices — so the one screen the scale story exists for never changed, though
  `estate.build(branches=N)` existed precisely to grow it.

Nothing caught either, because no test had ever run a scenario end to end.

### What was delivered

| Area | Change |
|---|---|
| Writer | `_write_dataset(policy, infra)` owns all ten exports; an export a scenario does not onboard is **removed**, because absence is what `_load_optional` reads as "not onboarded". `_write(algo, gc, wiz)` is kept verbatim as a shim — two failure tests assert its exact `replaced`/`pending` lists, and those assertions are the proof the atomic swap works |
| `demo` | A **second** cross-tool path to a second regulated database, disjoint from the first, and an **anti-cheat**: GC-001 moved to 9443 and ALGO-030 re-sourced to `app-segment`, so no cited grant has a broader twin. 35 → 38 findings, re-baselined line by line |
| `partial` | **New.** The same policy with AlgoSec alone onboarded: 38 identical findings, 4 devices, six lanes named dark, and a resilience report that says it analysed almost nothing |
| `clean` | **Rebuilt on both halves.** `estate.build_resilient()` (10 devices, two carriers, protected dual handoffs, everything criss-crossed) + an eight-rule internal-only policy. Measured: 0 policy findings, 0 resilience findings, `analysable: true` |
| `scale` | Grows the topology too (`n/4` branch sites), and the synthetic address space moved **out of `10.0.0.0/8`** |
| `seed_scale.py` | Was three bare `write_text` calls — the exact non-atomic pattern `_swap` exists to eliminate, in a second implementation. Now a six-line wrapper |
| Docs | `docs/DEMO.md` rewritten to nine beats with every number measured; the stale root `DEMO.md` deleted |

### The three things worth recording

**1. The flagship's headline fix was cosmetic, and the demo walked into it.**
`ALGO-030` (`internal-app` /16 → `db-prod-01`, 5432) covered `ALGO-029`, and
`GC-001` covered `GC-002` the same way. The engine does not model CIDR-membership
expansion (ENGINE.md §10.2), so `remove ALGO-029` **resolved the finding and left
the access open** — on the Risk To-Do screen, whose entire pitch is that it does
not do that. Fixed in the FIXTURE, not by weakening a rule, and pinned by a new
check that cuts each cited grant out of the record set and re-derives the graph:
`P5 cutting a cited grant cuts the ACCESS, not just the finding`.

**2. `multi_path` was a lie and is deleted.** It advertised two cross-tool paths
and reported **one**: its second pivot was `data-segment`, a `/16`, and
`_valid_traversal` correctly refuses to originate from an address range. It had
also started appending an `ALGO-031` and a `GC-002` that `seed_demo` already
defines. Its content is now the flagship's second path, through a concrete host
two tools independently name — data, not a relaxed traversal rule.

**3. 516 of `scale`'s 535 findings were one finding, 516 times.** The synthetic
hosts sat at `10.200.x.y` with `10.201.x.0/24` sources — both inside ALGO-001's
destination (`0.0.0.0/0 → 10.0.0.0/8`, service any) — so every synthetic rule was
shadowed by it. Moving them to `172.20`/`172.24` leaves **38**, the flagship's own
number: the ranked list does not grow with the estate, which is the claim "At
scale" is actually making.

### Measured, all four scenarios end to end

| scenario | consoles | devices | VLANs | circuits | policy findings | paths | resilience | `analysable` | lanes named dark |
|---|---|---|---|---|---|---|---|---|---|
| `demo` | 10 | 13 | 8 | 3 | 38 (5 critical) | 2 | 6 | true | `endpoint` |
| `partial` | 4 | 4 | 0 | 0 | **38, identical** | 2 | 0 | true | 6 lanes |
| `clean` | 10 | 10 | 5 | 2 | **0** | 0 | **0** | **true** | `endpoint` |
| `scale` (n=500) | 10 | 513 | 133 | 3 | **38, identical** | 2 | 256 | true | `endpoint` |

`1,921 tests pass` (from 1,899), `verify_engine` green with **39** checks (from
35), snapshot `snap_173ab466881a`.

### ⚠️ Carried forward

**1. `ResilienceReport.clean` is `true` for `partial`.** It is `analysable and
not findings`, and `partial` observes four devices and no circuit. The summary
sentence does carry the denominators — *"…in the 4 devices, 4 adjacencies and 0
circuits observed. That is a statement about what the onboarded sources reported,
not about the estate."* — and `caveats` names the `device_connectivity` basis, so
the payload is honest. But a caller reading the boolean alone gets "clean". The
fix is to surface `summary()` from `/api/resilience` and render it wherever the
empty list is rendered; gating `analysable` on `circuit_count > 0` would be the
wrong fix, because it would destroy the one beat `partial` exists for.

**2. `LANE_SOURCE_HINT` has no `internet` key.** With no circuits observed the
internet lane is filtered out of `unobserved_layers` entirely, so `partial` draws
neither the lane nor an account of its absence. One entry in `app/main.py`.

**3. At `scale` the unlinked rail holds 126 devices** — 125 branch APs plus
`ap-wifi-01`, each correctly reported (Meraki returns no neighbour table at any
size). The Explorer must render that as a count, a sample and one shared reason,
never as 126 boxes.

**4. `Topology.subnets` is 0 on the reconstructed object** while the Inventory's
gauge reads 8 from the VLAN pools. A bare zero on the screen that counts things
is the empty-vs-unknown conflation appearing where it is least affordable.

---

## Phase 4 — Production hardening, platform half 🟡

**Branch:** `feat/frr-platform` (from `main` at `8667c7e` + the UI design-system commits). Feature-level status lives in [frr/TRACKER.md](frr/TRACKER.md); design in [frr/ARCHITECTURE.md](frr/ARCHITECTURE.md).

### Closed

| Audit item | Fix | Evidence |
|---|---|---|
| D4 proxy boundary fails open | staging/prod refuse to boot without `NPR_PROXY_SECRET`, `DATABASE_URL`, artifact key, cloud storage; image preflight exits 1 | `tests/test_production_startup.py`; container run exits 1 |
| Stateful single process | Active-snapshot pointer + HMAC-signed engine artifacts; replicas load instead of rebuild (0.09 s vs 2.03 s at 2,000 assets, measured) | `tests/test_snapshot_artifacts.py` |
| No job queue | Postgres queue (SKIP LOCKED, leases, retries, dead state) + worker process | 22 real-DB tests incl. 8-worker contention |
| No rate limits / unbounded LLM inputs | Shared per-identity + per-deployment limits on 11 model routes; 1 MB body cap incl. chunked; field caps | `tests/test_limits.py` |
| Unpinned deps, pytest in prod | Hash-pinned `requirements.lock`; dev deps split; verified absent from image | CI `images` job |
| App connects as DB admin | Runtime role with row access only; migrations as owner | full suite green as that role |
| No GCP support | Vertex provider (ADC), native-platform routing | live call verified on sandbox |
| Fragile schema setup (3 files by hand) | `migrate.py --bootstrap` + advisory lock | fresh DB → full suite green |

### Real defects found on the way

- Artifact publish skipped the upload when the key existed, so a corrupted object would never be repaired.
- The body-size middleware first sat outside the request-id middleware (Starlette order), and a mid-read exception became a 400; both fixed and tested.
- uvicorn's supervisor exits 0 when a worker refuses to boot; the preflight makes it exit 1.

### ⚠️ Carried forward

- Recompute, dataset switch and merge still rebuild on the request path (now published to all replicas); moving them onto jobs needs the frontend to poll (tracker PLAT-4).
- ~~Not yet applied to a real cloud~~ — GCP and Azure staging both applied 2026-10-29 and exercised end to end; the deploy workflows are linted but not yet run on GitHub.
- Load testing (PLAT-15), Azure Front Door + WAF (PLAT-18), OpenTelemetry export.

### First real deployment (GCP staging, 2026-10-29) — what only a real cloud showed

| Finding | Fix |
|---|---|
| Org policy forbids unauthenticated Cloud Run | Invoker IAM kept on; frontend and smoke test call the API with Google ID tokens |
| Cloud SQL's admin is not a superuser; `ALTER ROLE ... NOSUPERUSER` refused | Role created with defaults, attributes verified, fail closed |
| Smoke test could not reach the internal-only API | Job egress through the VPC |
| Monitoring API rejected the alert query (int vs double) | Float literal |
| Impact narratives ran sequentially (134 s for 7 items) | Bounded parallel pool: 54 s |
| No request spans: Cloud Run's unsampled trace parent was obeyed | Ratio applies under unsampled parents |

Server-side API latency under the staging load test: p50 8 ms, p95 11 ms; 0 errors in 3,515 requests.

### Azure staging (2026-10-29)

First apply created all 55 resources without error; migrations ran on Flexible Server with the role fix from GCP. One defect found: `az containerapp job start --args` delivers a command line as a single argument and parses `-m` as its own flag, so the deploy workflow's migrate and smoke steps would have failed on first run; replaced by `scripts/azure/start-job.sh` (REST, env and secret references carried over). Docker build context trimmed (Terraform provider caches were being uploaded).

### Review correctness: partial shadowing (2026-10-29)

Found while profiling memory. Shadowing is computed per grant (one per source × destination × service), but the review marked the whole rule "never matched" when **any** grant was covered. A rule allowing ssh and https under an ssh-only rule was therefore drafted for removal, cutting https. Fixed: a rule is shadowed on a gateway only when every grant is covered there; every covering rule is named; a rule truncated at parse time (> 512 grants) is never claimed. Regression tests in `tests/test_frr_partial_shadowing.py`. The eval generator now plants partly-covered, never-hit rules; against the old code shadowed precision is 0.66 and the CI gate fails.

### Ingest memory (2026-10-29)

The 300 MB byte cap did not bound memory: the raw JSON is ~1% of an ingest's peak, which follows grants. Measured 44.5 KiB a rule, so a 4 GiB worker would have been OOM-killed and retried in a loop near 85,000 rules. Now 20.8 KiB a rule (40k rules: 1.87 → 0.94 GiB): pydantic's per-instance field set shared on fully-specified grants and findings, network parsing cached, one shadowing finding per rule, stored documents serialized one at a time. `NPR_MAX_GRANTS` (450,000) rejects with the count before the review instead of crashing. Live check on a staging worker is T23 in the test backlog.

### First browser walkthrough (2026-10-30)

Headless Chromium through every FRR screen (`scripts/ui_walkthrough.py`): no console errors or failed requests at 1440, 1280 or 1024 px. Reading the screenshots found what no automated gate did:

| Defect | Fix |
|---|---|
| The AI package summary told the approver "this review analyzed 183 firewall rules" — 183 was the number of proposed changes, of 400 rules reviewed | Counts passed under unmistakable names (`rules_reviewed`, `proposed_changes`); prompt `package.v2`; the narrative evaluator flags a misstated rules-reviewed count; the new prompt re-evaluated live before the CI gate accepted it |
| Packages drafted by the agents showed "unattributed" | The run job acts for the person who started it (`request_ctx.acting_as`), audit rows marked `agent` on their behalf with no role claimed; identity reset after each job |
| Checkboxes had no accessible name, and clicking their text did nothing | Shared `Checkbox` labelled via `aria-labelledby`; the whole row toggles |
| Sign-out button left the user's name one letter wide | Icon button with an accessible name |
| Register row detail ran off-screen at 1024 px; bulk buttons split across lines; package header showed only an id | Layout fixes; export file name shown |

### Night of 2026-10-30: staging rehearsals (Azure)

| Rehearsal | Found | Fix |
|---|---|---|
| Largest export at the grant limit (110k rules) | Two such ingests at once on the default two worker slots would OOM a 4 GiB worker; drafting its package in the 2 GiB API would too | One heavy job per worker process; drafting reads a compact input and runs in the worker above 20k rules |
| Proxy-secret rotation | Restarting a revision keeps the cached secret, so "rotate, restart" changed nothing, and the next new revision of one app broke frontend to API with 401s | API accepts a previous secret during rotation; three-step procedure, rehearsed with zero failed probes |
| Point-in-time restore | Worked as documented (~10 min, same VNet) | Measured procedure in the runbook |
| Model provider down | Fallback works; a draining revision still takes jobs during a switch | Noted in the backlog |
| Rate limit across 3 replicas | Holds exactly (30 of 90) | — |

### Load at staging size (2026-10-30)

160 concurrent clients through the Azure staging frontend against a 110,000-rule export, 5 minutes each:

| Run | Change | Throughput | Success |
|---|---|---|---|
| 1 | — | 5.6 req/s | 4.5% (PoolTimeout after 30 s; database CPU 30%, no I/O, no refused connections) |
| 2 | Index-only paging (items had an unindexable ORDER BY: 262 ms + 70 MB sort per page; deep OFFSET read 100 MB); 5 s pool wait, 503 + Retry-After | 36.9 req/s | 99.7% |
| 3 | Review head 375 KB → 980 B (per-gateway lists in their own column) | 87.4 req/s | 99.996% |
| 4 | Register totals cached per export and filter | 124.8 req/s | 99.99% |

Also found: staging's own settings could open ~100 connections against a 50-connection server; Terraform now refuses such a plan on both clouds. The remaining limit is the 1-vCore burstable staging database.

