# Remediation Log

Running record of work against `docs/PROD-READINESS-AUDIT.md` (155 surviving findings, 19 blockers).
One entry per phase. Updated as each phase completes.

**Started:** 2026-09-01 · **Branch:** `main` · **Baseline commit:** `c0789d6`

Every number below was verified by running the command, not taken from an agent's report.
Claims that could **not** be verified in this environment are called out explicitly as such.

---

## Status at a glance

| Phase | Scope | Status |
|---|---|---|
| **0** — Stop the bleeding | Crash, authz, audit-trail wipe, silent failures, CI | ✅ Complete |
| **1** — Engine math defensible | Resolved CIDRs, port ranges, internet classification, identity scoping, content-hash snapshot id | ✅ Complete |
| **2** — System of record | Governance survival, audit identity, migrations, logging, transaction boundaries | ⬜ Not started |
| **3** — Pilot-ready | Real ingestion path, bounded algorithms, analyzer coverage | ⬜ Not started |
| **4** — Production hardening | Provider parity, cost/latency limits, full coverage, reproducible builds | ⬜ Not started |

| Metric | Baseline | Now |
|---|---|---|
| Tests passing | 16 | **1,107** |
| Test suite runtime | 60.2s | **2.2s** |
| Silent frontend catches (`.catch(() => {})`) | 11 | **0** |
| Bare `except Exception:` (backend) | 29 | **16** |
| CI | none | pytest + verify_engine + typecheck + lint |
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
