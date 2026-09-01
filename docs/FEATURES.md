# Network Policy Reviewer — Feature Catalog (USP)

> Living document. Update this whenever a feature is added, changed, or shipped.
> **Status legend:** ✅ shipped · 🚧 in progress · 📋 planned

**The one rule that governs everything below:** the deterministic **engine owns all facts and
math** (normalization, identity resolution, CIDR/subnet math, reachability, shadowing,
effective policy, change deltas, conflict math). The **AI owns only language and judgment**
(explaining, ranking, classifying, drafting). The model never computes reachability or
subnet math — it calls deterministic tools and reasons over their structured results.

---

## 1. Core differentiators (the defensible IP)

### 1.1 ✅ Cross-tool consolidation into one policy model
Normalizes **AlgoSec**- (firewall), **Guardicore**- (microsegmentation) and **Wiz**-shaped
(cloud exposure) exports into a single canonical `PolicyRecord` — *"source X may reach
destination Y on service Z"* means the same thing regardless of which console it came from.
One model, one graph, instead of four consoles and four mental models.
- *Where:* `backend/src/normalizers/`, `backend/src/models.py:PolicyRecord`, `db/schema.sql:canonical_rules`.
- ⚠️ *Scope of the current build:* **there is no upload path and no live API client.**
  `normalizers/__init__.py:normalize_all()` reads three fixed files from
  `backend/data/mock/` (`algosec_export.json`, `guardicore_export.json`,
  `wiz_export.json`), and `tasks.py demo` regenerates them from
  `backend/scripts/seed_demo.py` on every cold build — so an edit to those files does not
  survive a rebuild. The adapters also assume well-formed rows; a missing or list-valued
  field in an export currently aborts the run rather than being reported per-row. What the
  canonical model, graph, analyzers and severity math do with those records is real and
  tool-agnostic — swapping the mock adapters for live API clients is the remaining work.

### 1.2 ✅ Deterministic identity resolution (IP is an attribute, not a key)
Merges the same asset seen under different names across tools — `appsrv-07` (Wiz) and
`app-server-07` (AlgoSec/Guardicore) become **one** asset by IP. This merge is the only
reason cross-tool attack paths are visible at all.
- *Where:* identity layer feeding `backend/src/graph/build.py`.

### 1.3 ✅ Cross-tool reachability graph + "the money shot"
A directed effective-policy graph surfaces multi-hop attack paths that cross tool boundaries
and reach sensitive assets — e.g. `Internet → lb-public-01 → app-server-07 → internal-app →
db-prod-01`, a path across **3 tools** into PCI/customer data that **no single console can
show**. Each hop is labelled with the tool that enforces it.
- *Where:* `backend/src/graph/reachability.py`, `backend/src/analyzers/path_trace.py`.

### 1.4 ✅ Deterministic risk findings with an explicit severity vector
**Five** detectors — over-permissive rules, CIDR overlap/redundancy, rule shadowing,
cross-tool paths, and transport-/application-layer exposure (§1.9) — each with an exact
`E × P × D × B` severity vector and guardrail floors that **force critical** on
internet+any/any, internet+admin-port, internet→sensitive paths, and an uninspectable
application reachable from the internet.
- *Where:* `backend/src/analyzers/` (`over_permissive`, `cidr_overlap`, `shadowing`,
  `path_trace`, `transport_exposure`, `severity`). The five names are exactly
  `models.py:FindingType`.
- *The formulas, constants and guardrail clauses are documented per detector in
  [ENGINE.md §6](ENGINE.md).* Note that several detectors emit **per rule ref** rather than
  per distinct problem — `transport_exposure`'s QUIC check most visibly — so one underlying
  issue can produce several findings. Read ENGINE.md §6.5 before treating a finding total as
  a count of distinct problems.

### 1.5 ✅ Local-first AI advisory layer — **10 capabilities**, 5 of them agentic

> **This subsection is the single source of truth for the capability list and count.**
> README.md and AGENTS.md link here instead of restating it, because the count previously
> drifted to four different values across four documents. The list below is
> `backend/src/tools_registry.py:TOOLS` filtered to `kind == "ai_capability"` — the same
> registry that drives the admin Tools screen and per-role enablement — so it can be checked
> mechanically, not by reading prose.

| # | `tools_registry` key | Capability | Kind |
|---|---|---|---|
| 1 | `classify` | Change-request triage (auto-approve vs escalate) | **agentic** — guardrailed, fail-closed |
| 2 | `assistant` | "Ask your network" | **agentic** — tool-calling over the engine (⚠️ Ollama only, see [AGENTS.md](AGENTS.md)) |
| 3 | `remediate` | Remediation **fix-as-code** | **agentic** — propose → re-simulate → revise |
| 4 | `campaign` | Remediation **campaign** (worst-first, cumulative) | **agentic** — composes #3 |
| 5 | `authoring` | Connector-authoring assist (design-time — see §1.7) | **agentic** — propose → normalize sample → revise |
| 6 | `explain` | Plain-English explanation of every finding | language |
| 7 | `rank` | Root-cause grouping + worst-first ranking | judgment |
| 8 | `report` | Executive / PCI-DSS / Zero-Trust posture report | language |
| 9 | `intake` | Change-intake extraction (free text → structured rule) | language → structure |
| 10 | `entity_suggest` | Entity-resolution **suggestions** for human review (never auto-merge) | embeddings |

`TOOLS` holds **11** `ai_capability` rows: the ten above plus `embed`, the embedding job that
backs #10. It is infrastructure rather than a user-facing capability, which is why the
headline number is 10. Separately, `TOOLS` holds **6** `agent_tool` rows — the deterministic
engine functions #2 may call (`resolve`, `reachable`, `find_paths`, `effective_policy`,
`risk_findings`, `simulate_change`). Those are engine, not AI.

**On #3, precisely.** "Re-simulated by the engine" means the full analyzer suite is re-run on
the modified record set (`run_all.reanalyze`) and the fix is accepted **only if the target
finding disappears and no new *critical* appears**. Three honest limits: new **high/medium/low**
findings are not checked; the proof is against the snapshot as it stood at draft time and is
**not re-run at push time**; and the fallback used when no model fix certifies clean is
**conservative (removal-based)** — `remediation.py:_fallback_change` deletes the offending
rule (or reorders it, for a shadowed rule). Call it conservative, not *surgical*.

**Residency.** Inference is local-first *by configuration*, not by construction — see
[README.md](../README.md) and the residency chip in the app header. `ADVISORY_PROVIDER=auto`
falls back to a hosted provider when no local model is reachable, the shipped Render blueprint
pins `ADVISORY_PROVIDER=openai`, and the system of record is cloud Postgres (Neon) regardless.
- *Where:* `backend/src/advisory/`, `backend/src/agent/`, `backend/src/tools_registry.py`.

### 1.6 ✅ Change Gate — judges the computed delta, not the requester's words
Simulates a proposed change, computes the delta, and auto-approves **only inside an
already-safe envelope** — it can never raise the risk tolerance, even under prompt injection.
- *Where:* `backend/src/advisory/`, `frontend/components/ChangeGate.tsx`.

### 1.7 🚧 Connector-authoring assist (design-time preview)
Paste a sample of an unknown tool's export → the model proposes a declarative
`SourceProfile` (config, not code) → the engine checks it by **actually normalizing that
sample** and reports which fields it could and could not map → a human reviews the result.
The value is real and demonstrable: a proposed adapter, proven against the client's own
export, in one round trip, with no Python written.
- ⚠️ **Not yet shipped: registration and ingestion.** There is no endpoint that persists an
  approved profile and no path that ingests live data through one — `/api/connectors/propose`
  returns a proposal and a validation report, and that is where it ends. The engine still
  reads only the three fixed mock exports (§1.1). Until that lands, describe this as a
  **design-time preview**, not as "bring your own source" — and the `approved: false` flag in
  the response is accurate: nothing is registered.
- *Where:* `backend/src/advisory/authoring.py` (the loop), `backend/src/normalizers/profile.py`
  (the deterministic profile normalizer that validates the sample).

### 1.8 ✅ Unified change pipeline (Risk → Gate → Staging) + Admin Tools & Metrics
Iterate a remediation in Risk To-Do with comments → send to Change Gate → after a decision,
send to a **Staging Area** → **Stage for the source system** runs a *simulated, stepped* push
that detects and resolves real conflicts in real time.
- **What is simulated:** the push itself. There is no connector to AlgoSec / Guardicore / Wiz
  in any build of this product, so `build_push_plan` flags the payload `simulated: true`, every
  fabricated step is labelled *"Simulated:"* on screen, and the UI says *"Staged for {tool}
  (simulated push — no live connector)"* rather than claiming the data source was updated.
- **What is real:** the conflict math (genuine engine math against the current snapshot) and
  the consequence of the final status — `pushed` is folded into the record set by
  `change/apply.py:apply_overlay` on the next recompute (which yields a new snapshot id);
  `no_op` (every conflict resolved to "skip") records **nothing**, so the narrated skip and the
  overlay now agree; `conflict` blocks on a contradiction or stale target for human review.
- **Per-role tool enable/disable** (admin Tools screen) and an admin KPI/cost dashboard.
  ⚠️ *The toggle is a **feature flag, not an authorization boundary**.* It is **default-on and
  best-effort**: an absent `ztpa.tool_settings` row enables the capability for **all** roles,
  and a DB error against a cold cache also yields the default-on map
  (`tools_registry.enabled_roles`). Write paths are gated by the `require_admin` /
  `require_approver` / `require_operator` route dependencies in `app/main.py` — those are the
  authorization boundary. Do not rely on a capability toggle to restrict one.
- *Where:* `backend/src/change/staging.py`, `backend/src/change/apply.py`, `backend/src/metrics.py`,
  `backend/src/tools_registry.py`, `frontend/components/Staging.tsx`, `frontend/components/admin/`.

### 1.9 ✅ Transport- & application-layer rule decoding (QUIC / HTTP-3 / L7 App-ID)
**Why it matters (the USP angle):** QUIC (HTTP/3) rides **UDP/443**. Most legacy firewalls
can't inspect it, so a `udp/443` allow is an **inspection blind spot** — encrypted traffic
that bypasses the controls teams *think* they have. NPR previously modelled only L4
(`tcp`/`udp`/`any`, single port) and dropped application identity (the `l7_app` schema column
was never written). It now decodes the L7 layer. A policy advisor that can *decode* and
*reason about* QUIC and transport-layer semantics flags a class of risk every single-console
tool misses.

**What "decode" means here (engine owns the facts):**
- **Richer L4:** add `icmp`/`sctp` to the protocol set; support **port ranges**
  (the DB `ports` JSONB already models `{proto, port_start, port_end}` — the canonical model
  needs to catch up).
- **L7 application identity (`l7_app`):** capture explicit App-IDs from source exports
  (`quic`, `http3`, `tls`, `dns`, `ssh`, …) **and** deterministically *infer* the likely app
  from `(protocol, port)` via a fixed `APP_BY_PORT` map (e.g. `udp/443 → quic`,
  `udp/53 → dns`, `tcp/443 → tls`). Every L7 tag is marked `declared` vs `inferred` so the
  provenance is auditable — inference is a deterministic table lookup, **not** a model call.

**What "reason" means (new analyzers + reachability):**
- **QUIC blind-spot finding:** `udp/443` reachable from a lower-trust zone (especially
  internet) to a sensitive dest → "QUIC (UDP/443) reachable — likely uninspected."
- **Fallback-not-blocked:** `tcp/443` *and* `udp/443` both open → can't force the inspectable
  TLS path; QUIC silently wins.
- ~~**Broad UDP / ICMP exposure** as transport-layer hygiene findings.~~ 📋 **Not built.**
  `analyzers/transport_exposure.py` ships the two checks above and no third one; the
  protocol set decodes `icmp`/`sctp`, but nothing scores broad UDP or ICMP as its own
  finding. Left here as the planned extension, not as a shipped claim.
- **Reachability by protocol + app:** replace the fragile `f"/{port}"` substring match in
  `graph/reachability.py` with structured protocol/port-range/app matching. ✅ *Shipped —
  `reachability.py:_grant_matches` / `_edge_matches`.*

**How we demo it (fits the existing 7-min script):**
1. Seed the three mock exports with transport/L7 rules:
   `algosec_export.json` — an internet `udp/443` allow to the app tier;
   `guardicore_export.json` — a rule carrying App-ID `quic`;
   `wiz_export.json` — a cloud exposure on `udp/443`.
2. `python tasks.py db && python tasks.py demo` to recompute the snapshot.
3. **Network Map:** filter by protocol/app → a **QUIC** edge lights up that the old L4 view
   couldn't distinguish from plain UDP.
4. **Risk To-Do:** the new **"QUIC reachable — uninspected"** critical appears worst-first.
   Draft a fix (block `udp/443` / force TLS fallback) → engine re-simulates → resolves.
5. **Change Gate → Staging:** push the fix through the new pipeline; conflict math runs live.
6. One line for the manager: *"Every other tool sees a UDP allow on 443. We see QUIC — and
   we see that it's the one path nobody is inspecting."*

**Implementation (engine-first — shipped):**
- `models.py` — `PolicyRecord.protocol` now `tcp|udp|icmp|sctp|any`; added `l7_app`,
  `l7_source`, `port_end`. New `transport_exposure` finding type.
- `config.py` — `L7_APPS`, `APP_BY_PORT` (inference), `APP_TRANSPORT` (App-ID → transport),
  `INSPECTION_BLIND_APPS`, `TRANSPORT_CONFIG` (severity knobs).
- `normalizers/common.py:parse_service` → returns `DecodedService` (L4 + L7); recognizes
  App-ID tokens, infers L7 from `(proto, port)`, parses port ranges. Wired through
  `algosec`/`guardicore`/`wiz`/`profile` (+ a profile `app` field mapping) and every other
  caller (intake, remediation, staging, agent tools, severity).
- `persist.py` — writes `l7_app` + port ranges to `canonical_rules` and `graph_edges`.
- `graph/build.py` + `graph/reachability.py` — grants/edges carry `l7_app`/`apps`; new
  structured `reachable(port, protocol, app)` matcher replaces the substring check.
- `analyzers/transport_exposure.py` — `quic_blind_spot` + `tls_fallback_not_blocked`;
  `severity.score_transport_exposure`; wired into `run_all.run()` + `reanalyze()`.
- `remediation.py` — fallback fix drops the uninspectable (QUIC/UDP) grant.
- `db/schema.sql` — widened `findings.type` CHECK (idempotent).
- API `/api/graph` exposes edge `apps`; frontend shows L7 chips in Risk To-Do, the report
  breakdown, and the cross-tool path hops.
- `scripts/verify_engine.py` — added P6/P7 acceptance checks; all pass.

**Demo dataset (in `seed_demo.py`):** `ALGO-080` (internet→app-server-09 udp/443 → FORCED
critical QUIC blind spot), `ALGO-082` + `GC-020` (declared `quic` App-ID rules), `WIZ-020/021`
(QUIC at the edge + lateral). Measured on the 27-rule seeded dataset at the time of that
change: 9 `transport_exposure` findings, cross-tool path still singular, all engine
self-checks green. Treat those numbers as a dated measurement of one fixture, not an
invariant — `backend/scripts/verify_engine.py` is what actually holds the line, and it
asserts the *properties* (P1–P7 exist, are forced where they should be, and re-run
byte-identically) rather than a total.

---

## Changelog
- **2026-06-25** — Document created. Catalogued shipped core USPs (§1); added the QUIC /
  transport-layer decoding feature with demo + implementation plan.
- **2026-06-25** — Change pipeline (Risk→Gate→Staging) + Admin Tools/Metrics marked shipped
  (§1.8). QUIC / transport-layer decoding promoted to in progress; implementation started,
  engine-first.
- **2026-06-25** — QUIC / transport-layer decoding **shipped** (§1.9): L7 decode layer
  (declared App-IDs + deterministic inference + port ranges), `transport_exposure` analyzer
  (QUIC blind spot + TLS-fallback-not-blocked), structured reachability matching, demo seed
  rules, frontend L7 chips. Engine self-check + frontend build green; snapshot recomputed.
- **2026-09-01** — **Documentation-accuracy pass** against `PROD-READINESS-AUDIT.md`
  ("Documentation corrections"). No feature change; every edit is a claim brought back into
  line with the code. §1.5 is now the **single source of truth for the AI capability list
  and count** (10 user-facing, 5 of them agentic, from `tools_registry.TOOLS`) and README.md
  / AGENTS.md reference it instead of restating it. §1.1 states that there is no upload path
  and that the three mock exports are regenerated on every cold build. §1.4 now says **five**
  detectors, not four, and points at the new [ENGINE.md §6.5](ENGINE.md) for
  `transport_exposure` — previously absent from the formula reference despite being one of
  the largest contributors to the demo finding count. §1.7 is demoted to 🚧 **design-time
  preview**: registration and ingestion are not implemented. §1.8 separates what the staging
  push simulates from the conflict math that is real, and records that the per-role
  capability toggle is a **default-on feature flag, not an authorization boundary**. §1.9
  marks the never-built broad-UDP/ICMP check as 📋 planned and dates its measured counts.
  The residency claim ("data never leaves the host") is qualified everywhere it appeared:
  `ADVISORY_PROVIDER=auto` falls back to a hosted provider silently, `render.yaml` pins
  `openai`, and the system of record is cloud Postgres regardless.
