# ZeroTrust Policy Advisor — Feature Catalog (USP)

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
Ingests **AlgoSec** (firewall), **Guardicore** (microsegmentation), and **Wiz** (cloud
exposure) and normalizes every rule into a single canonical `PolicyRecord` — *"source X may
reach destination Y on service Z"* means the same thing regardless of which console it came
from. One model, one graph, instead of four consoles and four mental models.
- *Where:* `backend/src/normalizers/`, `backend/src/models.py:PolicyRecord`, `db/schema.sql:canonical_rules`.

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
Over-permissive rules, CIDR overlap/redundancy, rule shadowing, and cross-tool paths — each
with an exact `E × P × D × B` severity vector and guardrail floors that **force critical** on
internet+any/any, internet+admin-port, and internet→sensitive paths.
- *Where:* `backend/src/analyzers/` (`over_permissive`, `cidr_overlap`, `shadowing`, `path_trace`, `severity`).

### 1.5 ✅ Local-first AI advisory layer (8 capabilities, on Ollama)
1. Change-request triage (auto-approve vs escalate) — agentic, guardrailed, fail-closed
2. "Ask your network" assistant — agentic tool-calling over the engine
3. Plain-English explanation of every finding
4. Root-cause grouping + worst-first ranking
5. Remediation **fix-as-code**, re-simulated by the engine to *prove* it resolves
6. Executive / PCI-DSS / Zero-Trust posture report
7. Change-intake extraction (free text → structured rule)
8. Entity-resolution **suggestions** for human review (never auto-merge)

Data stays local; the topology never leaves the machine.
- *Where:* `backend/src/advisory/`, `backend/src/agent/`.

### 1.6 ✅ Change Gate — judges the computed delta, not the requester's words
Simulates a proposed change, computes the delta, and auto-approves **only inside an
already-safe envelope** — it can never raise the risk tolerance, even under prompt injection.
- *Where:* `backend/src/advisory/`, `frontend/components/ChangeGate.tsx`.

### 1.7 ✅ Bring-your-own source (dynamic connector authoring)
Paste a sample of an unknown tool's export → the model proposes a declarative
`SourceProfile` → the engine validates it by actually normalizing the sample → a human
approves. New source, no new Python.
- *Where:* `backend/src/normalizers/profile.py`.

### 1.8 ✅ Unified change pipeline (Risk → Gate → Staging) + Admin Tools & Metrics
Iterate a remediation in Risk To-Do with comments → send to Change Gate → after a decision,
send to a **Staging Area** → **Push to source system** runs a *simulated, stepped* push that
detects and **resolves real conflicts in real time** (push is simulated; the conflict math is
genuine engine math). Plus per-role tool enable/disable and an admin KPI/cost dashboard.
- *Where:* `backend/src/change/staging.py`, `backend/src/metrics.py`, `backend/src/tools_registry.py`,
  `frontend/components/Staging.tsx`, `frontend/components/admin/`.

### 1.9 ✅ Transport- & application-layer rule decoding (QUIC / HTTP-3 / L7 App-ID)
**Why it matters (the USP angle):** QUIC (HTTP/3) rides **UDP/443**. Most legacy firewalls
can't inspect it, so a `udp/443` allow is an **inspection blind spot** — encrypted traffic
that bypasses the controls teams *think* they have. ZTPA previously modelled only L4
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
- **Broad UDP / ICMP exposure** as transport-layer hygiene findings.
- **Reachability by protocol + app:** replace the fragile `f"/{port}"` substring match in
  `graph/reachability.py` with structured protocol/port-range/app matching.

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
(QUIC at the edge + lateral). Verified: 9 transport findings, cross-tool path still singular,
all engine self-checks green.

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
