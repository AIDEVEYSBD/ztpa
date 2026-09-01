# Production-Readiness Audit — Network Policy Reviewer

> Independent adversarial audit of the deterministic engine and the agentic layer, checked against every claim in `README.md`, `docs/FEATURES.md`, `docs/ENGINE.md`, `docs/AGENTS.md` and `docs/HOW-IT-WORKS.md`.
> Method: 9 independent auditors over the full source, every finding then handed to an adversarial verifier instructed to **refute** it, plus a completeness critic. **159 findings raised, 4 refuted, 155 survived**, 13 added by the critic. Empirical probes (mutation testing, input perturbation, cross-process determinism, scale timing) were run against the real engine.

---

## Verdict

**No — the core engine is not production-ready: its determinism, provenance and guardrail architecture are genuinely well-built, but its math is correct only for the one data encoding the demo fixture happens to use, it has zero tests on any of its own arithmetic, and the layers wrapped around it (authz, persistence, error handling) turn every failure into a confident, silent, wrong-looking-fine screen.**

### Readiness by layer

| Layer | Rating | Assessment |
|---|---|---|
| Determinism, content-addressed ids, provenance | 🟢 solid | Real union-find rooted at min(name), everything explicitly sorted, SHA-1 over sorted JSON, zero randomness in the fact path — verified byte-identical across 5 processes and 5 hash seeds. This part earns the word engineering. |
| Severity model (E x P x D x B) as a formula | 🟢 solid | The formula matches ENGINE.md constant-for-constant, the worked example reproduces to 100 exactly, and every finding carries its vector so a client can recompute by hand — a genuinely rare, defensible property. |
| Severity model as applied to real inputs | 🔴 not-ready | Blind to port ranges (tcp/1-65535 to a non-sensitive host = ZERO findings), scores named objects and the keyword 'any' as a single host (E=0.1), and 'the internet' means the literal string 0.0.0.0/0 so 0.0.0.0/1 drops from 90/critical to 56/medium. |
| Normalization + canonical model | 🔴 not-ready | algosec.py:49 resolves a named object's CIDR and then discards it (_s_cidr) while keeping the label; the model is scalar where real policy is multi-valued and ordered; four unguarded subscripts mean one malformed rule in 40,000 aborts the whole snapshot. |
| Identity resolution | 🟠 fragile | The union-find is real and order-independent, but it keys on the bare IP string with no VRF/VPC/tenant scope — the exact duplicate-IP problem the product is sold on solving — and merges transitively, so one shared VIP or 0.0.0.0 placeholder fuses unrelated hosts. |
| Graph + reachability | 🟠 fragile | Genuinely emergent, no demo hardcoding, real networkx traversal — but effective_policy and reachable give OPPOSITE answers for app-segment on the shipped demo, and the money-shot path pivots through a /16 that _valid_traversal's own docstring says it rejects. |
| Analyzers (5 of them, docs say 4) | 🟡 demo-grade | Correct on the fixture they were written against; shadowing cannot detect the canonical broad-rule-at-the-top case (dest matched by name, service by string equality), and shadowing/cidr_overlap are O(n^2) — 11.5s at 2,000 rules, ~5 min at 10k. |
| Change pipeline + simulation | 🔴 not-ready | The 'evaluate your own rule' path has raised TypeError on every call since the initial commit (main.py:584 unpacks a 6-field dataclass into 3 names) and the frontend's empty catch swallows the 500 — only two hardcoded demo requests have ever worked. |
| AI advisory layer (architecture) | 🟢 solid | Three-layer guardrail is real and correctly ordered, engine-validated remediation with genuine feedback, campaign's cumulative gate cannot regress criticals, every agent has a re-validated deterministic fallback, full by/attempts/trace provenance. Better than most production LLM features. |
| AI advisory layer (as shipped) | 🔴 not-ready | render.yaml pins ADVISORY_PROVIDER=openai, and the tool-calling assistant only calls tools on Ollama — on the only documented deployment it answers path questions from a list of finding titles while the UI renders a fake 'Tool trace'. |
| API + persistence (system of record) | 🔴 not-ready | Every recompute cascade-deletes the entire change-request and decision audit trail, because delete_snapshot_children drops the parent snapshots row and change_requests is ON DELETE CASCADE against it. |
| Security / authorization | 🔴 not-ready | Verified by enumeration: 9 state-mutating endpoints have zero role guard, including POST /api/staging, /api/staging/{id}/push, DELETE /api/staging/{id}, /api/assets/merge and /api/recompute — a legitimately-authenticated viewer can push a rule into the durable overlay. |
| Frontend | 🟠 fragile | NetworkMap's scale banner and the two-phase explain design show real care, but 20 call sites do .catch(() => {}) so a broken backend renders as '0 findings, 0 prioritized actions' with no banner. |
| Tests + CI | 🔴 not-ready | 16 genuinely good agent tests, zero on the engine. A mutation matrix showed 6 of 10 injected engine defects — including moving the critical band 80->95 and emptying ADMIN_LATERAL_PORTS — pass BOTH pytest and verify_engine green. |
| Docs | 🟠 fragile | ENGINE.md sec 10 and HOW-IT-WORKS.md sec 14 are unusually honest and will earn you credit; README.md and FEATURES.md carry none of those caveats and overreach on ingestion, local-first residency and BYO-source. |

### Finding counts

| Severity | Count |  | Category | Count |
|---|---|---|---|---|
| **blocker** | 19 |  | claim-overreach | 29 |
| **high** | 52 |  | correctness-bug | 45 |
| **medium** | 62 |  | security | 9 |
| **low** | 35 |  | demo-grade | 8 |
|  |  |  | prod-readiness-gap | 47 |
|  |  |  | robustness-gap | 30 |

---

## Why it doesn't inspire confidence

You do not trust it because it has repeatedly taught you not to, through four specific mechanics. (1) IT CANNOT TELL YOU IT FAILED. console/page.tsx:59-62 wraps findings, graph and actions in .catch(() => {}) and the error banner is fed only by /api/health — which hardcodes status:'ok' even when db:false (main.py:153-160) — while engine() swallows persist failures with a bare `except Exception: pass` (main.py:117). A dead database and a clean estate are pixel-identical: '0 findings across three tools, 0 prioritized actions.' There is no logging anywhere in ~6,500 LOC to contradict the screen. [silent-empty-ui-on-api-failure, health-lies-when-db-down, engine-swallows-persist-failure, no-application-logging-at-all] (2) THE PRODUCT CONTRADICTS ITSELF IN FRONT OF YOU. On the shipped demo, with no crafted input, effective_policy('app-segment') returns internet_exposed:true while reachable('0.0.0.0/0','app-segment') returns reachable:false — because who_can_reach uses bare nx.has_path with no _valid_traversal filter (reachability.py:180). Both are tools the assistant can call in the same turn. [who-can-reach-contradicts-reachable] (3) BUTTONS DO NOTHING, OR LIE ABOUT WHAT THEY DID. 'Simulate a custom change' has 500'd on every call since the initial commit and ChangeGate.tsx:90's empty catch makes it look like nothing happened. The recompute overlay renders a green check and 'Snapshot recomputed' on failure (Topbar.tsx:158). Staging tells you 'Applied to AlgoSec — data source updated' for a push that contacts nothing, and reports 'Skip: no-op' for a duplicate it then appends anyway. [classify-custom-500, fake-progress-reports-success-on-failure, staging-claims-data-source-updated, conflicts-narrated-not-resolved] (4) THE STATE YOU BUILD UP DISAPPEARS. Pressing Recompute — even with zero data change, because _fingerprint hashes only records — deletes the snapshots row, and change_requests/change_decisions cascade with it. Your decision log empties and the staged card is left dangling with a null requester. [recompute-wipes-audit-trail, snapshot-id-excludes-identity-state] Underneath all four sits the real reason they could ship: nothing tests the engine. A mutation matrix showed you can move the critical band from 80 to 95, empty ADMIN_LATERAL_PORTS, or make every PCI asset score like an untagged one, and both `pytest` and `tasks.py verify` still print green. And the demo hides the biggest gap of all — I checked the fixture: 15 of 16 AlgoSec rules put a raw CIDR in the src column, which is the one encoding exposure_score handles correctly. Real exports use named objects, which score E=0.1 and produce FEWER findings, so a client's file would read as 'clean'.

---

## What is genuinely well built

These were verified, not taken on trust. They are the foundation the plan below builds on — the problems are at the edges, not in the core idea.

- Determinism is real and I verified it independently, not just read the claim: full engine output (snapshot_id + assets + alias_map + correlations + all finding fields incl. signals + sorted nodes/edges) hashes identically across 5 separate processes with PYTHONHASHSEED in {0,1,42,12345,99999}. identity.py earns it with sorted() at 9 sites and a union-find that roots at min(name); ids.py has no randomness and no timestamps.
- No demo hardcoding in the engine. A grep of all of backend/src for the seeded asset names (db-prod-01, app-server-0, lb-public, ALGO-, GC-0, WIZ-, app-segment...) returns ZERO matches in graph/ and analyzers/ outside prose docstrings. The money-shot cross-tool path is genuinely emergent from generic predicates — the single thing most worth worrying about, and it holds up.
- The severity model is auditable by hand. Every constant in severity.py/config.py matches ENGINE.md section-by-section, the worked example reproduces to exactly 100, and signals['severity_vector'] ships on every finding. A client can recompute any score from published tables — genuinely rare.
- The three-layer change gate is architecturally sound and correctly ordered: Layer 1 returns on forced_escalate BEFORE any model call (test_agents.py:183 asserts zero model calls), Layer 2 fails closed on unparseable output, and Layer 3's _clean(delta) is computed purely from engine output so the model can only ever narrow the envelope. Prompt injection genuinely cannot widen what the gate approves.
- The engine, not the model, decides. main.py:650 computes `decision = 'auto_approve' if (resolves and not new_crit) else 'escalate'` with model:'engine' recorded, there is no request field that lets a client POST a verdict, and /api/staging re-reads the persisted decision rather than trusting the request body. I looked specifically for that attack and it is correctly closed.
- Simulation is genuinely side-effect free — fresh graph per call, pydantic model_copy, no module-level cached graph. The most common way this class of codebase corrupts itself, and it is right here.
- The campaign's cumulative gate is the strongest engineering in the AI layer: each candidate is re-simulated against the ACCUMULATED record set and applied only if it resolves without introducing a critical, so the plan structurally cannot regress the critical count.
- Provenance is modelled honestly: PolicyRecord carries source_tool + raw_ref back to the vendor rule id, build.py keeps parallel grants as a list instead of collapsing them, and l7_source records whether an App-ID was declared or inferred. A real differentiator, not faked.
- Every endpoint is `def`, not `async def` — all 40 of them. The single most common way FastAPI apps with slow LLM calls destroy themselves, correctly avoided throughout. The pure-ASGI _ActorMiddleware with its accurate comment about ContextVar propagation is a subtle detail most people get wrong.
- The DB layer is written with real care for Neon specifically: check=ConnectionPool.check_connection, max_lifetime/max_idle cycling, search_path set once per connection and committed, every table schema-qualified as a second defence, and correct graceful degradation when psycopg_pool is absent.
- SQL injection and secret hygiene are genuinely clean and I actively hunted for both: every backend query uses %s binding, every frontend query uses $1, .env is gitignored and was never committed, render.yaml uses sync:false for both secrets, and there are no NEXT_PUBLIC_* variables at all.
- The SSO/OIDC implementation is well done: PKCE + state + nonce, JWKS-verified ES256, endpoints from discovery, absolute (not rolling) session deadline so role revocation takes effect, RP-initiated logout with id_token_hint, and provisionSsoUser is carefully written against exactly the account-linking takeover bug this code usually has.
- The 16 tests that exist are well above smoke level — they assert that the engine's rejection verdict physically reached the next prompt, that the guardrail path made zero model calls, that an LLM auto_approve on an unsafe delta is overridden, and that campaign criticals are monotonically non-increasing. Whoever wrote these understood what to test about an agent loop. The suite is also already CI-ready offline: 16 pass with DATABASE_URL and OLLAMA_HOST pointed at dead sockets and both API keys blank.
- ENGINE.md section 10 and HOW-IT-WORKS.md section 14 volunteer real limitations (no deny precedence, no CIDR-membership expansion, path bounds, synthesised Guardicore ordering) before a client can find them. That instinct to disclose is the right one and will earn you credit — the fix is to make README/FEATURES carry the same caveats, not to remove these.

---

## Gap themes (clustered by root cause)

Most of the 155 findings collapse into these. Fixing the root cause is the real work.

### 1. The canonical model keeps the label and throws away the resolved value  
`BLOCKER` · 6 findings

**Root cause.** algosec.py:49 resolves a named object to its CIDR and then discards it — the variable is literally `_s_cidr`, underscore-prefixed — while PolicyRecord.source stores the object NAME with source_kind='identity'. exposure_score then short-circuits `if source_kind == 'identity': return E_IDENTITY` (0.1), cidr_overlap skips the rule entirely (`if rec.source_kind != 'cidr': continue`), and identity.py:96's `abstract = all(e.abstract...)` marks a /16 network object 'concrete' so it can act as a path pivot. Everything downstream reasons over a string that names an address space instead of over the address space.

**If ignored.** A real export reports FEWER findings than the demo, and 'near-zero findings' reads to a client as 'clean'. I verified the fixture: 15 of 16 demo rules use raw CIDRs in src, which is why everything looks perfect. The same rule written four ways (0.0.0.0/0, any, ANY-EXTERNAL, INTERNET) yields severity 100 once and NO FINDING AT ALL three times. This is the single most damaging gap and it is invisible — it fails in the direction of under-reporting risk.

### 2. The canonical model is scalar and unordered where real firewall policy is multi-valued, ordered and stateful  
`BLOCKER` · 12 findings

**Root cause.** PolicyRecord has scalar source/destination/service, no enabled flag, no device, no direction, no negation, and port_end is parsed and stored but read by NOBODY in analyzers/ except reachability._grant_matches. Guardicore's real priority is discarded and order synthesized from array index. build_graph drops every non-allow record, so deny precedence does not exist. Scoring, guardrails, shadowing coverage and staging conflict math all read the single `port` scalar and the display-label string.

**If ignored.** The two most common real-world over-permissive patterns are invisible. `0.0.0.0/0 -> host tcp/1-65535` produces ZERO findings (scored P=0.5 'unknown' from the range START port) while the same rule on tcp/3389 is forced-critical at 90. A rule whose service is the Palo/ASA keyword `ip` decodes to plain tcp so the any/any guardrail never fires. Comma-separated port lists — the most common AlgoSec service encoding — lose their ports silently. A client's own scanner will flag the rules you call clean.

### 3. Identity merges on a bare IP with no tenancy scope — the exact problem the product claims to solve  
`BLOCKER` · 4 findings

**Root cause.** identity.py:56-64 builds `ip_to_names[e.ip]` keyed on the raw IP string and unions every name sharing it. ObservedEntity has no context field at all; Asset.context is populated only AFTER the merge. The correlation is even labelled match_key='context_ip' — the name promises a context that is nowhere in the code. Union-find is transitive by construction, and the only filter is `if e.ip:`, which lets through 0.0.0.0, 127.0.0.1, cluster VIPs and NAT addresses.

**If ignored.** README.md:12 sells 'IP is an attribute, not a key' and the merge treats the IP AS the key. RFC1918 reuse across VPCs is universal. A wrong merge does not mislabel an asset — build_graph collapses both nodes' edges onto one, so the tool reports reachability that does not exist, and dest_score takes MAX over unioned tags so a dev box inherits `pci`. Fabricated reachability in a security tool is worse than no tool. Six hosts sharing a 0.0.0.0 placeholder collapse the entire estate into one asset.

### 4. snapshot_id is a cache key, not a content hash — and governance rows are children of it  
`BLOCKER` · 8 findings

**Root cause.** Two compounding decisions. (a) `_fingerprint` (run_all.py:57) hashes only tool|ref|source|destination|service|action|order — omitting dest_tags, port, port_end, protocol, l7_app, the object catalog, and the manual_merges argument that materially changes assets, graph and findings. (b) `delete_snapshot_children` (db.py:222) implements 'clear the children' by deleting the PARENT snapshots row, and change_requests.snapshot_id is `REFERENCES snapshots(snapshot_id) ON DELETE CASCADE` (schema.sql:192). Same id + delete-parent = in-place mutation of a supposedly immutable snapshot, taking the governance record with it.

**If ignored.** The compliance story dies on the first recompute. Confirming an asset merge or pressing Recompute on UNCHANGED data destroys every change_request and change_decision for that snapshot, leaves staged_changes dangling with null requester/justification, and mutates the analysis an exported report claims to be based on. Retag one asset as PCI and the verdict flips from nothing to forced-critical while the system of record insists it is the same snapshot. This is exactly the audit property a regulated client will test.

### 5. Authorization is advisory: the boundary is a forgeable header and 9 mutating endpoints have no guard at all  
`BLOCKER` · 11 findings

**Root cause.** request_ctx trusts x-npr-role from the proxy and its own docstring says the backend 'must stay private' — but render.yaml deploys it as a public `type: web` service with no shared secret. Worse, and undocumented: even inside the intended, correctly-proxied deployment, role checks were added per-branch rather than as a dependency. I enumerated every mutating route: /api/recompute, /api/campaign/plan, /api/campaign/submit, /api/actions/recompute, /api/assets/merge, /api/assets/unmerge, /api/staging, /api/staging/{id}/push and DELETE /api/staging/{id} have NO role guard. tools_registry defaults an absent row to ALL_ROLES, so the capability flags are a feature toggle, not an authz layer.

**If ignored.** A product whose entire value is change GOVERNANCE enforces its approval gate on one branch out of five. An authenticated npr_viewer — the role you hand an auditor — can drive remediate -> submit -> stage -> PUSH and write a rule into the durable overlay that is re-applied on every recompute, with the audit row reading actor='user'. Separately, on any pre-SSO or cutover deployment the magic-link login returns a live sign-in token to the unauthenticated browser, which is a ten-second account takeover of any known email including the admin.

### 6. Failures are swallowed and rendered as empty state — the app cannot tell you it is broken  
`BLOCKER` · 14 findings

**Root cause.** A consistent convention of degrading silently on paths that change the ANSWER, with nothing to observe it. 29 `except Exception: pass/return []` in the backend (including _load_merges, _load_applied, persist, write_scenario), zero logging statements in ~6,500 LOC, no global exception handler, health hardcoded to status:'ok', and 20 frontend call sites doing `.catch(() => {})` while the error banner is fed only by /api/health. lib/api.ts throws away the HTTPException detail so every failure — 403, 409, 500 — renders as 'is the API running?'.

**If ignored.** This is the direct mechanical cause of the user's stated lack of confidence, and it is the worst possible failure mode for a security tool: a transient DB error makes the engine silently recompute WITHOUT confirmed merges or pushed changes and then persists that as authoritative, while the dashboard reads '0 critical' and the green toast says recompute complete. Deploy against a Neon project nobody migrated and Render marks it healthy while every panel is blank. When a user reports 'the findings disappeared' there is no log, no metric, no audit row and no request id to investigate with.

### 7. The AI layer's provider abstraction does not hold on the configuration that actually ships  
`BLOCKER` · 11 findings

**Root cause.** assistant.ask() gates the entire tool-calling loop on `if settings.active_provider() == 'ollama'` and otherwise falls through to a single-shot over a precomputed finding-title blob — while render.yaml pins ADVISORY_PROVIDER=openai with the comment 'no local Ollama on Render'. Compounding it: ollama_probe reports ok if ANY model is pulled rather than the configured tag; active_provider silently escalates to a hosted provider when the probe fails; provider_status computes `data_residency` and the frontend types it but no component renders it; ranked_by is hardcoded 'llm' on the cached path; the Anthropic path hardcodes max_tokens=1500.

**If ignored.** On the only deployment the repo documents, the flagship 'ask your network' agent calls zero deterministic tools — risk_findings returns only {id,type,title,severity,band,forced_critical}, no paths, no ports, no hops — and is still instructed to 'cite the concrete path', so it confabulates while the UI renders a 'Tool trace' header and says every answer is grounded in computed facts. Meanwhile a laptop where the developer ran `ollama pull qwen3-coder` (producing :latest, not the configured :30b) gets a probe that says local, a residency badge that says local, and an entire AI layer silently on deterministic fallback.

### 8. There is no ingestion path — and the app deletes whatever you put in the input directory  
`BLOCKER` · 8 findings

**Root cause.** normalize_all() hardcodes three filenames under backend/data/mock, and engine()/recompute() call write_scenario() first with the comment 'keep data/mock consistent with the active scenario', which REGENERATES those three files from a Python fixture. There is no upload endpoint in main.py's 1018 lines, no source_profiles table, and apply_profile has exactly one caller — the validator in authoring.py. Compounding it, the SourceProfile validator's only checks are 'any rows?' and 'are source/dest/service non-empty?', and a missing field becomes the truthy string 'None'.

**If ignored.** Day one of a pilot is impossible. Copy the client's three exports into data/mock, restart, and the warm-engine thread overwrites all three with the 25-asset fixture. Even the documented `tasks.py seed-scale 1000` workflow is undone by the next cold build. And when ingestion does exist, one malformed row aborts the entire run with a raw KeyError — no partial ingest, no skipped-rows report — while a profile whose field names are all wrong returns valid=True with every source normalized to the literal string 'None' and a green 'the engine validated it' badge.

### 9. Unbounded work sits on synchronous request paths  
`HIGH` · 16 findings

**Root cause.** No wall-clock budgets, no job queue, no chunking, and CPU-quadratic algorithms. _PATH_SCAN_CAP bounds yielded paths but not DFS backtracking (34-node mesh = 117s, 62 nodes never finishes) and truncation is invisible to the caller. shadowing/cidr_overlap are O(n^2) per tool/group. /api/actions runs a live LLM call INSIDE an open pooled DB transaction. campaign_submit runs a full reanalyze per step inside one transaction. upsert_many builds one giant multi-VALUES statement that blows the 65,535 bind-parameter limit at ~2,620 rules. DatasetBody.n and the limit params have no bounds.

**If ignored.** The scale story is unearned: seed_scale generates a star topology with in-degree 1 and out-degree 0, so the one artefact whose stated purpose is proving the engine scales is topologically incapable of exercising path enumeration — which is the actual cliff. A client's Guardicore export with one 60-host meshed app tier hangs the service. A 40k-rule rulebase spends ~7 minutes in shadowing alone. And three people opening the Risks tab on a cold model starve a 10-connection pool because ranking holds a connection across the LLM call.

### 10. Nothing tests the deterministic core, and the one 'proof' is a golden assertion on an unrepresentative fixture  
`BLOCKER` · 15 findings

**Root cause.** The only test file is 355 lines and 100% advisory/agent layer — no assertion anywhere touches severity, severity_band, a sub-score, an alias_map entry, a graph edge or a finding count. verify_engine.py is existence-predicates plus a hardcoded 5-hop node list against one 27-rule file, its determinism check runs both passes in ONE process (so PYTHONHASHSEED cannot differ) and compares 3 of a Finding's fields. No CI, no `test` command in tasks.py or the Makefile, no lint/type config, and persist.py + app/main.py have literally zero executed coverage.

**If ignored.** This is the root cause that let every other defect ship. Measured: 6 of 10 injected engine defects pass BOTH pytest and verify_engine — including moving the critical band from 80 to 95, flattening dest_score so PCI scores like untagged, emptying ADMIN_LATERAL_PORTS (deleting the RDP-from-internet guardrail), and changing impact_base. The test named for Layer 3 short-circuits at Layer 1 and never invokes its own model stub. Until this is fixed every other fix in this plan is unprotected and will regress. It is also the cheapest item on the list — the suite already runs green fully offline.

### 11. The docs oversell what the code does, in exactly the places a security-savvy reader checks first  
`HIGH` · 17 findings

**Root cause.** ENGINE.md sec 10 and HOW-IT-WORKS.md sec 14 are honest and current-ish; README.md and FEATURES.md were written to the ambition and never reconciled. Nobody owns doc/code drift, so ENGINE.md still confesses a substring port bug that was fixed while omitting five live gaps, four docs give four different capability counts, and README instructs the operator to pull a model (gemma4:26b) that settings.py never uses and that cannot be pulled.

**If ignored.** This is the cheapest confidence you can buy and the fastest to lose. An architect who reads ENGINE.md sec 10.3, greps reachability.py:124 for the confessed substring bug and finds an unrelated islice call now treats the whole document as unverified — which retroactively discredits sec 10.1 and 10.2, which are TRUE and important. Same shape on the Staging screen: the conflict math is genuinely real, and the fabricated 'Connected to the algosec policy data source' step is what the client will remember.

---

## Remediation plan

### Phase 0 — Stop the bleeding (demo cannot lie or crash)
**Duration:** 1 week (2-3 engineers)

Make every screen either correct or visibly failed. Nothing here changes the engine's math; it removes the failures that would embarrass you live and the authz hole that ends the meeting. After this phase you can demo with a straight face on the seeded dataset.

**Exit criteria (objectively checkable):**

- [ ] POST /api/change/classify with {source,destination,service} returns 200 with a decision — proven by a new TestClient test, not by clicking
- [ ] For every asset in the seeded snapshot, effective_policy(a).internet_exposed == reachable('0.0.0.0/0', a).reachable — asserted as a property test over all nodes
- [ ] curl with x-npr-role: viewer receives 403 from all 9 previously-unguarded mutating routes; a test parametrised over the route list asserts it
- [ ] Pressing Recompute twice leaves /api/change-decisions row count unchanged (currently drops to zero) — asserted by a DB test
- [ ] Killing the backend mid-session makes the console render an explicit error panel; grep of frontend/ for `.catch(() => {})` and `catch { /*` returns zero hits in app/ and components/
- [ ] `python tasks.py test` exists and .github/workflows/ci.yml runs pytest + verify_engine + `npm run typecheck` green on push
- [ ] The Topbar overlay renders a distinct failure state (never a green check) when the underlying call throws
- [ ] A provider/residency chip is visible in the Topbar reading the already-present health.ai payload, and reads 'Hosted — data leaves this host' whenever active_provider != ollama

**Workstreams:**

- **(S)** Fix the custom-change crash AND the dest_tags hole together — they MUST ship in the same commit. Replace `proto, port, label = parse_service(...)` with `svc = parse_service(...)` and use svc.protocol/port/port_end/label/l7_app; then resolve dest_tags from the engine inside simulate_change (which already has `assets`) so no caller can strip them again.
  - *Files:* `backend/app/main.py:583-594`, `backend/src/change/simulate.py:39-60`, `backend/src/advisory/intake.py:33-43`, `backend/src/normalizers/common.py:72-87`
- **(M)** Reimplement who_can_reach on the same primitive as reachable — require at least one _valid_traversal-passing path per candidate source (a reverse BFS that refuses to expand through abstract nodes, which also kills the O(V*(V+E)) has_path loop) and return the witness path so the two tools are provably consistent.
  - *Files:* `backend/src/graph/reachability.py:171-189`, `backend/src/agent/tools.py:37-52`
- **(M)** Add require_approver (admin|analyst) and require_operator (admin) FastAPI dependencies and attach them to the 9 unguarded mutating routes; make stage_change check the role unconditionally, not only on the escalate branch. Add a NPR_PROXY_SECRET compared with hmac.compare_digest in _ActorMiddleware, injected by frontend/middleware.ts, rejecting 401 for any request carrying x-npr-* without it.
  - *Files:* `backend/app/main.py:69-77`, `backend/app/main.py:163,418,443,489,531,543,703,746,769`, `backend/src/request_ctx.py`, `frontend/middleware.ts:36-39`, `render.yaml`
- **(M)** Stop deleting the parent snapshot row to clear children: delete only engine-owned tables explicitly (assets, canonical_rules, graph_nodes, graph_edges, findings, resolved_objects, asset_correlations), and change change_requests.snapshot_id to a plain column or ON DELETE SET NULL — it is a 'baseline evaluated against' pointer, not ownership. Add campaign_plans to the explicit cache-clear list.
  - *Files:* `backend/src/persist.py:60-63`, `backend/src/db.py:222-225`, `db/schema.sql:190-201,320-324`, `backend/app/main.py:179,210,525`
- **(M)** Give the console a per-resource state machine {status:'loading'|'ok'|'error'}. Replace every `.catch(() => {})` with an error state, render a distinct error panel, and NEVER render a zero count while any dependent fetch is errored. Make lib/api.ts throw a typed ApiError carrying status + the HTTPException detail so a 403 reads as a permissions message, not 'is the API running?'.
  - *Files:* `frontend/app/console/page.tsx:44-78`, `frontend/lib/api.ts:6-10`, `frontend/components/RiskTodo.tsx:54-71`, `frontend/components/Staging.tsx:23,98-101`, `frontend/components/ChangeGate.tsx:51,59,67,88`, `frontend/components/IngestInspector.tsx:24`
- **(S)** Truth-in-labelling pass on the two screens that assert things that did not happen: prefix the fabricated staging steps with 'Simulated', change 'Applied to AlgoSec — data source updated' to 'Staged for AlgoSec (simulated push — no live connector)', return simulated:true in the push-plan payload, and branch the Topbar overlay on result.error so a failure never renders a green check and 'Snapshot recomputed'.
  - *Files:* `backend/src/change/staging.py:100-126`, `frontend/components/Staging.tsx:36-39,162`, `frontend/components/Topbar.tsx:51-61,158-183`
- **(S)** Stand up the CI skeleton and surface the residency signal that is already on the wire: add cmd_test to tasks.py + a Makefile target, a pyproject.toml with [tool.pytest.ini_options] pythonpath=['backend'], a backend/conftest.py autouse fixture stubbing record_metric and ollama_probe (the suite currently writes junk rows into the live ai_metrics table), .github/workflows/ci.yml, an .eslintrc.json, and a Topbar chip bound to health.ai.
  - *Files:* `tasks.py:195-212`, `Makefile:7`, `pyproject.toml`, `backend/conftest.py`, `.github/workflows/ci.yml`, `frontend/.eslintrc.json`

### Phase 1 — Make the engine's math defensible
**Duration:** 3 weeks

Fix the arithmetic that is wrong on valid input, and pin all of it with tests so it cannot silently regress. This is the phase that answers 'is the core engine production-ready'. Test-first: write the failing table-driven test, then fix.

**Exit criteria (objectively checkable):**

- [ ] The same policy expressed four ways (0.0.0.0/0, any, a named object resolving to 0.0.0.0/0, an address group) yields IDENTICAL severity, band and forced_critical — asserted as a parametrised test
- [ ] `0.0.0.0/0 -> host tcp/1-65535` produces a forced-critical finding; port_score is range-aware and the two port-dependent guardrails fire on ranges
- [ ] A mixed IPv4/IPv6 record set completes run() without raising; cidr_overlap and shadowing guard on .version
- [ ] 0.0.0.0/1 and 1.0.0.0/8 classify as ZONE_INTERNET and score within one band of 0.0.0.0/0 for the same destination and port
- [ ] Re-running the mutation matrix: all 10 injected engine defects now FAIL pytest (currently 6 of 10 pass green)
- [ ] A cross-process determinism test (subprocess x2, PYTHONHASHSEED 0 and random) asserts sha256 equality of the FULL engine dump including signals, assets, alias_map and sorted edges
- [ ] resolve_identities refuses to union two entities on an unscoped IP collision and emits a manual_review correlation instead; sentinel addresses (0.0.0.0, 127/8, 169.254/16, ::, ::1) never union
- [ ] Changing only an asset tag, an object's CIDR, an object type, or the manual_merges list produces a DIFFERENT snapshot_id

**Workstreams:**

- **(M)** Carry the resolved value, not the label. Add source_cidrs/dest_cidrs to PolicyRecord, populate from the object catalog in every normalizer, and drive exposure_score, cidr_overlap and shadowing off the resolved list — falling back to E_IDENTITY only when an object genuinely has no address. Recognise any/Any/ANY/all as 0.0.0.0/0. Mark network/group/range/subnet object types abstract=True so _valid_traversal treats them consistently.
  - *Files:* `backend/src/models.py:34-53`, `backend/src/normalizers/algosec.py:18-32,49-60`, `backend/src/normalizers/guardicore.py`, `backend/src/normalizers/wiz.py`, `backend/src/normalizers/profile.py:58-59`, `backend/src/analyzers/severity.py:26-37`
- **(M)** Make scoring range-aware and protocol-honest. Change port_score to take port_end and return the max class over the interval (short-circuit on ADMIN_LATERAL/DATA_STORE intersection; treat a full-range or >N-port span as P_ANY_PORT). Thread port_end through over_permissive, the two guardrails at severity.py:106-109, transport_exposure's pair match and staging._svc_match. Map ip/all to protocol 'any', add gre/esp/ah, parse comma port lists, validate 0<=port<=65535 and lo<=hi, and return an explicit unparsed/warnings signal instead of coercing.
  - *Files:* `backend/src/analyzers/severity.py:40-52,100-115`, `backend/src/analyzers/over_permissive.py:42`, `backend/src/analyzers/transport_exposure.py:78-89`, `backend/src/normalizers/common.py:20,89-159`, `backend/src/change/staging.py:31-38,60-61`, `backend/src/models.py:43-45`
- **(M)** Classify address space instead of comparing strings. Replace zone_of's `node_key == '0.0.0.0/0'` and severity._is_internet's `E >= 1.0` with a shared is_public(net) built on ipaddress .is_global/.is_private, handling ::/0 and any 0-prefix network. Make the cross-tool force-critical guardrail independent of the destination zone label so an internet-facing PCI asset cannot escape it.
  - *Files:* `backend/src/graph/zones.py:11-19`, `backend/src/analyzers/severity.py:90-91,160-170`, `backend/src/config.py:133-140,153-169`
- **(M)** Scope the identity merge. Add context to ObservedEntity (VPC/account/VRF/tenant from each normalizer) and key the union on (context, ip); when context is unknown on either side, do NOT union — emit an entity_suggest candidate. Maintain a sentinel-address ignore set, cap merge-by-IP fan-out, refuse to union entities with mutually exclusive env tags, and return a counter of suppressed merges. Fix _host_cidr to use ip_address(ip).max_prefixlen.
  - *Files:* `backend/src/identity.py:32-33,56-64,85-104,123-130`, `backend/src/normalizers/common.py:24-32`, `backend/src/normalizers/wiz.py`, `backend/src/normalizers/guardicore.py`
- **(S)** Make the snapshot id a real content hash: fold protocol, port, port_end, l7_app and sorted dest_tags into the per-record string, plus a sorted digest of the entity/object view (tool|name|kind|ip|cidr|tags|abstract), the applied manual_merges and the applied_changes overlay ids.
  - *Files:* `backend/src/analyzers/run_all.py:57-61,64-82`
- **(M)** Write the tests that pin all of the above: test_severity.py (table-driven exact values across band boundaries 34/35/59/60/79/80, one case per TAG_SENSITIVITY entry, one per guardrail clause asserted independently), test_engine_invariants.py (0<=severity<=100, forced_critical implies band=='critical', every raw_ref resolves, every hop pair is a real edge), test_determinism.py (cross-process, full dump), test_normalizers.py (the four crashing shapes + garbage CIDR), test_reachability.py (_grant_matches, _valid_traversal, reachable-vs-who_can_reach property). Split verify_engine into a pytest golden test.
  - *Files:* `backend/tests/test_severity.py`, `backend/tests/test_engine_invariants.py`, `backend/tests/test_determinism.py`, `backend/tests/test_normalizers.py`, `backend/tests/test_reachability.py`, `backend/tests/test_demo_golden.py`
- **(S)** Guard the analyzer suite against one bad input taking down the snapshot: version-check in cidr_overlap._relation and shadowing._covers, per-analyzer try/except in run_all recording a degraded-analyzer marker instead of aborting, and a try/except around the _ENGINE build in main.py so a bad dataset yields a diagnosable 4xx rather than a permanently poisoned singleton.
  - *Files:* `backend/src/analyzers/cidr_overlap.py:22-27`, `backend/src/analyzers/shadowing.py:32-38`, `backend/src/analyzers/run_all.py:85-89`, `backend/app/main.py:102-119`

### Phase 2 — Make the system of record trustworthy
**Duration:** 2 weeks

Governance records survive, carry identity, and are observable. Migrations become real. This is what turns 'a dashboard' into something you can put in front of a compliance function.

**Exit criteria (objectively checkable):**

- [ ] A recompute, a dataset switch, an asset merge and a reset each leave change_requests, change_decisions and audit_log intact — asserted by DB tests
- [ ] audit_log carries actor_email/actor_sub/actor_role populated inside audit() itself from request_ctx, so no call site can forget; every one of the 15 call sites is covered by a test
- [ ] An admin Audit screen exists and is role-gated; staged_changes.created_by is populated; manual escalate-override requires and persists a reason
- [ ] A structured log line with a request id exists for every currently-silent degradation (_load_merges failure, persist failure, tools_registry cache miss, metrics failure), and X-Request-Id round-trips into the error envelope
- [ ] /api/health returns 503 with status 'degraded' when the ztpa schema or the active snapshot is missing; a separate /api/live is the platform probe
- [ ] `alembic upgrade head` (or an equivalent versioned runner) is the only way schema changes apply; every ensure_* runtime DDL helper is deleted and asset_merges exists in a migration
- [ ] No LLM call executes inside an open DB transaction — asserted by a test that patches get_conn to fail if complete() is called while a connection is checked out

**Workstreams:**

- **(M)** Stop silent degradation on inputs that change the ANSWER: let _load_merges/_load_applied raise a specific EngineInputError so /api/recompute returns 503 and leaves the previous snapshot intact, mark the EngineResult persisted=False on write failure and have read endpoints return 503 rather than an empty 200, and add a global exception handler returning {error, request_id}.
  - *Files:* `backend/app/main.py:83-99,110-119,44-66`, `backend/src/persist.py:282-292`
- **(M)** Add structured logging (structlog or stdlib + JSON formatter), mint an X-Request-Id in _ActorMiddleware and bind it to every line, and replace all 29 `except Exception: pass/return []` with a logged warning. Wire Sentry on both backend and Next.js.
  - *Files:* `backend/app/main.py:50-66`, `backend/src/request_ctx.py`, `backend/src/db.py`, `backend/src/persist.py`, `backend/src/metrics.py:52-53`, `backend/src/tools_registry.py:93-94`
- **(M)** Give the audit trail a who and a reader: add actor_email/actor_sub/actor_role columns, have db.audit() read request_ctx.current() itself rather than taking a literal, populate staged_changes.created_by, require+persist a reason on manual_approve, make audit_log.snapshot_id a plain column so the correlation survives, and add a role-gated admin Audit screen bound to /api/audit with pagination.
  - *Files:* `db/schema.sql:213-222,298-314`, `backend/src/db.py:228-236`, `backend/app/main.py:717-730,764,256,527,855,1014-1018`, `frontend/lib/api.ts`, `frontend/app/console/page.tsx:24-38`, `frontend/components/admin/AuditAdmin.tsx`
- **(L)** Adopt a real migration system (Alembic or a schema_migrations table + numbered forward-only files applied one-per-transaction). Move every ensure_* runtime DDL into a migration and delete the helpers and their module-level READY flags. Add the migration step to render.yaml buildCommand/preDeploy. Fix the known drift: asset_merges missing from schema.sql, match_key CHECK missing 'manual_review'.
  - *Files:* `db/migrate.py:49-57`, `db/schema.sql:82-83,170-174,225-240`, `backend/src/persist.py:43-57,170-184,256-268,297-314`, `render.yaml:16`, `docs/DEPLOY.md:51`
- **(M)** Correct the transaction boundaries: move rank_mod.rank() and every campaign validation OUTSIDE the get_conn block (the pattern /api/campaign/plan already uses at main.py:429), make /api/actions a pure read with recomputation on the existing POST, wrap merge-confirm and reset-demo in one transaction each, add a single-flight guard on ranking, and chunk upsert_many at 65535//len(cols).
  - *Files:* `backend/app/main.py:476-486,443-470,531-540,800-818,956-969`, `backend/src/db.py:191-199`, `backend/scripts/precompute_ai.py:27-44`
- **(S)** Add a module-level threading.Lock with double-checked locking around the _ENGINE build and every rebind (recompute, switch_dataset, _apply_merges_and_persist, reset_demo), make scenarios._write atomic via tmp + os.replace, and persist {scenario, n} so a restart does not silently revert everyone to demo.
  - *Files:* `backend/app/main.py:79-80,102-119,135-149,169-173,195-204`, `backend/src/scenarios.py:31-35,89-96`

### Phase 3 — Pilot-ready: survive a real client's data
**Duration:** 4 weeks

Accept a customer export, ingest it partially and honestly, and finish in bounded time. Nothing before this phase lets you point the product at a client file at all.

**Exit criteria (objectively checkable):**

- [ ] A real (or realistically-shaped) 5,000-rule multi-device AlgoSec export ingests end-to-end and produces findings, with a visible 'N rules ingested, M skipped' report naming each skipped row and reason
- [ ] No code path regenerates data/mock during engine() or recompute(); a file placed in the input store survives a restart and a Recompute
- [ ] A 10,000-rule snapshot completes run() under a pinned wall-clock budget asserted by a perf test; a meshed-topology scale fixture exercises path enumeration (the current star topology gives path_trace 0.00s)
- [ ] Path enumeration reports truncated:true on the finding, the EngineResult and the API when the scan cap is hit — silent truncation is gone
- [ ] shadowing detects the canonical case: a broad rule whose destination CIDR contains a later rule's host, and a service range covering a later single port
- [ ] A rule marked disabled in the export produces no allow edge; Guardicore records carry order_source='synthesized' and shadowing surfaces it
- [ ] Every mutating remediation validates target_ref is in the finding's raw_refs and matches on (source_tool, raw_ref); apply_overlay returns a per-item applied/skipped outcome surfaced on /api/staging

**Workstreams:**

- **(L)** Build the ingestion path that does not exist: remove write_scenario from engine()/recompute() (scenario generation becomes an explicit admin action only), add POST /api/ingest/upload storing the raw blob in a table rather than a shared file on ephemeral disk, and have normalize_all read from that store with the demo fixtures as seeded default.
  - *Files:* `backend/app/main.py:106-110,170`, `backend/src/normalizers/__init__.py:12-24`, `backend/src/scenarios.py:89-96`, `db/schema.sql`, `backend/scripts/seed_scale.py:26-33`
- **(L)** Make normalization survive real data: wrap each rule in try/except accumulating skipped:[{index,reason}] on NormalizeResult and surface the count in the UI; normalize the action vocabulary ({allow,permit,accept} / {deny,drop,reject,block}, case-insensitive) and raise on unmapped rather than crashing in pydantic; accept list-valued src/dst/service and fan out one record per tuple keeping the parent ref; honour enabled/disabled; carry device and Guardicore's real priority.
  - *Files:* `backend/src/normalizers/algosec.py:49-60`, `backend/src/normalizers/guardicore.py:32,43`, `backend/src/normalizers/wiz.py:23,38-52`, `backend/src/normalizers/common.py:57-65`, `backend/src/models.py:34-53`, `backend/src/persist.py:29-30,105-106`
- **(L)** Bound the expensive algorithms: replace unbounded all_simple_paths with a bounded traversal that caps VISITED EDGES and prunes abstract pivots at expansion time, propagate truncated:true, cut the per-target loop with one reverse BFS from all sensitive targets, bucket shadowing by canonical destination and pre-parse source networks once, replace cidr_overlap's pairwise combinations with a sort-by-(network_address, prefixlen) sweep, and add a per-snapshot wall-clock budget.
  - *Files:* `backend/src/graph/reachability.py:19-21,118-133,150,165`, `backend/src/analyzers/shadowing.py:19-24,41-56`, `backend/src/analyzers/cidr_overlap.py:34-41`, `backend/src/analyzers/path_trace.py`, `backend/scripts/seed_scale.py`, `backend/src/scenarios.py:75-83`
- **(M)** Fix analyzer coverage predicates now that resolved CIDRs and port ranges exist: extend shadowing._covers to a full 5-tuple test (source, destination via asset ip_set containment, protocol, port interval), replace _service_overlaps string equality with interval intersection resolving declared apps through APP_TRANSPORT, branch shadowing on the (earlier.action, later.action) pair so a deny-after-deny is a redundant_deny not a fabricated 'traffic is actually allowed', gate transport_exposure on source overlap and zone/sensitivity, and score cross-tool paths on the MAX over terminal grants rather than the alphabetically-first.
  - *Files:* `backend/src/analyzers/shadowing.py:28-38,53-72`, `backend/src/analyzers/transport_exposure.py:43-44,78-89`, `backend/src/graph/reachability.py:28-29,79-102`, `backend/src/analyzers/severity.py:161`, `backend/src/config.py:85,97`
- **(M)** Tighten the model-output -> state-mutation path: reject any target_ref not in the finding's raw_refs, match on (source_tool, raw_ref), validate new_source parses as a CIDR and new_service as proto/port, widen _validate to report new findings across ALL bands and fail _is_clean on new critical OR high, make apply_remediation raise on an unmatched ref instead of silently no-op'ing, make apply_overlay return per-item outcomes, honour conflict resolutions as executable actions (skip must not append), and re-prove at push time against the live engine.
  - *Files:* `backend/src/advisory/remediation.py:97-128`, `backend/src/change/apply.py:30-72`, `backend/src/change/staging.py:52-56,71-126`, `backend/app/main.py:647-664,746-766`
- **(L)** Broaden the change-gate delta to use the primitive the remediation path already trusts: reanalyze(records + [proposed]) diffed against ctx.findings by signature, force-escalating on any new critical or high, keeping the internet->sensitive path diff as an additional well-named signal. Skip over-permissive scoring when proposed.action == 'deny' (a deny is currently scored and force-escalated as a permissive grant) and drop 'deny' from the simulate_change tool schema until build_graph subtracts it.
  - *Files:* `backend/src/change/simulate.py:21-27,42-59`, `backend/src/agent/tools.py:141-143`, `backend/src/graph/build.py:45-46`

### Phase 4 — Production hardening
**Duration:** 6 weeks

Operate it for someone else: bounded cost, bounded latency, real provider parity, real coverage, reproducible builds.

**Exit criteria (objectively checkable):**

- [ ] Tool-calling works identically on Ollama, OpenAI and Anthropic, verified by a per-provider test against a stubbed SDK client; the assistant never answers a path question without a tool result
- [ ] Per-actor rate limits and a daily cost ceiling read from ai_metrics trip capabilities closed; every LLM-bound body has a max_length and a byte cap
- [ ] Campaign and report run as background jobs with a status endpoint and incremental progress; no synchronous request can exceed a pinned wall-clock bound
- [ ] TestClient coverage of every endpoint (2xx shape, 4xx for bad input, 403 for viewer on each mutating route); persist.py and app/main.py leave 0% coverage
- [ ] requirements.lock is committed and render.yaml installs from it; @app.on_event is replaced by lifespan and close_pool() is actually called
- [ ] A deterministic PCI control-map table exists (requirement id -> predicate over findings) and the model narrates engine verdicts rather than inventing requirement numbers
- [ ] Adversarial test: a finding whose title contains an injected instruction leaves severity, band, ordering and the chosen target_ref unchanged

**Workstreams:**

- **(L)** Implement provider-portable tool calling (OpenAI tools=/tool_choice, Anthropic tools=/tool_use) behind one interface, or route ask() through the already provider-portable JSON ReAct loop in classify_change.investigate. Make max_tokens a per-call parameter sized by role and check stop_reason so a truncated Anthropic response sets ok=False. Route _run_tool through agent.tools.dispatch so the admin Tools kill switch actually applies.
  - *Files:* `backend/src/advisory/client.py:93-119,55-148`, `backend/src/agent/assistant.py:31-95`, `backend/src/advisory/classify_change.py:74-84`, `frontend/components/Assistant.tsx:60-61`
- **(M)** Add cost and latency control: per-actor token-bucket rate limiting on the six LLM endpoints, max_length on question/text/tool_hint and a byte cap on sample, a daily cost ceiling from ai_metrics that trips _require_capability closed, price_for returning (price, known) with a price_known column so the dashboard reports unpriced calls instead of $0.00, explicit timeout= on every complete() call, and a defensible OLLAMA_TIMEOUT default.
  - *Files:* `backend/app/main.py:912-1011,418-436`, `backend/src/config.py:199-224`, `backend/src/metrics.py:31-46`, `backend/src/settings.py:35`, `backend/src/advisory/rank.py:112`, `backend/src/advisory/classify_change.py:191`
- **(L)** Convert the long-running capabilities to jobs: POST returns {job_id}, work runs on a bounded worker writing progress, UI polls — following the two-phase pattern orchestrator.py already uses correctly for the report. Reconcile the explain polling budget with _EXPLAIN_TIMEOUT (client gives up at 64.5s, server is allowed 180s) by returning a server-derived deadline.
  - *Files:* `backend/app/main.py:418-436,320-362`, `backend/src/advisory/campaign.py:99-118`, `frontend/components/Campaign.tsx:30-40`, `frontend/components/RiskTodo.tsx:200-216`
- **(L)** Close the coverage gap on the layers with 0%: TestClient tests for every endpoint (2xx shape, 4xx on bad input, 403 for viewer on each mutating route, classify with a custom body, decisions surviving a recompute, limit=-1 returning 4xx), recording-fake-cursor tests for persist.py asserting every column exists in schema.sql, pure-function tests for staging.detect_conflicts and apply_overlay, stubbed-model tests for rank/report/explain/intake, and a Playwright smoke spec.
  - *Files:* `backend/tests/test_api.py`, `backend/tests/test_persist.py`, `backend/tests/test_staging.py`, `backend/tests/test_rank.py`, `frontend/e2e/smoke.spec.ts`, `.github/workflows/ci.yml`
- **(M)** Reproducibility and hygiene: commit requirements.lock and install from it, replace @app.on_event with a lifespan that joins background threads and calls close_pool(), propagate contextvars into background threads so metrics are attributed correctly, add the missing indexes (audit_log(ts DESC), staged_changes(request_id), change_requests(snapshot_id), findings(snapshot_id,type)) plus a retention policy, and fix tasks.py stop killing every node.exe on the developer's machine.
  - *Files:* `backend/requirements.txt`, `render.yaml:16-20`, `backend/app/main.py:43,135-149,356-358`, `db/schema.sql:329-347`, `tasks.py:181-185`, `frontend/lib/db.ts:5-15`
- **(M)** Make compliance and injection handling defensible: build a deterministic requirement-id -> predicate-over-findings table so the model narrates engine verdicts instead of inventing control numbers, wrap all ingested strings in explicit <untrusted_data> delimiters across every prompt, and add an adversarial regression test.
  - *Files:* `backend/src/advisory/report.py:15-64`, `backend/src/advisory/orchestrator.py:32-41`, `backend/src/advisory/prompts/`, `backend/src/advisory/remediation.py:50-53`, `backend/src/advisory/rank.py:20-24`, `backend/tests/test_injection.py`

---

## Quick wins (< 1 day each)

- **backend/app/main.py:584 — replace `proto, port, label = parse_service(body.service)` with `svc = parse_service(body.service)` and use svc.protocol/svc.port/svc.port_end/svc.label/svc.l7_app.**
  - *Payoff:* One line un-breaks the flagship 'Simulate a custom change' card, which has raised TypeError on every call since the initial commit. Ship it in the same commit as the dest_tags fix — alone it exposes an auto-approve hole.
- **backend/src/analyzers/cidr_overlap.py:24 and shadowing.py:36 — add `if na.version != nb.version: continue` / `return False` before the subnet_of comparison.**
  - *Payoff:* Two lines stop one IPv6 rule from 500-ing every route permanently. Any real firewall export from the last decade contains one, and the failure poisons the cached _ENGINE singleton until restart.
- **backend/app/main.py:80 — set `_ACTIVE_SCENARIO = settings.DEFAULT_SNAPSHOT_LABEL` (or change precompute/precompute_ai to run(label='demo')).**
  - *Payoff:* One line makes the entire precompute-ai step actually take effect. Today the API computes snap_hash('demo',fp) while precompute wrote snap_hash('seed-demo',fp), so zero cached explanations are ever served and every finding fires a live model call.
- **frontend/components/Topbar.tsx:158 — branch on `busy.result.error` so a failed recompute renders a failure state instead of a green check and the words 'Snapshot recomputed'.**
  - *Payoff:* Removes the single most misleading pixel in the product. Currently a 500 shows a tick, '? ms', 0 ms per stage and '-' for every count, then reloads to stale data.
- **frontend/components/Topbar.tsx — add a provider/residency chip bound to the existing `health.ai` payload (active_provider, judge/prose model, data_residency).**
  - *Payoff:* The backend already computes and returns data_residency, and frontend/lib/types.ts already declares the type — no component reads it. Cheapest possible fix for the local-first claim: it makes a silent hosted fallback visible instead of undisclosed.
- **frontend/app/actions.ts:17,24 — gate `devLink` on `process.env.NODE_ENV !== 'production'` (better: remove it from the server-action return type entirely and keep it console-only).**
  - *Payoff:* Closes a ten-second unauthenticated account takeover of any known email, including the admin, on every pre-SSO or cutover deployment. Also closes the user-enumeration oracle created by devLink's presence or absence.
- **frontend/lib/db.ts:12 — remove `ssl: { rejectUnauthorized: false }` and stop stripping `channel_binding` from the connection string.**
  - *Payoff:* Restores both defences on the connection that carries bcrypt hashes, unhashed magic/reset tokens and role assignments. Neon presents a publicly-trusted cert, so this is almost certainly a local-dev workaround that shipped.
- **docs/ENGINE.md — delete sec 10.3 (the substring port bug that no longer exists) and change 'four analyzers' to five in sec 1, sec 6 and the source map at line 27.**
  - *Payoff:* sec 10 is the section a security architect grades you on. Confessing a fixed bug while omitting five live ones turns the strongest part of your documentation into the weakest, and the analyzer miscount is noticed in 30 seconds.
- **tasks.py — add cmd_test running pytest, plus .github/workflows/ci.yml (pytest + verify_engine + npm run typecheck) and a pyproject.toml with pythonpath=['backend'].**
  - *Payoff:* 16 genuinely good tests are installed but orphaned — no runner exposes them and no doc mentions them. The suite already passes fully offline with dead DB and model sockets, so CI is a config file away, not a rewrite.
- **backend/conftest.py (currently 0 bytes) — add an autouse fixture stubbing src.metrics.record_metric and src.settings.ollama_probe, and blanking DATABASE_URL.**
  - *Payoff:* Stops every local `pytest` writing junk rows into the live Neon ai_metrics table the admin dashboard demos (rows attributed to a phantom role='viewer' are already there), and cuts the offline suite from 61s to ~5s.
- **backend/src/db.py:228-236 — have audit() read request_ctx.current() itself and write actor_email/actor_sub, instead of taking a literal 'user' from 15 call sites.**
  - *Payoff:* Turns an event log into an audit trail in one function. Requires one small migration, and no call site can then forget the identity.
- **backend/app/main.py:190-192 and :607 — add Field(ge=1, le=2000) to DatasetBody.n and Query(25, ge=1, le=200) to the limit params.**
  - *Payoff:* Removes a stack-trace 500 on ?limit=-1 and an unbounded synchronous engine rebuild, both reachable by anyone who can reach the Render URL.
- **backend/src/persist.py:148-157 + a ranked_by column — record and read back the real provenance instead of hardcoding ranked_by='llm' at main.py:962.**
  - *Payoff:* Stops the Report tab attributing four hardcoded deterministic buckets to the LLM in front of a client. The explanation cache already does this correctly (explanation_by) — mirror it.
- **tasks.py:184 — delete the unconditional `taskkill /F /IM node.exe`.**
  - *Payoff:* Stops a documented command force-killing every Node process on the developer's Windows machine, including unrelated editors and projects. The line immediately after it already admits the WINDOWTITLE filter does not work.

---

## Documentation corrections

The cheapest confidence win available: make the claims match the code. Note `ENGINE.md` §10 and `HOW-IT-WORKS.md` §14 are already unusually honest — the fix is to bring `README.md` and `FEATURES.md` up to that standard, not to remove the caveats.

**README.md:35 and DEMO.md:10**

> Currently: Running inference locally on Ollama means that data never leaves the host. / (DEMO.md presenter line) the topology never leaves this machine.

Suggested: Inference runs locally on Ollama by default, so the topology never leaves your infrastructure in that configuration. Note that ADVISORY_PROVIDER=auto will fall back to a hosted provider if the local model is unavailable, and the shipped Render blueprint pins ADVISORY_PROVIDER=openai — check the provider chip in the header for the active residency before making this claim.

**README.md:29 and docs/FEATURES.md sec 1.7**

> Currently: Bring-your-own source without writing a normalizer. / New source, no new Python. (marked with a completed tick)

Suggested: Connector-authoring assist (design-time preview): paste a sample export and the model drafts a declarative SourceProfile which the engine checks by normalizing that sample. Registering an approved profile and ingesting data through it is not yet implemented. Also remove 'approve to register this connector' from the note returned by advisory/authoring.py:118.

**docs/FEATURES.md sec 1.1**

> Currently: Ingests AlgoSec, Guardicore and Wiz exports and normalizes them into one canonical policy model.

Suggested: Normalizes AlgoSec-, Guardicore- and Wiz-shaped exports into one canonical policy model. The current build reads three fixed simulated exports from backend/data/mock; there is no upload path, and the engine regenerates those files on every cold build. Adapters assume well-formed rows — a missing or list-valued field currently aborts the run.

**README.md:82**

> Currently: # Optional: prove the engine meets every acceptance criterion — python tasks.py verify

Suggested: # Regression-check the seeded demo dataset (golden acceptance checks) — python tasks.py verify. Then: # Run the unit test suite — python tasks.py test. Note verify_engine.py asserts existence and exact values against the one 27-rule demo fixture; it is not a correctness proof on arbitrary input.

**docs/AGENTS.md:188**

> Currently: Provider-agnostic. Local Ollama, OpenAI, or Anthropic — same contracts, same guardrails.

Suggested: Same contracts and guardrails on every provider for the structured-judgment capabilities. Tool-calling is currently implemented for Ollama only: on OpenAI/Anthropic the 'Ask your network' assistant degrades to a single grounded completion over a precomputed findings list and cannot call reachability tools. The Anthropic path is additionally capped at 1500 output tokens.

**docs/ENGINE.md sec 1, sec 6 and the source map at line 27**

> Currently: analyze (4 detectors) / The four analyzers / {over_permissive,cidr_overlap,shadowing,path_trace}.py

Suggested: analyze (5 detectors) / The five analyzers / {over_permissive,cidr_overlap,shadowing,path_trace,transport_exposure}.py — and add a sec 6.5 documenting transport_exposure, its TRANSPORT_CONFIG constants and its guardrail, since it produces 8 of the 17 demo findings and is currently absent from the formula reference entirely.

**docs/ENGINE.md sec 10.3 (line ~403)**

> Currently: Port match is substring, not numeric (reachability.py:124) — the optional port filter in reachable() matches f"/{port}" as a substring of the service string, which can false-positive (e.g. port=3 matches tcp/3389).

Suggested: Delete this item — reachability.py:50-72 now does structured protocol/port-range/app matching and the comment at line 51 says 'replaces fragile substring checks'. Replace it with the live gaps: port ranges are scored from the range START port only; 'the internet' is the literal string 0.0.0.0/0; named network objects are classified concrete and can act as path pivots; a mixed IPv4/IPv6 record set raises TypeError; and _PATH_SCAN_CAP bounds yielded paths, not DFS work (measured: 117s on a 34-node mesh).

**docs/ENGINE.md sec 9 (line ~386)**

> Currently: The snapshot fingerprint hashes each normalized record's tool|ref|source|destination|service|action|order (run_all.py:_fingerprint), so any change to the inputs yields a new snapshot id.

Suggested: The snapshot fingerprint currently hashes only the normalized rule rows. Changes to asset tags, the object catalog, protocol/port/l7_app decoding, or the confirmed manual merges do NOT change the snapshot id — so a snapshot can be re-persisted in place with different assets and different findings under the same id. Treat the id as identifying the rule set, not the analysis, until the fingerprint is widened.

**docs/AGENTS.md:73 and docs/FEATURES.md:47**

> Currently: the engine has proven [the fix] resolves the finding without opening a new critical / re-simulated by the engine to prove it resolves

Suggested: Re-simulated by the engine: the full analyzer suite is re-run on the modified record set and the fix is accepted only if the target finding disappears and no NEW CRITICAL appears. New high/medium/low findings are not currently checked, the proof is against the snapshot at draft time and is not re-run at push time, and the deterministic fallback used when the model is unavailable is removal-based, not scoped — say 'conservative (removal-based) fallback', not 'surgical'.

**docs/FEATURES.md:68-70 and frontend/components/Staging.tsx:36-39,162**

> Currently: (UI) Connect to algosec — Connected to the algosec policy data source / Change written to the algosec data source / Applied to AlgoSec — data source updated

Suggested: The FEATURES.md wording is already honest ('push is simulated; the conflict math is genuine engine math') — the on-screen copy is not. Change to: 'Connect to algosec (simulated)', 'Change staged for algosec — simulated push, no live connector configured', and 'Staged for AlgoSec (simulated)'. Return simulated:true in the push-plan payload. Also stop reporting a conflict resolution the overlay does not perform: a 'Skip: no-op' step currently still appends the record.

**docs/SSO.md:46**

> Currently: npr_viewer | viewer | Read-only: findings, graph, reports, evidence. Cannot approve or apply changes

Suggested: Either implement it or state it: as of this build the backend enforces no role check on POST /api/staging, POST /api/staging/{id}/push, DELETE /api/staging/{id}, /api/change/submit, /api/campaign/submit, /api/assets/merge, /api/assets/unmerge, /api/recompute or /api/actions/recompute, so a viewer can drive a change to a simulated push. Fix the code rather than the doc — but until it ships, the doc must not promise an enforcement that does not exist.

**README.md:37 and README.md:68**

> Currently: Model routing (default): qwen3-coder:30b for structured judgment + tool-calling, gemma4:26b for prose, nomic-embed-text for embeddings. / Prerequisites: Ollama running with qwen3-coder + gemma4 + nomic-embed-text

Suggested: Model routing (default): qwen3-coder:30b for both structured judgment and prose (settings.py sets OLLAMA_PROSE_MODEL to the same tag), nomic-embed-text for embeddings. Prerequisites: `ollama pull qwen3-coder:30b` and `ollama pull nomic-embed-text` — note the exact tag, because the availability probe only checks that SOME model is present, so a mismatched tag silently puts every capability on deterministic fallback.

**backend/app/main.py:74-77 docstring, and docs/FEATURES.md capability-toggle wording**

> Currently: 403 a disabled AI capability for the caller's role (fail-closed).

Suggested: 403 a disabled AI capability for the caller's role. Note this is default-on and best-effort: an absent tool_settings row enables the capability for all roles, and a DB error with a cold cache also yields the default-on map. It is a feature-flag layer, not an authorization boundary — do not rely on it to restrict write paths.

**README.md:16, docs/FEATURES.md:42, docs/AGENTS.md:54, docs/HOW-IT-WORKS.md:672-683**

> Currently: 8 capabilities / 8 capabilities / The five agentic capabilities / (a list of 10, with campaign.py labelled 'Capability #9')

Suggested: Pick one canonical count, put it in FEATURES.md as the source of truth, and have the other three docs reference it rather than restate it. HOW-IT-WORKS.md sec 14.7 already flags this drift itself. Add a CI check that greps the capability count and the detector count from each doc and asserts they agree with len(FindingType.__args__) and the advisory module list.

---

## Findings register

Full detail for every **blocker** and **high**. Medium and low are tabulated below.


### BLOCKER

<details>
<summary><b>"Ask the network" only tool-calls on Ollama; on OpenAI/Anthropic it silently degrades to a single-shot over a findings list while the UI still claims every answer is tool-grounded</b><br/><code>claim-overreach</code> &middot; <code>backend/src/agent/assistant.py:89</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The flagship agentic feature is not agentic on two of the three advertised providers, and there is no signal to the user. The fallback labels itself `by: "openai:gpt-4o"` — identical provenance styling to a real tool-calling answer — while the model has been handed no reachability facts at all and is still instructed to answer. Worse, this is not just a hosted-provider concern: under ADVISORY_PROVIDER=auto, `active_provider()` (settings.py:109-117) returns "openai"/"anthropic" the moment the Ollama probe fails, so a laptop where Ollama was not started silently flips the assistant into the confabulating mode.

**Failure scenario.** Deploy with ADVISORY_PROVIDER=openai (or auto with Ollama down and OPENAI_API_KEY set). Ask the app's own suggested question — main.py:936 generates "Can the internet reach db-prod-01, and through which path and tools?". No tool ever runs. The model has a list of finding titles and is told to "cite the concrete path when something is reachable" (_SYSTEM, assistant.py:22-24), so it invents a hop sequence. The UI beneath it says every answer is grounded in computed facts.

**Evidence.** assistant.py:89-95 is the entire entry point:
    def ask(ctx, question: str) -> dict:
        try:
            if settings.active_provider() == "ollama":
                return _ollama_loop(ctx, question)
        except Exception:
            pass
        return _grounded_fallback(ctx, question)
and _grounded_fallback (assistant.py:76-86) stuffs ONE precomputed blob and asks for an answer anyway:
    facts = {"findings": T.risk_findings(ctx)}
    fr = complete(system=_SYSTEM + "\n(No live tools available; answer ONLY from the provided facts.)", user=f"Question: {question}\n\nFacts:\n{json.dumps(facts)[:6000]}", ...)
    return {"answer": ..., "trace": [{"tool": "risk_findings", ...}], "by": f"{fr.provider}:{fr.model}"}
risk_findings returns only {id,type,title,severity,band,forced_critical} — no paths, no hops, no ports, no asset attributes.
Docs/UI: AGENTS.md:188 "Provider-agnostic. Local Ollama, OpenAI, or Anthropic — same contracts, same guardrails."; AGENTS.md:62 lists "Ask the network ... tool-calling Q&A over the engine"; frontend/components/Assistant.tsx:61 "The agent calls deterministic engine tools, so every answer is grounded in computed facts."

**Fix.** Either (a) implement the tool loop for the hosted providers — both SDKs support the same OpenAI-style schemas already in T.SCHEMAS, so `_openai_complete`/`_anthropic_complete` need a tool_calls-returning variant and `_ollama_loop` needs to become provider-neutral; or (b) if hosted tool-calling is out of scope, make `_grounded_fallback` refuse reachability/path questions outright and return `by: "engine_fallback (no tools)"`, and change Assistant.tsx:61 to state the limitation. Do not ship a fallback that answers path questions from titles.

**Verifier note.** The finding is UNDER-evidenced, not over-stated. The committed deployment blueprint pins this exact configuration: render.yaml sets `ADVISORY_PROVIDER: openai` with the comment 'Force the hosted OpenAI provider (no local Ollama on Render)', and docs/DEPLOY.md:40 instructs the operator to set OPENAI_API_KEY. So the degraded single-shot path is not a hypothetical misconfiguration -- it is the only path the shipped hosted deployment ever takes. One small precision: 'No tool ever runs' is imprecise -- risk_findings(ctx) IS a real deterministic engine call at assistant.py:78 (it just bypasses tools.dispatch and therefore the per-role registry too). The substance stands: no tool-calling loop, and the facts supplied contain nothing the model could use to answer a path question truthfully.

</details>

<details>
<summary><b>/api/change/classify custom-change path raises TypeError on every call (500)</b><br/><code>correctness-bug</code> &middot; <code>backend/app/main.py:584</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** The Change Gate is the flagship demo. Half of it -- the 'evaluate any change you type in' path -- is dead code that has never once executed successfully. Only the three hardcoded DEMO_REQUESTS work. This is the single clearest 'demo-grade' proof point: the feature works only on the seeded fixtures.

**Failure scenario.** In the UI, Change Gate -> pick 'Custom' -> the prefilled form (ChangeGate.tsx:42 `{source:'10.20.5.0/24', destination:'app-server-07', service:'tcp/443'}`) -> click Evaluate. Backend raises TypeError at main.py:584 -> unhandled -> 500. ChangeGate.tsx:90 `catch { /* ignore */ }` swallows it, `setLoading(false)` fires, and the panel just goes blank. No error, no result, nothing. A client asks 'what happened?' and there is no answer on screen.

**Evidence.** main.py:583-584:
    from src.normalizers.common import is_cidr, parse_service
    proto, port, label = parse_service(body.service)

But normalizers/common.py:72-86 defines `DecodedService` as a plain `@dataclass` (6 fields, not a NamedTuple, no __iter__), and parse_service returns it. I executed this:
  $ python -c "from src.normalizers.common import parse_service; proto,port,label = parse_service('tcp/22')"
  UNPACK FAILS: TypeError cannot unpack non-iterable DecodedService object

Every other caller uses it correctly, e.g. change/staging.py:60-61 `svc = parse_service(...)` then `svc.protocol, svc.port`. main.py is the only site that unpacks.

**Fix.** Replace with `svc = parse_service(body.service)` and use `svc.protocol, svc.port, svc.label` (and pass `svc.l7_app` into the PolicyRecord so the custom path decodes L7 like every other path does). Then add a TestClient test that POSTs the custom body -- there is currently no test that imports app.main at all.

</details>

<details>
<summary><b>Recompute silently deletes the entire change-governance audit trail via ON DELETE CASCADE</b><br/><code>correctness-bug</code> &middot; <code>backend/src/persist.py:63</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The whole compliance story is 'every change is evaluated, ruled on, and logged'. Pressing the Recompute button in the Topbar wipes change_requests and change_decisions for that snapshot. Four separate endpoints do this: /api/recompute (main.py:176), /api/admin/dataset (208), /api/assets/merge + /unmerge via _apply_merges_and_persist (524), /api/admin/reset-demo (813). An auditor asking 'show me the decision history' after any recompute gets an empty table.

**Failure scenario.** 1. Change Gate -> evaluate ALGO-014 -> decision logged, visible in the Decision log. 2. Click Recompute (or confirm an asset merge). 3. /api/change-decisions returns []. 4. Worse: the staged_changes row survives (no FK, schema.sql:298-314) but its request_id now dangles, so /api/staging still lists it with null justification/requested_by, and stage_change (main.py:707-712) returns 404 'change request/decision not found' for it forever.

**Evidence.** persist.py:60-63:
    def persist_engine_result(cur, r):
        sid = r.snapshot_id
        ensure_finding_types(cur)
        delete_snapshot_children(cur, sid)

db.py:222-225:
    def delete_snapshot_children(cur, snapshot_id):
        cur.execute(f"DELETE FROM {DB_SCHEMA}.snapshots WHERE snapshot_id = %s", [snapshot_id])

schema.sql:190-197:
    CREATE TABLE IF NOT EXISTS change_requests (
        request_id    text PRIMARY KEY,
        snapshot_id   text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,

schema.sql:199-201: change_decisions.request_id REFERENCES change_requests(request_id) ON DELETE CASCADE.

And the engine is deterministic: run_all.py:82 `sid = make_snapshot_id(label, _fingerprint(records))` -- so a plain recompute of unchanged data produces the SAME snapshot_id, meaning the DELETE hits the live row.

**Fix.** Drop the CASCADE: make change_requests.snapshot_id a plain text column (or FK with ON DELETE SET NULL) -- it is a 'baseline evaluated against' pointer, not ownership. Governance records must outlive the snapshot. Same for anything else meant to be durable. Then have persist_engine_result delete only engine-owned children (assets, canonical_rules, graph_*, findings, resolved_objects, asset_correlations) explicitly, rather than deleting the parent row and relying on cascade semantics it does not control.

</details>

<details>
<summary><b>"Simulate a custom change" has never worked: /api/change/classify raises TypeError on every non-demo change</b><br/><code>correctness-bug</code> &middot; <code>backend/app/main.py:584</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** This is the branch the UI's flagship "Simulate a custom change" card hits (ChangeGate.tsx:87 `const body = sel === "custom" ? custom : { request_id: sel }`). Only the two hardcoded DEMO_REQUESTS work. Worse, ChangeGate.tsx:90 is `catch { /* ignore */ }`, so the 500 is swallowed: the operator clicks "Simulate & evaluate", the spinner stops, and absolutely nothing happens. The entire Change Gate is demo-grade - it can only rule on two rules baked into requests.py.

**Failure scenario.** In a client demo, the presenter says "and you can try any change you like", types `10.0.0.0/8 -> db-prod-01, tcp/1433`, clicks Simulate & evaluate. Backend logs a 500 TypeError; the UI silently returns to the idle decision log with no error and no result.

**Evidence.** main.py:583-584:
    from src.normalizers.common import is_cidr, parse_service
    proto, port, label = parse_service(body.service)

But normalizers/common.py:72-87 defines:
    @dataclass
    class DecodedService:
        protocol: str; port: Optional[int]; port_end: Optional[int]
        label: str; l7_app: Optional[str]; l7_source: Optional[str]

Reproduced against the real module:
    >>> proto, port, label = parse_service('tcp/443')
    TypeError: cannot unpack non-iterable DecodedService object

`git log -S "proto, port, label = parse_service"` returns only 94e0cc2 (Initial commit) - this line has been broken since day one.

**Fix.** Replace with `svc = parse_service(body.service)` and use `svc.protocol / svc.port / svc.port_end / svc.label / svc.l7_app / svc.l7_source` when building the PolicyRecord (mirroring intake.py:33-43, which does it correctly). Add an endpoint test that POSTs a custom body.

</details>

<details>
<summary><b>Every recompute cascade-deletes the entire change-request and decision audit trail</b><br/><code>correctness-bug</code> &middot; <code>backend/src/persist.py:63</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The Change Gate's audit trail is the governance artifact. Any recompute - including one that produces the IDENTICAL snapshot_id because nothing changed - deletes the snapshots row and cascades away every change_request and change_decision recorded against it. staged_changes has no FK (schema.sql:300 `snapshot_id text,`), so those rows survive but now dangle with a request_id pointing at nothing; /api/change-decisions (main.py:620-622) INNER JOINs change_requests, so the decisions silently vanish from the log, and /api/staging's LEFT JOIN starts returning NULL justification/requested_by. The system loses the record of who requested what and how the gate ruled, with no error and no warning.

**Failure scenario.** Analyst evaluates three changes, approves one, stages it. Someone clicks "Recompute" (or confirms an asset merge). The Decision log is now empty; the staged change is still sitting there with no requester, no justification, no ruling. In an audit, the only evidence that a firewall change was approved has been destroyed by a read-path refresh.

**Evidence.** persist.py:60-63:
    def persist_engine_result(cur, r):
        sid = r.snapshot_id
        ensure_finding_types(cur)
        delete_snapshot_children(cur, sid)
db.py:222-225:
    def delete_snapshot_children(cur, snapshot_id):
        cur.execute(f"DELETE FROM {DB_SCHEMA}.snapshots WHERE snapshot_id = %s", [snapshot_id])
schema.sql:190-201:
    CREATE TABLE IF NOT EXISTS change_requests (
        request_id    text PRIMARY KEY,
        snapshot_id   text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    CREATE TABLE IF NOT EXISTS change_decisions (
        request_id    text NOT NULL REFERENCES change_requests(request_id) ON DELETE CASCADE,

persist_engine_result is called unconditionally by /api/recompute (main.py:176), /api/admin/dataset (206), _apply_merges_and_persist (524, i.e. every asset merge/unmerge), reset_demo (813), and the lazy engine() bootstrap (116).

**Fix.** Stop deleting the snapshot row to clear children. Either (a) delete only the engine-owned child tables explicitly (assets, canonical_rules, graph_nodes, graph_edges, findings, resolved_objects, asset_correlations) and leave governance tables alone, or (b) change change_requests.snapshot_id to ON DELETE SET NULL / drop the FK, since it is a historical reference to the baseline that was evaluated, not ownership.

**Verifier note.** Three evidence corrections, none of which change the verdict. (1) main.py:116 does NOT wipe anything — persist there is guarded by `if not row` after a SELECT for that snapshot_id, so it only runs when the snapshot is absent. (2) main.py:206 /api/admin/dataset switching to a DIFFERENT scenario produces a different snapshot_id, so it does not destroy the previous scenario's governance rows. (3) audit_log survives (schema.sql:221 uses ON DELETE SET NULL) and persist.py:365-367 writes actor='agent', action='classify_change', subject=request_id, detail={decision, forced_escalate, decided_by}; /api/audit-log (main.py:1015-1017) exposes the last 50. So 'the only evidence has been destroyed' overstates it — what is destroyed is the structured record (proposed rule, justification, requester, criteria, delta_summary, confidence).

</details>

<details>
<summary><b>Public backend trusts an x-npr-role header, and the stage/push/delete endpoints have no role check at all</b><br/><code>security</code> &middot; <code>backend/app/main.py:746</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The whole change-governance story rests on role separation ("only admin or analyst can approve an escalated change", main.py:718). But anyone who can reach the Render URL can send `-H 'x-npr-role: admin'` and get admin. Even staying inside the intended auth, a **viewer** can call /api/change/submit -> /api/staging -> /api/staging/{id}/push and thereby write a durable overlay change (persist.py:288 selects every `status='pushed'` row; apply.py:63 folds them into records on every run). A read-only role can permanently mutate the canonical policy model, or DELETE staged changes, or push a change nobody approved.

**Failure scenario.** curl -X POST https://ztpa-backend.onrender.com/api/admin/reset-demo -H 'x-npr-role: admin' wipes the governance tables. Or, as a legitimately-logged-in viewer: POST /api/change/submit {finding_id, change:{op:'remove', target_ref:'ALGO-030'}} -> auto_approve -> POST /api/staging -> POST /api/staging/{id}/push -> that rule is now deleted from every future snapshot.

**Evidence.** main.py:703-731 `stage_change` has no `Depends(require_admin)` and no `_require_capability`; the only role check is inside the escalate branch (718-719). main.py:746-766 `staging_push` and 769-774 `staging_delete` have NO authorization whatsoever. main.py:682-693 `change_submit` requires only `_require_capability("classify")`, and tools_registry.py:103-105 `enabled_roles()` returns ALL_ROLES when no tool_settings row exists ("default-on").

request_ctx.py:12-15 states the premise plainly:
    "The proxy strips any client-supplied `x-npr-*` headers before setting its own, so
     this backend must stay private (reachable only through the proxy); it does not
     independently validate AutoX tokens."

render.yaml deploys it as `type: web` - a public internet-facing Render service. There is no bearer token, no shared secret, no IP allowlist. FRONTEND_ORIGIN is only a CORS allowlist, which is irrelevant to curl.

**Fix.** Two things, both required: (1) make the backend non-public or require a shared secret / signed header the proxy injects and the backend verifies (a `NPR_PROXY_SECRET` compared in _ActorMiddleware is the minimum); (2) add explicit role gates - `/api/staging` POST, `/api/staging/{id}/push` and DELETE, and `/api/change/submit` are all state-mutating governance actions and should require admin/analyst, not a default-on AI capability flag.

**Verifier note.** Fairness correction on framing: the header-trust half is NOT undiscovered — docs/DEPLOY.md:107-110 states it verbatim ('**Backend is public.** It trusts x-npr-role/x-npr-email headers... Anyone hitting the Render URL directly could forge these. Fine for a demo; before anything real, add a shared secret'). That half is an openly acknowledged limitation. The genuinely undocumented and more damning half is the internal authz gap: even in the intended, correctly-proxied deployment where the AutoX role is authentic, a role='viewer' user can POST /api/change/submit, POST /api/staging, POST /api/staging/{id}/push and DELETE /api/staging/{id} — pushing a rule into the durable overlay (persist.py:282-292 -> apply.py:63-75) with no approver check anywhere. Lead with that, not with the curl, when reporting it. Severity stays blocker.

</details>

<details>
<summary><b>Change Gate's "evaluate your own rule" path throws TypeError on every call (500)</b><br/><code>correctness-bug</code> &middot; <code>backend/app/main.py:584</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** The Change Gate is capability #1, the flagship "agentic, guardrailed, fail-closed" claim, and the demo's §4. The two preset requests work; the moment a client says "try my rule instead", the endpoint 500s. This is the single most likely live-demo failure in the repo.

**Failure scenario.** In Change Gate, pick "custom", enter source=10.20.5.0/24, destination=app-server-07, service=tcp/443, click Evaluate -> POST /api/change/classify with {source,destination,service} -> TypeError at main.py:584 -> HTTP 500, blank result panel.

**Evidence.** main.py:584  `proto, port, label = parse_service(body.service)`

but normalizers/common.py:72-87 defines:
```
@dataclass
class DecodedService:
    protocol: str
    port: Optional[int]
    port_end: Optional[int]
    label: str
    l7_app: Optional[str]
    l7_source: Optional[str]
```
A plain @dataclass is not iterable, so the 3-way unpack raises `TypeError: cannot unpack non-sequence DecodedService`. Frontend ChangeGate.tsx:87 sends exactly this shape: `const body = sel === "custom" ? custom : { request_id: sel };` and line 42 defaults `custom = { source, destination, service, justification }`.

FEATURES.md 1.9 claims parse_service was "Wired through algosec/guardicore/wiz/profile ... and every other caller (intake, remediation, staging, agent tools, severity)." This caller was missed.

**Fix.** Replace with `svc = parse_service(body.service)` and use `svc.protocol / svc.port / svc.port_end / svc.label / svc.l7_app / svc.l7_source`, matching intake.py:33-42 which does it correctly. Add one API-level test that posts the custom shape.

</details>

<details>
<summary><b>There is no ingestion path for a real export at all — the engine REGENERATES the three synthetic files over backend/data/mock/ on every cold build and every Recompute</b><br/><code>demo-grade</code> &middot; <code>backend/app/main.py:107</code> &middot; PLAUSIBLE &middot; effort L</summary>

**Why it matters.** Nine auditors found that the SourceProfile connector is never wired into ingestion. The gap is much wider than that: even for AlgoSec, Guardicore and Wiz — the three FIRST-CLASS, hand-written normalizers — there is no way to load a customer file. The only data source is a Python function that emits a fixture, and the app actively deletes whatever is in the input directory. FEATURES.md §1.1's 'ingests AlgoSec, Guardicore and Wiz' describes an operation the product cannot perform. Every downstream finding about 'what happens on a real export' is moot until this exists, and it also silently undoes the repo's own documented scale workflow.

**Failure scenario.** Day one of a pilot: the client hands you three JSON exports. You copy them into backend/data/mock/ and restart the API. `_warm_engine` fires -> `engine()` -> `_ENGINE is None` -> `write_scenario('demo')` overwrites all three files with the 25-asset fixture. The dashboard shows the demo findings against the demo assets, with the client's filenames on disk. Same for the documented scale run: `python tasks.py seed-scale 1000` (docstring line 5: 'then refresh the UI') writes 1016 rules; the backend's next cold build or any press of Recompute restores 16.

**Evidence.** engine(): `if _ENGINE is None:` -> `try: write_scenario(_ACTIVE_SCENARIO)   # keep data/mock consistent with the active scenario` (main.py:106-109), and recompute(): `write_scenario(_ACTIVE_SCENARIO)   # regenerate the active scenario so data/mock stays consistent` (main.py:170). write_scenario -> scenarios._demo() -> `_write(seed_demo.algosec_export(), ...)` which does `(MOCK_DIR / "algosec_export.json").write_text(...)` (scenarios.py:31-39). The engine's ONLY input is `normalizers/__init__.py:12-23`: `MOCK_DIR = .../data/mock`; `out.extend(algosec.normalize(_load("algosec_export.json")))`. There is no upload/import endpoint anywhere in main.py's 1018 lines. Verified empirically: `seed_scale.main(1000)` -> algosec_export.json sha a3d4d41edee3, 1016 rules; then a single `write_scenario('demo')` (exactly what the first API request does) -> sha 5a8c8f5281cf, 16 rules. `scale dataset survived backend boot? False`.

**Fix.** Remove write_scenario() from engine() and recompute() — a recompute must re-read whatever is on disk, never regenerate it. Move scenario generation to an explicit admin action only (/api/admin/dataset already does this). Then add the actual missing feature: a POST /api/ingest/upload that takes {tool, payload}, persists the raw blob to a table (not to a shared file on the container's ephemeral disk), and makes normalize_all() read from that store with the demo fixtures as the seeded default.

</details>

<details>
<summary><b>Identity merge keys on the bare IP with no VRF/VPC/tenant context — the exact 'duplicate IP' problem the product claims to solve</b><br/><code>correctness-bug</code> &middot; <code>backend/src/identity.py:57</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** README.md:12 and FEATURES.md §1.2 sell this as the defensible IP: 'Resolves identities deterministically — IP is an attribute, not a key'. But the merge treats the IP AS the key. RFC1918 reuse across VPCs/accounts/VRFs is universal — 10.0.1.5 exists in prod and in dev at almost every enterprise. A wrong merge does not just mislabel an asset: build_graph (`build.py:48 canon(r.source)`) collapses both nodes' edges onto one node, so reachability reports paths that do not exist, and dest_score takes the MAX over the unioned tags so a dev box inherits `pci`. Fabricated reachability in a security tool is worse than no tool.

**Failure scenario.** Two Wiz assets, both 10.0.1.5, different accounts:
  prod-vpc-web-01 (aws-prod, tags pci+prod) and dev-vpc-web-01 (aws-dev, tags dev)
resolve_identities returns ONE asset: `asset_key='dev-vpc-web-01' tags=['dev','pci','prod'] ips=['10.0.1.5/32'] context='aws-prod'` — the dev box now carries the PCI tag, the prod asset's name is gone from the graph, `context` is the wrong account, and alias_map rewrites `prod-vpc-web-01 -> dev-vpc-web-01` so every prod firewall rule is re-pointed at the dev node.

**Evidence.** identity.py:56-64 — `ip_to_names: dict[str, set[str]] = defaultdict(set)` / `for e in entities: if e.ip: ip_to_names[e.ip].add(e.name)` / `for ip, ns in ip_to_names.items(): ordered = sorted(ns); for other in ordered[1:]: union(ordered[0], other)`. The key is the raw IP string. `ObservedEntity` has no context field at all (common.py:24-32), and `Asset.context` is only assigned AFTER the merge, at identity.py:102: `context=identifiers.get("env") or identifiers.get("cloud")`. The correlation is even labelled `match_key="context_ip"` (identity.py:128) — the name promises a context that is nowhere in the code.

**Fix.** Add `context: str|None` to ObservedEntity (populate from VPC/account/VRF/tenant in each normalizer) and key the merge on `(context, ip)` instead of `ip`. When context is unknown on either side, do NOT union — emit an `entity_suggest` candidate for human review instead (the codebase already has that review path and claims it never auto-merges). Also refuse to union two entities whose tag sets contain mutually exclusive environment tags (prod vs dev) without human confirmation.

</details>

<details>
<summary><b>A rule sourced from a named address object or the keyword `any` silently scores as a single host — every guardrail is bypassed</b><br/><code>correctness-bug</code> &middot; <code>backend/src/normalizers/algosec.py:31</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** This is the single most damaging gap in the engine and it is invisible. Real AlgoSec/Palo/Check Point policies express sources as named objects or the literal keyword `any` in the overwhelming majority of rules — raw CIDRs in the src column are the exception, not the rule. The demo data uses literal `0.0.0.0/0` everywhere, which is exactly why everything looks perfect. On a real export the tool reports FEWER findings, and "0 findings" reads to a client as "clean". A security-savvy reviewer who pastes a realistic export and gets a near-empty report will conclude the product does not work.

**Failure scenario.** I ran the identical rule `allow <src> -> db-prod-01 tcp/3389` (db tagged pci/customer-data/prod) through algosec.normalize + over_permissive.analyze four ways:
  src=`0.0.0.0/0`            -> E=1.0, 1 finding, severity=100, band=critical, forced_critical=True
  src=`any`                  -> E=0.1, 0 findings
  src=`ANY-EXTERNAL` (object value 0.0.0.0/0) -> E=0.1, 0 findings
  src=`INTERNET` (object value 0.0.0.0/0)     -> E=0.1, 0 findings
Same policy, same exposure, and three of the four encodings produce NO finding at all — not a lower score, nothing. Separately: two rules `CORP`(10.0.0.0/8) and `BRANCH`(10.20.5.0/24) to the same dest/service produce 0 cidr_overlap findings; rewritten as raw CIDRs the same policy produces 1.

**Evidence.** algosec.py:23-32 — `obj = objects.get(token)` ... `ent = ObservedEntity(name=token, kind="identity", tool=TOOL, cidr=value, tags=tags)` / `return token, "identity", None, value, tags, ent`. The resolved CIDR (`value`) is put on the ObservedEntity and then THROWN AWAY for the PolicyRecord: algosec.py:50-57 builds the record with `source=s_val` (the object NAME) and `source_kind="identity"`. severity.py:26-29 then short-circuits: `if source_kind == "identity": return E_IDENTITY` (0.1). severity.py:90-91 `_is_internet(E) -> E >= 1.0`. cidr_overlap.py:34-36 skips the rule entirely: `if rec.action != "allow" or rec.source_kind != "cidr": continue`.

**Fix.** Make the record carry the resolved value, not the label. Add `source_cidrs: list[str]` / `dest_cidrs: list[str]` to PolicyRecord and populate them from the object catalog in every normalizer; keep the name in `source` for display. Drive `exposure_score`, `cidr_overlap`, and `shadowing` off the resolved CIDR list, falling back to E_IDENTITY only when the object genuinely has no address (a pure label, e.g. Guardicore). Add `any`/`Any`/`ANY`/`all` as recognized src/dst tokens mapping to 0.0.0.0/0. Add a regression test asserting the four encodings above yield identical severity.

</details>

<details>
<summary><b>The headline cross-tool path pivots THROUGH a /16 subnet — the exact fallacy `_valid_traversal` claims to reject</b><br/><code>claim-overreach</code> &middot; <code>backend/src/graph/reachability.py:47</code> &middot; CONFIRMED &middot; effort L</summary>

**Why it matters.** The cross-tool path is the product's differentiator and its demo climax. A security-savvy client will ask exactly one question: 'how does the attacker originate traffic as the 10.40.0.0/16 segment?' There is no answer — that is precisely the reason `_valid_traversal` exists. Meanwhile the rule that DOES represent the real catastrophe (ALGO-001 any/any from the internet into 10.0.0.0/8, which contains app-server-07 at 10.30.7.7) is dropped from path analysis because its subnet node happens to be spelled as a CIDR instead of as a named object. Whether a path is reported depends on the *notation the source export used for the same thing*.

**Failure scenario.** Demo Q&A: 'Is internal-app a host or a subnet?' 'A 10.40.0.0/16 segment.' 'So how does the attacker become the segment?' — there is no answer, and the finding is force-critical at 100. Conversely on real data, every subnet-to-subnet firewall rule written as a raw CIDR is invisible to path tracing.

**Evidence.** reachability.py:39-47:
```
def _valid_traversal(g, path) -> bool:
    """Reject paths that pivot THROUGH an abstract node (subnet/internet).
    Reaching hosts inside a range does not let you originate as that range..."""
    return all(g.nodes[n].get('kind') == 'concrete' for n in path[1:-1])
```
The shipped money-shot path (verified by running the engine):
  ['0.0.0.0/0', 'lb-public-01', 'app-server-07', 'internal-app', 'db-prod-01']
  node kinds: ['abstract', 'concrete', 'concrete', 'concrete', 'concrete']
`internal-app` is AlgoSec object `{'type':'network','value':'10.40.0.0/16'}` (seed_demo.py:41) and a Guardicore label with `role: 'segment'` (seed_demo.py:83). It is a SUBNET. It is 'concrete' only because algosec.py:31-32 builds non-host objects as `ObservedEntity(name=token, kind='identity', cidr=value, tags=tags)` WITHOUT `abstract=True` (contrast algosec.py:22 for a raw CIDR token, which does set abstract=True), and identity.py:96 `abstract = all(e.abstract for e in ents)` therefore yields kind='concrete' (identity.py:101).

The consequence is a straight contradiction. In the same run, the semantically identical path through a raw CIDR IS rejected:
  ['0.0.0.0/0', '10.0.0.0/8', 'app-server-07', 'internal-app', 'db-prod-01']  -> dropped (10.0.0.0/8 is abstract)

**Fix.** Pick one semantics and apply it uniformly. Either (a) mark AlgoSec `type != 'host'` objects and Guardicore `role == 'segment'` labels as `abstract=True` in the normalizers so `_valid_traversal` treats them consistently (this will delete the current money-shot until (b) lands), or preferably (b) implement CIDR-membership expansion: when a node is a range, expand the hop to the concrete assets whose ip_set falls inside it and route the path through those real pivots. (b) is the honest fix and it also recovers the any/any path. Until then, ENGINE.md must not claim subnet pivots are rejected.

**Verifier note.** Half of the failure scenario IS a documented simplification: ENGINE.md sec 10.2 'No CIDR-membership expansion' openly covers the raw-CIDR path being under-counted. The UNDOCUMENTED and indefensible half — which the finding correctly identifies as the real defect — is that a named network object is silently classified 'concrete' and IS allowed to be a pivot, contradicting the docstring on the very function that is supposed to prevent it. Blocker stands on that half alone.

</details>

<details>
<summary><b>`_PATH_SCAN_CAP` bounds results, not work — a 34-node east-west mesh takes 117 seconds; 62 nodes never finishes</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/src/graph/reachability.py:21</code> &middot; CONFIRMED &middot; effort L</summary>

**Why it matters.** ENGINE.md §7 states the cap 'keeps the engine bounded at thousands of assets/edges'. It is not bounded at 34. Worse, `cross_tool_paths` runs this loop once PER sensitive target (reachability.py:121-133), and `change/simulate.py:39-43` builds it TWICE (base graph + new graph) on every single change-gate classification. Truncation is also silent: nothing in the Finding, the EngineResult, or the API says 'results incomplete', so under-reporting looks identical to a clean estate.

**Failure scenario.** Client's Guardicore export has one 60-host application tier meshed east-west and 20 PCI-tagged assets. `precompute.py` / the first `GET` that calls `engine()` hangs for hours. Or, if it does return, it silently reports a subset of paths with no truncation flag and the client's pen-test finds a path the tool missed.

**Evidence.** reachability.py:19-21 `# all_simple_paths is worst-case exponential; cap how many candidates we examine\n# per (source,target) so the engine stays bounded at thousands of assets/edges.\n_PATH_SCAN_CAP = 4000` and reachability.py:124 `for path in islice(nx.all_simple_paths(g, source, target, cutoff=cutoff), _PATH_SCAN_CAP):`.

`islice` stops PULLING after 4000 yields; it does not bound the DFS backtracking between yields. Measured on a fully-meshed east-west segment (N hosts mesh + internet->h0 + h1->pci-db), which is exactly what a Guardicore microsegmentation export looks like:

  N=16  nodes=18  edges=242   -> 4000 paths in   1.94s
  N=20  nodes=22  edges=382   -> 4000 paths in   5.74s
  N=24  nodes=26  edges=554   -> 4000 paths in  18.90s
  N=28  nodes=30  edges=758   -> 4000 paths in  52.78s
  N=32  nodes=34  edges=994   -> 4000 paths in 117.41s
  N=60  nodes=62  edges=3542  -> DID NOT COMPLETE in 120s

~3x per +4 hosts. And it returns exactly 4000 every time — i.e. it silently truncates AND still burns two minutes.

**Fix.** Replace unbounded all_simple_paths with (a) a bounded BFS/DFS that caps *visited edges* not yielded paths, and abort with an explicit `truncated: true` flag propagated onto the finding and the API response; (b) prune to k-shortest paths (nx.shortest_simple_paths) with an explicit k; (c) cut the per-target loop with a single reverse-BFS from all sensitive targets first to eliminate unreachable targets before enumeration. Also add a wall-clock budget per snapshot. Independently: make scenarios._scale/seed_scale actually generate east-west edges (see the seed-scale finding).

**Verifier note.** I did not re-run the N=60 'did not complete in 120s' datapoint, but the reproduced growth curve makes it certain. Note this is both a perf gap AND a silent-correctness gap (truncation is invisible to the caller), so 'prod-readiness-gap' undersells the kind.

</details>

<details>
<summary><b>A port RANGE defeats every detector and every guardrail: `0.0.0.0/0 -> host tcp/1-65535` produces ZERO findings</b><br/><code>correctness-bug</code> &middot; <code>backend/src/analyzers/severity.py:44</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** This is the single most common real-world over-permissive pattern after any/any — a range rule that covers RDP, SSH, SMB and every database port. The engine scores it P=0.5 ('unknown / ephemeral'), fails every `_reasons` predicate (protocol!='any'; P=0.5 < admin_data_min_P 0.85; dest not sensitive), and fires no guardrail. cidr_overlap, shadowing and transport_exposure ignore port_end too. On real AlgoSec/Palo/Fortinet exports, range services are everywhere; the tool will report a clean bill of health on the worst rules in the file.

**Failure scenario.** Client uploads a real firewall export containing `allow any -> 10.0.0.0/8 tcp/1024-65535`. NPR reports zero findings for it. The client's own scanner reports it as critical. The whole product's credibility is gone in one screen.

**Evidence.** severity.py:40-52 `def port_score(protocol, port): ... if port in ADMIN_LATERAL_PORTS: return P_ADMIN ...` — it only ever reads the single `port` scalar. `PolicyRecord.port_end` (models.py:44 `port_end: Optional[int] = None  # range end`) is parsed by common.py:102-114 `_parse_ports` and stored, then read by NOBODY in analyzers/ except reachability._grant_matches. over_permissive.py:42 calls `P, _ = port_score(rec.protocol, rec.port)`.

Reproduced end-to-end:
  parse_service('tcp/1-65535') -> DecodedService(protocol='tcp', port=1, port_end=65535, ...)
  port_score('tcp', 1) -> (0.5, 'unknown / ephemeral')
  over_permissive.analyze([0.0.0.0/0 -> app-server-07 tcp/1-65535]) -> []      <-- NO FINDINGS
  over_permissive.analyze([0.0.0.0/0 -> app-server-07 tcp/3389])     -> [(90,'critical',forced=True,'RDP open from the internet to app-server-07')]

**Fix.** Make port_score range-aware: `port_score(protocol, port, port_end)` returning `max` over the class of every port in [port, port_end] (short-circuit: if the range intersects ADMIN_LATERAL_PORTS -> P_ADMIN, etc.), and treat a range spanning >N ports (or the full 1-65535) as P_ANY_PORT. Thread port_end through over_permissive.py:42, severity.score_over_permissive/score_shadowed/score_transport_exposure, the ADMIN_LATERAL guardrail at severity.py:108, and the transport_exposure fallback-pair match at transport_exposure.py:82.

**Verifier note.** The title over-claims: it does NOT defeat *every* guardrail. I tested the same range against a PCI destination — `0.0.0.0/0 -> db-prod-01 tcp/1-65535` still returns (100,'critical',forced=True), because the `sensitive and _is_internet(E)` floor at severity.py:110-111 is port-independent, and `protocol=='any'` rules are unaffected. The accurate statement is: a port RANGE is scored as its START port only, so the two port-dependent guardrails (severity.py:108-109 'admin/lateral port from the internet' and the OVERPERMISSIVE_CONFIG P>=0.85 predicates) are silently bypassed, and a range to a NON-sensitive destination produces zero findings. Severity stays blocker.

</details>

<details>
<summary><b>`effective_policy` and `reachable` give opposite answers on the shipped demo data</b><br/><code>correctness-bug</code> &middot; <code>backend/src/graph/reachability.py:180</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** These two functions are the deterministic ground truth the assistant is told never to second-guess. On the demo dataset they disagree about whether the internet can reach app-segment. The assistant will confidently assert both, in the same session, depending on which tool it happens to call. The doc calls who_can_reach 'effective_policy(asset): which nodes can actually reach target' (reachability.py:172) — 'actually' is exactly what it does not compute.

**Failure scenario.** Live demo. 'Is app-segment exposed to the internet?' -> assistant calls effective_policy -> 'Yes, internet_exposed: true.' 'Show me the path.' -> assistant calls reachable/find_paths -> 'There is no path.' In front of a security client.

**Evidence.** reachability.py:171-189 `who_can_reach` uses bare `nx.has_path(g, n, target)` with NO `_valid_traversal` filter and no port/grant awareness, unlike `reachable` (line 151-156) and `find_paths` (line 166) which both apply it. Reproduced on the shipped demo:
  who_can_reach(g, 'app-segment') -> {'sources': ['0.0.0.0/0', '10.0.0.0/8', '10.20.5.0/24'], 'internet_exposed': True}
  reachable(g, '0.0.0.0/0', 'app-segment') -> {'reachable': False, 'paths': []}
Both are exposed to the LLM as tools: agent/tools.py:37-41 `reachable` and agent/tools.py:51-52 `effective_policy -> who_can_reach`.

**Fix.** Reimplement who_can_reach on the same primitive as reachable — for each candidate source, require at least one path passing `_valid_traversal` (a reverse BFS that refuses to expand through abstract nodes is O(V+E) and avoids the per-node has_path loop, which is also O(V*(V+E)) and will not scale). Return the witness path alongside each source so the two tools are provably consistent.

**Verifier note.** UNDER-RATED — raising high -> blocker. This is the only finding in the set that reproduces on the default seeded dataset, through the shipped assistant tools, with no crafted input. Two tools the model is free to call in the same turn return 'internet_exposed: true' and 'there is no path' for the same asset. That is precisely the live-demo failure mode the user asked about, and it requires no client data at all to trigger.

</details>

<details>
<summary><b>The "tool-calling assistant" only calls tools on Ollama — the documented production config (ADVISORY_PROVIDER=openai) silently degrades to a single canned completion while the UI still renders a "Tool trace"</b><br/><code>claim-overreach</code> &middot; <code>backend/src/agent/assistant.py:88</code> &middot; CONFIRMED &middot; effort L</summary>

**Why it matters.** The headline claim is "the model NEVER computes reachability — it calls deterministic tools and reasons over their structured results." On the only deployment configuration the repo documents, the model calls exactly zero tools; it receives one truncated `risk_findings` blob (`[:6000]` chars) and answers from it. Ask "can the internet reach db-prod-02 over QUIC?" and the model is guessing from a truncated summary — which is precisely the failure mode the governing rule exists to prevent. And the UI labels the fabricated trace "Tool trace", so it looks like it worked.

**Failure scenario.** Client demo on the Render/Vercel deploy. Analyst asks "What can reach db-prod-02 on tcp/5432?". `active_provider()` returns "openai", so `_ollama_loop` is skipped entirely. `_grounded_fallback` sends a 6,000-char truncated finding list and the model free-associates an answer. The Tool trace panel shows `risk_findings()`, implying a deliberate tool call. If db-prod-02's path was truncated out of the 6,000 chars, the answer is confidently wrong.

**Evidence.** assistant.py:88-94 — the entire provider gate:
    def ask(ctx, question: str) -> dict:
        try:
            if settings.active_provider() == "ollama":
                return _ollama_loop(ctx, question)
        except Exception:
            pass
        return _grounded_fallback(ctx, question)

assistant.py:74-86 — the fallback makes ONE call with one pre-baked fact blob, no tools:
    def _grounded_fallback(ctx, question: str) -> dict:
        """No tool-calling available -> still ground the answer in deterministic facts."""
        facts = {"findings": T.risk_findings(ctx)}
        fr = complete(system=_SYSTEM + "\n(No live tools available; answer ONLY from the provided facts.)",
                      user=f"Question: {question}\n\nFacts:\n{json.dumps(facts)[:6000]}", role="judge", temperature=0.2)
        return {..., "trace": [{"tool": "risk_findings", "args": {}, "result": facts["findings"]}], ...}

render.yaml:24-27 — the shipped production config:
      # Force the hosted OpenAI provider (no local Ollama on Render).
      - key: ADVISORY_PROVIDER
        value: openai

The UI presents the synthetic single-element trace as if the agent chose it:
  Assistant.tsx:60-61  "The agent calls deterministic engine tools, so every answer is grounded in computed facts."
  Assistant.tsx:83-89  <div className="label ..."> Tool trace </div> {t.a.trace.map(...)}

Both the OpenAI and Anthropic SDKs support function calling; there is simply no implementation for them (client.py:93-119 have no `tools=` parameter).

**Fix.** Implement tool-calling for OpenAI (`tools=` + `tool_choice`) and Anthropic (`tools=` + `tool_use` blocks) in client.py, and route `_ollama_loop`'s ReAct loop through a provider-agnostic interface. Until then, make the degradation visible: return `by: "grounded_fallback (no tool calling on <provider>)"` and have Assistant.tsx render a warning banner instead of a "Tool trace" header. Do not ship render.yaml pointing at a provider whose agent path is unimplemented.

**Verifier note.** RAISE high -> blocker. Strengthen the evidence: agent/tools.py:55-64 shows risk_findings returns only {id,type,title,severity,band,forced_critical} — no paths, no involved entities, no rule refs. So on the hosted config the assistant has NO reachability facts at all, not merely truncated ones, while the UI labels it a 'Tool trace' and the spinner says 'Calling deterministic tools…'.

</details>

<details>
<summary><b>The FastAPI backend has ZERO authentication; all authorization is a client-forgeable `x-npr-role` header, and render.yaml deploys it as a public web service</b><br/><code>security</code> &middot; <code>backend/app/main.py:62</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** This is not a hardening gap, it is the absence of an authentication boundary on the service that holds the customer's firewall policy, microsegmentation policy, cloud exposure map, reachability graph and full audit trail. The entire SSO/OIDC investment in the frontend protects nothing that an attacker cannot bypass with one HTTP header. In front of a security-savvy client this is the single question that ends the meeting: "so your network-attack-map API is on the internet with no auth?"

**Failure scenario.** `curl https://ztpa-backend.onrender.com/api/graph` returns the complete cross-tool topology, node IP sets and tags with no credential at all. `curl https://ztpa-backend.onrender.com/api/ingest` dumps every canonical rule from AlgoSec/Guardicore/Wiz. `curl -H 'x-npr-role: admin' -X POST .../api/admin/reset-demo` wipes every change request, decision and staged change. `curl -H 'x-npr-role: admin' -X DELETE .../api/snapshots/<id>` deletes a historical snapshot (schema.sql cascades to all children). `curl -H 'x-npr-role: admin' .../api/admin/metrics` returns token spend and per-user emails. No log entry identifies the attacker, because audit_log has no actor-identity column.

**Evidence.** main.py:59-63  `async def __call__(self, scope, receive, send):\n    if scope.get("type") == "http":\n        h = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}\n        request_ctx.set_actor(h.get("x-npr-role"), h.get("x-npr-email"), h.get("x-npr-sub"))`

main.py:69-71  `def require_admin() -> None:\n    if request_ctx.role() != "admin":\n        raise HTTPException(403, "admin only")`

There is no token verification anywhere in backend/. `request_ctx.py:13-15` states it outright: "The proxy strips any client-supplied `x-npr-*` headers before setting its own, so this backend must stay private (reachable only through the proxy); it does not independently validate AutoX tokens."

But render.yaml:11-18 deploys it as a PUBLIC service, not a private one:
`services:\n  - type: web\n    name: ztpa-backend\n    ...\n    startCommand: uvicorn app.main:app --host 0.0.0.0 --port $PORT`

and docs/DEPLOY.md:107-110 admits it: "**Backend is public.** It trusts `x-npr-role`/`x-npr-email` headers injected by the Vercel middleware. Anyone hitting the Render URL directly could forge these. Fine for a demo; before anything real, add a shared secret..."

There is no shared secret, no mTLS, no IP allowlist, no JWT check. `FRONTEND_ORIGIN` only feeds CORSMiddleware (main.py:44-47), which a browser enforces and curl ignores.

**Fix.** Two layers. (1) Immediately: require a high-entropy shared secret on every backend request — a `Depends` that compares `x-npr-proxy-key` against an env var with `hmac.compare_digest`, applied as a global `dependencies=[...]` on `FastAPI(...)` so no route can be forgotten; set it as a `sync: false` var on Render and inject it in `frontend/middleware.ts` alongside the actor headers. Reject before the ASGI actor middleware trusts anything. (2) Properly: have the middleware mint a short-lived signed JWT (HS256 over AUTH_SECRET, or forward the AutoX access token) carrying sub/email/role, and verify signature + exp + iss + aud in the backend, deriving `request_ctx` only from verified claims. Until (1) ships, do not expose the Render URL — bind it behind Render private services or an allowlist.

**Verifier note.** One factual overstatement: /api/admin/metrics does NOT return per-user emails. It returns role-level aggregates only (main.py:883-885 `SELECT role, count(*)... GROUP BY role`). ai_metrics DOES store actor_email (metrics.py:41) but no endpoint selects it. Everything else stands.

</details>

<details>
<summary><b>Unauthenticated account takeover: `requestMagic`/`requestReset` return a live sign-in link to the caller's browser whenever RESEND_API_KEY is unset</b><br/><code>security</code> &middot; <code>frontend/app/actions.ts:17</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** Anyone who knows a user's email address becomes that user — including the admin — with no email access, no password, and no second factor. It is a one-request, no-tooling takeover reachable from the public login page. The 'don't leak which emails exist' comment on line 15 is also defeated: the presence or absence of `devLink` in the response is a perfect user-enumeration oracle.

**Failure scenario.** SSO is not yet configured (the documented default for a fresh clone: `.env.example:55 SSO_CLIENT_ID=` is blank, and `lib/sso.ts:34-35 localLoginEnabled()` returns true when SSO is off), or `AUTH_LOCAL_LOGIN=true` during cutover, and RESEND_API_KEY was left unset per DEPLOY.md. An attacker opens `https://<app>.vercel.app/login`, switches to the Magic-link tab, types the admin's email (or the `ADMIN_EMAIL` from any leaked config), clicks send, and the page renders a clickable `/login/magic?token=...` link. Clicking it signs them in as that admin. Total time: ~10 seconds.

**Evidence.** app/actions.ts:11-21
`export async function requestMagic(email: string) {\n  if (!localLoginEnabled()) return { ok: true };\n  const u = await getUserByEmail(email);\n  if (u && u.status !== "disabled") {\n    const token = await createToken(email, "magic");\n    const r = await emails.magic(u.email, `${getBaseUrl()}/login/magic?token=${token}`);\n    return { ok: true, devLink: (r as any).devLink as string | undefined };\n  }\n  return { ok: true };\n}`

lib/email.ts:24-28 produces that devLink whenever the key is missing:
`async function send(to, subject, html, devLink) {\n  if (!KEY) {\n    console.log(`\\n[email disabled — no RESEND_API_KEY]...`);\n    return { sent: false, devLink };\n  }`

and the client renders it verbatim — components/auth/LoginForm.tsx:89 `{sent.devLink && <DevLink href={sent.devLink} />}`, components/auth/ForgotForm.tsx:24 the same, with AuthShell.tsx:42-48 `export function DevLink({ href }) { ... <Link href={href} ...>{href}</Link> }`.

docs/DEPLOY.md:68 lists the key as optional: "| `RESEND_API_KEY` | *(optional — magic/reset links print to logs without it)* |" — the doc frames the vulnerable configuration as a supported production choice. `/login` and `/forgot` are unauthenticated (auth.config.ts:8 `const PUBLIC = ["/login", "/forgot", "/reset", "/sso"]`).

**Fix.** Never return a credential to the client. Gate the devLink on `process.env.NODE_ENV !== "production"` at minimum, and preferably remove `devLink` from the server-action return type entirely — keep it console-only. Fail closed instead: if `RESEND_API_KEY` is unset in production, refuse to mint magic/reset tokens and surface a configuration error to the operator rather than silently downgrading to 'print the credential to the browser'. Make RESEND_API_KEY required (not 'optional') in DEPLOY.md whenever `localLoginEnabled()` is true.

**Verifier note.** The title is imprecise: it is NOT 'whenever RESEND_API_KEY is unset'. Two conditions must both hold — localLoginEnabled() (SSO_CLIENT_ID blank or AUTH_LOCAL_LOGIN=true) AND no RESEND_API_KEY (or a Resend send error, per finding #8). Under the documented final production config (SSO_CLIENT_ID set), actions.ts:12 and :24 return {ok:true} before minting anything, so the path is dead. The failure_scenario states this correctly; the title does not. Severity stays blocker because a fresh clone and every pre-SSO/cutover deployment is in the vulnerable state by default.

</details>

<details>
<summary><b>A `viewer` can submit, stage, PUSH and discard changes, merge assets and force recomputes — 10 state-mutating endpoints have no role guard at all, contradicting docs/SSO.md</b><br/><code>security</code> &middot; <code>backend/app/main.py:747</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** Unlike the previous finding, this does NOT depend on the backend being publicly reachable. A legitimately authenticated `npr_viewer` — the role you hand to an auditor or a client stakeholder — can drive the whole change pipeline to a simulated production push through the normal, SSO-authenticated frontend. For a product whose entire value proposition is change GOVERNANCE, having the approval gate enforced on one branch out of five is indefensible. It also means the per-role Tools admin screen is the only thing standing between a viewer and the write paths, and it defaults to on.

**Failure scenario.** A user with only `npr_viewer` signs in through AutoX. Middleware sets `x-npr-role: viewer`. They open Risk To-Do -> Remediate (capability `remediate`, default-on for viewer) -> Send to Change Gate (`POST /api/change/submit`, capability `classify`, default-on). The engine validates the fix resolves with no new criticals, so `_submit_remediation` (main.py:650) sets `decision = "auto_approve"`. They click Stage: `POST /api/staging` takes the `else` branch at main.py:721 with no role check. They open the Staging screen and click Push: `POST /api/staging/{id}/push` has no guard, writes `status='pushed'` and the change enters `load_applied_changes` so every subsequent `run()` applies it. A read-only user has just mutated the golden policy state and the audit row says `actor='user'`.

**Evidence.** The "push to the source system" endpoint has no guard whatsoever:
`main.py:746-748`
`@app.post("/api/staging/{staged_id}/push")\ndef staging_push(staged_id: str):\n    """Simulated, stepped push. Conflicts are detected with real engine math..."""`

Staging an approved change checks a role ONLY on the escalated branch:
`main.py:711-722`
`if row["decision"] == "escalate":\n    if not body.manual_approve: raise HTTPException(400, ...)\n    if request_ctx.role() not in ("admin", "analyst"):\n        raise HTTPException(403, "only admin or analyst can approve an escalated change")\n    staged_decision = "manual_approved"\nelse:\n    staged_decision = "auto_approve"`  <- the auto_approve path is reachable by anyone.

Also unguarded and mutating: `main.py:163 @app.post("/api/recompute")`, `main.py:489 @app.post("/api/actions/recompute")`, `main.py:531 @app.post("/api/assets/merge")`, `main.py:543 @app.post("/api/assets/unmerge")`, `main.py:769 @app.delete("/api/staging/{staged_id}")`. `POST /api/change/submit` (main.py:682) and `POST /api/campaign/submit` (main.py:443) are gated only by `_require_capability("classify")`, and tools_registry.py:105 says `return _settings_map().get(key, list(ALL_ROLES))` — "Absent row -> all roles (default-on)", i.e. enabled for viewer out of the box.

docs/SSO.md:46 claims the opposite: "| `npr_viewer` | `viewer` | Read-only: findings, graph, reports, evidence. Cannot approve or apply changes |"

The frontend does not compensate: `components/Staging.tsx:82` `const res = await api.stagingPush(item.staged_id);` and `:100` `await api.stagingDiscard(item.staged_id)` have no `canApprove` check, and `Staging` is rendered for every role (console/page.tsx:99). Only ChangeGate.tsx:201/478/483 gates the escalate-approve and reject buttons — the two paths the backend also happens to guard.

**Fix.** Add a `require_approver()` dependency (role in admin/analyst) and a `require_operator()` (admin only, for push) and attach them: `staging_push`, `staging_delete`, `stage_change` (unconditionally, not just the escalate branch), `change_submit`, `campaign_submit`, `confirm_merge`, `undo_merge`, `recompute`, `switch dataset`, `recompute_actions`. Do NOT rely on the capability toggles for this — they are a feature-flag layer with a default-on fallback, not an authorization layer. Then mirror the same predicate in `Staging.tsx`/`AssetsPanel.tsx`/`Topbar.tsx` so the UI does not offer buttons that 403. Add a test that asserts each mutating route 403s for `x-npr-role: viewer`.

</details>

<details>
<summary><b>Mutation test: 6 of 10 injected engine defects pass BOTH pytest and verify_engine — the entire severity formula is unguarded</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/tests/test_agents.py:1</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The headline claim is 'an exact E x P x D x B severity vector and guardrail floors'. That number is the product. It has zero regression protection: you can change `impact_base`, move the critical band from 80 to 95, make every PCI asset score like an untagged one, delete the admin-port guardrail floor entirely, or introduce an off-by-one on every score in the product, and the full test suite plus the script README calls 'prove the engine meets every acceptance criterion' both report green. severity.py shows 91.3% *executed* coverage purely because the `eng` fixture calls run(); 0% of it is *asserted*.

**Failure scenario.** A developer tunes `SEVERITY_CONFIG["impact_base"]` in config.py while calibrating, or a refactor changes `severity_from_vector` rounding. `pytest` prints '16 passed', `python tasks.py verify` prints 'ALL CHECKS PASSED'. The change ships. In front of a client, an RDP-from-internet rule to a PCI database now shows severity 62/'high' instead of 100/'critical', or the PCI database and a dev sandbox rank identically. Nothing in the repo would have flagged it.

**Evidence.** I ran a mutation matrix in-process (nothing on disk modified), injecting one defect at a time then running `pytest backend/tests` AND `verify_engine.main()`:

  impact_base 0.5->0.9 (severity formula) ......... pytest PASS, verify PASS
  band_critical 80->95 (band thresholds) .......... pytest PASS, verify PASS
  exposure_span 0.6->0.1 (exposure factor) ........ pytest PASS, verify PASS
  dest_score() flat -> 0.4 (PCI == untagged) ...... pytest PASS, verify PASS
  ADMIN_LATERAL_PORTS.clear() (RDP/SSH guardrail) . pytest PASS, verify PASS
  round() -> floor() on every score ............... pytest PASS, verify PASS
  exposure_score() flat -> 0.1 .................... pytest PASS, verify FAIL
  SENSITIVE_TAGS.clear() .......................... pytest FAIL, verify FAIL
  _valid_traversal -> always True ................. pytest FAIL, verify FAIL
  identity IP-merge disabled ...................... pytest FAIL, verify FAIL

Corroborating grep of every numeric assertion in the whole suite:
  test_agents.py:69  assert res["attempts"] == 2
  test_agents.py:73  assert len(res["trace"]) == 2
  test_agents.py:111 assert traj[-1] == 0
  test_agents.py:114 assert res["final_counts"]["critical"] == 0
  test_agents.py:115 assert res["needs_review_count"] == 0
  test_agents.py:140 assert res["applied_count"] == 0
  test_agents.py:183 assert called["n"] == 0
  test_agents.py:317 assert res["attempts"] == 2
Not one assertion anywhere touches `.severity`, `.severity_band`, a sub-score, a finding count, an alias_map entry, or a graph edge.

**Fix.** Add `backend/tests/test_severity.py` with table-driven exact-value cases: `severity_from_vector(1.0, 0.9, 1.0, 1.4) == <pinned int>` for ~15 (E,P,D,B) tuples spanning every band boundary; `band(79)=='medium'`/`band(80)=='critical'`; one case per TAG_SENSITIVITY entry; and one forced-critical case per guardrail clause in `score_over_permissive` (any/any, admin port from internet, sensitive-from-internet) each asserted independently so removing one clause fails one test. Then add `backend/tests/test_engine_golden.py` that snapshots the full `run()` output (every finding's id/type/severity/band/forced/signals) to a committed JSON fixture and diffs it.

</details>


### HIGH

<details>
<summary><b>engine() swallows persistence failures, so every DB-backed endpoint returns empty and the UI shows an all-clear estate</b><br/><code>robustness-gap</code> &middot; <code>backend/app/main.py:112</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** If persist fails for ANY reason -- FK violation, bind-parameter limit, statement timeout, a rolled-back ensure_* DDL -- the snapshots row never exists, but `sid()` still returns a valid-looking id. /api/findings, /api/graph, /api/assets, /api/actions all return empty result sets with HTTP 200. The frontend cannot distinguish that from a clean estate.

**Failure scenario.** Switch to the 'scale' scenario with n=3000 (see the bind-parameter finding). persist_engine_result raises, the exception is swallowed here, and the app comes up reporting a network with 0 assets, 0 rules, 0 findings, HTTP 200 everywhere. There is no log, no banner, and no way to tell it apart from success.

**Evidence.** main.py:110-119:
    _ENGINE = run(label=_ACTIVE_SCENARIO, manual_merges=_load_merges(), applied_changes=_load_applied())
    try:
        with get_conn() as conn, conn.cursor() as cur:
            row = fetch_one(cur, "SELECT snapshot_id FROM ztpa.snapshots WHERE snapshot_id=%s", [_ENGINE.snapshot_id])
            if not row:
                persist_engine_result(cur, _ENGINE)
    except Exception:
        pass  # DB optional for live-only ops

Every dashboard read is DB-backed and scoped to that same id, e.g. main.py:301-308 /api/findings `WHERE snapshot_id=%s` with `view_sid(snapshot)` -> `engine().snapshot_id`.

**Fix.** Distinguish 'DB optional' (a deliberate live-only mode, gated by an env flag) from 'DB write failed'. On failure, mark the engine result `persisted=False` and have the read endpoints return 503 (or a `stale: true` envelope) rather than an empty 200. Never let a write failure masquerade as an empty dataset.

</details>

<details>
<summary><b>Live LLM calls run while holding a pooled DB connection; 10 concurrent report/action loads exhaust the pool</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/app/main.py:479</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** A single cold local-model ranking call can hold a connection for up to 600 seconds. With max_size=10 and a 30s acquire timeout, eleven users opening the Risks or Report tab at once starve the pool; every unrelated endpoint then raises PoolTimeout, which (per the no-exception-handler finding) becomes a 500 and an empty dashboard. Also: /api/actions is a GET that performs writes and triggers an LLM call -- any prefetch, retry, or double-render fires two ranking runs.

**Failure scenario.** Demo to a room: three people open the app simultaneously on a cold Ollama. Three /api/actions and three /api/report requests each grab a connection and block on the model. /api/findings and /api/graph now wait 30s for a connection, then 500. The whole dashboard blanks out mid-demo.

**Evidence.** main.py:476-486 (/api/actions, a GET that also WRITES):
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, "SELECT ... FROM ztpa.ranked_actions ...")
        if rows or t != sid():
            return {...}
        ranked = rank_mod.rank(engine().findings)      # <-- live LLM call, connection held
        persist_ranked_actions(cur, t, ranked)

Same shape in _ranked_cached, called from inside the connection block by /api/report (main.py:978-980) and /api/report/narrative (988-990):
    with get_conn() as conn, conn.cursor() as cur:
        ranked = _ranked_cached(cur)     # main.py:967 -> rank_mod.rank(engine().findings)

rank.py:112-113: `r = complete(system=_PROMPT, user=..., role='judge', temperature=0.1, expect_json=True)`
settings.py:35: `OLLAMA_TIMEOUT: float = float(os.environ.get('OLLAMA_TIMEOUT', '600'))`
db.py:63-70: `min_size=1, max_size=int(os.getenv('DB_POOL_MAX','10')), timeout=30.0`

**Fix.** Compute first, persist second: call `rank_mod.rank(...)` OUTSIDE the `with get_conn()` block (the pattern /api/campaign/plan already uses correctly at main.py:429-431), then open a short transaction only to write. Make /api/actions a pure read and move recomputation to the existing POST /api/actions/recompute. Add a process-level lock or single-flight guard so concurrent callers share one ranking run.

</details>

<details>
<summary><b>A transient DB error makes the engine silently recompute WITHOUT confirmed merges or applied changes -- then persists it</b><br/><code>correctness-bug</code> &middot; <code>backend/app/main.py:83</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** This produces a wrong-but-plausible answer with no signal. The human-confirmed identity merges (the 'IP is an attribute, not a key' story) and every operator-pushed change vanish from the analysis. The resulting snapshot is then written to Postgres as the system of record by the very next line. There is no log line -- there is no logging in this backend at all -- so nobody ever learns it happened.

**Failure scenario.** Neon cold-start latency exceeds the pool's 30s acquire timeout during /api/recompute. `_load_merges()` returns [] and `_load_applied()` returns []. The engine unmerges appsrv-07 from app-server-07, so the cross-tool path finding disappears, and every pushed remediation is reverted so resolved findings reappear. persist_engine_result writes this as authoritative. The analyst sees a completely different risk picture with a green 'recompute complete' toast.

**Evidence.** main.py:83-99:
    def _load_merges() -> list[tuple[str, str]]:
        try:
            with get_conn() as conn, conn.cursor() as cur:
                return load_asset_merges(cur)
        except Exception:
            return []

    def _load_applied() -> list[dict]:
        try:
            with get_conn() as conn, conn.cursor() as cur:
                return load_applied_changes(cur)
        except Exception:
            return []

Both feed every engine build: main.py:110, 173, 204, 521, 810 all call `run(label=..., manual_merges=_load_merges(), applied_changes=_load_applied())`.
run_all.py:74-78: `if applied_changes: records = apply_overlay(...)` then `resolve_identities(entities, manual_merges)`.
persist.py:282-292 `load_applied_changes` ALSO has its own `except Exception: return []`.

**Fix.** Do not degrade silently on inputs that change the ANSWER. Let the exception propagate (or raise a specific EngineInputError) so /api/recompute returns 503 and leaves the previous snapshot intact. Reserve fail-soft for cosmetic paths only. At minimum, thread a `degraded: true` flag through EngineResult into the persisted snapshot row and surface it in the UI.

</details>

<details>
<summary><b>Backend has zero authentication and is deployed as a public Render web service; role comes from a spoofable header</b><br/><code>security</code> &middot; <code>backend/src/request_ctx.py:13</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The documented precondition ('must stay private') is violated by the shipped deploy config. Anyone who finds the Render URL is an admin. Separately, even the intended model is broken: /api/staging (703), /api/staging/{id}/push (746), /api/staging/{id} DELETE (769), /api/change/submit (682) and /api/recompute (163) have NO role check at all -- so a `viewer` can push simulated changes into the source-of-truth and recompute the estate. Only reject_change and escalated-approval are gated.

**Failure scenario.** `curl -X POST https://ztpa-backend.onrender.com/api/admin/reset-demo -H 'x-npr-role: admin'` wipes the change workflow. `curl -X DELETE .../api/snapshots/<id> -H 'x-npr-role: admin'` deletes history. No header at all still lets you POST /api/staging/<id>/push, because that endpoint never consults the role. A security-savvy client will test this in the first five minutes.

**Evidence.** request_ctx.py:13-15 docstring: "The proxy strips any client-supplied `x-npr-*` headers before setting its own, so this backend must stay private (reachable only through the proxy); it does not independently validate AutoX tokens."

main.py:59-62 (_ActorMiddleware): `h = {k.decode(...): v.decode(...) for k,v in scope.get('headers', [])}` then `request_ctx.set_actor(h.get('x-npr-role'), ...)`.
main.py:69-71: `def require_admin(): if request_ctx.role() != 'admin': raise HTTPException(403, 'admin only')`

render.yaml:11-17:
    services:
      - type: web
        name: ztpa-backend
        startCommand: uvicorn app.main:app --host 0.0.0.0 --port $PORT

`type: web` on Render is internet-reachable. There is no IP allowlist, no shared secret, no token check anywhere in main.py.

**Fix.** (a) Require a shared secret between the Next.js proxy and the backend (e.g. `X-NPR-Proxy-Key` compared with hmac.compare_digest against an env var) in _ActorMiddleware, rejecting 401 otherwise -- and reject any request carrying x-npr-role without it. (b) Add explicit role dependencies to the staging/submit/recompute endpoints (approver = admin|analyst for stage/push/discard). (c) Put the Render service behind a private network or at minimum document/enforce that it is not the public entrypoint.

**Verifier note.** Downgrade blocker -> high. The defect is real and a security-savvy client will still find it in five minutes, but it is openly documented as a known demo-only caveat in docs/DEPLOY.md:107-110, so it is a stated simplification rather than an undisclosed hole.

</details>

<details>
<summary><b>No global exception handler; unhandled 500s lose CORS headers and the UI renders them as 'all clear'</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/app/main.py:44</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** This is the most likely mechanical cause of 'I do not feel confident when working with it.' A backend failure and a genuinely clean estate are pixel-identical on screen: loading spinners resolve, the sidebar shows 0 findings / 0 critical, the map is empty, and no error banner appears (because `err` only tracks /api/health, which itself swallows DB errors -- see the health finding). In a security product, silently reporting 'no findings' when the query failed is the worst possible failure mode.

**Failure scenario.** Neon suspends or a query times out. /api/findings raises psycopg.OperationalError -> 500 with no CORS header -> the browser reports a network error -> `.catch(() => {})` -> findings stays `[]`, loading flips to false. Analyst sees a fully-rendered dashboard reading '0 critical' and believes the estate is clean.

**Evidence.** main.py:44-66:
    app.add_middleware(CORSMiddleware, allow_origins=[...])
    ...
    app.add_middleware(_ActorMiddleware)

There is no `@app.exception_handler(...)` anywhere in the file (grep for 'exception_handler': 0 hits). Not one of the ~40 endpoints wraps `get_conn()` in try/except -- every DB error propagates raw.

Starlette builds the stack as ServerErrorMiddleware -> [last-added first: _ActorMiddleware, CORSMiddleware] -> ExceptionMiddleware -> router. ServerErrorMiddleware is therefore OUTSIDE CORSMiddleware, so the 500 it synthesizes carries no access-control-allow-origin.

frontend/lib/api.ts:6-9: `if (!r.ok) throw new Error(...)`.
frontend/app/console/page.tsx:59-62:
    api.snapshot(viewSnap).then(...).catch(() => {});
    api.findings(viewSnap).then((f) => setFindings(f.findings)).catch(() => {}).finally(() => setLoading(l => ({...l, findings:false})));
    api.graph(...).catch(() => {}).finally(...);
    api.actions(...).catch(() => {}).finally(...);
console/page.tsx:44-47: `const [findings, setFindings] = useState<Finding[]>([]);` and `err` is set ONLY by the health call (line 52).
console/page.tsx:66: `const critical = findings.filter(f => f.severity_band === 'critical').length;`

**Fix.** (1) Add `@app.exception_handler(Exception)` returning a JSON envelope `{error, request_id}` with a 500, and a psycopg-specific handler returning 503 so DB unavailability is distinguishable from a bug. (2) Register CORSMiddleware LAST (so it is outermost) or add the CORS headers in the exception handler, so 5xx responses are readable by the browser. (3) In the frontend, replace `.catch(() => {})` with state that renders a 'could not load findings' banner -- never fall through to an empty array that reads as 'all clear'.

**Verifier note.** Strike the CORS half. The frontend proxies /api/* through Next.js rewrites (next.config.mjs) and fetches same-origin relative URLs (lib/api.ts), so allow-origin headers are never consulted. The finding stands purely as: no global exception handler + lib/api.ts throwing on !r.ok + four bare `.catch(() => {})` in console/page.tsx = a backend failure renders as a confident 'all clear' dashboard.

</details>

<details>
<summary><b>snapshot_id hashes only the records, so different merge states collide on one id and overwrite history in place</b><br/><code>correctness-bug</code> &middot; <code>backend/src/analyzers/run_all.py:82</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** 'Every analysis run is a point-in-time snapshot' (schema.sql:20) is only true for the rule data. Confirming or undoing a merge mutates an EXISTING historical snapshot in place rather than creating a new one -- so the snapshot you looked at last week is not the snapshot you look at today under the same id, and the change_requests attached to it are cascaded away in the process (see the CASCADE finding). Any reproducibility or evidentiary claim about snapshots is weaker than stated.

**Failure scenario.** Confirm that appsrv-07 and app-server-07 are the same asset. The snapshot id is unchanged, so the Snapshots list shows the same single entry -- but its asset count dropped by one and a cross-tool path finding appeared. There is no before/after and no way to reconstruct the earlier view. Undo the merge and it silently reverts.

**Evidence.** run_all.py:57-61, 82:
    def _fingerprint(records) -> str:
        return content_fingerprint(sorted(
            f"{r.source_tool}|{r.raw_ref}|{r.source}|{r.destination}|{r.service}|{r.action}|{r.order}"
            for r in records))
    ...
    sid = make_snapshot_id(label, _fingerprint(records))

`manual_merges` is passed to `resolve_identities` (run_all.py:78) and materially changes assets, alias_map, the graph and therefore the findings -- but it is not in the fingerprint.

main.py:517-528 `_apply_merges_and_persist` then calls `persist_engine_result` on that same id, which (persist.py:63) deletes and re-inserts the existing snapshot.

**Fix.** Fold the resolved identity state into the fingerprint: hash the sorted manual_merges list (and the applied_changes overlay ids) alongside the records. Every distinct input state then gets its own snapshot id, merges become additive history instead of destructive edits, and the snapshot timeline actually shows the identity decision.

**Verifier note.** Raise medium -> high. Verified by execution that a merge changes assets 25->24 and findings 17->18 under an identical snapshot_id. Because the id is unchanged, persist_engine_result's delete-and-reinsert overwrites the prior analysis AND cascades away that snapshot's change_requests/change_decisions — so this is the root cause feeding two of the blockers, not an isolated history nit.

</details>

<details>
<summary><b>The single test file never imports app.main, db.py, or persist.py -- 0% coverage of the entire audited surface</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/tests/test_agents.py:19</code> &middot; CONFIRMED &middot; effort L</summary>

**Why it matters.** This is the root cause, not a symptom. The parse_service unpack bug (a one-line TypeError on a flagship endpoint) survived to a deployable state purely because no test has ever called an endpoint. The same gap means the CASCADE data loss, the negative-limit 500, the historical-finding 404, and the bind-parameter ceiling are all undetected. The ratio the user should internalize: the AI advisory layer -- the part that is explicitly allowed to be wrong -- has 18 tests; the deterministic API and system of record -- the part that must never be wrong -- has zero.

**Failure scenario.** Any refactor of main.py or persist.py ships unverified. Concretely: it already did -- /api/change/classify's custom path has never worked.

**Evidence.** The complete import list of the only test file (backend/tests/test_agents.py:12-23):
    from src.advisory import authoring, campaign, classify_change
    from src.advisory import remediation as R
    from src.analyzers.run_all import run
    from src.change.requests import DEMO_REQUESTS
    from src.change.simulate import simulate_change

No `fastapi.testclient`, no `app.main`, no `src.db`, no `src.persist`, no `src.tools_registry`, no `src.request_ctx`. All 18 tests target the advisory/agent layer. Combined with the stated absence of .github/workflows, nothing at all exercises the HTTP surface or the database layer, ever.

**Fix.** Add `backend/tests/test_api.py` using `fastapi.testclient.TestClient` with a transaction-rolled-back Postgres fixture (or testcontainers). Smoke every endpoint for a 2xx, then assert the specific behaviours: classify with source+destination+service, change-decisions survive a recompute, limit=-1 returns 4xx not 5xx, a historical snapshot's finding detail resolves, persist is idempotent (run persist_engine_result twice, assert identical row counts and no orphans). Add a GitHub Actions workflow running pytest + a schema apply against a throwaway Postgres.

</details>

<details>
<summary><b>Conflict math ignores port ranges and rule order, and doesn't canonicalize source identities</b><br/><code>correctness-bug</code> &middot; <code>backend/src/change/staging.py:31</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** Three ways the "genuine engine math" gives the wrong answer on ordinary policy. (1) Range rules are extremely common in real exports; a staged rule landing inside an existing range reports "No conflicts with existing rules" and pushes a redundant grant. (2) Effective policy in a first-match firewall is order-dependent - the codebase has a whole shadowing analyzer that exists because of this - yet detect_conflicts declares any deny a blocking `contradiction` regardless of position, producing false blocks (and it would equally miss a deny that genuinely does precede). (3) Not canonicalizing the source directly contradicts the product's headline identity-resolution claim: the same host under two tools' names is treated as two different sources, so a cross-tool duplicate is invisible - in a product whose USP is that it unifies exactly those names.

**Failure scenario.** Client's AlgoSec export has `tcp/8000-8100` to an app tier. Operator stages `tcp/8050` from the same subnet. The push reports "Detect conflicts: ok - No conflicts with existing rules" and writes a redundant rule. Separately, a staged allow is blocked as contradicting a deny that sits below it in the rulebase and would never have matched.

**Evidence.** staging.py:31-38 - `port_end` is never consulted:
    def _svc_match(proto_a, port_a, proto_b, port_b) -> bool:
        if proto_a != "any" and proto_b != "any" and proto_a != proto_b: return False
        if port_a is None or port_b is None: return True
        return port_a == port_b
and staging.py:60-61 throws the range away at the call site: `svc = parse_service(...); proto, port = svc.protocol, svc.port`.

staging.py:59 vs 70 - destination is canonicalized, source is not:
    dst = _canon(ctx, payload.get("destination", ""))
    ...
    same_src = (r.source == src) or (src_is_cidr and is_cidr(r.source) and _overlap(src, r.source))

staging.py:45-89 never reads `r.order` anywhere.

Reproduced against the real functions:
    port-range overlap (existing tcp/8000-8100, staged tcp/8050) -> []          # no conflict found
    order-ignoring deny (deny at order=99, allow inserted before it) -> ['contradiction']
    aliased source ('appsrv-07' in records, 'app-server-07' staged) -> []       # missed

**Fix.** In `_svc_match`, compare `[port, port_end or port]` intervals for overlap instead of equality, and carry `svc.port_end` from the call site. Apply `_canon` to the source as well as the destination. For denies, compare `r.order` against the proposed rule's insertion order and only flag a contradiction when the deny would actually match first; report a non-blocking `shadowed_by` warning otherwise. Add unit tests for each of the three cases (there are currently none for staging.py at all).

**Verifier note.** The order sub-claim needs restating; the auditor's repro construction isn't reachable. A staged add_allow always carries the payload's order (999 in every path that produces one), so 'an allow inserted before the deny' cannot occur through the app. The real order defect is a false positive from EXISTING rules: I built allow@order=5 and deny@order=99 for the same source/dest/service — the allow already shadows the deny, so a new duplicate allow contradicts nothing — and detect_conflicts still returned ['duplicate','contradiction'], and 'contradiction' is in the unresolved set (staging.py:98), so build_push_plan blocks the push with status 'conflict'. Net effect is a spurious block, not a spurious approval. Severity stays high on the strength of (1) and (2).

</details>

<details>
<summary><b>Staging "resolves" conflicts in prose only - the duplicate it says it skipped is applied anyway</b><br/><code>claim-overreach</code> &middot; <code>backend/src/change/staging.py:72</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** FEATURES.md:68-70 claims the push "detects and **resolves real conflicts in real time**". It detects them and then narrates a resolution it never performs. The redundant rule is added despite the UI showing a green tick next to "Skip: no-op", and the "Merge into the broader rule" resolution merges nothing. This is exactly the kind of thing a security-savvy reviewer will probe, and the divergence between the animated story and the actual state change is indefensible.

**Failure scenario.** Operator stages a change that duplicates an existing allow. The push animation says "duplicate detected -> Skip: no-op -> Change written". They recompute and find the rule count went up by one and a new cidr_overlap finding appeared, contradicting what the screen just told them.

**Evidence.** staging.py:71-76 emits resolutions that promise an action:
    conflicts.append({"kind": "duplicate", ..., "resolution": "Skip: this flow is already permitted (no-op)."})
    conflicts.append({"kind": "overlap", ..., "resolution": f"Merge: fold into the broader rule {r.raw_ref} instead of adding a redundant one."})
staging.py:109-112 marks them `status: "ok"` (resolved), and 122-126 then unconditionally:
    steps.append({"key": "apply", ..., "detail": f"Change written to the {tool} data source."})
    final = "pushed"

But nothing consumes `resolution`. apply.py:67-72:
    if item.get("kind") == "add_allow":
        rec = _added_record(payload)
        if rec is not None:
            out = out + [rec]

Reproduced - build_push_plan on an exact duplicate returns:
    warn | Detect conflicts (1) | duplicate: an identical allow already exists (AFA-DUP)
    ok   | Resolve duplicate    | Skip: this flow is already permitted (no-op).
    ok   | Apply change         | Change written to the algosec data source.
  status -> pushed
then apply_overlay on the same payload:
    records after "skip: no-op" push -> 2 ['AFA-DUP', 'CR-1']

**Fix.** Make the resolution executable rather than descriptive: give each conflict an `action` field (`skip` / `merge` / `block`) and have apply_overlay honour it - a `skip` must not append the record, and the push step for it must read "no change written (already permitted)". Persist the chosen action on the staged row so the overlay and the animation read the same source of truth.

</details>

<details>
<summary><b>The Change Gate discards the destination's tags, so it can auto-approve SQL access to a PCI database</b><br/><code>correctness-bug</code> &middot; <code>backend/app/main.py:594</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** classify_change.py:156 `_clean()` is the whole Layer-3 override - it is the ONLY thing preventing the model from auto-approving. With dest_tags stripped, the delta is clean, `_clean()` returns True, the override never fires, and a model saying `auto_approve` is honoured. An analyst opening tcp/1433 from an entire /24 to a PCI + customer-data database gets AUTO-APPROVE with all four green criteria including "Opens no new path to a sensitive asset". The engine already knows the tags (they are on the asset and on the graph node used two lines earlier for the zone) - they are simply thrown away.

**Failure scenario.** Security-savvy client asks "what if someone requests SQL from the branch office subnet to your PCI database?" -> gate returns AUTO-APPROVE, four green ticks, confidence 90%. The product's entire thesis ("auto-approves only inside an already-safe envelope") is disproved live.

**Evidence.** main.py:591-594 builds the proposed record for a custom change with the destination's sensitivity hardcoded away:
    proposed=PolicyRecord(..., destination=body.destination, destination_kind=...,
                          dest_tags=[], service=label, port=port, protocol=proto, action="allow", order=999)
intake.py:39 does the same: `dest_tags=[],`
requests.py:19,32 hardcode `dest_tags=["prod"]` rather than the asset's real tags.

simulate.py:55-59 then feeds those empty tags straight into the guardrail math:
    op_reasons = _overpermissive_reasons(proposed, E, P)
    sc = score_over_permissive(..., dest_tags=proposed.dest_tags, ...)
and over_permissive.py:23 computes `sensitive = bool(set(rec.dest_tags) & SENSITIVE_TAGS)` - always False.

Reproduced on the seeded engine (db-prod-01 has tags ['customer-data','pci','prod']), proposing 10.20.5.0/24 -> db-prod-01 tcp/1433:
  dest_tags=[]   (what the API actually sends):
    forced_escalate = False []
    new_over_permissive = []
    boundaries = []  new_paths = 0
    CLEAN (model may auto-approve) -> True
  dest_tags=['customer-data','pci','prod'] (the truth):
    new_over_permissive = ['regulated destination reachable from more than a single host']
    CLEAN -> False

**Fix.** Resolve the destination through alias_map to the canonical Asset and populate `dest_tags` from `asset.tags` (and `dest_ip` from `asset.ip_set`) before constructing the PolicyRecord - in main.py:591, intake.py:35, and requests.py. Better: do it once inside `simulate_change`, which already has `assets`, so no caller can get it wrong. Add a regression test asserting a /24 -> PCI-asset data-port change is never clean.

**Verifier note.** Downgrade blocker -> high: the defect is latent, not live. It is currently masked by classify-custom-500 (the TypeError fires first), so the gate cannot be made to auto-approve PCI SQL access today — it just 500s. It becomes exactly the described blocker the moment finding #1 is fixed, so the two must be fixed together. Drop the requests.py:19,32 claim: ['prod'] matches app-server-07's actual tags.

</details>

<details>
<summary><b>No test, and no CI, covers simulate.py, staging.py, apply.py, or any endpoint in the change pipeline</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/tests/test_agents.py:1</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The single most reproducible defect in this dimension - a hard TypeError on the flagship /api/change/classify custom path - has survived since the initial commit because nothing calls the endpoint. Every one of the conflict-math gaps above was found by running staging.py's functions directly for the first time. Without endpoint tests the change pipeline's correctness rests entirely on someone clicking through the two hardcoded demo requests.

**Failure scenario.** Any refactor of parse_service, PolicyRecord, or the staged payload shape breaks the pipeline silently; the frontend's `catch { /* ignore */ }` hides it until a demo.

**Evidence.** test_agents.py is the only test file (16 tests). It imports `simulate_change` but only ever calls it as an input fixture for classify tests (`_delta`, line 168-170) - there is not one assertion about the delta's own math. There are zero tests importing `src.change.staging` or `src.change.apply`, and zero tests exercising any FastAPI endpoint (no TestClient anywhere). `.github/workflows` does not exist.

The classify tests also propagate the dest_tags bug into the fixture - test_agents.py:229 constructs the "unsafe" case with `dest_tags=[]` and passes only because the internet source trips the path diff, so the test suite actively normalizes the defect.

**Fix.** Add a TestClient-based test module covering: classify with a custom body, classify with a /24 -> PCI-tagged asset (asserting escalate), submit -> stage -> push happy path, push of a rejected request (expect 409), and a viewer-role attempt at each mutating endpoint (expect 403). Add pure-function tests for detect_conflicts (port range, order-dependent deny, aliased source) and apply_overlay (duplicate skip, malformed payload, stale ref). Wire a GitHub Actions workflow running pytest on push.

**Verifier note.** Raise medium -> high, because the gap is worse than reported. test_classify_engine_override_blocks_unsafe_approval (test_agents.py:219-241) documents itself as testing 'Layer 3 — engine override', but I computed its delta on the real engine: source 0.0.0.0/0 to db-prod-01 on tcp/3389 gives forced_escalate=True with forced_reasons ['admin/lateral-movement port exposed to the internet', 'creates new internet->internal exposure'], so classify_change returns at Layer 1 (classify_change.py:170-179) and the stubbed model is never consulted. The test passes for the wrong reason (Layer 1 also sets decided_by='engine_fallback'), and Layer 3 — the override that the docs headline as 'the model can only approve inside an already-safe envelope' — has ZERO coverage. Minor correction the other way: the suite does contain two assertions on the delta itself (`delta['forced_escalate'] is True/False` at lines 178 and 190), so 'not one assertion about the delta's own math' slightly overstates it.

</details>

<details>
<summary><b>"Ask your network" is only agentic on Ollama — on OpenAI/Anthropic it degrades to a prose summarizer with no reachability access</b><br/><code>claim-overreach</code> &middot; <code>backend/src/agent/assistant.py:89</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** This bites precisely when the auto-router falls back to a hosted provider (see local-first finding) — i.e. exactly when Ollama is down mid-demo. The system prompt still says "never compute reachability, subnet math, or paths yourself" while giving the model no tools to ask with, so it will either refuse or invent a path. The tool-trace panel — the credibility artifact — shows a single fake `risk_findings` entry.

**Failure scenario.** Ollama down, OPENAI_API_KEY set. DEMO.md §5: ask "Can the internet reach db-prod-01, and through which path and tools?" The model sees only finding titles, one of which is "Cross-tool path: Internet can reach db-prod-01 through 3 tools", and confabulates the hop list. Trace shows one call. Presenter's line "the agent calls deterministic tools" is visibly untrue.

**Evidence.** assistant.py:89-95:
```
def ask(ctx, question: str) -> dict:
    try:
        if settings.active_provider() == "ollama":
            return _ollama_loop(ctx, question)
    except Exception:
        pass
    return _grounded_fallback(ctx, question)
```
`_grounded_fallback` (assistant.py:76-86) passes only `T.risk_findings(ctx)` — a flat list of `{id,type,title,severity,band,forced_critical}`. No `resolve`, no `reachable`, no `find_paths`, no `effective_policy`, no graph.

This contradicts AGENTS.md:188 ("**Provider-agnostic.** Local Ollama, OpenAI, or Anthropic — same contracts, same guardrails"), README.md:22 ("agentic (tool-calling over the engine)"), and HOW-IT-WORKS.md:683 ("Can only see what the six tools return").

Also: AGENTS.md:48-50 claims "Model calls are bounded ... so a cold local model degrades to the fallback rather than hanging the HTTP request." `_ollama_loop` (assistant.py:49) uses `timeout=settings.OLLAMA_TIMEOUT`, which defaults to **600 seconds** (settings.py:35), across up to 5 iterations.

**Fix.** Implement the tool loop for OpenAI (its chat.completions already accepts `T.SCHEMAS` unchanged) and for Anthropic (`tools=` block), or route `ask` to the same provider-portable JSON ReAct loop already written in classify_change.investigate (classify_change.py:96-135), which is explicitly provider-portable. Until then, reword to "tool-calling assistant (local Ollama)". Separately, pass an explicit short timeout to `_ollama_loop`.

</details>

<details>
<summary><b>"Bring your own source without writing a normalizer" — a new tool is silently relabeled `algosec`, and an authored profile can never enter the pipeline</b><br/><code>claim-overreach</code> &middot; <code>backend/src/normalizers/profile.py:90</code> &middot; CONFIRMED &middot; effort L</summary>

**Why it matters.** Three downstream systems key off `source_tool`: cross-tool path detection (`_distinct_tools`, reachability.py:32-36), shadowing grouping (shadowing.py:46 `by_tool.setdefault(rec.source_tool,...)`), and edge provenance (build.py:57). A Palo Alto export ingested via a profile would be counted as AlgoSec rules, so (a) a genuine Palo-Alto↔Guardicore cross-tool path would not register as cross-tool, and (b) its rules would be shadow-compared against AlgoSec's rule order, producing fabricated shadowing findings. The relabel is also completely silent — no warning, no validation error.

**Failure scenario.** Client pastes a Cisco FTD export. Model authors a profile with `tool: "cisco_ftd"`. `validate_profile` reports valid. Every record is stamped `source_tool="algosec"`. If it were ever ingested, its rules interleave with AlgoSec's `order` values and the shadowing analyzer emits bogus "dead allow" findings across two unrelated devices. Today it is not ingested at all, so the client's next question — "great, now show me my data in the map" — has no answer.

**Evidence.** profile.py:90-92:
```
known = ("algosec", "guardicore", "wiz", "sd_wan", "sd_lan")
res.records.append(PolicyRecord(
    id=ref, source_tool=tool if tool in known else "algosec",
```
Because models.py:17 hard-codes `SourceTool = Literal["algosec","guardicore","wiz","sd_wan","sd_lan"]`, a genuinely new vendor cannot be represented at all.

DEMO.md:36 says the demo pastes "an SD-WAN export" — i.e. the only "unknown" tool the demo shows is one of the two names pre-added to the Literal.

And there is no ingest path: normalizers/__init__.py:19-24 hard-codes
```
out.extend(algosec.normalize(_load("algosec_export.json")))
out.extend(guardicore.normalize(_load("guardicore_export.json")))
out.extend(wiz.normalize(_load("wiz_export.json")))
```
The only connector endpoint is main.py:1008 `POST /api/connectors/propose`. There is no approve/register endpoint, no connectors table, and `apply_profile` is called from exactly one place: authoring.validate_profile (authoring.py:47). authoring.py:118 returns the text "Review the rows, then approve to register this connector" — aspirational; `"approved": False` is hard-coded and nothing consumes it.

**Fix.** Short term: reword the claim to "design-time connector authoring assist — the model drafts a profile and the engine proves it normalizes your sample; wiring an approved profile into a snapshot is the next step." Real fix: change `SourceTool` to `str` with a registered-connectors table, persist approved profiles, and have `normalize_all()` iterate registered profiles alongside the three built-in adapters. Never silently coerce an unknown tool id — raise.

**Verifier note.** Severity blocker -> high. It does not break the scripted demo (SD-WAN is pre-added to the Literal and the demo never ingests); it fails on the first client follow-up question.

</details>

<details>
<summary><b>"Auto-approves only inside an already-safe envelope" — custom and intake changes carry empty dest_tags, disabling the sensitive-destination guardrail</b><br/><code>correctness-bug</code> &middot; <code>backend/app/main.py:594</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** `_clean(delta)` (classify_change.py:156-158) is the entire Layer-3 override. If `new_over_permissive` is empty and no *new* internet path is opened, the delta is "clean" and the model is free to auto_approve — with the engine agreeing. The guardrail that is supposed to be un-overridable is simply not evaluated.

**Failure scenario.** Custom change: source `10.0.0.0/8`, destination `db-prod-01` (pci, customer-data), service `tcp/5432`. `_internet_sensitive_paths` finds no *new* internet path (10.0.0.0/8 is an abstract node and `_valid_traversal` forbids pivoting through it). src_zone and dst_zone are both `internal`, so no boundary crossing. `dest_tags=[]` so no over-permissive reason. delta is clean, `forced_escalate=False`, Layer 3 does not fire — the gate can auto-approve "the entire corporate /8 may reach the PCI database on PostgreSQL". (Today this specific request 500s first at main.py:584; fixing that crash without fixing this exposes the hole.)

**Evidence.** main.py:591-594 builds the proposed record for a custom change with `dest_tags=[]`. intake.py:38 does the same: `dest_tags=[],`.

Everything downstream that decides "is this a regulated destination" reads `proposed.dest_tags`:
- simulate.py:55 `op_reasons = _overpermissive_reasons(proposed, E, P)`
- over_permissive.py:23 `sensitive = bool(set(rec.dest_tags) & SENSITIVE_TAGS)`
- severity.py:105 (same, inside score_over_permissive)

Contrast agent/tools.py:70, which does it correctly:
```
dest_tags = ctx.graph.nodes[cd]["tags"] if cd in ctx.graph else []
```
So the agent's `simulate_change` tool sees real tags; the actual Change Gate does not.

With `dest_tags=[]`, `_reasons` predicates 2 and 3 (over_permissive.py:27-30) never fire on sensitivity, and `score_over_permissive`'s third guardrail ("regulated/crown-jewel asset reachable from the internet", severity.py:110-111) can never trigger.

**Fix.** In both main.py:591 and intake.py:35, resolve dest tags from the engine before constructing the record: `d = e.alias_map.get(dest, dest); dest_tags = e.graph.nodes[d]["tags"] if d in e.graph else []`. Add a regression test asserting that `10.0.0.0/8 -> <pci asset> tcp/5432` escalates.

**Verifier note.** The stated failure scenario is wrong. For source 10.0.0.0/8 -> db-prod-01 on tcp/5432: E=0.9 and P=0.9 (5432 is in DATA_STORE_PORTS), so over_permissive.py:31-32 predicate 4 ('admin/data port open to a broad source range', thresholds P>=0.85 / E>=0.5 from OVERPERMISSIVE_CONFIG) DOES fire even with dest_tags=[]. `new_over_permissive` is therefore non-empty, `_clean()` (classify_change.py:156-158) is False, and Layer 3 at classify_change.py:212-216 force-escalates. Auto-approve is impossible for that request. The real exploitable window is a general-app port, e.g. 10.0.0.0/8 -> db-prod-01 tcp/443: P=0.4 kills predicate 4, dest_tags=[] kills predicate 3, both zones resolve to `internal` (no ZONE_TAGS entry for pci/customer-data/prod, config.py:164-167) so B=1.0, and no new internet path appears -- the delta is fully clean and auto-approve is available. With real tags, predicate 3 ('regulated destination reachable from more than a single host', E>=0.3) would have fired. Also note internet-sourced requests are still caught independently by simulate.py:72-73, so the hole is narrower than 'the sensitive-destination guardrail is disabled' implies.

</details>

<details>
<summary><b>"Merging uses only signals that cannot be wrong" — shared-IP union-find has no tenancy/VRF/scope, and merges transitively</b><br/><code>robustness-gap</code> &middot; <code>backend/src/identity.py:57</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** Deterministic is not the same as correct. Overlapping RFC1918 space across business units, tenants, or cloud accounts is the normal case in any enterprise of the size that buys this. Because union-find is transitive, one duplicated 10.0.0.10 merges two unrelated hosts into one node, and every rule touching either becomes a grant on the merged node — inventing reachability that does not exist, and forcing it critical if either side carries a pci tag.

**Failure scenario.** Client's AlgoSec export has `db-dev-01 = 10.0.0.10` (dev VRF) and their Wiz export has `payments-db = 10.0.0.10` (prod account, tagged pci). identity.py unions them; canonical key is `db-dev-01` (lexicographically smaller under equal tool counts, identity.py:85). The merged asset now carries tags `[dev, pci, prod]`, D=0.9, and every dev-network allow into db-dev-01 becomes an over-permissive finding against regulated data. A confidence of 0.95 is stamped on it as an audit label (identity.py:128).

**Evidence.** identity.py:56-64:
```
ip_to_names: dict[str, set[str]] = defaultdict(set)
for e in entities:
    if e.ip: ip_to_names[e.ip].add(e.name)
for ip, ns in ip_to_names.items():
    ordered = sorted(ns)
    for other in ordered[1:]: union(ordered[0], other)
```
No filtering of RFC1918 collisions, no VRF/tenant/account scoping, no loopback/link-local exclusion, no cardinality cap. The `Asset` model *has* a `context` field for "vrf / segment / account / tenant" (models.py:114) but it is only populated *after* the merge (identity.py:101 `context=identifiers.get("env") or identifiers.get("cloud")`) and is never used as a merge key.

HOW-IT-WORKS.md:209 states: "A wrong merge does not produce a cosmetic error; it corrupts a fact about what can reach what. So merging uses only signals that cannot be wrong."

**Fix.** Require a scope match before an IP union: only union when both entities agree on a scope key (vrf/account/tenant/env) or when at least one side supplies a hard identifier (cloud instance id, MAC — both already in `AssetCorrelation.match_key`). Emit any unscoped IP collision as an `entity_suggest` candidate for human review instead of an automatic union, and reword the doc to "merges on hard signals within a declared scope."

</details>

<details>
<summary><b>"Data never leaves the host" is false on two independent code paths: Neon cloud Postgres, and silent hosted-LLM fallback</b><br/><code>claim-overreach</code> &middot; <code>backend/src/settings.py:111</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** This is the stated sales unlock ("a sales unlock for security-conscious clients"). A security-savvy client will ask exactly this question, and the honest answer is that the complete attack map is already in a third-party managed Postgres, and that the inference residency guarantee silently degrades. HOW-IT-WORKS.md:694-697 already contains the correct warning; README and DEMO.md contradict it.

**Failure scenario.** Presenter runs `tasks.py dev` with OPENAI_API_KEY in .env (README.md:71 explicitly suggests keys are optional-but-supported). Ollama OOMs or was never started. Banner may still show a provider, but every explain/classify/remediate call POSTs the finding signals (paths, IPs, PCI tags, rule refs) to api.openai.com. Presenter has just told the room the data never leaves the machine.

**Evidence.** README.md:35: "Running inference **locally on Ollama** means that data **never leaves the host**". DEMO.md:10 instructs the presenter to point at the header and say "the topology never leaves this machine."

But settings.py:109-117:
```
if ADVISORY_PROVIDER in ("ollama", "anthropic", "openai"): return ADVISORY_PROVIDER
if ollama_available(): return "ollama"
if has_openai(): return "openai"
if has_anthropic(): return "anthropic"
```
Default is `ADVISORY_PROVIDER=auto` (settings.py:29). `ollama_available()` is a cached 1.5s probe with a 30s TTL (settings.py:60-98). If Ollama is down or has no model pulled, every subsequent call silently routes the full topology to OpenAI/Anthropic with no user action and no confirmation.

Separately, the system of record is a hosted cloud DB: README.md:72 `DATABASE_URL="postgresql://...neon.tech/neondb?sslmode=require"`. persist.py writes canonical_rules, graph_nodes, graph_edges, assets, findings (incl. full `signals` with paths and IPs) to it; persist.py:349-364 writes `delta_summary` (which contains the investigation trace); metrics.py:34-51 writes provider/model/error strings per call.

**Fix.** Two changes. (1) Make `auto` refuse to silently escalate: if Ollama was reachable at process start and later fails, return an error rather than routing to a hosted provider; require an explicit `ADVISORY_PROVIDER=openai` opt-in. (2) Reword README.md:35 to "inference runs locally by default; the snapshot database is Postgres and can be self-hosted — the topology never leaves your infrastructure when configured that way", and drop the "never leaves the host" absolute from DEMO.md:10.

**Verifier note.** Drop the Neon/cloud-Postgres half -- README.md:35 scopes the claim to inference and README.md:47 discloses Neon as the system of record on the same page. The failure scenario's 'Banner may still show a provider' is also wrong in the other direction: I grepped frontend/components and frontend/app case-insensitively for 'data stays|stays local|ollama' and the DEMO.md:10 header ('Local · Ollama · Data stays local') DOES NOT EXIST in the UI at all -- only MetricsAdmin.tsx:37, ToolsAdmin.tsx:54 and RiskTodo.tsx:176 mention Ollama. So the presenter has no on-screen residency indicator to point at, true or false. Add the stronger evidence: client.py:171-180 `embed()` falls back to OpenAI even under an explicit ADVISORY_PROVIDER=ollama. Severity blocker -> high.

</details>

<details>
<summary><b>"The dashboard reads the precomputed snapshot from Postgres" is false — the API computes a different snapshot id than precompute writes</b><br/><code>correctness-bug</code> &middot; <code>backend/app/main.py:80</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** README.md:88 claims "the dashboard reads the precomputed snapshot from Postgres; only the AI calls run live" and DEMO.md:3 repeats it. In fact the AI cache is never hit: `_ranked_cached` (main.py:960-969) finds no rows and calls `rank_mod.rank()` live; `/api/findings` returns `explanation=None` and each card triggers a live explain. On a cold local model that is the difference between an instant demo and a multi-second-per-card stall — the exact thing precompute exists to prevent. It also leaves two duplicate snapshots in the DB.

**Failure scenario.** `python tasks.py demo` prints "explanations cached: 17". Start the backend, open Risk To-Do. Zero cached explanations are served; every finding fires a live LLM call. If Ollama is cold, the first card takes 30-120s.

**Evidence.** Snapshot ids are `snapshot_id(label, fingerprint)` (ids.py:30-32) — the **label is part of the hash**.

- `run_all.run()` default: `def run(label: str = "seed-demo", ...)` (run_all.py:64)
- `precompute.py:22`: `def main(label: str = "seed-demo")`
- `precompute_ai.py:28`: `r = run()`  -> label `"seed-demo"`
- but `main.py:80`: `_ACTIVE_SCENARIO = "demo"` and main.py:110: `_ENGINE = run(label=_ACTIVE_SCENARIO, ...)`

So `tasks.py demo` (tasks.py:121-122 = precompute + precompute-ai) persists ranked_actions, change_decisions and explanations against `snap_<hash("seed-demo",fp)>`, while every API read goes through `view_sid()` -> `engine().snapshot_id` = `snap_<hash("demo",fp)>`. Two different rows.

**Fix.** One-line fix: set `_ACTIVE_SCENARIO = settings.DEFAULT_SNAPSHOT_LABEL` (= "seed-demo", settings.py:45) or change precompute/precompute_ai to `run(label="demo")`. Then add a startup assertion that logs a warning when `engine().snapshot_id` has no persisted ranked_actions row.

**Verifier note.** The failure scenario's consequence is wrong. main.py:352-362 does NOT block on a cold model: it returns `explain_mod._fallback(f)` immediately with `pending: true` and computes the LLM version on a daemon thread (main.py:324-335). So the first card renders instantly with the deterministic text -- it never 'takes 30-120s'. Two other effects should be noted as partial mitigations: /api/actions self-heals (main.py:483-485 recomputes and re-persists ranked actions under the correct sid on first request), and /api/change-decisions (main.py:613-625) has no snapshot filter so the precomputed decisions do still appear. The net damage is that the whole precompute-ai step is voided and every explanation is a live model call, which falsifies README.md:88 and DEMO.md:3's 'reads the precomputed snapshot from Postgres'.

</details>

<details>
<summary><b>"The engine validates it by actually normalizing the sample" — the validator passes a profile whose field names are all wrong</b><br/><code>correctness-bug</code> &middot; <code>backend/src/normalizers/profile.py:47</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** The whole defensibility of capability #7 rests on "the engine, not the model, certified it" (authoring.py:12-13). If the certification can return green on a profile that maps every source to the literal string "None", the certification is theatre. In a client demo this shows as a green "validated" badge over a sample-rows table full of `None -> None`.

**Failure scenario.** Sample export uses `{"src_addr": ..., "dst_addr": ...}`. Model proposes `fields: {src: "source", dst: "destination", service: "svc"}` (plausible hallucination). apply_profile emits N records with source="None", destination="None", service="None" (parse_service on a bare unknown token -> label "None", common.py:150-152). validate_profile returns `{"valid": true, "records": N, "unmapped": []}`. UI shows green.

**Evidence.** profile.py:46-47:
```
def _resolve(token: str, objects: dict, profile: SourceProfile, tool: str):
    token = str(token)
```
When `fm.src` names a field that does not exist, `rule.get(fm.src)` returns `None`, and `str(None)` -> the truthy string `"None"`.

authoring.py:50-54 then checks:
```
unmapped = sorted({field for r in nr.records for field, val in
    (("source", r.source), ("destination", r.destination), ("service", r.service)) if not val})
ok = bool(nr.records) and not unmapped
```
`"None"` is truthy, so nothing is reported unmapped and `valid=True`.

The test suite dodges this exactly: test_agents.py:325 uses `"src": "blank"` where the sample field is `""` (falsy) — the one wrong-mapping case that *is* caught. A genuinely wrong field name is never tested.

**Fix.** In `_resolve`, return early with an explicit sentinel when `token is None` (e.g. `return "", "identity", [], None`) and have `apply_profile` skip/flag those rows. In `validate_profile`, additionally assert that every mapped field name actually exists as a key in at least one raw rule dict, and that `service` parsed to a known protocol or app.

**Verifier note.** One factual detail is wrong: the service does NOT become 'None'. A missing service field means `rule.get(fm.service)` is None, so `parse_service(service=None, app=None)` skips the `if service:` branch entirely and falls to common.py:154-156, returning label `'tcp'`. The finding's citation of common.py:150-152 (the bare-token branch) is the wrong code path. This does not change the conclusion -- 'tcp' is truthy too, so `unmapped` is still empty and `valid` is still True.

</details>

<details>
<summary><b>`tasks.py verify` — sold as "prove the engine meets every acceptance criterion" — asserts hard-coded demo output and tests determinism in-process</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/scripts/verify_engine.py:48</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The user's stated concern is whether the *core engine* is production-ready. The engine — ~2,000 lines of subnet arithmetic, graph traversal and scoring — has no unit tests at all. `verify` is 18 assertions pinned to one authored fixture; the moment a client swaps in their export, it fails by construction, so it cannot be used as a regression gate on real data. And the determinism check cannot detect the failure modes determinism claims guard against (dict/set iteration order across processes with hash randomization, filesystem order, DB-derived overlay state).

**Failure scenario.** A refactor of `exposure_score` bands or `_covers` ships silently: `verify` still passes because the demo's five planted problems happen to be insensitive to the change, and no test exercises boundary cases (/31 vs /32, non-strict networks, IPv6, an identity source with a slash in the name).

**Evidence.** verify_engine.py:46-52:
```
expected = ["0.0.0.0/0", "lb-public-01", "app-server-07", "internal-app", "db-prod-01"]
check("P5 path is the 5-hop chain", path == expected)
...
check("exactly one cross-tool path", sum(1 for f in fs if f.type == "cross_tool_path") == 1)
```
and verify_engine.py:24, 60-62:
```
r1, r2 = run(), run()
...
check("determinism (byte-identical re-run)",
      [(f.id, f.severity, f.severity_band) for f in r1.findings] == [...r2...])
```
Both `run()` calls are in the same process, reading the same files, with no DB and no restart. There are zero assertions on `exposure_score`, `port_score`, `dest_score`, `severity_from_vector`, `boundary_multiplier`, `_covers`, `_grant_matches`, or `_valid_traversal`. The only pytest file, tests/test_agents.py (355 lines), tests the advisory agents — not the engine.

README.md:82-83: "# Optional: prove the engine meets every acceptance criterion".

**Fix.** Add `backend/tests/test_engine.py` with table-driven unit tests: every EXPOSURE_BANDS boundary, every port class, the two worked examples from ENGINE.md §5.5 and HOW-IT-WORKS.md §6.6 as exact expected integers, `_covers`/`_service_overlaps` truth tables, `_valid_traversal` on a synthetic graph. Add a cross-process determinism test (`subprocess` twice with different PYTHONHASHSEED, compare finding ids). Keep verify_engine.py but rename it "demo acceptance check" in README.

**Verifier note.** Severity medium -> high. This is not polish; it is the root cause that let at least three of the other confirmed defects in this set ship undetected.

</details>

<details>
<summary><b>The finding explanation polls for 64.5 s but the server is allowed 180 s — a cold local model always leaves a permanent 'Refining…' spinner and the answer lands in the DB unseen</b><br/><code>robustness-gap</code> &middot; <code>frontend/components/RiskTodo.tsx:205</code> &middot; PLAUSIBLE &middot; effort S</summary>

**Why it matters.** The two clocks were never reconciled. A cold 30B local model — which settings.py:32 makes the default, and whose slowness is the stated reason the whole background-thread design exists (main.py:325-327) — routinely exceeds 64 s on first token. So the flagship 'AI explains this finding' interaction has a deterministic failure mode on the intended configuration: an infinite spinner, no error, no retry offered (the retry button only renders on `explain.error`, RiskTodo.tsx:281), and a perfectly good explanation sitting in Postgres that only appears if the user happens to collapse and re-open the card.

**Failure scenario.** Cold-start demo. Operator clicks the top critical finding. Deterministic text appears instantly with 'Refining with the local model…'. At t=64.5 s the client stops asking. At t=~90 s the server caches a good explanation. The spinner is still turning at t=10 min. The operator either reloads (losing the accordion state) or narrates over a spinner. With Ollama down entirely the same 15 polls each re-spawn a doomed background thread (`if fid not in _explaining`, main.py:356 — the set is cleared in `finally` on every fast failure), so one click fires up to 15 duplicate LLM jobs.

**Evidence.** Client: `if (r.pending && attempt < 14) { const wait = Math.min(800 * 1.5 ** attempt, 6000); pollRef.current = setTimeout(() => fetchExplain(attempt + 1), wait); }` (RiskTodo.tsx:205-211). The 14 waits are 800, 1200, 1800, 2700, 4050 then 6000×9 = 64,550 ms total. At attempt 14 polling simply stops — nothing sets `pending` false and there is no timeout branch, so the render at RiskTodo.tsx:274-279 (`{explain?.pending && (<span className="...animate-spin"/> Refining with {providerLabel(explain.provider)}…)}`) stays on screen for the life of the component. Server: `_EXPLAIN_TIMEOUT = 180.0` (main.py:320) is passed to `explain_mod.explain(f, timeout=_EXPLAIN_TIMEOUT)` in the background thread (main.py:329) — 2.8× the client's budget. On success the thread writes `cache_explanation(...)` (main.py:332) and returns; the UI is no longer asking.

**Fix.** Extend the client budget past _EXPLAIN_TIMEOUT (e.g. attempt < 40 with a 6 s cap ≈ 200 s), and on exhaustion set pending=false and surface 'the model is still working — reopen to check' with the retry button. Better: have the endpoint return a `retry_after`/`deadline` derived from _EXPLAIN_TIMEOUT so the two clocks cannot drift again.

</details>

<details>
<summary><b>'Local model available' means ANY model is pulled, not the configured one — the README's own setup instructions produce an app whose entire AI layer is silently dead</b><br/><code>robustness-gap</code> &middot; <code>backend/src/settings.py:84</code> &middot; PLAUSIBLE &middot; effort S</summary>

**Why it matters.** This is the actual first-run experience for a new developer, and it is indistinguishable from success. The probe reports reachable, active_provider says 'ollama', provider_status says data_residency 'local' — and every one of the nine AI capabilities returns its deterministic fallback. Combined with the previous finding (no status UI) and the next one (the explain spinner never resolves), a correctly-installed-but-mistagged Ollama produces an app that looks like it is thinking and never is. There is no log line anywhere in the backend to tell you otherwise; the only trace is an ai_metrics row with ok=false.

**Failure scenario.** Developer follows README.md:68, runs `ollama pull qwen3-coder` and `ollama pull nomic-embed-text` (gemma4 fails, they move on). `/api/tags` lists two models -> ok=True. Every `complete()` posts model='qwen3-coder:30b' -> HTTP 404 -> ok=False. Risk To-Do shows deterministic fallback text labelled 'via engine_fallback', ranked_by is engine_fallback but the report reports 'llm' (per the known provenance bug), the assistant answers from `_grounded_fallback`, and the Change Gate classifier never gets a model opinion. Nothing anywhere says 'the configured model is not installed'.

**Evidence.** settings.ollama_probe(): `models = sorted(m["name"] for m in r.json().get("models", []))` then `ok = bool(models)` (settings.py:83-84). ollama_available() docstring: 'True when a local Ollama server is reachable AND serving ≥1 model' (settings.py:93). active_provider() -> `if ollama_available(): return "ollama"` (settings.py:111). client.model_for() then returns the *configured tag* regardless: `return settings.OLLAMA_JUDGE_MODEL if role == "judge" else settings.OLLAMA_PROSE_MODEL` (client.py:36), default `qwen3-coder:30b` (settings.py:32-33). _ollama_complete does `r.raise_for_status()` (client.py:56) -> a 404 'model not found' becomes an exception -> `except Exception ... ok=False` (client.py:142-143) -> every caller takes its deterministic fallback. README.md:68 tells the developer: 'Ollama running with qwen3-coder + gemma4 + nomic-embed-text' — `ollama pull qwen3-coder` produces the tag `qwen3-coder:latest`, not `qwen3-coder:30b`, and `gemma4:26b` (README.md:37) is not a model that can be pulled at all.

**Fix.** In ollama_probe, keep the model list but make ok = the configured judge/prose/embed tags are actually present (allow bare-name matching against `name:latest`). Return the per-role availability in provider_status (`judge_model_available`, `prose_model_available`) so the status chip can say 'Ollama up, qwen3-coder:30b NOT pulled'. Fix README.md:37/68 to name the exact tags settings.py defaults to.

</details>

<details>
<summary><b>provider_status() — the only signal that would reveal the local-first→hosted degradation — is computed, typed in the frontend, and rendered nowhere</b><br/><code>prod-readiness-gap</code> &middot; <code>frontend/lib/types.ts:68</code> &middot; PLAUSIBLE &middot; effort S</summary>

**Why it matters.** README/DEMO sell 'local-first, data never leaves the host', and settings.active_provider() (settings.py:109-117) will silently route to OpenAI/Anthropic the moment the Ollama probe fails under ADVISORY_PROVIDER=auto. The backend already computes the exact field that discloses this — `data_residency: 'hosted'` — and the UI throws it away. The residency guarantee is therefore unobservable by the operator by construction, which turns a disclosable degradation into an undisclosed one. It is also the single cheapest fix in this audit: the data is already on the wire.

**Failure scenario.** Mid-demo Ollama crashes (or was never started). `ollama_probe()` fails, `active_provider()` returns 'openai', every explanation, ranking, classification and report narrative is now generated by a hosted model over a third party's network, and `/api/health` truthfully reports `data_residency: 'hosted'`. Nothing on any screen changes. The operator continues telling the client the topology never leaves the box.

**Evidence.** Backend: `provider_status()` (client.py:215-228) returns `{active_provider, judge_model, prose_model, ollama_reachable, ollama_models, data_residency: 'local' if active=='ollama' else 'hosted', anthropic_available, openai_available}`, surfaced at main.py:160 `return {"status": "ok", "db": db_ok, "snapshot_id": sid(), "ai": provider_status()}`. Frontend: types.ts:63-77 declares the full `Health.ai` shape; app/console/page.tsx:52 `api.health().then(setHealth)`; page.tsx:68 uses `health.snapshot_id` ONLY. `grep -rn 'active_provider|data_residency|ollama_reachable|ollama_models' frontend/` returns exactly one hit: the type declaration. No component reads `health.ai`.

**Fix.** Render a status chip in Topbar/Sidebar bound to `health.ai`: active provider, judge/prose model, and a explicit 'Local (Ollama)' vs 'Hosted — data leaves this host' badge with the ollama_models list on hover. Make the hosted state visually loud, not neutral.

</details>

<details>
<summary><b>PolicyRecord cannot express what the three tools actually export: multi-valued src/dst/service, deny precedence, disabled rules, direction, negation, real priority</b><br/><code>claim-overreach</code> &middot; <code>backend/src/models.py:34</code> &middot; CONFIRMED &middot; effort L</summary>

**Why it matters.** Two of these are actively dangerous rather than merely incomplete. (a) A rule flagged disabled/inactive in the export is ingested as a live allow — I verified `{'enabled': False, 'disabled': True}` produces `action='allow'` with no trace — so the tool reports exposure that does not exist and the change-simulator computes deltas against a fictional baseline. (b) The shadowing analyzer treats `order` as policy precedence, but for Guardicore `order` is just the position in the JSON array; reordering the export changes which rules are reported as shadowed. That is a fabricated fact presented with the same confidence as a computed one. Deny-precedence is honestly disclosed in ENGINE.md §10 but NOT in README.md or FEATURES.md, both of which claim the engine owns 'effective policy'.

**Failure scenario.** Guardicore export with `[{policy_id:'G1', priority:900}, {policy_id:'G2', priority:5}]` normalizes to `order=10` for G1 and `order=20` for G2 — the exact inverse of the real precedence. Any shadowing verdict derived from that ordering is wrong. A multi-source rule (`src: ['10.1.0.0/16','10.2.0.0/16']`) cannot be represented at all and crashes with `TypeError: unhashable type: 'list'`.

**Evidence.** models.py:34-53: `source: str` and `destination: str` are single scalars; `service: str` is one scalar; there is no `enabled`, no `direction`, no `negate_source`, no `interface/zone`, no `nat`, no `schedule`, no `user`. persist.py:105-106 hardcodes the DB columns the schema was clearly designed for: `"enabled": True, "schedule": None, "direction": None, "nat_original": None, "nat_translated": None` (schema.sql:110-115 defines all of them). guardicore.py:43 discards any real priority and synthesizes `order=(i + 1) * 10` from array position. graph/build.py:45-46 `if r.action != "allow": continue` — deny is never subtracted.

**Fix.** Short term (before any client demo): honour an `enabled`/`disabled` field and skip disabled rules (or carry `enabled` and filter in build_graph); read Guardicore's real priority when present and only fall back to index ordering with an explicit `order_source='synthesized'` marker that the shadowing analyzer surfaces in its signals. Medium term: make src/dst/service list-valued (fan out at normalize time, keep the parent ref) and implement first-match deny subtraction in build_graph. Update README.md/FEATURES.md to carry ENGINE.md §10's caveats.

**Verifier note.** One component is a documented, acknowledged simplification and should not be counted against the engine: ENGINE.md §10.1 explicitly states 'Deny precedence not implemented (graph/build.py) — effective policy = union of allow edges'. The undocumented parts (no multi-valued src/dst/service, no enabled/direction/negation, discarded-and-inverted Guardicore priority) are what carry this finding. Also narrow the priority claim: 'Any shadowing verdict derived from that ordering is wrong' is too broad — shadowing._covers (shadowing.py:36-37) only matches identity-source pairs when earlier.source == later.source exactly, so the order inversion changes verdicts only for same-source/same-dest/overlapping-service pairs within one tool.

</details>

<details>
<summary><b>A malformed CIDR is not an error — it becomes an identity node, so a typo'd broad rule scores as a single host and disappears from all subnet math</b><br/><code>correctness-bug</code> &middot; <code>backend/src/normalizers/common.py:57</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** For a security tool the failure direction is the worst one: bad input silently reduces reported risk. `10.0.0.0/33` and `300.1.1.1/24` both become invented assets in the asset inventory, with E=0.1, no tags, and no participation in cidr_overlap or shadowing. The operator sees a clean-looking asset list and a low score, with nothing indicating the input was garbage. It also means a bare host IP written in the src column (extremely common) becomes a dangling node never linked to the asset that actually owns that address.

**Failure scenario.** `{'rule_id':'R1','src':'10.0.0.0/33','dst':'10.0.0.0/8','service':'any','action':'allow'}` normalizes cleanly to `source='10.0.0.0/33', source_kind='identity'`; an asset named '10.0.0.0/33' appears in the inventory. `src='10.50.0.10'` (a bare host IP) -> `source_kind='identity'`, a node named '10.50.0.10' with no ip attribute, which the identity layer never merges with `db-prod-01` (10.50.0.10) because ip_to_names only sees entities that carry an `ip` field.

**Evidence.** common.py:57-65 — `def is_cidr(token): if "/" not in token: return False; try: ipaddress.ip_network(token, strict=False); return True; except ValueError: return False`. algosec.py:23-26: when `is_cidr` is False and the token is not in the object catalog, `return token, "identity", None, None, [], ObservedEntity(name=token, kind="identity", tool=TOOL)` — no error, no warning. severity.py:30-33 also swallows it: `except ValueError: return E_IDENTITY`.

**Fix.** Split the classification: if a token contains '/' but fails ip_network, raise/collect it as a malformed-input error rather than falling through to identity. Treat a bare literal IPv4/IPv6 address as a /32 or /128 CIDR (`ipaddress.ip_address` succeeds -> host CIDR) so it participates in subnet math and merges with the asset that owns it. Surface a per-snapshot `malformed_tokens` count in the UI.

</details>

<details>
<summary><b>Named network objects are marked concrete, so the flagship 'money shot' path pivots THROUGH a /16 subnet — the same network written as a raw CIDR cannot</b><br/><code>demo-grade</code> &middot; <code>backend/src/normalizers/algosec.py:31</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** This is the demo's hero finding and a security-savvy client will ask about it in the first five minutes. The engine's own stated rule — you cannot originate as a subnet — is bypassed purely by whether the export happens to name the network. It means reachability is a function of export notation, not of the network, which contradicts 'source X may reach destination Y means the same thing regardless of which console it came from' (FEATURES.md §1.1).

**Failure scenario.** In the shipped demo run: node `internal-app` has `kind=concrete, ip_set=['10.40.0.0/16']` while node `10.30.0.0/16` has `kind=abstract`. The single cross-tool_path finding is `0.0.0.0/0 -> lb-public-01 -> app-server-07 -> internal-app -> db-prod-01`, i.e. the critical path traverses a /16 SUBNET as if it were a host. `app-segment` (10.30.0.0/16) is likewise concrete. Rewrite ALGO-030's src as the literal `10.40.0.0/16` instead of the object name `internal-app` and the money-shot path disappears.

**Evidence.** algosec.py:20-22 sets `abstract=True` only for raw CIDR tokens; algosec.py:31 builds a network object's entity as `ObservedEntity(name=token, kind="identity", tool=TOOL, cidr=value, tags=tags)` with `abstract` left at its default False (common.py:32). identity.py:96 `abstract = all(e.abstract for e in ents)`. ENGINE.md §7 documents `_valid_traversal` as rejecting paths that 'pivot through an abstract node (a subnet/internet node may be an endpoint but never an intermediate hop)'.

**Fix.** Set `abstract=True` for object types that denote a range (`network`, `group`, `range`, `subnet`) in algosec.py:31 and profile.py:58-59, and add an `Asset.kind == 'network'` distinct from concrete/abstract so the UI can still show it. Then either accept the (correct) loss of the demo path, or implement the documented CIDR-membership expansion so the path is rebuilt from real host membership (10.30.7.7 ∈ 10.30.0.0/16) rather than from a subnet acting as a host.

</details>

<details>
<summary><b>The deterministic core has zero unit tests; the one 'verification' script hardcodes demo asset names and cannot detect order-dependence</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/scripts/verify_engine.py:60</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** Everything above would have been caught by a handful of property tests, and none of it can regress-guard today. The determinism check as written cannot detect the failures it exists to prevent: it does not vary input ordering, does not run in a second process, and does not cover ids/assets/alias_map — only finding ids. And because it asserts on specific demo asset names, editing the seed data breaks the 'verification' rather than validating the engine. With no CI (.github/workflows absent) nothing runs it automatically.

**Failure scenario.** Any of the findings in this report could be introduced or reintroduced with a green verify_engine.py. Concretely: I demonstrated that `run()` and `run(manual_merges=...)` produce different assets and findings under the SAME snapshot id — verify_engine.py reports ALL CHECKS PASSED on that build.

**Evidence.** backend/tests/test_agents.py (the only test file, 355 lines) contains no test for models.py, ids.py, identity.py, or any normalizer — every test targets the LLM agents with a mocked `complete`. verify_engine.py:60-62 is the entire determinism check: `check("determinism (byte-identical re-run)", [(f.id, f.severity, f.severity_band) for f in r1.findings] == [...r2.findings])` where `r1, r2 = run(), run()` (line 24) — two calls in the SAME process over the SAME file order. verify_engine.py:48 hardcodes `expected = ["0.0.0.0/0","lb-public-01","app-server-07","internal-app","db-prod-01"]`.

**Fix.** Add `backend/tests/test_core.py` with: (1) a shuffle-invariance property test over resolve_identities (I ran 200 shuffles — it passes today, lock it in); (2) a cross-process determinism test that shells out twice and compares snapshot_id + all finding ids; (3) a parse_service table test asserting the intended value for every encoding in this report; (4) a normalizer fuzz test over missing/renamed/list-valued fields asserting 'skipped with a reason', not a traceback; (5) an equivalence test asserting the same policy written as raw CIDRs and as named objects yields identical severity. Add a GitHub Actions workflow running pytest + verify_engine.py.

**Verifier note.** Raised from medium. Given the user's actual question — is the core engine production-ready — a ~6,500-LOC deterministic engine with zero unit tests on its math, no CI, and a 'verification' script that asserts hardcoded demo asset names is the direct cause of the correctness bugs above being shippable, not a separate polish item. It is also the cheapest thing on this list to fix.

</details>

<details>
<summary><b>Normalizers validate nothing — any real-world field name, action verb, or list-valued field kills the entire snapshot with an uncaught exception</b><br/><code>robustness-gap</code> &middot; <code>backend/src/normalizers/algosec.py:49</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** There is no partial-ingest story and no validation report. One malformed row out of 40,000 aborts the whole run, and the API returns a 500 with a raw `KeyError: 'action'`. This is also the first thing that happens when a client hands over a real export: it will not parse. FEATURES.md §1.1 claims the product 'ingests AlgoSec, Guardicore and Wiz' — it ingests three specific hand-authored JSON files.

**Failure scenario.** Measured, each aborts the whole normalize:
  missing `action`            -> KeyError: 'action'
  action='drop' / 'reject' / 'accept' / 'Allow' -> pydantic ValidationError (only lowercase allow/deny accepted — Check Point uses drop/reject, Palo uses deny/allow, Cisco uses permit/deny)
  missing `src` / `rule_id`   -> KeyError
  `src` is a LIST (a multi-source rule — the normal shape of a real firewall rule) -> TypeError: unhashable type: 'list'
  `src` is null               -> TypeError: argument of type 'NoneType' is not iterable
  a rule row that is not a dict -> TypeError: string indices must be integers
  `objects` is a list not a dict -> AttributeError: 'list' object has no attribute 'items'
  wiz exposure with kind='egress' -> KeyError: 'src'
  wiz `assets: null`          -> AttributeError: 'NoneType' object has no attribute 'items'
An address-group object whose `value` is a list is silently ACCEPTED and puts a Python list into ObservedEntity.cidr, which later hits `ips.add(e.cidr)` (identity.py:93) -> TypeError: unhashable type: 'list'.

**Evidence.** algosec.py:49-60 indexes required fields directly: `rule["src"]`, `rule["dst"]`, `rule["rule_id"]`, `action=rule["action"]` — no `.get`, no try/except, no per-row skip counter. `PolicyRecord.action` is `Literal["allow","deny"]` (models.py:48). guardicore.py:32 `pol["src_label"]`; wiz.py:38-41 `exp["kind"]` / `exp["src"]`; wiz.py:23 `assets.items()`. `normalizers/__init__.py:19-24` calls all three with no error handling.

**Fix.** Wrap each rule in try/except, accumulate `skipped: list[{index, reason}]` on NormalizeResult, and surface the count in the snapshot notes and the UI ('38,412 rules ingested, 6 skipped'). Normalize the action vocabulary through a lookup ({allow, permit, accept} -> allow; {deny, drop, reject, block} -> deny; case-insensitive) and raise on an unmapped verb rather than crashing in pydantic. Accept list-valued src/dst/service and fan them out into one PolicyRecord per (src, dst, service) tuple, preserving the parent rule ref.

**Verifier note.** Downgraded from blocker: no exposed input path currently reaches these functions. There is no upload/ingest endpoint in main.py (only a read-only GET /api/ingest inspector), normalize_all() reads three fixed files under backend/data/mock, and the one place user-pasted JSON enters (/api/connectors/propose) goes through profile.apply_profile, which uses .get() throughout and is wrapped in try/except at authoring.py:48. So this is a genuine must-fix-before-production gap that will hard-fail on the first real customer export, but it cannot be triggered from the shipped UI and will not break a demo.

</details>

<details>
<summary><b>The declarative SourceProfile engine silently turns DENY into ALLOW, relabels every custom tool as 'algosec', and its 'engine validates it' loop certifies a profile whose field names do not exist</b><br/><code>correctness-bug</code> &middot; <code>backend/src/normalizers/profile.py:92</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** README.md:29 and FEATURES.md §1.7 say 'the engine validates it by actually normalizing the sample'. The validator's only checks are 'did we get any rows' and 'are source/destination/service non-empty' — both of which pass on garbage. Turning a deny rule into an allow rule and attributing another vendor's rules to AlgoSec are not degraded behaviours, they are wrong facts presented as certified. The single test that covers 'unmapped fields' (tests/test_agents.py:322-338) only passes because the fixture contains a deliberate `"blank": ""` key for the test to point at; a field name that simply doesn't exist — the actual real-world failure — sails through.

**Failure scenario.** Sample `{'rules':[{'name':'a','from':'0.0.0.0/0','to':'db-prod','svc':'tcp/3389','act':'deny'}]}` with a profile whose fields are `src='source', dst='dest', action='action'` (all three wrong): apply_profile returns 1 record `source='None' destination='None' service='tcp/3389' action='allow' source_tool='algosec'`, and validate_profile returns `records=1, unmapped=[], valid=True`. A DENY of RDP from the internet has become an ALLOW between two nodes literally named 'None', attributed to AlgoSec, and the loop reports the engine certified it. Separately, `rules_path='policy.rules'` (any nested export — i.e. most real ones) silently yields 0 records with no error, and a CSV-shaped `rules: [[...]]` raises AttributeError.

**Evidence.** profile.py:90-96 — `known = ("algosec","guardicore","wiz","sd_wan","sd_lan")` / `source_tool=tool if tool in known else "algosec"` / `action=action if action in ("allow","deny") else "allow"`. profile.py:47 `token = str(token)` turns a missing field into the string `"None"`. authoring.py:50-54 — `unmapped = sorted({field for r in nr.records for field, val in (("source", r.source), ...) if not val})` / `ok = bool(nr.records) and not unmapped` — `"None"` is a non-empty string, so it is never 'unmapped'. profile.py:76 `rules = raw.get(profile.rules_path, [])` is a flat single-key lookup: no dotted paths, no lists-of-lists.

**Fix.** In validate_profile: reject records where source/destination equals the literal 'None' or where `rule.get(fm.src)` was absent for any row; require every mapped field name to actually exist in at least 90% of sample rows; require the sample's distinct action values to all map (do not default). In profile.py: never coerce an unknown action — raise, and let the loop feed the error back. Do not remap the tool name: widen the SourceTool Literal and the `sources.tool` CHECK, or store the declared tool in a `source_tool_raw` column. Support dotted `rules_path` and list-indexed field maps.

**Verifier note.** Two sub-claims over-state the case and should be dropped. (1) rules_path='policy.rules' does NOT 'silently yield 0 records with no error': apply_profile returns 0 records, but validate_profile then returns valid=False and authoring._feedback emits 'The engine produced ZERO records -- rules_path does not point at the list of rules', which the loop feeds back to the model. (2) A CSV-shaped `rules: [[...]]` does raise AttributeError inside apply_profile, but its only caller catches it (authoring.py:48) and returns {'valid': False, 'error': "'list' object has no attribute 'get'"}. Severity downgraded from blocker because the blast radius is capped: an authored profile is never ingested (see byo-source-is-not-wired-into-ingestion), so a bad profile cannot corrupt any snapshot. It is a credibility problem — a green 'engine validated' on a profile that mapped nothing — not a data-corruption one.

</details>

<details>
<summary><b>Service parsing silently drops ports and downgrades every non-TCP/UDP protocol to `tcp`, so true any-protocol rules never trip the any/any guardrail</b><br/><code>correctness-bug</code> &middot; <code>backend/src/normalizers/common.py:89</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The guardrail floor is the project's headline safety property ('no downstream model error can bury a true emergency'). But a rule whose service is the Palo/ASA keyword `ip` or `all` — the standard way to write any-protocol — is decoded as plain `tcp` with an unknown port, so it scores P=0.5 (unknown/ephemeral) instead of P=1.0 and never trips 'internet any/any'. GRE/ESP/AH/IPsec rules are likewise reported as TCP. And a comma-separated port list — the single most common AlgoSec/Palo service encoding — loses its ports entirely with no signal.

**Failure scenario.** Measured outputs of parse_service:
  'tcp/443,8443'        -> proto=tcp, port=None            (both ports lost, scored 'unknown')
  '80-443' (bare range) -> proto=tcp, port=None            (range lost)
  'ip' / 'gre' / 'esp' / 'application-default' / 'HTTP_AND_HTTPS' -> proto='tcp', port=None (protocol silently rewritten; any-protocol guardrail never fires)
  protocol='GRE' or 'ip' -> proto='tcp'
  'tcp/443-80' (reversed) -> port=443, port_end=80         (accepted, downstream range logic is meaningless)
  'tcp/99999' -> port=99999 ; port=-5 -> port=-5           (invalid ports accepted; PolicyRecord.port has no ge/le bound, models.py:43-44)

**Evidence.** common.py:89-91 — `def _clamp_proto(proto): p = proto.strip().lower(); return p if p in _PROTOCOLS else "tcp"` where `_PROTOCOLS = {"tcp","udp","icmp","sctp","any"}` (common.py:20). common.py:102-114 `_parse_ports` returns `(None, None)` on any int() failure. common.py:150-152: a bare unrecognized token falls through to `_clamp_proto(low)` -> 'tcp' with port None. severity.py:106 fires the any/any guardrail only on `protocol == "any"`.

**Fix.** Return an explicit `unparsed: bool` / `warnings: list[str]` on DecodedService instead of coercing, and surface the count per snapshot. Map `ip`/`all`/`any-proto` to protocol 'any'. Add the real IP protocols (gre, esp, ah, igmp, ipsec) to the Protocol literal or keep a `protocol_raw` field so nothing is silently rewritten. Parse comma lists into multiple port ranges (`ports: list[tuple[int,int]]` — the DB `ports` JSONB already models this, schema.sql:107). Validate 0 <= port <= 65535 and lo <= hi; reject rather than accept.

</details>

<details>
<summary><b>snapshot_id is not a content hash of everything that determines the result — same id, different assets and different findings</b><br/><code>correctness-bug</code> &middot; <code>backend/src/analyzers/run_all.py:57</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** persist.py:63 does `delete_snapshot_children(cur, sid)` then re-inserts under the same id, and every cached AI artifact (explanations, ranked_actions, reports, change decisions) is keyed on snapshot_id. So confirming an entity merge silently mutates a snapshot in place: the id in an exported report no longer identifies the analysis it came from. That is exactly the audit property a regulated client will test, and it is the one the docs lead with.

**Failure scenario.** `run('seed-demo')` -> snap_d065e3248774, 25 assets, 17 findings. `run('seed-demo', manual_merges=[('app-server-08','app-server-09')])` -> snap_d065e3248774 (IDENTICAL id), 24 assets, and a different finding-id list. Also proven: two record sets differing only in dest_tags (`['dev']` vs `['pci','crown-jewel']`) fingerprint identically, and an App-ID record whose service label is 'quic' fingerprints identically whether protocol/port decode to udp/443 or tcp/80.

**Evidence.** run_all.py:57-61 — `return content_fingerprint(sorted(f"{r.source_tool}|{r.raw_ref}|{r.source}|{r.destination}|{r.service}|{r.action}|{r.order}" for r in records))`. It omits `dest_tags`, `port`, `port_end`, `protocol`, `l7_app`, and it is computed only over `records` — the `manual_merges` argument (run_all.py:64, 78) changes the assets, the alias_map, the graph and the findings without touching the fingerprint. ENGINE.md §9 claims 'any change to the inputs yields a new snapshot id' and 'a cold re-run UPSERTs byte-identical rows'.

**Fix.** Fingerprint the full canonical tuple — add protocol, port, port_end, l7_app, and sorted dest_tags to the per-record string — and fold in a sorted digest of the applied manual_merges and of the asset tag sets, since both are inputs to the analysis. Cheapest correct version: `content_fingerprint(sorted(r.model_dump_json() for r in records), sorted(manual_merges), sorted((a.asset_key, tuple(a.tags)) for a in assets))`.

**Verifier note.** The finding under-states the consequence and should say so. manual_merges is the LIVE path, not a test-only argument: main.py:110, 173, 204, 521, 810 all call run(..., manual_merges=_load_merges(), applied_changes=_load_applied()). So (a) _apply_merges_and_persist (main.py ~521) re-persists a materially different asset/finding set under the SAME snapshot_id, mutating a supposedly immutable snapshot in place and destroying history; and (b) the cold-start path in engine() only persists 'if not row' — so if precompute.py already wrote snap_X with no merges, the merged engine result is never written, and DB-backed panels show the pre-merge estate while in-memory endpoints show the post-merge one.

</details>

<details>
<summary><b>One shared or sentinel IP transitively collapses the entire estate into a single asset</b><br/><code>robustness-gap</code> &middot; <code>backend/src/identity.py:61</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** Real exports are full of shared addresses: a NAT/SNAT pool address on many rules, a cluster VIP, `0.0.0.0` as an unknown-IP placeholder, `127.0.0.1` for local agents. Any one of them fuses every asset that carries it into one node. The graph then has one super-node with every edge attached, `all_simple_paths` reports that everything reaches everything, and the cross-tool path count explodes or the run times out. There is no warning — the asset count just drops and the findings become nonsense.

**Failure scenario.** 6 Wiz hosts with `ip="0.0.0.0"` plus `db-prod-01` (pci) with the same placeholder: resolve_identities returns exactly 1 asset — `key='db-prod-01' tags=['pci'] ips=['0.0.0.0/32']` — and alias_map rewrites all 7 names to it. Every rule in the estate now terminates on the PCI database node. A three-name chain (nat-gw / db-prod-01 / dev-box all on 10.1.1.1) likewise merges into one asset tagged `['dev','pci']`.

**Evidence.** identity.py:61-64 unions every name sharing an IP, and union-find is transitive by construction. There is no cardinality guard, no ignore-list for sentinel addresses, and no cap on component size. The only falsy filter is `if e.ip:` (identity.py:59), which lets through `"0.0.0.0"`, `"127.0.0.1"`, a shared VIP, a NAT address, or an unresolved-DNS default.

**Fix.** Maintain an ignore set for non-identifying addresses (0.0.0.0, 127.0.0.0/8, 169.254.0.0/16, ::, ::1) — never union on them. Cap merge-by-IP fan-out: if an IP maps to more than N (e.g. 2) distinct names, do not auto-union; emit an `AssetCorrelation` with `match_key='manual_review'` and confidence 0 so it surfaces for a human. Log/return a counter of suppressed merges so the operator sees it happened.

**Verifier note.** Real, but it is the same root defect as `context-free-ip-merge` (unguarded union on a raw IP string) with a more degenerate input, and the full-estate collapse needs a repeated sentinel address rather than the ordinary duplicate-RFC1918 case. Reported as a separate blocker it double-counts; high is the honest standalone rating. The realistic sub-case (a shared VIP/NAT address merging 2-3 real hosts, which I did reproduce) is the part that will actually bite.

</details>

<details>
<summary><b>'The internet' means the literal string `0.0.0.0/0` — `0.0.0.0/1` is classified as an internal zone, B=1.0, and trips no guardrail</b><br/><code>correctness-bug</code> &middot; <code>backend/src/graph/zones.py:12</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The guardrail floor is the one thing the docs say cannot be defeated ('so no model error downstream can bury a true emergency', severity.py:5-7). It is defeated by writing the source as two /1s instead of one /0 — a completely ordinary way to express the same rule — or by any genuinely public range (1.0.0.0/8, a partner's public /24). 'internal->internal' for a rule sourced from half the internet is the kind of line a client screenshots. (Mitigating: classify_change Layer 3 `_clean(delta)` at classify_change.py:156-158/212 still escalates it because `new_over_permissive` is non-empty — so the gate holds, but only via the LLM path, not the deterministic guardrail that is advertised as model-independent.)

**Failure scenario.** Any real dataset. Analyst sees 'RDP open from 0.0.0.0/1 to app-server-07 — medium' next to 'RDP open from the internet to db-prod-01 — critical' and correctly concludes the severity model is not trustworthy.

**Evidence.** zones.py:11-13 `def zone_of(node_key, tags): if node_key == INTERNET_CIDR: return ZONE_INTERNET` — string equality against '0.0.0.0/0'. severity.py:90-91 `def _is_internet(E): return E >= 1.0  # only 0.0.0.0/0 yields E == 1.0`. There is no public/private address-space concept anywhere in graph/ or analyzers/.

Reproduced through the real analyzer path:
  allow 0.0.0.0/0 -> app-server-07 tcp/3389 -> severity 90, band 'critical', forced_critical=True
  allow 0.0.0.0/1 -> app-server-07 tcp/3389 -> severity 56, band 'medium',   forced_critical=False
  (0.0.0.0/1 gives E=0.9, and because '0.0.0.0/1' != '0.0.0.0/0' its zone is 'internal' so B collapses 1.5 -> 1.0)

And through the change gate (change/simulate.py:52-53 uses the same zone_of):
  proposed: allow 0.0.0.0/1 -> db-prod-01 tcp/5432   (Postgres to the PCI crown jewel from half the public IPv4 internet)
  -> forced_escalate = False, new_paths = 0, proposed_boundary = 'internal->internal'

**Fix.** Replace the string check with address-space classification: compute `is_public(net)` via `ipaddress.ip_network(...).is_global` / not `is_private`, and treat any source whose network is (mostly) globally routable as ZONE_INTERNET. Make `_is_internet` a function of that classification rather than of `E >= 1.0`. Add `::/0` handling for IPv6 while you're there.

**Verifier note.** One consequence is overstated. The 0.0.0.0/1 -> PCI-Postgres change does NOT sail through the change gate: simulate_change still returns new_over_permissive=['regulated destination reachable from more than a single host','admin/data port open to a broad source range'], and classify_change.py:156-158 `_clean()` + the Layer-3 override at :212-216 refuse to auto_approve any non-clean delta. So it escalates — it just skips the pre-model guardrail short-circuit. The severity-model half (56/medium vs 90/critical for the same RDP exposure) is fully confirmed and is the real defect. High stands.

</details>

<details>
<summary><b>One IPv6 rule alongside IPv4 raises an unhandled TypeError and takes the whole API down</b><br/><code>robustness-gap</code> &middot; <code>backend/src/analyzers/cidr_overlap.py:24</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** Any real firewall export from the last decade contains at least one IPv6 rule. The failure is not degraded output — it is a 500 on every route, permanently, because `_ENGINE` never gets set and the same exception is re-raised on every subsequent request. There is no isolation between analyzers either: run_all.py:85-89 calls them in sequence with no per-analyzer guard.

**Failure scenario.** Client uploads their real AlgoSec export containing `allow 2001:db8:a::/48 -> app-tier tcp/443`. The app returns 500 on every page and stays down until the process is restarted with different data.

**Evidence.** cidr_overlap.py:22-27 `def _relation(a, b): if a == b or a.subnet_of(b) or b.subnet_of(a): ...` and shadowing.py:32-36 `def _covers(earlier, later): ... return ln.subnet_of(en)`. Python's `ipaddress._BaseNetwork._is_subnet_of` raises `TypeError` (it does not return False) when versions differ.

Reproduced:
  cidr_overlap.analyze([10.0.0.0/8 -> db, 2001:db8::/32 -> db])  -> CRASH TypeError: 10.0.0.0/8 and 2001:db8::/32 are not of the same version
  shadowing.analyze([2001:db8::/32 order 1, 10.0.0.0/8 order 2]) -> CRASH TypeError: same

Blast radius: app/main.py:110 `_ENGINE = run(label=_ACTIVE_SCENARIO, ...)` inside `engine()` has NO try/except around `run()` (the try at 111-118 only wraps DB persistence). Every endpoint funnels through `engine()`.

**Fix.** Guard the family comparison in both places: `if na.version != nb.version: continue` in cidr_overlap._relation and `if en.version != ln.version: return False` in shadowing._covers. Separately, wrap each analyzer call in run_all.py:85-89 with a try/except that records a degraded-analyzer marker on the EngineResult instead of aborting the snapshot, and add a try/except around main.py:110 so a bad dataset yields a diagnosable 4xx rather than a permanently poisoned singleton.

</details>

<details>
<summary><b>Cross-tool path severity is scored from an alphabetically-chosen grant, not the worst-case one — the demo would call an RDP terminal hop 'general app / web'</b><br/><code>correctness-bug</code> &middot; <code>backend/src/graph/reachability.py:29</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** build.py deliberately preserves every parallel grant (build.py:51-62, and ENGINE.md §3 highlights 'Parallel grants are kept, not collapsed') — and then the scoring path throws all but one away on an ordering that has nothing to do with risk. The engine both under-scores the path AND prints a false characterisation of it: the UI hop card and the LLM explanation will say the internet reaches the PCI database over 'general app / web' when the actual terminal grant is RDP. 'The engine owns all facts' fails here: the fact it emits is wrong.

**Failure scenario.** Two tools both report the last hop (very common — AlgoSec sees the firewall rule, Wiz sees the security group). The path finding says 'general app / web', the client's own console says RDP, and the AI narrative repeats the engine's wrong fact.

**Evidence.** reachability.py:28-29:
```
def _representative(data: dict) -> dict:
    return sorted(data['grants'], key=lambda gr: (gr['tool'], gr.get('ref') or ''))[0]
```
describe_path (reachability.py:79-84) puts that ONE grant's `service`/`tool`/`ref` on the hop, and reachability.py:101 sets `terminal_service = hops[-1]['service']`, which severity.py:161 feeds to `port_score_from_service` for P.

Since 'algosec' < 'guardicore' < 'wiz' lexicographically, AlgoSec always wins. Reproduced on a terminal edge carrying BOTH `tcp/443 (algosec)` and `tcp/3389 (wiz)` into a pci asset:
  terminal_service picked: 'tcp/443'   (edge services: ['tcp/443','tcp/3389'])
  score: severity 94, vector P=0.4, port_class 'general app / web'
Worst-case scoring would give P=1.0, severity 100, port_class 'admin / lateral-movement'.

**Fix.** Score on the worst case: in score_cross_tool_path, take `max(port_score(...) for grant in terminal_edge.grants)` rather than the representative. In describe_path, keep the representative for display but add `terminal_worst_service` / `terminal_port_class` computed over all grants, and surface the full `services` list (already present as hops[-1]['services']) in the finding title.

**Verifier note.** Does not fire on the shipped demo — I checked, the money-shot terminal edge internal-app->db-prod-01 carries a single grant (ALGO-030 tcp/5432), so the demo shows the correct 'data store'. Mitigation worth noting: describe_path DOES carry the full `services`/`apps`/`tools` lists on each hop (reachability.py:86-88), so the UI has the data — only the SCORING and the port_class label use the arbitrary representative. High still stands: it is a wrong number on the product's headline finding type.

</details>

<details>
<summary><b>Shadowing matches destinations by NAME and services by exact STRING — it cannot detect the classic 'broad rule at the top' shadow</b><br/><code>correctness-bug</code> &middot; <code>backend/src/analyzers/shadowing.py:53</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** Rule order IS modelled and IS used (shadowing.py:50 sorts by `(r.order, r.raw_ref)`), so the analyzer is not unsound in the way you feared — but its coverage predicate is so narrow it only detects the case the seed data was written to contain (ALGO-020 tcp/443 allow then ALGO-021 tcp/443 deny — identical service string, identical dest name). The two shapes that actually cause shadowing in production firewalls — a broad rule whose DESTINATION is a network object containing the later rule's host, and a service RANGE covering a later single port — are both invisible. ENGINE.md §6.3 says 'same destination, and overlapping service' without disclosing that both are string equality.

**Failure scenario.** Real rulebase: `#1 allow any -> DMZ_NET any` then `#847 deny 10.20.5.7/32 -> web-01 tcp/443`. The security team believes 10.20.5.7 is blocked. NPR reports no shadowing. The deny never fires.

**Evidence.** shadowing.py:53-56:
```
if alias_map.get(earlier.destination, earlier.destination) != \
        alias_map.get(later.destination, later.destination):
    continue
if not _service_overlaps(earlier, later) or not _covers(earlier, later):
```
and shadowing.py:28-29 `def _service_overlaps(a, b): return a.protocol == 'any' or b.protocol == 'any' or a.service == b.service` — raw string equality on the service label.

So destination coverage is name-identity only (no CIDR containment on the DEST side, even though `_covers` does it on the SOURCE side), and service coverage is `'tcp/443' == 'tcp/443'`. Reproduced, both return `[]`:
  order 1: allow 0.0.0.0/0 -> 10.0.0.0/8 any        (dest = a /8 containing app-server-07 @ 10.30.7.7)
  order 2: allow 0.0.0.0/0 -> app-server-07 tcp/3389
  shadowing.analyze(...) -> []

  order 1: allow 0.0.0.0/0 -> app-server-07 tcp/1-65535
  order 2: deny  10.0.0.0/8 -> app-server-07 tcp/3389
  shadowing.analyze(...) -> []

**Fix.** Extend `_covers` to a full 5-tuple coverage test: source (already CIDR-aware), destination (add the same CIDR/asset-ip containment logic using Asset.ip_set), protocol, and port INTERVAL containment (`earlier.port <= later.port and later.port_end <= earlier.port_end`, treating protocol=='any' / port==None as full range). Replace `_service_overlaps` string equality with interval intersection.

**Verifier note.** Worth noting the direction: this is a false-NEGATIVE bug (missed shadows), not a false-positive one, so it will not blow up live in a demo — it fails quietly. High is still right because a security team acting on 'no shadowing detected' is the exact harm.

</details>

<details>
<summary><b>The entire graph + 5 analyzers + severity model has ZERO unit tests; the only check is a golden assertion on the seeded demo with the money-shot path hardcoded</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/scripts/verify_engine.py:48</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** Every finding above is a bug that a five-line unit test would have caught: port ranges, IPv6, 0.0.0.0/1, the representative-grant pick, the who_can_reach divergence. The 'defensible IP' is the only part of the system with no test coverage at all, and verify_engine.py will keep printing ALL CHECKS PASSED while all of them are live, because it only ever sees the one dataset that was written to satisfy it.

**Failure scenario.** Any refactor of severity.py or reachability.py silently changes client-facing risk numbers and verify_engine.py still passes, because the demo happens to have no port ranges, no IPv6, and one grant per edge.

**Evidence.** verify_engine.py:48-52:
```
expected = ['0.0.0.0/0', 'lb-public-01', 'app-server-07', 'internal-app', 'db-prod-01']
check('P5 path is the 5-hop chain', path == expected)
...
check('exactly one cross-tool path', sum(1 for f in fs if f.type == 'cross_tool_path') == 1)
```
That is a golden-output snapshot of the seed data, not a test of any computation. The only pytest file, backend/tests/test_agents.py (355 lines), contains 18 tests — all of them named test_remediation_*, test_campaign_*, test_classify_*, test_authoring_* — i.e. 100% advisory/agent layer. Grep of every `def test_` and `assert` in that file shows not one assertion against severity_from_vector, exposure_score, port_score, band, build_graph, cross_tool_paths, _valid_traversal, _covers, or _relation. No CI exists.

**Fix.** Add backend/tests/test_engine.py with table-driven cases: (1) severity_from_vector against the ENGINE.md §5.5 worked example plus band boundaries at 34/35/59/60/79/80; (2) exposure_score for /0,/1,/8,/9,/16,/23,/24,/27,/28,/32, identity, malformed, IPv6; (3) port_score with ranges; (4) _covers/_relation for nested, disjoint, equal, mixed-family, host-bits-set; (5) shadowing order semantics with a deliberately reordered rule list; (6) _valid_traversal on a subnet pivot; (7) reachable vs who_can_reach consistency as a property test. Then add a .github/workflows/ci.yml running pytest + verify_engine.py.

**Verifier note.** Minor factual error: `grep -c 'def test_' backend/tests/test_agents.py` returns 16, not 18. The naming claim is exact — all 16 are test_remediation_*/test_campaign_*/test_classify_*/test_authoring_*. Everything else stands.

</details>

<details>
<summary><b>/api/actions runs an unbounded, uncapped LLM call inside an open DB transaction with a 600-second timeout — on every console page load after a recompute</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/app/main.py:483</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** This is the single most likely thing to break a live demo. Hit "Recompute" (a headline demo button), navigate to Risk To-Do, and the request may block for up to 10 minutes while holding one of only 10 pooled Neon connections (db.py:64 `max_size=int(os.getenv("DB_POOL_MAX", "10"))`). Behind Vercel's rewrite the gateway kills it long before that, the frontend swallows the failure, and the user sees "0 prioritized actions" — silently combining this bug with the one above.

**Failure scenario.** Demo flow: click Recompute (ranked_actions deleted) -> open Risk To-Do -> GET /api/actions -> cache empty -> rank() sends all N findings to Ollama with a 600 s timeout while holding a Neon connection. Vercel's rewrite returns 504 after its gateway timeout. `.catch(() => {})` swallows it. Screen reads "0 findings ... 0 prioritized actions". Ten concurrent viewers exhaust DB_POOL_MAX=10 and every other endpoint blocks on `timeout=30.0` (db.py:70) then errors.

**Evidence.** main.py:476-486
    @app.get("/api/actions")
    def actions(snapshot: str | None = None):
        t = view_sid(snapshot)
        with get_conn() as conn, conn.cursor() as cur:          # <- transaction OPEN
            rows = fetch_all(cur, "SELECT ... FROM ztpa.ranked_actions WHERE snapshot_id=%s ...", [t])
            if rows or t != sid():
                return {"actions": rows, "ranked_by": "cache"}
            ranked = rank_mod.rank(engine().findings)            # <- synchronous LLM call

rank.py:111-113
    def rank(findings: list[Finding]) -> RankedActions:
        if not findings: ...
        r = complete(system=_PROMPT, user=json.dumps({"findings": _payload(findings)}),
                     role="judge", temperature=0.1, expect_json=True)   # <- no `timeout=` argument

client.py:55  r = httpx.post(f"{settings.OLLAMA_HOST}/api/chat", json=payload, timeout=timeout or settings.OLLAMA_TIMEOUT)
settings.py:35 OLLAMA_TIMEOUT: float = float(os.environ.get("OLLAMA_TIMEOUT", "600"))

The cache is deliberately invalidated by every recompute:
main.py:179  cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])   (also in switch_dataset:210, _apply_merges_and_persist:525, reset_demo:816)

And the browser calls it unconditionally on mount with no timeout:
console/page.tsx:62  api.actions(viewSnap)... ; api.ts:7 `const r = await fetch(url, { cache: "no-store", ...init });`  // no AbortController

`_payload` (rank.py:19-24) serializes EVERY finding with no slice or cap.

**Fix.** Never do LLM work on a GET in the request path. Move ranking to the same background-thread pattern already used for explain (`_bg_explain`, main.py:324-335): return the deterministic `_fallback(findings)` ranking immediately with `pending: true`, compute the LLM ranking off-path, cache it, and let the UI poll. Separately: (a) pass an explicit `timeout=` to every `complete()` call and lower the default OLLAMA_TIMEOUT from 600 s, (b) cap `_payload` to the top ~150 findings by severity, (c) never hold a `get_conn()` transaction across an LLM call, (d) add an AbortController with a timeout to `j()` in api.ts.

**Verifier note.** Downgrade blocker -> high and drop '600-second'. On the shipped render.yaml config (ADVISORY_PROVIDER=openai) the call is bounded at ~120s by client.py:69-70/78-79, because `timeout=` is consumed only by _ollama_complete (client.py:141). 600s is the local-Ollama-only case. Also note complete() never raises, so the endpoint degrades to the deterministic _fallback rather than erroring.

</details>

<details>
<summary><b>/api/health hardcodes status:"ok" and its db check is a bare SELECT 1 — it reports green against an unmigrated database while every data endpoint 500s</b><br/><code>robustness-gap</code> &middot; <code>backend/app/main.py:153</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** Combined with the frontend's silent-empty rendering, a fresh Neon database that nobody ran `tasks.py db` against produces a fully green deploy — Render's health check passes, /api/health returns {"status":"ok","db":true} — while the entire dashboard is blank. That is the worst possible failure signature for a security tool: healthy-looking and empty.

**Failure scenario.** Deploy to Render against a brand-new Neon project. `ping()` succeeds (SELECT 1). `engine()` builds the snapshot in memory, tries to persist, hits `relation "ztpa.snapshots" does not exist`, and `except Exception: pass` (main.py:117) swallows it. Render sees 200 and marks the service live. /api/findings, /api/graph, /api/assets all 500. The frontend swallows all three. Everything reads "0".

**Evidence.** main.py:152-160
    @app.get("/api/health")
    def health():
        db_ok = False
        try:
            db_ok = ping()
        except Exception:
            pass
        return {"status": "ok", "db": db_ok, "snapshot_id": sid(), "ai": provider_status()}

db.py:115-117
    def ping() -> bool:
        with get_conn() as conn:
            return conn.execute("SELECT 1 AS ok").fetchone()["ok"] == 1

`status` is a literal. `ping()` never touches the `ztpa` schema. `provider_status()` (client.py:215-228) is reported but never gates the status. render.yaml:19 `healthCheckPath: /api/health`.

DEPLOY.md:49-51 acknowledges the gap in prose only:
    "On first boot the engine builds in a background thread and self-seeds its
     snapshot into Postgres if missing — so a clean Neon DB is fine too (as long as
     the `ztpa` schema exists; run `python tasks.py db` once if it does not)."
But nothing checks that condition at runtime; main.py:117-118 swallows the persist failure.

**Fix.** Make health a real readiness probe: `SELECT count(*) FROM ztpa.snapshots` (proves the schema exists), assert the active snapshot has rows in `findings`, and set `status` to "ok"|"degraded"|"error" accordingly, returning 503 on error so Render actually fails the deploy. Split `/api/health` (liveness, cheap, always 200) from `/api/ready` (readiness, checks DB+schema+snapshot, used as healthCheckPath). Stop swallowing the persist exception — record it in a `last_persist_error` field surfaced by health.

</details>

<details>
<summary><b>Zero application logging, no request/correlation id, no error tracking — nothing to debug production with</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/app/main.py:1</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The AI-metrics table (ai_metrics) is good, but it only covers LLM/embed calls. For everything else — a failed snapshot persist, a swallowed DB error at startup, a 500 on /api/findings, a normalizer crash — there is literally no artifact. On Render you would see uvicorn's default access log line and a bare traceback, with no request id to correlate to the user, role, or snapshot. When the user says "it showed nothing", there is no way to answer "why".

**Failure scenario.** A user reports the dashboard was empty for ten minutes yesterday. There is no request id, no structured log, no error tracker, and the three most likely culprits (`_load_merges` DB failure, `persist_engine_result` failure, `write_scenario` failure) all `except Exception: pass`. The incident is unreproducible and undiagnosable.

**Evidence.** grep for `import logging|logger|getLogger|structlog|sentry|traceback` across backend/src, backend/app, backend/scripts (excluding .venv) returns ZERO hits. Same grep across frontend/app, frontend/lib, frontend/components (incl. `console.error`) returns ZERO hits.

Meanwhile 29 `except Exception` handlers swallow silently. main.py alone:
  main.py:86-89   def _load_merges():  ... except Exception: return []
  main.py:107-109 try: write_scenario(_ACTIVE_SCENARIO) \n except Exception: pass
  main.py:117-118 except Exception: pass  # DB optional for live-only ops
  main.py:146-147 except Exception: pass  # a real request will retry the build lazily
metrics.py:52-53  except Exception: pass  # metrics are best-effort; never break the measured call

There is no _ActorMiddleware equivalent that assigns a request id; request_ctx.py carries only role/email/sub.

**Fix.** Add `structlog` (or stdlib logging with a JSON formatter). Extend `_ActorMiddleware` to mint/propagate an `X-Request-Id`, stash it in `request_ctx`, echo it on the response, and bind it to every log line. Replace every `except Exception: pass` with `except Exception: log.exception(...)` — swallowing is fine, silence is not. Add a global `@app.exception_handler(Exception)` that logs with the request id and returns `{detail, request_id}`. Wire Sentry (free tier) on both backend and Next.js.

**Verifier note.** Downgrade blocker -> high. Fix two evidence errors: frontend/lib/email.ts:26,33 do contain console.log (no console.error anywhere); and uvicorn's default access log + Starlette's ServerErrorMiddleware traceback mean unhandled 500s ARE logged. The finding should be scoped to 'no structured logging, no request id, no error tracking, and 29 silently swallowed exception paths'.

</details>

<details>
<summary><b>No CI at all, and the single test file covers only the AI advisory loop — zero tests for the analyzers, severity math, normalizers, identity, graph, API, or persistence</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/tests/test_agents.py:1</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The entire value proposition is "the deterministic engine owns all facts and math." That engine — the E×P×D×B severity vector, the guardrail floors, subnet containment, shadowing precedence, boundary multipliers — has zero unit tests. Every test in the repo mocks away the model and tests the wrapper around it. A one-character change to a threshold in config.py, or an off-by-one in `_covers`, would silently reprice every finding in the product with nothing to catch it. In front of a security-savvy client, "how do you know the severity math is right?" has no answer.

**Failure scenario.** Someone tunes `EXPOSURE_BANDS` in config.py:133-140 or flips a comparison in `severity.py`. `verify_engine.py` is not in CI so nobody runs it; the 16 agent tests all still pass because they stub the model and only assert on loop control flow. The change ships. Every severity score in every snapshot is now wrong, and the guardrail floors may no longer fire on the any/any rule.

**Evidence.** `ls -a .github` -> NO .github (no workflows directory anywhere in the repo).

backend/tests/ contains exactly one file. Its 16 tests, by name:
  test_remediation_revises_until_clean / falls_back_when_model_dead / prefers_clean_over_dirty
  test_campaign_drives_criticals_to_zero_offline / labels_llm_steps / no_targets_is_noop / skips_unfixable_without_regressing
  test_classify_guardrail_short_circuits... / investigates_then_approves... / engine_override_blocks... / fails_closed_on_garbage / investigation_tolerates_bad_tool_calls
  test_authoring_converges_after_bad_first_profile / reports_unmapped_fields / needs_review_when_never_valid / fails_closed_when_model_dead

Every one takes `monkeypatch` and stubs the LLM. NOT ONE exercises severity.py, over_permissive.py, cidr_overlap.py, shadowing.py, path_trace.py, transport_exposure.py, identity.py, graph/build.py, graph/reachability.py, normalizers/*, persist.py, or any FastAPI route.

The only engine coverage is scripts/verify_engine.py, which is a single-fixture acceptance script hardcoded to the demo dataset:
  verify_engine.py:48  expected = ["0.0.0.0/0", "lb-public-01", "app-server-07", "internal-app", "db-prod-01"]
  verify_engine.py:52  check("exactly one cross-tool path", sum(1 for f in fs if f.type == "cross_tool_path") == 1)
...and it is not run by anything automated.

**Fix.** Add `.github/workflows/ci.yml` running (1) `pytest backend/tests`, (2) `python backend/scripts/verify_engine.py`, (3) `npm run build` + `tsc --noEmit` in frontend, on every PR. Then write table-driven unit tests for `severity.py` (each of E/P/D/B in isolation plus the combination formula and every guardrail floor), for `cidr_overlap._relation`/`shadowing._covers` against known subnet pairs, for `reachability._grant_matches` port/range/app cases, and golden-file tests for each normalizer.

**Verifier note.** Correct 'NOT ONE exercises severity.py, over_permissive.py, …': the module-scoped `eng` fixture calls run(), so the full pipeline executes and several tests (e.g. _worst_cross_tool's bare next()) would fail if the analyzers stopped emitting a cross_tool_path or criticals. The accurate claim is that no test ASSERTS on a severity score, band, guardrail floor, or any analyzer output — only on agent loop control flow.

</details>

<details>
<summary><b>upsert_many builds one giant multi-VALUES statement — snapshots over ~2,620 rules or ~5,950 findings exceed Postgres's 65,535 bind-parameter limit and fail to persist</b><br/><code>correctness-bug</code> &middot; <code>backend/src/db.py:198</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** This is a hard, opaque failure exactly at the scale the project advertises (`seed-scale 1000` is the documented default in seed_scale.py:42; the docstring says "see how the engine and the map behave at hundreds / thousands of assets"). It fails in `persist_engine_result`, which is called inside `/api/recompute` and `/api/admin/dataset` — and in `engine()` the persist attempt is wrapped in `except Exception: pass` (main.py:117-118), so at boot the snapshot silently never lands in the DB and every DB-backed read returns empty.

**Failure scenario.** Admin runs `python tasks.py seed-scale 3000`, then `python tasks.py precompute`. The demo now has ~3,030 canonical rules. `upsert_many(cur, "canonical_rules", ...)` builds a statement with 3,030 × 25 = 75,750 parameters. psycopg raises before the server even sees it. `precompute.py` dies with an unfamiliar driver error; via the API, `engine()`'s bare `except Exception: pass` swallows it and the dashboard is permanently empty while /api/health still reports ok.

**Evidence.** db.py:191-199
    one = "(" + ", ".join(["%s"] * len(cols)) + ")"
    values_sql = ", ".join([one] * len(deduped))
    sql = (f"INSERT INTO {DB_SCHEMA}.{table} ({', '.join(cols)}) "
           f"VALUES {values_sql} "
           f"ON CONFLICT ({', '.join(pk)}) DO UPDATE SET {set_clause}")
    params = [r[c] for r in deduped for c in cols]        # <- len(rows) * len(cols) params, unbatched
    cur.execute(sql, params)

There is no chunking anywhere. Column counts from persist.py:
  canonical_rules (persist.py:98-108): rule_uid, snapshot_id, source_tool, source_device, raw_rule_id,
    policy_id, rule_order, action, src_kind, src_value, src_context, dst_kind, dst_value, dst_context,
    protocol, ports, l7_app, nat_original, nat_translated, tags, enabled, schedule, direction,
    src_asset_refs, dst_asset_refs = 25 cols  ->  65535 // 25 = 2,621 rows max
  findings (persist.py:126-131) = 11 cols     ->  65535 // 11 = 5,957 rows max
  graph_edges (persist.py:118-124) = 10 cols  ->  65535 // 10 = 6,553 rows max
  assets (persist.py:83-87) = 8 cols          ->  65535 //  8 = 8,191 rows max

The project ships two ways to blow past this:
  tasks.py:17   "python tasks.py seed-scale N  base demo + N synthetic assets"
  main.py:190-192  class DatasetBody(BaseModel): scenario: str; n: int = 500      # <- no upper bound
  scenarios.py:75-83  def _scale(n: int = 500): for i in range(n): a["rules"].append(...)

The Postgres extended-query protocol encodes the parameter count as an int16, so >65535 is a hard server-side/driver error, not a slowdown.

**Fix.** Chunk inside `upsert_many`: `batch = max(1, 65535 // len(cols))`, loop `for i in range(0, len(deduped), batch)`. Better, switch to `cur.executemany` with psycopg3 pipeline mode, or `COPY` into a temp table + a single `INSERT ... SELECT ... ON CONFLICT`. Also bound `DatasetBody.n` (`Field(le=5000)`) and stop swallowing the persist exception in `engine()`.

**Verifier note.** Downgrade blocker -> high; kind is 'robustness/scale gap', not 'correctness-bug' (it is a hard failure, not a wrong result). Fix the arithmetic: assets is 9 columns (persist.py:83-87), so its ceiling is 7,281 rows, not 8,191. Note it needs a deliberate n >= ~2,600 — the shipped scale default of 500 is ~13k params.

</details>

<details>
<summary><b>shadowing and cidr_overlap are O(n²) in rules-per-destination — measured 11.5 s at 2,000 rules, ~5 min at 10k, and reanalyze() runs this ~200× per campaign</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/src/analyzers/shadowing.py:51</code> &middot; CONFIRMED &middot; effort L</summary>

**Why it matters.** docs claim this is a production policy engine. Real AlgoSec estates are 5k-50k rules. Extrapolating the measured 4x-per-doubling curve from the 10-destination case: 10k rules ≈ 290 s, 50k ≈ 2 hours, 100k ≈ 8 hours for one snapshot build. Worse, `reanalyze()` is on the interactive path — a single "Draft & validate a fix" click at 4,000 rules costs 4 × 3.2 s = 13 s of pure CPU before any LLM latency, and a campaign plan costs ~200 × that. FastAPI runs these sync endpoints in a threadpool, so a couple of concurrent campaigns saturate the box.

**Failure scenario.** A client uploads a realistic 8,000-rule AlgoSec export where 800 rules target the same 'dmz-web-farm' object on tcp/443. `cidr_overlap.analyze` alone does C(800,2)=319,600 pair comparisons with 2 `ipaddress.ip_network` constructions each, and `shadowing.analyze` does 32M pair iterations. The first /api/recompute never returns; the process pegs one core for minutes; the Render free instance is killed.

**Evidence.** shadowing.py:49-56
    for tool, recs in by_tool.items():
        recs = sorted(recs, key=lambda r: (r.order, r.raw_ref))
        for i, later in enumerate(recs):
            for earlier in recs[:i]:                       # <- O(n^2) per tool
                if alias_map.get(earlier.destination, ...) != alias_map.get(later.destination, ...):
                    continue
                if not _service_overlaps(earlier, later) or not _covers(earlier, later):

_covers -> _src_net -> `ipaddress.ip_network(rec.source, strict=False)` is re-parsed on EVERY pair; no memoization (shadowing.py:19-24, 32-38).

cidr_overlap.py:38-41
    for (tool, dest, service), recs in groups.items():
        for a, b in combinations(sorted(recs, key=lambda r: r.raw_ref), 2):
            na, nb = _net(a.source), _net(b.source)         # <- 2 ip_network per pair

I benchmarked this against the real code with synthetic PolicyRecords (read-only, nothing written to the repo):

  n_dests = n/10 (rules spread thin):
    rules= 500 shadowing=   91.6ms  cidr_overlap=   59.9ms
    rules=1000 shadowing=  250.8ms  cidr_overlap=  119.2ms
    rules=2000 shadowing=  844.7ms  cidr_overlap=  230.0ms
    rules=4000 shadowing= 3136.2ms  cidr_overlap=  449.9ms      <- exactly 4x per doubling

  10 destinations (realistic: many rules to the same server group):
    rules= 500 shadowing=  455.1ms  cidr_overlap=  366.9ms
    rules=1000 shadowing= 1604.5ms  cidr_overlap= 1343.3ms
    rules=2000 shadowing= 5809.5ms  cidr_overlap= 5670.2ms      <- 11.5 s combined

  1 destination + 1 service (legal input: 'allow tcp/443 to web-farm' x N):
    rules= 500 cidr_overlap=  3658.3ms
    rules=1000 cidr_overlap= 14574.2ms
    rules=2000 cidr_overlap= 56366.4ms                          <- 56 s in ONE analyzer

And this pipeline is re-run per validation:
  remediation.py:114  after = reanalyze(_apply(ctx.records, change), ctx.assets, ctx.alias_map)   (up to 4x per draft)
  campaign.py:94,128  reanalyze(...) once at start + once per step
  campaign.py:99      budget = min(... , _MAX_STEPS_CEILING)   with _MAX_STEPS_CEILING = 40

**Fix.** shadowing: bucket `recs` by canonical destination first (dict of dest -> list) so the inner loop only walks same-destination rules, and pre-parse each record's source network ONCE into a `{raw_ref: ip_network}` map. cidr_overlap: replace the pairwise `combinations` with a sort-by-(network_address, prefixlen) sweep that finds containment in O(k log k), and cap the number of emitted findings per group. Add a hard `MAX_RULES` guard that fails loudly with a clear message instead of hanging. Add a perf regression test that asserts a 10k-rule snapshot builds in <30 s.

**Verifier note.** Downgrade blocker -> high. The measurements are correct and I reproduced them, but the pathology is not reachable on any shipped scenario: _scale gives every rule a unique destination, so at the UI default (n=500) the analyze stage is ~90ms. It is a genuine algorithmic ceiling that makes 'ingests real firewall exports' indefensible, not a demo-day failure. Also note shadowing.py:90 `break` bounds the inner loop when a shadower is found.

</details>

<details>
<summary><b>Every core data fetch swallows its error, so a broken backend renders as "0 findings, 0 prioritized actions"</b><br/><code>robustness-gap</code> &middot; <code>frontend/app/console/page.tsx:60</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** This is the direct, mechanical cause of the user's lack of confidence. There is no way for a viewer to distinguish "the engine found nothing" from "the API 500'd". In a security product, a screen that confidently says "0 prioritized actions" when the backend is dead is worse than a crash — it is a false all-clear. A security-savvy client who notices this once will not trust any number on the dashboard again.

**Failure scenario.** Neon suspends (free tier) or the `ztpa` schema is missing. GET /api/findings and /api/actions return 500. `.catch(() => {})` discards both; `loading` flips to false. The Risk To-Do screen renders "0 findings across three tools, grouped by root cause into 0 prioritized actions, worst first" followed by "No actions match this filter." The Network Map's Stat tiles render Critical 0 / High 0 / Medium 0 / Low 0. No banner, no console.error, no toast, nothing in any log.

**Evidence.** console/page.tsx:59-62
    api.snapshot(viewSnap).then((s) => { if (live) setCounts(s.counts); }).catch(() => {});
    api.findings(viewSnap).then((f) => { if (live) setFindings(f.findings); }).catch(() => {}).finally(() => { if (live) setLoading((l) => ({ ...l, findings: false })); });
    api.graph(viewSnap).then((g) => { if (live) setGraph(g); }).catch(() => {}).finally(...);
    api.actions(viewSnap).then((a) => { if (live) setActions(a.actions); }).catch(() => {}).finally(...);

The `err` banner at page.tsx:76 is fed ONLY by api.health() (line 52), never by these three.

RiskTodo.tsx:54-57 then renders:
      {findings.length} findings across three tools, grouped by root cause into{" "}
      <b className="text-ink">{actions.length} prioritized actions</b>, worst first.
RiskTodo.tsx:70-71:
      {shown.length === 0 ? (
        <div className="panel p-6 text-center text-[13px] text-text3">No actions match this filter.</div>

This is systemic — 20 call sites do the same. grep output:
  Staging.tsx:23   api.staging().then(...).catch(() => setItems([]))          -> "Nothing staged yet."
  ChangeGate.tsx:51 api.changeDecisions().then(...).catch(() => setDecisions([]))
  ChangeGate.tsx:88 } catch { /* ignore */ } finally { setLoading(false); }   -> Evaluate button does nothing
  IngestInspector.tsx:24 api.ingest(snapshot).then(setD).catch(() => {})      -> skeleton forever
  AssetsPanel.tsx:22, Campaign.tsx:30, Topbar.tsx:33, admin/SnapshotsAdmin.tsx:15, admin/ToolsAdmin.tsx:18 ...
Only admin/MetricsAdmin.tsx:18 sets an error flag.

**Fix.** Give the page a per-resource state machine: `{status: 'loading'|'ok'|'error', data, error}`. Replace every `.catch(() => {})` with `.catch(e => setX({status:'error', error: e}))`. Render a distinct error panel ("Could not load findings — <detail>. Retry") that is visually unmistakable from the empty state, and NEVER render a zero count or an empty list while any dependent fetch is in the error state. Add an ESLint rule banning empty catch blocks in `frontend/`.

**Verifier note.** Downgrade blocker -> high. Add: a *total* outage does surface via the api.health() catch at page.tsx:52; the silent-zeros case requires a partial failure. Add the stronger evidence that `Health.db` is fetched (api.ts:18, types.ts:65) and never displayed — page.tsx:68 reads only health.snapshot_id.

</details>

<details>
<summary><b>The staging UI and push plan tell the operator "Change written to the AlgoSec data source" and "Data source updated" for a push that touches nothing</b><br/><code>claim-overreach</code> &middot; <code>backend/src/change/staging.py:122</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** "Connected to the AlgoSec policy data source" and "Applied to AlgoSec — data source updated" are factual assertions about a system the product has never contacted. A security-savvy client who asks "so it pushed to our firewall?" gets a yes from the UI and a no from the code. That is the kind of discovery that retroactively taints every other claim in the demo — including the ones (the conflict math) that are genuinely true.

**Failure scenario.** During a client walkthrough, the operator pushes a staged change. The UI animates "Connect to AlgoSec ✓ / Validate change payload ✓ / Detect conflicts ✓ / Apply change ✓ / Update data source ✓" and settles on "Applied to AlgoSec — data source updated". The client's firewall admin checks AlgoSec, finds nothing, and asks what else in the demo was simulated.

**Evidence.** staging.py:1-8 is honest in the docstring:
    "We are not wired to AlgoSec / Guardicore / Wiz, so the push is *simulated* -- but
     the conflict math is genuine engine math"

But the strings it emits to the operator are not:
staging.py:100-125
    {"key": "connect", "label": f"Connect to {tool}", "status": "ok",
     "detail": f"Connected to the {tool} policy data source."},
    ...
    steps.append({"key": "apply", "label": "Apply change", "status": "ok",
                  "detail": f"Change written to the {tool} data source."})
    steps.append({"key": "verify", "label": "Update data source", "status": "ok",
                  "detail": "Data source updated — the change is reflected on the next recompute."})

Staging.tsx:162 renders the terminal state with no simulation caveat:
    <span className="flex items-center gap-1.5 text-[12px] text-ok"><ShieldCheck size={13} /> Applied to {TOOL_LABEL[item.target_tool] ?? item.target_tool} — data source updated</span>

Staging.tsx:36-39 does say "Push runs a stepped, deterministic deployment ... then writes the change to the data source" — again with no "simulated".

The conflict detection IS real engine math (staging.py:65-79 walks `ctx.records` with `ipaddress` overlap checks) — that part of the claim holds.

**Fix.** Relabel every step and terminal state to be explicit: "Simulate connect to AlgoSec", "Change staged for AlgoSec (simulated push — no live connector configured)", and add a persistent `simulated: true` badge on the staged card. Return `"simulated": true` in the push-plan payload so the honesty is in the API contract, not just the copy. Keep the conflict-math language exactly as it is — that claim is earned.

**Verifier note.** RAISE medium -> high. The rest of the product is careful to mark simulation (Topbar.tsx:111 'Demo only', :118 'Demo dataset · simulated'), which makes Staging the sole screen that affirmatively tells an operator a change was written to AlgoSec. Truthfulness defect on the highest-visibility demo screen; two-word fix.

</details>

<details>
<summary><b>The audit trail records no human identity — `actor` is a three-value enum and every call site passes the literal string "user"</b><br/><code>claim-overreach</code> &middot; <code>db/schema.sql:218</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** main.py:554 calls the merge list "the human-decision audit trail for identity" and the product is sold on change governance with an audit trail. A trail that cannot answer "who deleted that snapshot" or "who pushed that firewall change" is not an audit trail — it is an event log. Any client with a compliance function (and PCI-DSS is named in the report capability) will fail this on inspection. Combined with the forgeable role header, it also means an attacker leaves no attributable trace.

**Failure scenario.** Two analysts and an admin share the app. A staged change is pushed that opens an exposure. The client asks who approved and pushed it. `GET /api/audit` returns `{actor: "user", action: "push_staged_change", subject: "stage_ab12...", detail: {status: "pushed", target_tool: "algosec"}}` — indistinguishable across all three users, and identical to what an unauthenticated internet caller would have produced.

**Evidence.** db/schema.sql:215-222
`CREATE TABLE IF NOT EXISTS audit_log (\n    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),\n    ts timestamptz NOT NULL DEFAULT now(),\n    actor text NOT NULL CHECK (actor IN ('agent', 'user', 'system')),\n    action text NOT NULL,\n    subject text,\n    snapshot_id text REFERENCES snapshots(snapshot_id) ON DELETE SET NULL,\n    detail jsonb NOT NULL DEFAULT '{}'::jsonb\n);`

There is no email/sub/actor_id column, and every write passes a hardcoded literal:
main.py:764 `audit(cur, "user", "push_staged_change", subject=staged_id, snapshot_id=row.get("snapshot_id"), detail={"status": plan["status"], "target_tool": row.get("target_tool")})`
main.py:256 `audit(cur, "user", "delete_snapshot", subject=snapshot_id, detail={})`
main.py:527 `audit(cur, "user", action, subject=f"{a}~{b}", ...)`
main.py:855 `audit(cur, "user", "set_tool_roles", subject=key, detail={"enabled_roles": roles})`
...15 call sites, all literal "user"/"agent"/"system".

`request_ctx.current().email` IS available (it is used at main.py:664 for `requested_by` and main.py:854 for `updated_by`) — it is simply never passed to `audit()`. The exposed endpoint returns only these columns: main.py:1017 `SELECT ts,actor,action,subject,detail FROM ztpa.audit_log ORDER BY ts DESC LIMIT 50`, and that endpoint (main.py:1014 `@app.get("/api/audit")`) has no guard.

**Fix.** Add `actor_email text` and `actor_sub text` (and optionally `actor_role`) to `ztpa.audit_log` in a migration, change `db.audit()` to read `request_ctx.current()` itself rather than taking a literal (keep the enum as `actor_kind`), and surface the identity in `/api/audit`. Then guard `/api/audit` — an audit log is a security artifact and should be admin-only.

**Verifier note.** Soften 'records no human identity' slightly: three adjacent places DO capture it — change_requests.requested_by (main.py:663), tool_settings.updated_by (main.py:854), and reject_change writes the email into the audit detail jsonb (persist.py:278, `detail={"by": by, ...}` where by = request_ctx.current().email, main.py:791). Also ai_metrics.actor_email exists (metrics.py:41). So identity is captured for submit/reject/tool-toggle but NOT for stage, push, discard, delete_snapshot, merge, recompute or reset — which is still the material half and leaves the audit_log table itself identity-free. Severity high stands for a product whose pitch is a governed change trail.

</details>

<details>
<summary><b>The frontend disables TLS certificate verification on the Postgres connection that holds all user, role and auth-token data</b><br/><code>security</code> &middot; <code>frontend/lib/db.ts:12</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** `rejectUnauthorized: false` means the connection is encrypted but unauthenticated: any attacker who can intercept the path between the Vercel function and Neon can present any certificate and transparently MITM the session. Everything in that session is the crown jewels of the auth system — the DATABASE_URL credential itself, bcrypt hashes, unhashed single-use magic/reset tokens as they are inserted, and role assignments as they are written. Stripping `channel_binding=require` removes the SCRAM binding that would have detected exactly this. It is also the kind of line a client's security reviewer greps for.

**Failure scenario.** An attacker in a position to intercept the Vercel-to-Neon egress (compromised upstream resolver, hostile transit, or a misconfigured egress proxy) terminates TLS with a self-signed cert. `pg` accepts it. The attacker reads the Neon connection string's credentials off the startup packet and every subsequent query, including `INSERT INTO ztpa.auth_tokens (token, ...)` — giving them a valid magic-link token for any user the moment one is requested. They can also rewrite the `role` returned by `getUserByEmail`, escalating any session to admin.

**Evidence.** lib/db.ts:9-15
`let _pool: Pool | undefined;\nfunction pool(): Pool {\n  if (!_pool) {\n    _pool = new Pool({ connectionString: connectionString(), ssl: { rejectUnauthorized: false }, max: 3 });\n  }\n  return _pool;\n}`

and connectionString() at lib/db.ts:5-7 strips the channel-binding protection too:
`return (process.env.DATABASE_URL || "").replace(/([?&])channel_binding=[^&]*/g, "$1").replace(/[?&]$/, "");`

This is the pool used by every auth query — users.ts:21 `SELECT * FROM ztpa.app_users WHERE email = $1`, users.ts:28 `bcrypt.compare(password, u.password_hash)` on the row it returns, tokens.ts:9 the magic/reset token insert, and users.ts:87 `provisionSsoUser` which writes the resolved app role. The backend's psycopg pool (backend/src/db.py:61) does NOT do this — it passes DATABASE_URL through unmodified, so the two halves of the app disagree about DB transport security.

**Fix.** Drop the override: use `ssl: true` (or `ssl: { rejectUnauthorized: true }`) and keep `sslmode=require` in the URL. Neon presents a publicly-trusted certificate, so verification succeeds with Node's default CA bundle — the `rejectUnauthorized: false` is almost certainly cargo-culted from a local-dev workaround. Stop stripping `channel_binding`; if `pg` genuinely rejects it, pin `channel_binding=prefer` rather than removing the parameter. Add a startup assertion that refuses to boot in production with verification disabled.

**Verifier note.** The stated mechanism ('the two halves disagree about DB transport security') is right in outcome but the reasoning needs a fix: libpq/psycopg with Neon's default `sslmode=require` ALSO does not verify the server certificate (only `verify-ca`/`verify-full` do). The genuine asymmetry is that the backend keeps `channel_binding=require` — SCRAM channel binding, which is precisely what defeats an active TLS-terminating MITM — while the frontend strips it AND turns off cert verification, removing both defences at once. The exploit therefore requires an active network position on the Vercel→Neon egress, not passive observation. High still fits given the data at stake.

</details>

<details>
<summary><b>No rate limiting, no request-size limit, and no auth on the cost-bearing LLM endpoints — a direct billing-DoS on the hosted OpenAI key</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/app/main.py:916</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** Combined with finding #1 (no backend auth), an anonymous internet caller can convert your OpenAI account balance into their own denial-of-service, and `POST /api/recompute` (also unguarded, main.py:163) rebuilds the entire engine synchronously on a Render free instance. Even if you fix the auth boundary, any authenticated viewer can do it. There is no per-actor quota despite `ai_metrics` recording exactly the data a quota would need.

**Failure scenario.** A loop of `curl -X POST https://ztpa-backend.onrender.com/api/campaign/plan -d '{}'` runs unauthenticated. Each call executes the multi-round agentic remediation campaign against gpt-4o with no cap. The OPENAI_API_KEY is drained overnight, `provider_status()` starts reporting failures, and every advisory feature silently degrades to `engine_fallback` mid-demo. Simultaneously `POST /api/recompute` in a tight loop reassigns the module-global `_ENGINE` (main.py:173) while other requests read it, pegging the free instance.

**Evidence.** There is no rate-limiting middleware and no such dependency — backend/requirements.txt lists only `fastapi, uvicorn[standard], pydantic, networkx, python-dotenv, anthropic, openai, psycopg[binary], psycopg_pool, pytest, httpx` (no slowapi/limits). The only middlewares registered are CORS and the actor reader (main.py:44-66).

The expensive endpoints are gated only by a default-on capability toggle:
main.py:916-919 `@app.post("/api/agent/ask")\ndef agent(body: AskBody):\n    _require_capability("assistant")\n    result = agent_ask(engine(), body.question)`  — `AskBody.question: str` is unbounded (main.py:912-913).
main.py:418-429 `@app.post("/api/campaign/plan")` -> `campaign_mod.plan(e, target_bands=bands)` — an N-round propose/re-simulate loop over every critical finding.
main.py:1008-1011 `@app.post("/api/connectors/propose")\ndef propose_connector(body: ProposeBody):\n    _require_capability("authoring")\n    return authoring.propose_profile(body.sample, body.tool_hint)` — `sample: dict` unbounded, and authoring.py:97 runs up to `MAX_ATTEMPTS = 3` model calls, each re-normalizing the FULL sample via `apply_profile` (only the prompt is truncated: authoring.py:80 `json.dumps(sample)[:6000]`).
main.py:997-1000 `@app.post("/api/intake")` — unbounded `text`.
On Render the provider is forced hosted: render.yaml:25-28 `ADVISORY_PROVIDER=openai`, `OPENAI_MODEL=gpt-4o`.

There is also no login rate limiting: auth.ts:18-22 `authorize: async (c) => { const u = await verifyUserPassword(...) }` with no attempt counter, and app/actions.ts:11/23 mint a fresh token on every `requestMagic`/`requestReset` call with no throttle.

**Fix.** Fix the auth boundary first (finding #1). Then: add a rate limiter (slowapi or an in-process token bucket keyed on `request_ctx.sub()`) with tight per-actor limits on the six LLM endpoints; add `max_length` constraints to the Pydantic bodies (`question: str = Field(max_length=2000)`, `text`, `tool_hint`) and a byte cap on `sample` (reject > ~256 KB before `propose_profile`); put a global body-size limit in front of uvicorn (`--limit-max-requests` is not it — use a Starlette middleware that reads `content-length`); and add a daily cost ceiling read from `ztpa.ai_metrics` that trips `_require_capability` closed. Add login/reset throttling by email+IP.

</details>

<details>
<summary><b>Malformed or partial vendor exports crash the whole engine with an uncaught KeyError/TypeError — zero tests for any bad input</b><br/><code>robustness-gap</code> &middot; <code>backend/src/normalizers/algosec.py:49</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** The product's roadmap headline is dynamic connector authoring — 'paste a sample, the model proposes a SourceProfile, the engine validates it'. That path exists precisely to consume exports nobody has seen. The static normalizers, which are what a real AlgoSec/Guardicore/Wiz integration would use, assume every rule is perfectly shaped. One missing field in one rule of a 4,000-rule export takes down the whole snapshot with a raw traceback — no partial result, no 'skipped 3 malformed rules' report, no row-level provenance for what was dropped.

**Failure scenario.** A client exports from AlgoSec with a disabled rule that omits `action`, or a rule whose `src` is a group object the exporter serialised as null. `python tasks.py precompute` dies with `KeyError: 'action'`. Zero findings are produced, the dashboard has no snapshot, and the operator has a stack trace instead of a report. Worse silent case: a typo'd CIDR `999.999.999.999/8` fails `is_cidr()` (common.py:57-65) and is silently created as a *named identity asset* — the rule now appears to allow traffic from a host that does not exist, produces 0 findings, and nothing warns anyone.

**Evidence.** ```python
for rule in export.get("rules", []):
    s_val, s_kind, s_ip, _s_cidr, _s_tags, s_ent = _resolve(rule["src"], objects)   # line 49
    d_val, ... = _resolve(rule["dst"], objects)                                     # line 50
    ...
    id=rule["rule_id"], source_tool=TOOL, raw_ref=rule["rule_id"],                  # line 55
    action=rule["action"], order=rule.get("order"),                                 # line 59
```
Four unguarded subscripts. I fed a scratch MOCK_DIR (repo untouched) 11 shapes through `run()`:
  [FAIL] missing 'action' key ...... KeyError: 'action'      (algosec.py:59)
  [FAIL] missing 'src' key ......... KeyError: 'src'         (algosec.py:49)
  [FAIL] src: null ................. TypeError: argument of type 'NoneType' is not iterable
  [FAIL] rules is a dict not list .. TypeError: string indices must be integers, not 'str'
  [OK]   empty snapshot ............ 0 records, 0 findings
  [OK]   single asset, no rules .... 0 findings
  [OK]   disconnected graph ........ 1 finding
  [OK]   IPv6 (::/0 -> 2001:db8::1 tcp/3389, pci) ... sev=90 critical forced=True
  [OK]   duplicate rule_id ......... 2 records, 2 findings
  [OK]   garbage CIDR '999.999.999.999/8' ... 1 record, 0 findings (silently reclassified)
  [OK]   tcp/-5 and tcp/99999 ...... 2 findings
No test in test_agents.py exercises any of these; the only input the suite has ever seen is backend/data/mock/*.json.

**Fix.** Add `backend/tests/test_normalizers.py` with a parametrised bad-input table covering exactly the 4 crashing shapes plus the silent-garbage-CIDR case, asserting the engine returns a result with a populated `skipped`/`warnings` list rather than raising. Then make the normalizers honour it: replace `rule["src"]` etc. with a `_require(rule, "src", "dst", "rule_id", "action")` guard that appends to `NormalizeResult.warnings` and `continue`s, and have `is_cidr` reject anything containing '/' that fails to parse (surface it as a warning instead of coercing to an identity).

**Verifier note.** One important nuance the auditor missed, which cuts BOTH ways. `backend/src/normalizers/profile.py` — the declarative 'bring your own source' normalizer — is fully defensive (`rule.get(fm.src)` at :78, `raw.get(profile.rules_path, []) or []` at :76, `action if action in ('allow','deny') else 'allow'` at :96) and would not crash. But `apply_profile` is called from exactly one place in the entire repo — `advisory/authoring.py:47` inside `validate_profile` — and its output is never persisted or fed to `normalize_all()`. So the guarded path is a validation stub, and algosec.py IS the only way real AlgoSec data can enter the engine, which makes the crash more reachable, not less. Severity high stands, driven by the silent 0-findings case more than the loud KeyErrors.

</details>

<details>
<summary><b>No CI, and the test suite is not reachable from any documented command — `verify` is what the docs sell as proof</b><br/><code>prod-readiness-gap</code> &middot; <code>D:/EY DEV/ZTPA/ztpa/tasks.py:195</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** 16 genuinely good agent tests exist and a new contributor following the README will never learn they exist, never run them, and nothing will run them on push. The word 'Optional' next to the only verification command sets the exact wrong expectation. For a security product this is the first thing a technical buyer asks about, and 'we have no CI' plus 'the test command isn't documented' is an indefensible answer.

**Failure scenario.** Any commit that breaks `campaign.plan`'s monotonicity guarantee or `classify_change`'s fail-closed path merges to main unchallenged, because the only gate anyone knows about is `tasks.py verify` — which does not import advisory/ at all.

**Evidence.** `.github/` does not exist (confirmed by `ls -la .github` -> NO .github). The COMMANDS dict in tasks.py:195-212 is: help, setup, db, seed, seed-scale, precompute, precompute-ai, demo, backend, frontend, dev, verify, admin, set-password, send-reset, stop. There is no `test`. The Makefile `.PHONY` line 7 is identically test-free. Grepping README.md, DEMO.md, docs/ENGINE.md, docs/FEATURES.md, docs/AGENTS.md for `pytest|test suite|coverage` returns nothing about running tests — the only hit is README.md:82 `# Optional: prove the engine meets every acceptance criterion` / `python tasks.py verify`. `pytest>=8.0` is in requirements.txt:14 under `# dev / test`, so the suite is installed but orphaned.

**Fix.** Add `cmd_test` to tasks.py COMMANDS running `[venv_python(), "-m", "pytest", "backend/tests", "-q"]`, a matching `test:` Makefile target, and `.github/workflows/ci.yml`: python 3.12 -> pip install -r backend/requirements.txt -> `python tasks.py verify` -> `python tasks.py test` -> `cd frontend && npm ci && npm run build`. Add a `pytest.ini` with `testpaths`, `pythonpath = backend`, and `-p no:randomly`. Document `python tasks.py test` in the README quickstart, above `verify`.

**Verifier note.** Severity lowered blocker->high. 'There is no CI' was given to the auditor as stated context in the task prompt, so half this finding restates the premise; and unlike #1 and #2 it produces no wrong result and breaks no demo. The novel, load-bearing half — the suite is installed but orphaned, and `verify` is what the docs sell as proof while importing none of advisory/ — is fully verified and worth acting on.

</details>

<details>
<summary><b>The snapshot fingerprint ignores the object catalog — different postures collapse to the same snapshot_id and the same finding ids</b><br/><code>correctness-bug</code> &middot; <code>backend/src/analyzers/run_all.py:57</code> &middot; CONFIRMED &middot; effort S</summary>

**Why it matters.** A content fingerprint exists to answer 'did anything that matters change?'. This one answers 'did a rule row change?' — and asset tagging is exactly what the entire severity model keys on (D sub-score, SENSITIVE_TAGS, all three guardrail floors, cross_tool_path sensitivity). Retag one asset as PCI and the engine's verdict flips from nothing to forced-critical while the system of record insists it is the same snapshot. Cached AI artifacts are keyed by (snapshot_id, finding_id) — precompute_ai.py:41-42 does `cache_explanation(cur, f.id, ...)` — so an explanation written for the old posture is served verbatim against the new severity.

**Failure scenario.** Ops adds the `pci` tag to `app-server-08` in the AlgoSec object catalog and re-runs `python tasks.py demo`. The snapshot id is unchanged, so any 'has the posture changed since last scan' check says no. The finding for ALGO-046 keeps id F_xxx but its severity jumps from medium to critical; the cached explanation from the previous run — narrating a medium ops-RDP rule — is what the dashboard renders next to a red CRITICAL badge. In a client demo the AI prose directly contradicts the engine number, which is the single worst thing that can happen to a product whose pitch is 'the engine owns the facts'.

**Evidence.** ```python
def _fingerprint(records: list[PolicyRecord]) -> str:
    return content_fingerprint(sorted(
        f"{r.source_tool}|{r.raw_ref}|{r.source}|{r.destination}|{r.service}|{r.action}|{r.order}"
        for r in records
    ))
```
No asset tags, no IPs, no object types. docs/ENGINE.md:386-388 claims: "The snapshot fingerprint hashes each normalized record's `tool|ref|source|destination|service|action|order` (`run_all.py:_fingerprint`), so any change to the inputs yields a new snapshot id."

I ran the engine against a scratch MOCK_DIR (repo untouched) with one rule `0.0.0.0/0 -> host-a tcp/8443 allow`, varying only the object catalog:

  host-a tags []                     sid=snap_d5ffc06f8db9  findings=[]
  host-a tags [pci, crown-jewel]     sid=snap_d5ffc06f8db9  findings=[('over_permissive', 100, 'critical', True)]
  SAME SNAPSHOT ID? True

  host-a ip 10.0.0.1                 sid=snap_d5ffc06f8db9
  host-a ip 10.99.99.99              sid=snap_d5ffc06f8db9   (IP drives cross-tool identity merging -> graph shape)
  SAME SNAPSHOT ID? True

  host-a type "host"                 sid=snap_d5ffc06f8db9
  host-a type "network"              sid=snap_d5ffc06f8db9   (drives concrete/abstract -> path traversal validity)
  SAME SNAPSHOT ID? True

And the finding id is `det_id("F", sid, f.id)` (run_all.py:94) where the local key is `f"over_permissive|{rec.source_tool}|{rec.raw_ref}"` (over_permissive.py:73) — also unchanged. So the *same* F_ id exists at severity 100 in one posture and does not exist at all in the other.

**Fix.** Fold the entity/asset view into the fingerprint: hash `sorted(f"{e.tool}|{e.name}|{e.kind}|{e.ip}|{e.cidr}|{sorted(e.tags)}|{e.abstract}" for e in nr.entities)` alongside the record digest. Then add `backend/tests/test_snapshot_id.py::test_fingerprint_changes_when_tags_change` asserting the two ids differ, plus the IP and object-type cases above. Correct the ENGINE.md §9 sentence to describe what is actually hashed.

**Verifier note.** Two corrections. (1) The stated failure scenario is wrong in its most vivid detail: cached explanations CANNOT go stale this way. persist.py:63 calls `delete_snapshot_children` (db.py:222-225 = `DELETE FROM ztpa.snapshots WHERE snapshot_id=%s`, cascading to findings) and the re-insert at persist.py:126-131 explicitly writes `"explanation": None`. Every `tasks.py demo` wipes explanations, so the 'AI prose contradicts the engine number' demo disaster does not occur on that path. (2) The real downstream victims are better than the one cited, and the auditor missed them: `campaign_plans` (schema.sql:319-323), `staged_changes` (schema.sql:298) and `remediation_revisions` (schema.sql:279) have NO foreign key to `snapshots`, so they survive a recompute — and persist.py:325-326 states the assumption in code: 'or None if it was never planned (or the snapshot changed -- a recompute yields a new id, so the plan is naturally stale)'. A tag-only edit breaks exactly that invariant: the campaign plan and remediation thread from the old posture are served verbatim against the new one, and `remediation_thread_id(sid, finding_id)` (persist.py:211-212) resolves to the same thread. Severity lowered blocker->high because it produces no wrong severity number and is unreachable on the shipped seed path (seed_demo regenerates rules and objects together), but it is a genuine correctness bug plus a false doc claim on real data.

</details>

<details>
<summary><b>verify_engine.py is an existence-check golden test on ONE hardcoded dataset, not acceptance criteria — it cannot catch a regression on new data</b><br/><code>claim-overreach</code> &middot; <code>backend/scripts/verify_engine.py:30</code> &middot; CONFIRMED &middot; effort M</summary>

**Why it matters.** It is a useful smoke test for 'did I break the demo' and it is honestly wired (exits 1, prints per-check PASS/FAIL, reachable from both runners). But it verifies that five deliberately planted problems in one 27-rule file are still found. It says nothing about correctness on a customer's export, which is the only question a buyer cares about. Calling that 'proving every acceptance criterion' is the single largest gap between what a doc claims and what the code does in this dimension.

**Failure scenario.** A client hands over a 4,000-rule AlgoSec export. verify_engine passes (it always will — it runs against backend/data/mock, never the client data). The engine mis-scores their environment because a sub-score table or a band threshold regressed, and the only signal anyone had was a green 'ALL CHECKS PASSED' about a fixture that has nothing to do with their network.

**Evidence.** Every check is `find(lambda f: ...)` — an existence predicate over the seeded demo — or a literal pinned to that seed:
```python
p2 = find(lambda f: f.type == "over_permissive" and f.signals.get("exposed_port") == 3389 and "pci" in f.signals.get("dest_tags", []))
...
expected = ["0.0.0.0/0", "lb-public-01", "app-server-07", "internal-app", "db-prod-01"]
check("P5 path is the 5-hop chain", path == expected)
check("exactly one cross-tool path", sum(1 for f in fs if f.type == "cross_tool_path") == 1)
```
There is not one invariant check: no 'severity is in [0,100]', no 'forced_critical implies band == critical', no 'every path in a cross_tool_path finding is a real path in the graph', no 'every raw_ref resolves to a record', no 'no finding references a node absent from the graph'. Note also `check("P3 overlap present + low", ...)` and `check("P4 shadowed-deny present + low", ...)` only assert the band is `low` — the weakest possible band, satisfied by any score under 35 — and P5's `critical` comes from `forced_critical` (over_permissive.py:77 `severity_band="critical" if sc["forced_critical"] else band(...)`), so `band()` itself is never exercised by any check. That is why moving `band_critical` from 80 to 95 passes.

README.md:82 sells this as `# Optional: prove the engine meets every acceptance criterion`. docs/FEATURES.md:134: `scripts/verify_engine.py — added P6/P7 acceptance checks; all pass.`

**Fix.** Split into two files. Keep the demo golden checks as `backend/tests/test_demo_golden.py` (pytest, so CI runs it). Add `backend/tests/test_engine_invariants.py` with property checks that hold for ANY input, driven by a small generator of synthetic exports: 0 <= severity <= 100; `forced_critical` implies `severity_band == 'critical'`; every `f.raw_refs` entry exists in `records`; every `f.involved` node exists in the graph; every hop pair in a `cross_tool_path` is a real graph edge; `len(f.signals['severity_vector']) == 4` for every scored type. Soften the README/FEATURES wording from 'prove every acceptance criterion' to 'regression-check the demo dataset'.

**Verifier note.** Three factual corrections that do not change the verdict. (1) 'There is not one invariant check' is overstated — verify_engine.py:59 `check("every finding has a severity_vector", all("severity_vector" in f.signals for f in fs))` IS a universally-quantified structural invariant over all findings. The accurate statement is that there is no *numeric or semantic* invariant (no 0<=severity<=100, no forced_critical=>band=='critical', no path-exists-in-graph, no raw_ref-resolves). (2) 'band() itself is never exercised by any check' is false: P3 and P4 assert `severity_band == 'low'`, which is produced by `band()` via cidr_overlap.py:57 and shadowing.py:80. The correct statement is that only the *low* threshold is exercised, so band_critical/band_high can be moved freely. (3) The P5 citation is to the wrong analyzer: P5 is a `cross_tool_path` finding, so its forced-critical shortcut is path_trace.py:25, not over_permissive.py:77 — the quoted line text is identical in both files, so the quote is real but misattributed.

</details>

<details>
<summary><b>Ten src modules plus the entire 1018-LOC FastAPI app have literally zero executed coverage — including the whole DB write path</b><br/><code>prod-readiness-gap</code> &middot; <code>backend/src/persist.py:60</code> &middot; UNVERIFIED &middot; effort L</summary>

**Why it matters.** This is the deliverable list. Four of the nine advertised AI capabilities (rank, explain, report, intake) and two of the headline features ('ask your network' assistant, the staging conflict math) have never executed under test. persist.py at 0% means nothing verifies that an EngineResult actually maps into the schema — the layer between 'the engine computed it' and 'the dashboard shows it' is completely unguarded, and it is the layer that runs `delete_snapshot_children` then re-inserts. app/main.py at 0% means no endpoint has ever been called in a test: no auth check, no error shape, no 404, no pagination.

**Failure scenario.** A schema change in db/schema.sql (add a NOT NULL column) or a rename in models.py breaks `persist_engine_result`'s upsert dict. `pytest` prints 16 passed and `tasks.py verify` prints ALL CHECKS PASSED, because neither touches persist.py. The failure surfaces for the first time when someone runs `python tasks.py demo` before a demo and gets a psycopg error, or worse, `delete_snapshot_children` succeeds and the re-insert fails — leaving the demo with an empty snapshot 10 minutes before the client call.

**Evidence.** Measured with a stdlib line tracer wrapped around `pytest backend/tests` (coverage.py is not installed in the venv). Statement coverage of backend/src during the suite: TOTAL 61.7% (1461/2366).

ZERO EXECUTED LINES:
  backend/src/persist.py .................. 0/146 stmts (368 LOC) <- every DB write
  backend/src/advisory/rank.py ............ 0/73  (118 LOC)
  backend/src/change/staging.py ........... 0/71  (129 LOC) <- the 'genuine engine conflict math'
  backend/src/scenarios.py ................ 0/43  (96 LOC)
  backend/src/advisory/orchestrator.py .... 0/40  (111 LOC)
  backend/src/advisory/entity_suggest.py .. 0/35  (63 LOC)
  backend/src/advisory/explain.py ......... 0/31  (58 LOC)
  backend/src/advisory/report.py .......... 0/22  (73 LOC)
  backend/src/agent/assistant.py .......... 0/51  (95 LOC) <- 'ask your network' assistant
  backend/src/advisory/intake.py .......... 0/16  (48 LOC)
  backend/app/main.py ..................... never imported (1018 LOC, every endpoint)
  db/migrate.py ........................... never imported (64 LOC)

PARTIAL, and only incidentally:
  agent/tools.py 32.8% | advisory/client.py 33.9% | change/apply.py 40.8% | tools_registry.py 45.2% | db.py 52.0% | graph/reachability.py 66.3%

HIGH EXECUTED / ZERO ASSERTED (driven only by the `eng` fixture at test_agents.py:26-28):
  analyzers/over_permissive.py 100%, path_trace.py 100%, transport_exposure.py 100%, graph/zones.py 100%, ids.py 100%, models.py 100%, normalizers/* 90-97%, severity.py 91.3%, identity.py 94.9% — with zero assertions on any of their outputs.

Ratio: 6,167 LOC of backend/src+app against a single 355-line test file.

**Fix.** Ordered by value-per-effort: (1) `backend/tests/test_api_smoke.py` using `fastapi.testclient.TestClient` with the DB layer monkeypatched to a fake — assert 200/shape on the ~10 read endpoints and 401/403 on the guarded ones; this alone lifts app/main.py from 0. (2) `backend/tests/test_persist.py` — assert the row dicts `persist_engine_result` builds against a recording fake cursor, checking every column exists in db/schema.sql and every id is deterministic. (3) `backend/tests/test_staging.py` — the conflict math is pure and needs no mocks: pin duplicate / overlap / shadow / contradiction detection on hand-built rule pairs. (4) `backend/tests/test_rank.py` and `test_report.py` with a stubbed `complete`, mirroring the fail-closed pattern already used well in test_agents.py.

</details>


### MEDIUM and LOW

| Sev | Finding | Location | Category |
|---|---|---|---|
| medium | The Anthropic path hardcodes max_tokens=1500, silently truncating the six-section board-ready posture narrative mid-sentence and returning it as a success | `backend/src/advisory/client.py:98` | correctness-bug |
| medium | Assistant tool results are truncated with a raw string slice, feeding the model invalid JSON; effective_policy's source list is uncapped | `backend/src/agent/assistant.py:69` | robustness-gap |
| medium | Layer 3 — the engine override the README sells as injection-proof — has zero test coverage; the test named for it short-circuits at Layer 1 and never calls the model stub | `backend/tests/test_agents.py:219` | prod-readiness-gap |
| medium | "PCI-DSS / Zero-Trust" reporting is unmapped model prose over finding counts; the only deterministic compliance content is one hardcoded sentence | `backend/src/advisory/report.py:15` | claim-overreach |
| medium | The remediation loop never constrains target_ref to the finding's own rules, and "proven" only means "no NEW CRITICAL" — a model-authored change to an unrelated rule can be certified and auto-approved into the durable overlay | `backend/src/advisory/remediation.py:97` | correctness-bug |
| medium | The assistant loop and the campaign planner have no effective latency bound: up to ~1 hour and ~36 minutes respectively on a single synchronous request, contradicting the docs' "per-call timeout" guarantee | `backend/src/agent/assistant.py:49` | prod-readiness-gap |
| medium | /api/health returns status:ok with a dead database, and pays a ~10s cold engine build | `backend/app/main.py:153` | prod-readiness-gap |
| medium | There is no migration system: migrate.py re-executes schema.sql, and schema.sql is already out of sync with the code | `db/migrate.py:50` | prod-readiness-gap |
| medium | Merge confirm and reset-demo split one logical operation across two or three independent transactions | `backend/app/main.py:537` | robustness-gap |
| medium | Cached ranked actions are always reported as ranked_by 'llm', even when produced by the deterministic fallback | `backend/app/main.py:962` | claim-overreach |
| medium | _ACTIVE_SCENARIO stores the scenario id but not n, so any recompute silently regenerates a different 'scale' dataset | `backend/app/main.py:203` | correctness-bug |
| medium | Schema migrations run as ALTER TABLE inside request transactions, guarded by a module flag set before commit | `backend/src/persist.py:46` | prod-readiness-gap |
| medium | _ENGINE / _ACTIVE_SCENARIO are unlocked module globals, and every rebuild rewrites shared JSON files on disk | `backend/app/main.py:79` | robustness-gap |
| medium | Unvalidated limit parameter (negative -> 500) and no pagination on any collection endpoint | `backend/app/main.py:607` | robustness-gap |
| medium | upsert_many exceeds Postgres' 65535 bind-parameter limit above ~2600 rules; /api/admin/dataset accepts an unbounded n | `backend/src/db.py:191` | robustness-gap |
| medium | Zero logging in the entire backend, combined with 14 bare exception swallows | `backend/src/metrics.py:52` | prod-readiness-gap |
| medium | Apply silently drops malformed or stale changes while the UI and DB report success | `backend/src/change/apply.py:53` | robustness-gap |
| medium | The audit log records no identity - including for the manual override of an escalate verdict - and is not tamper-evident | `backend/src/db.py:228` | prod-readiness-gap |
| medium | simulate_change computes only internet->sensitive path diffs, and never re-analyzes for new findings | `backend/src/change/simulate.py:21` | claim-overreach |
| medium | The "proof" that a fix resolves only checks criticals, and nothing re-proves at push/apply time | `backend/src/advisory/remediation.py:115` | claim-overreach |
| medium | A rejected change request can still be pushed; an already-pushed one can be re-pushed | `backend/app/main.py:750` | correctness-bug |
| medium | target_ref is never validated against the finding, and raw_ref matching is not scoped by tool | `backend/src/change/apply.py:35` | robustness-gap |
| medium | "Exactly one cross-tool path" is an artifact of seed data authored so no two tools ever describe the same edge | `backend/src/graph/reachability.py:32` | demo-grade |
| medium | ENGINE.md — the formula reference a technical client will read — is materially stale in three places | `docs/ENGINE.md:262` | claim-overreach |
| medium | "Exact E x P x D x B severity vector" — the cross-tool path's P is taken from an alphabetically-chosen grant, not the most permissive one | `backend/src/graph/reachability.py:28` | correctness-bug |
| medium | The 4000-path scan cap silently drops findings with no truncation signal anywhere in the output | `backend/src/graph/reachability.py:124` | prod-readiness-gap |
| medium | "PCI-DSS / Zero-Trust posture report" is an LLM paragraph over 8 counters with one hard-coded requirement number; entity suggestions only ever consider PCI-tagged pairs | `backend/src/advisory/report.py:15` | claim-overreach |
| medium | The QUIC blind-spot detector fires on any rule with a blind app, ignoring reachability and zone — and one of the "apps" it detects is invented | `backend/src/analyzers/transport_exposure.py:43` | claim-overreach |
| medium | "Re-simulated by the engine to PROVE it resolves" is tautological for the most common finding type, and the "surgical" fallback is always `remove the rule` | `backend/src/advisory/remediation.py:60` | claim-overreach |
| medium | "Shadowed deny = traffic you meant to block is actually allowed" — the analyzer never checks that the shadowing rule is an allow | `backend/src/analyzers/shadowing.py:69` | correctness-bug |
| medium | Shadowing's "overlapping service" test is exact string equality on the display label | `backend/src/analyzers/shadowing.py:28` | correctness-bug |
| medium | "Detects and resolves real conflicts in real time" is a one-shot response replayed by setTimeout, with fabricated "Connected to AlgoSec" steps | `backend/src/change/staging.py:100` | demo-grade |
| medium | _ACTIVE_SCENARIO is an unpersisted module global that resets to 'demo' on every restart — and the reset also regenerates the exports on disk | `backend/app/main.py:80` | robustness-gap |
| medium | The audit trail the governance story rests on has no reader: 20+ write sites, one endpoint, and zero frontend consumers — and every recompute nulls its snapshot link | `backend/app/main.py:1014` | claim-overreach |
| medium | The persisted campaign plan has no FK and is excluded from every cache-clear — after a merge or a no-op recompute the UI shows a stale 'criticals 4 → 0' proof for findings that no longer exist | `backend/src/persist.py:325` | correctness-bug |
| medium | campaign_submit runs a full engine re-analysis per step inside a single open DB transaction — one failure discards every submission, and the connection is held for the whole batch | `backend/app/main.py:451` | prod-readiness-gap |
| medium | The 'Metrics & Cost' dashboard reports $0.00 for any model outside a 6-entry hardcoded price map, and the 'flagged' behaviour the comment promises does not exist | `backend/src/config.py:212` | correctness-bug |
| medium | Entity-merge suggestions do an unbounded O(n²) pair scan and then issue ONE embedding request containing 2 texts per candidate pair — no cap, no batching, inside the request | `backend/src/advisory/entity_suggest.py:44` | robustness-gap |
| medium | 'Bring your own source' has no ingestion path — an authored SourceProfile is validated against a sample and then discarded | `backend/src/normalizers/__init__.py:19` | claim-overreach |
| medium | Identity resolution is O(merged assets x distinct IPs) — 3.3 s at 2,000 merged assets, ~80 s at 10,000, on every single run | `backend/src/identity.py:123` | prod-readiness-gap |
| medium | IPv6 is silently wrong: a host address becomes a /32 network of 7.9e28 addresses, and exposure bands apply IPv4 prefix semantics to v6 | `backend/src/identity.py:32` | correctness-bug |
| medium | Canonical rule ids ignore the device, so duplicate rule ids upsert over each other and rules vanish without error | `backend/src/persist.py:29` | correctness-bug |
| medium | `cidr_overlap` is O(n²) within a destination group (500 same-dest rules = 4.25s for zero findings) and groups on the un-aliased raw destination | `backend/src/analyzers/cidr_overlap.py:39` | prod-readiness-gap |
| medium | Boundary inversion: a PCI asset that is ALSO internet-facing gets B=1.0 and escapes the cross-tool force-critical guardrail | `backend/src/analyzers/severity.py:167` | correctness-bug |
| medium | A fully-shadowed dead allow still emits a forced-critical over_permissive finding — no analyzer cross-talk | `backend/src/analyzers/over_permissive.py:38` | correctness-bug |
| medium | `reachable(src, dst, port)` filters only the terminal hop but is advertised to the model as an end-to-end port question | `backend/src/graph/reachability.py:153` | claim-overreach |
| medium | The shipped 'at scale' scenario adds only leaf nodes — it exercises none of the exponential path enumeration it claims to stress | `backend/scripts/seed_scale.py:28` | demo-grade |
| medium | Shadowing is O(n²) over a tool's rulebase — 25.4 seconds at 10k rules, and that is the best case | `backend/src/analyzers/shadowing.py:51` | prod-readiness-gap |
| medium | `tls_fallback_not_blocked` fires when the tcp/443 and udp/443 rules come from completely different sources — including on the shipped demo | `backend/src/analyzers/transport_exposure.py:82` | correctness-bug |
| medium | Background threads start with an empty ContextVar, so AI metrics from the explain path are attributed to the anonymous "viewer" default | `backend/app/main.py:358` | correctness-bug |
| medium | POST /api/campaign/plan is a synchronous request that can run for hours: up to 40 steps × 3 LLM calls × 120 s, plus ~200 full engine re-analyses | `backend/src/advisory/campaign.py:106` | prod-readiness-gap |
| medium | Startup race: the warm-engine thread and the first request both rebuild the engine with no lock, each truncating and rewriting data/mock/*.json while the other json.loads() them | `backend/app/main.py:102` | robustness-gap |
| medium | The recompute/reset overlay is a 300 ms timer decoupled from the backend, and renders a green "Snapshot recomputed" even when the call failed | `frontend/components/Topbar.tsx:56` | demo-grade |
| medium | The fetch wrapper throws away the backend's HTTPException detail, so a 403 role denial is displayed as "the API is not running" | `frontend/lib/api.ts:8` | robustness-gap |
| medium | Schema evolution happens as ALTER TABLE executed from API request handlers; there is no versioned migration tool, no rollback, and no backup story | `backend/src/persist.py:53` | prod-readiness-gap |
| medium | POST /api/admin/dataset accepts an unbounded `n` and rebuilds the engine synchronously — a single request can wedge the process for hours | `backend/app/main.py:190` | robustness-gap |
| medium | Backend dependencies are all `>=` ranges with no lockfile — the Render build is not reproducible and a transitive major bump can break a deploy with no code change | `backend/requirements.txt:2` | prod-readiness-gap |
| medium | Magic-link and password-reset URLs — bearer credentials — are written verbatim to the application log | `frontend/lib/email.ts:26` | security |
| medium | The analyze stage is super-linear and the advertised scale dataset produces zero extra findings — no perf test, no scale assertion | `backend/scripts/seed_scale.py:26` | demo-grade |
| medium | The determinism check runs both passes in ONE process and compares only 3 fields — it is structurally incapable of catching the likely failure mode | `backend/scripts/verify_engine.py:60` | prod-readiness-gap |
| medium | Frontend: zero tests, no ESLint config despite an `npm run lint` script, no typecheck step in any runner | `frontend/package.json:5` | prod-readiness-gap |
| medium | The suite has hidden network dependencies — it is 12x slower with no DB/Ollama because record_metric and ollama_probe are on the tested path | `backend/src/metrics.py:32` | prod-readiness-gap |
| low | The assistant's iteration-exhausted summarizer never checks fr.ok — a dead model produces an empty answer labelled with a successful provider | `backend/src/agent/assistant.py:71` | robustness-gap |
| low | The "Remediation Campaign agent" is a deterministic worst-first for-loop; the model never chooses the sequence, the target, or when to stop | `backend/src/advisory/campaign.py:106` | claim-overreach |
| low | Entity-merge suggestions emit a numeric confidence even when no embedding provider exists — sim silently becomes 0.0 and the score is pure tag overlap | `backend/src/advisory/entity_suggest.py:49` | robustness-gap |
| low | The triage investigator calls engine tools directly, bypassing the per-role tool registry the admin Tools screen controls | `backend/src/advisory/classify_change.py:74` | prod-readiness-gap |
| low | Ingested rule refs, asset names and display names flow raw into every prompt with no delimiting or escaping; only classify has a structural envelope behind it | `backend/src/advisory/remediation.py:50` | security |
| low | _normalize_args is annotated -> dict but returns whatever json.loads produced, including a list | `backend/src/agent/assistant.py:31` | robustness-gap |
| low | The agent's simulate_change tool advertises action="deny" but every non-allow record is dropped by the graph builder, so a simulated deny always reports "no change" | `backend/src/agent/tools.py:142` | demo-grade |
| low | Background explain threads lose actor context and leak entries into an unbounded process-global set | `backend/app/main.py:321` | robustness-gap |
| low | The AI-capability gate documented as 'fail-closed' actually fails OPEN during a DB outage | `backend/src/tools_registry.py:93` | claim-overreach |
| low | persist writes a hard FK asset_id for every graph node, but build_graph deliberately creates nodes with no backing asset | `backend/src/persist.py:114` | robustness-gap |
| low | Missing indexes on columns the API actually filters, joins, and sorts on | `db/schema.sql:329` | prod-readiness-gap |
| low | Unbounded free-text/dict request bodies forwarded to the LLM and stored as jsonb; pool never closed on shutdown | `backend/app/main.py:993` | prod-readiness-gap |
| low | The campaign's cumulative proof does not survive submission - each step is re-validated in isolation | `backend/app/main.py:466` | claim-overreach |
| low | The cached _ENGINE global has no lock; the warm-up thread races the first request into a concurrent snapshot delete+reinsert | `backend/app/main.py:102` | robustness-gap |
| low | Four docs give four different capability counts, and README's stated model routing does not match settings.py | `README.md:37` | claim-overreach |
| low | The Network Map's highlighted 'money shot' path is picked by SHA-derived finding id, not by severity | `backend/app/main.py:278` | correctness-bug |
| low | `python tasks.py stop` on Windows unconditionally kills every node.exe on the developer's machine | `tasks.py:184` | prod-readiness-gap |
| low | The per-role capability kill switch is enforced from a 5-second per-process cache that only the process serving the admin POST invalidates | `backend/src/tools_registry.py:80` | prod-readiness-gap |
| low | The `overlaps` relation is unreachable dead code — CIDR blocks are always nested or disjoint | `backend/src/analyzers/cidr_overlap.py:25` | claim-overreach |
| low | ENGINE.md's 'Known simplifications' section is stale and undercounts the analyzers — it reads as a complete caveat list and is not | `docs/ENGINE.md:405` | claim-overreach |
| low | 46% of critical-band vectors collapse to exactly 100 — the top of the scale cannot rank | `backend/src/analyzers/severity.py:76` | prod-readiness-gap |
| low | Shadowing is scoped by TOOL, not by firewall/rulebase, and Guardicore's rule order is invented from list index | `backend/src/analyzers/shadowing.py:46` | correctness-bug |
| low | Dead computation in the change-delta path: `dest_score(proposed.dest_tags)` is computed and discarded | `backend/src/change/simulate.py:49` | prod-readiness-gap |
| low | /api/graph returns the full node/edge/path payload with no pagination, and NetworkMap's default "Focus" mode has no node cap | `frontend/components/NetworkMap.tsx:88` | prod-readiness-gap |
| low | close_pool() is written for shutdown but never called — there is no shutdown hook at all, so SIGTERM drops pooled Neon connections mid-flight | `backend/app/main.py:135` | prod-readiness-gap |
| low | cross_tool_paths silently truncates at 4,000 candidate paths per target — findings are dropped at scale with no signal anywhere in the response | `backend/src/graph/reachability.py:21` | correctness-bug |
| low | precompute_ai --explanations holds one Postgres transaction open across a serial LLM call per finding | `backend/scripts/precompute_ai.py:29` | prod-readiness-gap |
| low | RiskTodo initialises the open-accordion state from an empty actions array, so the first action never auto-expands | `frontend/components/RiskTodo.tsx:36` | correctness-bug |
| low | Staging discard has a try/finally with no catch — a failed DELETE produces an unhandled promise rejection and no user feedback | `frontend/components/Staging.tsx:98` | robustness-gap |
| low | Background threads run with the default anonymous actor, so LLM metrics and per-role tool enforcement inside them are attributed to `viewer`/null | `backend/app/main.py:358` | robustness-gap |
| low | `consumeToken` single-use enforcement is a read-then-write race, so a magic/reset token can be redeemed twice | `frontend/lib/tokens.ts:19` | correctness-bug |
| low | CORS permanently allows `http://localhost:3000` in every deployment, with wildcard methods and headers | `backend/app/main.py:45` | security |
| low | The 'Known simplifications' section — the doc whose entire job is honesty about limits — describes code that no longer exists | `docs/ENGINE.md:398` | claim-overreach |
| low | The suite only imports because of an undocumented 0-byte conftest.py — no pytest.ini, no pyproject.toml, no pythonpath declaration | `backend/conftest.py:1` | prod-readiness-gap |
| low | A documented command overwrites the git-tracked file the test suite uses as its only fixture | `backend/scripts/seed_scale.py:33` | prod-readiness-gap |

---

## Findings that were refuted

Recorded so they are not re-raised.

- **Within one tool, a second IP or conflicting identifier for the same name is silently discarded (first-write-wins)** — The quoted code at common.py:169-171 is real and I did reproduce first-write-wins by calling merge_entities directly (10.0.1.5 wins, and reversing the order yields 52.20.10.10). But the finding is unreachable as described and the stated failure scenario is wrong about the call graph. wiz.py — the tool named in the scenario — never calls merge_entities at all: its import at wiz.py:10 is `from .common import INTERNET_CIDR, NormalizeResult, ObservedEntity, ResolvedObject, parse_service`, and it builds entities via a name-keyed dict (wiz.py:23-28, wiz.py:42-46 `if nm not in entities`). Nor can a W
- **The Change Gate's custom-change path hardcodes dest_tags=[], blinding the sensitive-destination guardrail — a /24 → PCI database grant evaluates as CLEAN and is eligible for auto-approve** — The quoted `dest_tags=[]` at main.py:594 is real, and I reproduced the blinding at the model level: simulate_change on 10.20.5.0/24 -> db-prod-01 tcp/1433 gives new_over_permissive=[] with dest_tags=[] and ['regulated destination reachable from more than a single host'] with the real tags (E=0.3 == OVERPERMISSIVE_CONFIG['sensitive_dest_min_E']). BUT the described end-to-end scenario is impossible, because the auditor's quote silently skipped the line immediately above the one they cited. main.py:584 is `proto, port, label = parse_service(body.service)` and `parse_service` returns a `DecodedSer
- **/api/findings/{fid} hardcodes the active snapshot, so opening a finding from a historical snapshot 404s** — The code observation is accurate — main.py:311-317 uses `sid()` not `view_sid(snapshot)`, and _finding() (131-132) searches engine().findings — but the failure scenario does not happen. First, GET /api/findings/{fid} has NO caller: I grepped the whole frontend for 'api/findings/' and lib/api.ts only ever hits the /explain, /remediate, /remediate/refine and /remediation-thread sub-routes; there is no findingDetail method. Second, the historical view is deliberately read-only and never calls those sub-routes: console/page.tsx:68 computes `historical`, line 97 passes `readOnly={historical}` to Ri
- **No multi-tenancy of any kind: one global namespace, no tenant/org column, no RLS, and `/api/snapshots` enumerates every customer's snapshots unauthenticated** — The raw facts check out — `grep -c 'CREATE TABLE' db/schema.sql` = 18, the only tenancy-shaped hit is the schema.sql:69 comment `context text, -- vrf / segment / vpn / tenant / account`, there is no CREATE POLICY / ENABLE ROW LEVEL SECURITY in schema.sql or auth_schema.sql, view_sid (main.py:126-128) and listUsers (users.ts:47-49) are verbatim. But this is not a defect: I grepped README.md and every docs/*.md for multi-?tenan|per-customer|per-client|tenant isolation and got ZERO hits. Nothing in the product claims or implements multi-tenancy; it is a single-org tool. The failure_scenario is ex
