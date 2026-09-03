# Production-Readiness Audit — Round 2

**Subject:** Network Policy Reviewer (`ztpa`)
**Branch:** `remediation/prod-readiness` · findings verified at `473609c`, scale probes re-run at `1a9b756`
**Baseline for the diff:** `c0789d6` — 124 files changed, +31,989 / −3,581
**Scope:** independent re-audit of the current tree after three phases of remediation against the first audit
**Method:** every finding below was executed, not read. Probe scripts, raw output and mutation harnesses are cited inline.
**Suite state at audit time:** 1,297 tests collected, all passing; `scripts/verify_engine.py` prints `ALL CHECKS PASSED`; `git status` clean.

---

## 1. Verdict

**The core engine is not production-ready, and I would not put this in front of a client yet — but it is much closer than the state of the codebase suggests, and the reason it is not ready is narrower than last time.** The severity mathematics, the address-space classifier, the identity resolver and the analyzer-isolation layer are genuinely good work, pinned by an unusually strong test suite (18 of 19 injected defects in `severity.py` were killed; 9 of 9 in `config.py`; 9 of 9 in `run_all.py`). What blocks the client meeting is that the product's **headline differentiator does not fire on real input, and it fails silently in the direction of a clean bill of health.** `cross_tool_paths` looks the internet up by the literal string `"0.0.0.0/0"` (`backend/src/graph/reachability.py:190`), so an AlgoSec export that writes its internet source as `any` or as a named group — which `backend/src/normalizers/algosec.py:12-15` itself calls "the overwhelming majority of rules" — yields **zero** cross-tool paths and renders as "no internet-to-crown-jewel path exists". The same literal is hard-coded a third time inside the change-approval gate (`backend/src/change/simulate.py:53`), where I measured a proposed internal rule that newly exposes a PCI database flip from `forced_escalate=True` to `forced_escalate=False` purely because the pre-existing internet rule was spelled `ANY-EXTERNAL`. `docs/ENGINE.md:669` lists *"'The internet' is the literal string `0.0.0.0/0`"* under **"Fixed, and no longer gaps."** It is fixed in `zone_of` and in the guardrail floor. It is not fixed in the two places that decide what a buyer sees and what an operator is allowed to approve.

Layered on top of that: the analyzer that *does* work has a reporting gate (`over_permissive.py:68`, `is_internet = E >= 1.0`) that discards findings the published guardrail floor forces critical — a vendor `/24` with RDP to a prod host produces **zero findings from the entire engine** while `score_over_permissive` says severity 52, forced-critical. And the engine becomes unusable well below its own stated target: on a realistic 5,000-rule multi-tool export, `path_trace` took **1,266 seconds** (21 minutes), synchronously on the request path, and returned **0 findings**. `backend/src/db.py:206` names 5,000 rules as the target.

None of this is unfixable and none of it is architectural. Every blocker below is a small number of lines in a small number of files, and in most cases the correct machinery already exists one module over — `zones.zone_of` already classifies address space correctly, `shadowing._covers` already proves CIDR containment, `_bfs_witnesses` already answers reachability in 0.000 s on the graph where enumeration needs 143 s. This is a product whose hard parts are done and whose seams are open. Budget one focused phase, not another three.

**One line for the person deciding:** the maths is trustworthy, the plumbing between the maths and the answer is not, and every gap I found fails toward "you're clean."

---

## 2. Readiness by layer

| Layer | Rating | Assessment |
|---|---|---|
| **Severity model & guardrail floor** (`analyzers/severity.py`, `config.py`) | 🟢 **Strong** | 27 of 28 injected mutations killed across both files; `test_severity.py` recomputes the published worked example to exactly 100 and pins every band table by exact value. The one defect is in the *reason gate* upstream of it (`over_permissive.py:68`), not the maths. |
| **Address-space classification** (`netaddr.py`, `graph/zones.py`) | 🟢 **Strong** | 5/6 and 1/1 mutations killed; the survivor is a provably redundant fast path I verified across 22 tokens. `0.0.0.0/1` classifies public via exact IANA set arithmetic, CGNAT is excluded, IPv4-mapped v6 unwrapped. I tried to break it and could not. |
| **Identity resolution** (`identity.py`) | 🟢 **Strong** | Duplicate RFC1918 across two cloud accounts is *not* fused — the layer emits a withheld merge with the evidence attached. Linear: 0.002 s at 1,000 rules → 0.049 s at 20,000. 8/12 mutations killed; survivors are ordering/hygiene, not correctness. |
| **Persistence & schema** (`persist.py`, `db.py`) | 🟡 **Mixed** | `MAX_BIND_PARAMS` chunking verified at 501,499 findings with zero row loss; linear to 10,000 rules (1.18 s). But a 4-device export where each device numbers its rules 1..3 persists **3 of 12 canonical rules and 0 of 4 criticals ≥ 90** while `snapshots.notes` claims 12. |
| **Normalizers / ingest** (`normalizers/*`) | 🔴 **Not ready** | Of the object and service spellings real Palo/Check Point/AlgoSec exports use, a 300-rule cross-product resolved **50% of rules to no source address space at all** and dropped **45% of ground-truth internet→admin grants**. A wrong top-level key or an AFA multi-device shape yields 0 records, 0 findings and `health: ok`. |
| **Reachability & path tracing** (`graph/reachability.py`, `analyzers/path_trace.py`) | 🔴 **Not ready** | The differentiator. Keyed on a string literal; 21 min / 0 findings at 5,000 realistic rules; on a mesh the finding count is arithmetically `cap × targets` and carries no information. `path_trace.py` had 1 mutation injected and 0 killed. |
| **Change-approval gate** (`change/simulate.py`, `advisory/classify_change.py`) | 🔴 **Not ready** | The two engine-override layers in `classify_change` are real and tested — the weakness is what `simulate_change` puts *into* the delta. 6 of 20 mutations killed across `simulate`/`staging`/`apply`/`profile` (30%); removing the internet→internal force-escalate clause turns escalate into LLM `auto_approve` end to end. |
| **Analyzer isolation & degradation** (`run_all.py`) | 🟡 **Mixed** | 9/9 mutations killed; `degraded_analyzers` never fired spuriously across every adversarial export I built. But a degraded run is persisted as authoritative under the same snapshot id and published as `status:"ok"`. |
| **API surface** (`app/main.py`) | 🟡 **Mixed** | Routes behave; authz guards are real and the scanner provably fails on an injected route. But `sync:false` ships the boundary OFF while health reports `ok`, and `/api/findings` returned **57.8 MB** with no pagination. |
| **Test suite** | 🟢 **Strong, with a blind spot** | 1,297 tests; 84/112 injected defects killed (78% of non-equivalent mutants). The blind spot is systematic: tests call scoring functions *directly* and skip the analyzer wrapper, which is exactly where two of the three worst defects live. |
| **Documentation vs. code** | 🟡 **Mixed** | `ENGINE.md` §10 is unusually honest — it lists open gaps and self-corrects. But its "Fixed, and no longer gaps" block declares the literal-internet defect closed in a tree where two of three call sites still hard-code it. |

---

## 3. What changed since the last audit

### Closure rate

Against the previous audit's **155 findings**, with the 19 blocker entries deduplicated to **13 unique defects**:

| | Count | Rate |
|---|---|---|
| Unique blockers fully closed | 8 / 13 | **62%** |
| Partial | 3 / 13 | 23% |
| Open | 2 / 13 | 15% |
| As the register lists them (19 entries) | 12 fixed / 5 partial / 2 open | **63%** |

That is roughly the rate the remediation log's own framing implies — it claims Phases 0–2 complete and Phases 3–4 not started, and both fully-open blockers (no ingestion path; the path-scan cap bounding results rather than work) are explicitly Phase 3 scope. **The log is honest.** It self-reports the `degraded_analyzers` gap as blocker-class, the fail-open proxy secret, the archived-decisions reader and a docstring gap, and it corrects two of its own earlier claims. I found one case where it overstates: an `audit_log` FK row.

**Genuinely and verifiably closed**, each re-executed: the `/api/change/classify` custom-path 500 (4 bodies including `any` and a port range now return 200 with a decision); recompute cascade-deleting governance (FK `SET NULL` confirmed in `information_schema`; 0 rows lost over 12 operations through real routes); identity merge keying on a bare IP with no tenancy scope (all 7 scoping arms verified); the port-range detector bypass (`tcp/1-65535` → 90/critical/forced on a non-sensitive destination); `effective_policy` and `reachable` disagreeing (650 demo pairs + 40 random cyclic graphs, 0 disagreements); magic-link endpoints returning a live sign-in link; and the previous round's mutation-survivor problem (12 of 13 injected defects now caught, up from 4 of 10).

Also fixed and verified by execution: `engine()` swallowing persistence failures; LLM calls holding a pooled connection; a transient DB error recomputing without confirmed merges (now 503); missing global exception handler; `snapshot_id` not a content hash; the `upsert_many` bind-parameter ceiling; shadowing matching by name and exact string; zero application logging; `/api/health` hardcoding `status:'ok'` at the top level; the frontend TLS downgrade; 11 silent frontend catches; `provider_status` rendered nowhere; zero tests and no CI; the audit trail recording `actor='user'`; staging claiming a push that touches nothing; the change gate discarding destination tags.

### What remediation introduced or made worse

Five items. Three of them fail toward under-reporting, which for this product is the expensive direction.

1. **`degraded_analyzers` converted a loud crash into a silent, persisted, authoritative under-report.** The isolation fix is correct in itself (9/9 mutations killed, never fired spuriously) — but a degraded run overwrites the good rows under the same snapshot id and is published as `status:"ok"` / `served_from:"database"`. The log flags this as blocker-class and ships it anyway.
2. **`require_rows`/`require_mapping` return empty for an absent key.** The validation layer added to answer "normalizers validate nothing" converts a wrong field name into a completely clean estate — no error, no log, no marker. An AFA multi-device `devices[]` export produces 0 records, 0 findings, `health: ok`, `degraded_reasons: []`.
3. **A mutation guard now certifies a live defect.** `backend/tests/test_mutation_guards.py:740-775` (M56) pins `E >= 1.0` in `over_permissive._reasons` as "display-only and must stay pinned to its boundary," on the stated rationale that "the finding survives (the broad-source arm still fires)." That rationale is false for `E < 0.5` — which is precisely the gap in Blocker **B2**. The test written to prevent regressions now blocks the fix.
4. **Dead code in the severity path.** `severity.py:338-354` reads `path.get("entry_cidrs")` so a named internet entry can be scored on its resolved space — but `reachability.describe_path` never emits that key. `grep -rn entry_cidrs src/ tests/` shows the only producer is a hand-built dict at `tests/test_severity.py:783`. The branch is unreachable in production and tested as if it were live.
5. **`ENGINE.md` §10 over-claims one closure.** The "Fixed, and no longer gaps" block states *"'The internet' is the literal string `0.0.0.0/0`" — both `zone_of` and the guardrail floor now classify address space through `netaddr.is_public`.* That sentence is true and the fix is real. The problem is what it implies: `reachability.py:190` and `simulate.py:53` were not converted, and a reader who greps the cited lines and finds working code will reasonably stop checking.

**The pattern worth naming:** the two most damaging findings in this round are both cases where a fix was validated against the probe rather than against the defect class. The headline source-spelling fix was proved with nine *flat* named objects and declared closed; group-of-groups — the normal structure of a real firewall catalog — still resolves to `source_cidrs: []`. The four-encodings equivalence test (`tests/test_analyzers.py:291-340`) is the Phase-1 exit criterion and it calls **only** `over_permissive.analyze` — never `path_trace`, never `simulate_change`. The differentiator is tested with exactly the one spelling that works.

---

## 4. What is genuinely well built

This section is how you calibrate trust in the rest. These are the parts I attacked and could not break, with the evidence.

**Address-space classification is rigorous.** `netaddr.py` classifies `0.0.0.0/1` as public (critical 85, not medium) via exact set arithmetic against an explicit IANA special-use table, rather than the edge-address sampling `.is_private` would do. CGNAT `100.64.0.0/10` is correctly excluded. IPv4-mapped v6 is unwrapped before classification. `is_any` agrees numerically and lexically, so `any` / `Any` / `ALL` / `*` / `0.0.0.0/0` / `0.0.0.0/0.0.0.0` / `::/0` collapse to one answer. Five of six injected defects were killed — turning `_fully_special` into `covered > 0` (so `0.0.0.0/1` reads private) failed 18 tests; making an unparseable wildcard non-public failed 17. The survivor removes a `prefixlen == 0` short-circuit that I verified is redundant across 22 tokens.

**The severity formula and its guardrail floor are pinned hard.** 18 of 19 injected defects killed. Every band boundary, both `max`→`min` inversions, the class-table walk order, the port-class span threshold, all three guardrail clauses, `_covers_unclassified`, the cross-tool floor's address-space arm, the overlap bump and the transport subtype string were caught — several by double-digit numbers of tests. `test_severity.py` is the strongest file in the suite: it recomputes the published worked example to exactly 100 and asserts monotonicity in both directions (`test_p_never_falls_as_the_service_widens`, `test_exposure_never_falls_as_the_source_widens`).

**`config.py` cannot drift.** 9 of 9 killed. Moving `band_critical`, changing `PORT_SPAN_ANY` 1024→65536, dropping 3389 from `ADMIN_LATERAL_PORTS`, dropping `pci` from `SENSITIVE_TAGS`, collapsing the `(internet, internal)` blast multiplier from 1.5 to 1.0, running IPv6 through the v4 band table, swapping the last two rows of `PORT_CLASS_P`, retuning `TAG_SENSITIVITY['pci']` and moving `broad_source_E` each failed between 5 and 40 tests, because `test_severity.py` asserts every table by exact value.

**Duplicate RFC1918 across cloud accounts is handled exactly right — the best part of the codebase.** Two Wiz assets both on `10.0.1.5`, one in subscription `111111111111`/`vpc-aaa` tagged `pci`, one in `222222222222`/`vpc-bbb` tagged `dev`, are **not** fused. The identity layer emits `('dev-api-b', 'manual_review', 0.0, {'status': 'withheld', 'reason': 'context_mismatch', 'ip': '10.0.1.5', 'names': [...]})` — a withheld merge with the evidence attached, not a guess and not a silent drop. `scope_identifiers` lifted `subscriptionExternalId` and `vpcId` into canonical `subscription`/`vpc` keys with no per-export mapping, and correctly refused to treat `cloud`, `type` and `env` as namespaces.

**Identity resolution and graph construction are linear, and I expected them not to be.** `resolve_identities`: 0.002 s at 1,000 rules / 225 entities → 0.049 s at 20,000 / 3,584 — a clean 25× for 16× the entities. Reading `identity.py:395-460`, the shared-IP arm buckets by `(ip, context)` in one pass and only iterates inside each bucket; there is no hidden pairwise scan. `build_graph`: 0.002 s at 886 edges → 0.043 s at 18,773.

**`_bfs_witnesses` is the right primitive and it works.** On the 926-node / 4,645-edge graph where `all_simple_paths` needed **143 s** to produce one path, the BFS computed the entire reachability closure from `0.0.0.0/0` (529 reachable nodes) in **0.000 s**. The architectural decision to answer yes/no from BFS rather than enumeration is correct and is what keeps `reachable`, `who_can_reach` and `find_paths` agreeing. The defect is in the enumeration layered on top, not in this.

**`shadowing`'s coverage logic is directional and tested as such.** 5/5 killed. Turning service containment into overlap failed 2 tests, reversing source-containment direction failed 8 plus `verify_engine`, dropping the `break` on the earliest shadower failed 8, inverting the `order is None` filter failed 13 plus `verify_engine`.

**Persistence scales and does not lose rows at volume.** I persisted 501,499 findings (11 columns, ~85 chunked statements) in 38.3 s and 48,000 findings plus 1,202 graph edges in 5.94 s against the real Postgres, with no `too many parameters` error and no silent loss. `SELECT count(*)` per table matched the projection exactly for the 10,000-rule snapshot (assets 1,821, canonical_rules 10,000, graph_nodes 1,821, graph_edges 9,526, findings 2,045, resolved_objects 1,818, asset_correlations 474). Re-persisting the same snapshot id was idempotent.

**Analyzer isolation does what it says.** `_run_analyzers(isolate=True)` records a named `degraded_analyzers` entry rather than aborting the run, and across every adversarial export I built — malformed addresses, dict-valued services, list-valued ports, mixed IP families, 8,000-rule estates, unicode keys — `degraded_analyzers` was empty in every run. Nothing swallowed an exception and nothing crashed spuriously.

**IPv6 is a first-class citizen.** `::/0` as a source scores critical; a `2001:db8:1::/48` source and a `2001:4860:4860::8888` host object both normalize and score correctly; `netaddr.same_family` prevents the `IPv4Network.subnet_of(IPv6Network)` TypeError that would otherwise take down a whole snapshot when one v6 rule appears in a v4 record set. Verified by running mixed-family exports through the full engine with no analyzer degraded.

**Unicode object names round-trip cleanly** — `データベース本番` and `réseau-siège` resolve to their catalog CIDRs and score identically to ASCII equivalents. No encoding assumptions leaked.

**The four-spellings property genuinely holds for the source *token*.** `0.0.0.0/0`, `any`, a named `address-group` valued `["0.0.0.0/0"]`, a named group called `INTERNET`, and an address group with `0.0.0.0/0` among several members all score identically at critical 90. Whatever is wrong upstream, the fix this layer claims to have made *was* made — I could not find a spelling of the token that breaks it, only spellings of the *value* (ranges, wildcard masks, nested groups) that never resolve in the first place.

**Comma lists and port ranges are scored correctly by the analyzers**, via the deliberate service-label re-decode in `over_permissive._service_ports` and `shadowing._multi_intervals`. `tcp/3389,1433`, `tcp/3380-3400` and `tcp/1024-65535` all reach critical 90; `_parse_port_spec` rejects inverted ranges and out-of-band ports with warnings rather than coercing them, and merges intervals so `tcp/443,80` and `tcp/80,443` decode identically.

**Byte-level truncation fails loudly and correctly** — a file cut mid-flush raises `JSONDecodeError` → 422 → health 503. That is the right behaviour and it is worth saying, because the *array*-truncated case (below) does not.

---

## 5. Gap themes

Clustered by root cause, not by file. Counts are register entries in this document.

### Theme 1 — "The internet" is still a string in the two places that decide (blocker · 2 entries)

**Root cause.** The Phase-1 remediation replaced string comparison with address-space classification in `zones.zone_of` and in `severity.is_internet_source`, and stopped. `reachability.cross_tool_paths` (`reachability.py:188-191`) still takes `source: str = INTERNET_CIDR` and returns `[]` when that exact key is absent; `simulate._internet_sensitive_paths` (`simulate.py:53`) still calls `find_paths(g, "0.0.0.0/0", t)`. Both operate on a graph where the node is keyed by the object's *name* — by design, per `algosec.py`'s own docstring ("Named objects keep their NAME as the node key"). The two halves of the same fix disagree.

**If ignored.** The product's stated differentiator returns zero findings on the majority of real exports and renders as "clean". A change that newly exposes a PCI database to the internet loses its deterministic force-escalation and is handed to the LLM with a delta reading "no new internet paths" — the "engine, not the model, decides" claim inverted.

### Theme 2 — The reporting gate and the scoring floor use different predicates (blocker · 1 entry, high · 2 entries)

**Root cause.** Analyzers decide *whether to score* a record before they score it, using a cheap local predicate, and the cheap predicate has drifted from the authoritative one. `over_permissive._reasons` gates on `E >= 1.0`; the guardrail floor gates on `is_internet_source`. `transport_exposure.py:128` filters `r.port is not None`, excluding exactly the `any/any` rule its own `_opens` docstring says it handles. `dest_score(tags)` reads a label where `shadowing._covers` proves containment from `dest_cidrs` in the same run.

**If ignored.** The published guardrail floor — sold in `ENGINE.md` §5.4 as the safety net that means "no downstream model error can bury a true emergency" — is bypassable by the ordinary shape of a partner-access rule. A vendor `/24` with RDP to a prod host yields **zero findings from all five analyzers**. Since these are gates, the failure is total silence, not a wrong number.

### Theme 3 — Enumeration where a set operation belongs (blocker · 3 entries)

**Root cause.** Three analyzers answer set questions by enumerating members. `path_trace` enumerates simple paths (worst-case exponential; the cap bounds *yields*, not *work*, which `ENGINE.md` §10.3 concedes). `cidr_overlap` enumerates rule pairs (O(n²) findings, not just O(n²) time). `shadowing` enumerates ordered pairs (clean n², 27 s at 8,000 rules, ≈11 min extrapolated at 40,000 from three agreeing curves).

**If ignored.** Three independent cliffs, and a client hits whichever comes first: **~3,000 rules** on a realistic multi-tool export is where path tracing stops being interactive (41 s) and **5,000 rules is the first size at which the product is unusable** (1,266 s, synchronous, no lock, no timeout, zero cross-tool findings — against a stated target of 5,000 in `db.py:206`); **~1,000 rules** is enough if a meaningful slice share a destination group and a service, an utterly ordinary AlgoSec shape (501,499 findings, 2.2 GB RSS, `degraded_analyzers: []`); **~50 nodes** in one genuinely meshed segment is enough to defeat the change-approval gate. The demo fixture — 27 rules, 25 assets — is two to three orders of magnitude below all three, and `verify_engine.py` passes in 0.34 s while asserting nothing about any of them.

### Theme 4 — Real export shapes do not survive the normalizers (blocker · 2 entries, high · 1, medium · 1)

**Root cause.** The adapters were written against the three mock fixtures and one flat object catalog. They handle the shapes in `data/mock/` and refuse or drop the rest. On a 300-rule export assembled only from object and service spellings that real Palo / Check Point / AlgoSec exports use, **50% of rules resolved to no source address space at all**, 20% decoded to no port, and **45% of the ground-truth internet→admin/data grants (54 of 120) produced no over-permissive finding**. (That mix is a deliberate cross-product rather than a frequency-weighted sample, so 45% is an upper bound — but every constituent case is individually confirmed.) Silent no-finding cases include: nested groups, Check Point range objects, ASA wildcard masks, a separate `netmask` field, `MS-WBT-Server`, `ms-rdp`, `application-default`, list- and dict-valued services, and separate `port`/`protocol` columns with no `service` — the last with **zero warnings**.

**If ignored.** The first real customer export produces a report that is half empty and gives no indication of it. Worse, the failure modes are asymmetric: a *missing* field aborts the entire export loudly, but a *differently-named* top-level key produces 0 records, 0 findings and `health: ok`.

### Theme 5 — Degradation is recorded but never surfaced (blocker · 1 entry, high · 1, medium · 1)

**Root cause.** The remediation added the right signals — `degraded_analyzers`, `truncated` on `reachable()`, per-object `warnings`, malformed-field audit rows — and wired none of them to anything a human sees. The truncation flag is correctly implemented and correctly plumbed into `agent/tools.py:60,72`, but the two consumers that matter most, `cross_tool_paths` and `find_paths`, do not carry it. Object warnings land in `resolved_objects` and render as a truncated `JSON.stringify` in `IngestInspector.tsx:127-134` — no badge, no count, no filter, no health metric.

**If ignored.** A truncated cross-tool scan reports `forced_escalate: false`, `forced_reasons: []`, `notes: []`, `delta_is_clean: true`, `/api/health` `status: "ok"`, `degraded_reasons: []` — and 20,000 findings presented as a count. On the mesh probes, from 51 nodes upward the reported cross-tool finding count is arithmetically `_PATH_SCAN_CAP × sensitive_targets` (exactly 5×4,000 and 12×4,000) and carries no information about the estate at all.

### Theme 6 — The change pipeline is the least-tested code in the repo (high · 1 entry)

**Root cause.** Mutation kill rate by area: scoring core (`severity` + `config` + `netaddr` + `run_all` + `graph` + `models` + `shadowing`) = **50 of 51 killed**. Change pipeline (`simulate` + `staging` + `apply` + `profile` + `path_trace`) = **6 of 20 killed (30%)**. `change/apply.py` and `analyzers/path_trace.py`: **0 of 3**.

**If ignored.** Verified survivor consequences: removing the internet→internal force-escalate clause turns escalate into an LLM `auto_approve` end to end; `_granted_intervals` ignoring the service label loses the admin guardrail on `tcp/80,3389` from `0.0.0.0/0`; `apply.py:80` off-by-one leaves the shadowing finding alive after the fix is applied; three separate `staging.py` defects turn a real push into a `no_op`. These are not hypothetical — each was injected, executed and its consequence measured, and none of the 1,297 tests noticed.

### Theme 7 — Persistence loses data on ordinary multi-device input (blocker · 1 entry)

**Root cause.** Canonical rule identity does not include the emitting device, so four firewalls each numbering rules 1..3 collide.

**If ignored.** On a 12-rule / 4-device estate: 12 canonical rules → **3 persisted**; 11 findings → 6; 4 criticals ≥ 90 → **0**, while `snapshots.notes` and `audit_log` claim 12 and 11. Overwritten and never persisted: `SSH open from the internet to PCI-DB` (100), `RDP open from the internet to PCI-DB` (100), `PostgreSQL open from the internet to PCI-DB` (100), `RDP open from the internet to APP-SEG` (90). **The highest severity the console can display on that estate is 80.**

### Theme 8 — Tests validate the function, not the path (high · 1 entry, cross-cutting)

**Root cause.** The suite is strong where it tests pure functions and weak where the defect lives in the caller. Every guardrail test in `test_severity.py:445-560` calls `score_over_permissive` directly; none goes through `over_permissive.analyze`, which is why B2 survived 1,297 tests. The four-encodings exit-criterion test drives only `over_permissive`. The only `cross_tool_path` tests (`test_engine_invariants.py:225-247`) use a synthetic estate whose entry is a literal `0.0.0.0/0`. `test_normalizers.py:150-168` opens "It must not quietly become a single-host asset with E=0.1" and then asserts only `source_cidrs == []` — precisely the input that yields E=0.1; it never asserts a score, so it passes while the failure it names is live. And 18 mutants were killed by exactly **one** test each, one deletion from surviving — including analyzer isolation and `reanalyze` fail-closed.

Secondary observation: **`verify_engine.py` contributed zero independent detection power.** Across all 84 kills there is not one mutant it caught that `pytest` did not, because `test_demo_golden.py::test_every_verify_engine_check_passes` runs the same check set in-process. It is a duplicate CI step, not a second opinion.

---

## 6. Remediation plan

Phased, with exit criteria you can check by running something. Sizes are engineering days for one competent engineer who knows this codebase.

### Phase A — Make the differentiator fire (blocking for any client demo)

| # | Workstream | Size | Exit criterion |
|---|---|---|---|
| A1 | **Derive the internet entry set from the graph, not a string.** In `reachability.cross_tool_paths` (`graph/reachability.py:188-191`), replace `if source not in g: return []` with `entries = [n for n, d in g.nodes(data=True) if d.get("zone") == ZONE_INTERNET]` and union over them, deduping by path tuple. Same change in `who_can_reach`'s `internet_exposed`/`internet_path` (`:333-334`) and in `simulate._internet_sensitive_paths` (`change/simulate.py:53`). | **M** | Extend `tests/test_analyzers.py`'s `FOUR_ENCODINGS` matrix to drive `path_trace.analyze` and `simulate_change`, not just `over_permissive`. All four spellings must produce an identical cross-tool finding and an identical `forced_escalate`. |
| A2 | **Make `describe_path` emit `entry_cidrs`** from `g.nodes[entry]["ip_set"]`, so `severity.py:338-354`'s named-entry branch stops being dead code and E is computed on the resolved space. | **S** | `grep -rn entry_cidrs src/` shows a producer in `reachability.py`; the assertion at `tests/test_severity.py:783` is rewritten to consume a real `describe_path` output rather than a hand-built dict. |
| A3 | **Invert `over_permissive`'s control flow.** Score every allow record first; emit unconditionally when `sc["forced_critical"]`; use `_reasons` only to decide whether a *non-forced* rule is worth reporting. As a minimum, replace `is_internet = E >= 1.0` (`over_permissive.py:68`) with `severity.is_internet_source(...)`. Keep `_is_wildcard_source` for the display label — that narrowness is deliberate and correct. Correct `test_mutation_guards.py:740-775` (M56), whose stated rationale becomes true only after this fix. | **S** | A new test walks `over_permissive.analyze` (not `score_over_permissive`) over each of the three guardrail clauses' minimal inputs and asserts a finding is emitted. `allow 52.20.10.0/24 -> app-01 tcp/3389` produces a critical finding. |
| A4 | **Apply the wildcard vocabulary to the port half.** In `_parse_port_spec` (`normalizers/common.py:306`), test each token with the existing `netaddr.is_any` before `_decode_port` and expand a wildcard to `(_PORT_MIN, _PORT_MAX)`. Apply per comma element so `tcp/443,any` is all-ports. | **S** | `parse_service("tcp/all")` and `parse_service("tcp/0-65535")` produce the same `port_score`; `parse_service(None, "*", "tcp")` (the Wiz/Azure path) likewise. Rows added to `test_parse_service.py::SERVICE_CASES`. |

### Phase B — Make it survive a real export

| # | Workstream | Size | Exit criterion |
|---|---|---|---|
| B1 | **Object-resolution completeness.** Nested groups (recursive, with cycle detection), Check Point dash ranges, ASA wildcard masks, a separate `netmask` field, list-valued `src`/`dst` where the vendor genuinely allows it. | **L** | A fixture export containing one rule per shape from the Table-1 matrix produces a finding for every ground-truth internet→admin grant. `source_cidrs == []` becomes a *reported* condition, not a silent one. |
| B2 | **Make unresolvability a scored fact.** Carry a `source_unresolved` flag onto `PolicyRecord`; have `exposure_score` return a conservative floor for a malformed *network* object rather than `E_IDENTITY = 0.1`. `object_is_abstract` already fails closed on the identical warning — make `exposure_score` consistent with it. | **M** | `exposure_score("BAD-OBJ", "identity", [])` where the catalog value is `10.0.0.0/33` no longer returns 0.1; `test_a_garbage_cidr_is_recorded_as_malformed_not_reclassified` gains the score assertion its docstring already promises. |
| B3 | **Fail loud on shape mismatch.** `require_rows`/`require_mapping` must raise when the expected key is absent, not return empty. A zero-record normalize is an error condition, not a clean estate. | **S** | An export with `devices[]` instead of the expected top-level key returns 422, and `/api/health` reports non-`ok`. A test asserts 0 records ⇒ non-`ok` health. |
| B4 | **Per-rule error isolation in the normalizers.** One malformed row should degrade one rule with an audit entry, not abort a 40,000-rule export. | **M** | A 1,000-rule export with 5 malformed rows yields 995 records plus 5 named audit entries, and health reports partial ingest. |
| B5 | **Device-scoped rule identity.** Include the emitting device in the canonical rule key. | **S** | The 4-device / 12-rule fixture persists 12 canonical rules, 11 findings and 4 criticals ≥ 90, matching `snapshots.notes`. Asserted by a DB-backed test. |
| B6 | **Destination sensitivity from resolved space.** `dest_score(tags, dest_cidrs, asset_index)` where D is the max over the destination's own tags ∪ the tags of every asset inside `dest_cidrs`, plus the *merged* asset tags rather than the emitting tool's. Guardrail clause 3 must read the same union. `change/simulate.resolve_dest_tags` already does the CIDR half — lift and extend it (note it returns `[]` for a *named* object today, so it is not a drop-in). | **M** | `allow 0.0.0.0/0 -> DC-SUBNETS tcp/1433` where `db-prod-01` (crown-jewel, pci) is inside `10.0.0.0/16` scores critical/forced, and `advisory/report.build_summary` reports `internet_reaches_regulated_data: true`. A monotonicity test: widening the destination never lowers D. |

### Phase C — Make it hold at scale

| # | Workstream | Size | Exit criterion |
|---|---|---|---|
| C1 | **Bound the work, not the yields.** Give `path_trace` a wall-clock budget per target in addition to `_PATH_SCAN_CAP`, and surface exhaustion. Consider replacing enumeration with k-shortest-paths or a witness-plus-reconstruct approach — `_bfs_witnesses` already answers the yes/no in 0.000 s on the graph where enumeration needs 143 s. | **L** | A 5,000-rule realistic export completes `run()` in < 60 s wall clock. A target that exhausts its budget produces a `degraded`/`truncated` marker that reaches `/api/health` and the findings payload. |
| C2 | **Cap `cidr_overlap` output.** The analyzer emits O(n²) *findings*, not just O(n²) work — 12,497,500 findings and 12 GB RSS at 5,000 rules on a single-destination-group shape. Aggregate to one finding per (destination, service) cluster with a member count. | **M** | A 5,000-rule single-group export produces < 10,000 findings and peak RSS < 1 GB. |
| C3 | **Make `shadowing` sub-quadratic**, or bound it. Bucket by destination and service before the ordered pair scan. | **M** | 8,000 rules in < 5 s (currently 27.0 s); 40,000 rules completes rather than extrapolating to ~11 min. |
| C4 | **Move `run()` off the request path.** No lock, no timeout, no progress today; a SIGKILL from the OOM killer leaves `_ENGINE` unset so the next request repeats the work. | **M** | Recompute is a job with a status endpoint; a second concurrent recompute is rejected or queued, proven by a concurrency test. |
| C5 | **Paginate `/api/findings` and `/api/graph`** — measured at 57.8 MB and 50.1 MB with 975 MB process RSS on a 51-node mesh. | **S** | Both endpoints return < 2 MB by default with a documented cursor. |

### Phase D — Close the trust gaps

| # | Workstream | Size | Exit criterion |
|---|---|---|---|
| D1 | **A degraded run must never be published as authoritative.** Do not overwrite good rows under the same snapshot id; propagate `degraded_analyzers` to `/api/health` and to the findings payload; propagate `truncated` from `cross_tool_paths` and `find_paths`. | **M** | With one analyzer forced to raise, `/api/health` is not `ok`, the snapshot is marked partial, and the previous good snapshot is still served. |
| D2 | **Surface ingest warnings.** A count and a filter in the Ingest Inspector, and a health signal. Today they are a truncated `JSON.stringify` in `IngestInspector.tsx:127-134`. | **S** | A malformed object produces a visible badge and a non-zero warning count in the health payload. |
| D3 | **Test the change pipeline.** Target the 14 verified mutation survivors in `simulate`/`staging`/`apply`/`profile`/`path_trace` — the specs and probe scripts already exist. | **M** | Re-running the same 20 injected defects kills ≥ 18. |
| D4 | **Turn the role boundary on by default** and make `sync:false` a non-`ok` health condition. | **S** | A default deployment refuses `x-npr-role` spoofing, proven by a test against the real app. |
| D5 | **Give `verify_engine.py` independent power** or delete it. It caught nothing `pytest` missed across 84 kills. | **S** | It asserts at least one property the suite does not, or the CI step is removed and the duplication noted. |
| D6 | **Correct the docs.** `ENGINE.md` §10 must list the remaining literal-internet call sites, the containment-blindness of D and guardrail clause 3, and the `enabled`/`negate` gap. Fix the `README.md:3` / `FEATURES.md:41` cross-tool-path claim while A1 is outstanding. | **S** | Every "Fixed, and no longer gaps" bullet passes a grep of its own cited call sites. |

---

## 7. Quick wins

Each under a day, each with the payoff stated.

1. **`over_permissive.py:68` — one line.** Replace `is_internet = E >= 1.0` with `severity.is_internet_source(rec.source, rec.source_kind, rec.source_cidrs)`. *Payoff:* the published guardrail floor stops being bypassable; a partner `/24` with RDP to a prod host goes from 0 findings to critical. Requires correcting one mutation guard.
2. **`common.py:306` — three lines.** Wildcard test at the top of `_parse_port_spec`. *Payoff:* `tcp/any` / `tcp/all` / `tcp/*` and the Azure/Wiz `port: "*"` shape stop decoding to "port unknown"; the widest grant expressible stops being invisible.
3. **`transport_exposure.py:128` — one line.** Drop the `r.port is not None` filter; `_opens` already handles `protocol == "any"`. *Payoff:* an `any`-service rule, which ships in `data/mock/algosec_export.json` itself, stops being excluded from the analyzer whose docs claim it is covered.
4. **`severity.py:471` — one line.** Unwrap IPv4-mapped v6 before banding in `_exposure_of`, and in `prefixlen_of` so the printed prefix length stops saying 96. *Payoff:* the two halves of a published, documented rule stop disagreeing.
5. **`normalizers/profile.py::require_rule` — a guard.** Raise `NormalizeError` naming the rule when a truthy `disabled` / false `enabled` / any `*negate*` key is present. *Payoff:* the day a real export first arrives, unmodelled rule state fails loudly instead of producing a 100/critical on a rule that is switched off, or reading a negated source as its exact complement. Cheap, and it is in scope well before the Phase-3 ingest path.
6. **`ENGINE.md` §10 — a paragraph.** Add the three undisclosed gaps and scope the "Fixed" bullet honestly. *Payoff:* the doc's credibility is currently its best asset; one over-claim spends it.
7. **`/api/findings` default limit.** *Payoff:* 57.8 MB → a few hundred KB, and the browser stops being the bottleneck in a demo.
8. **Make `test_a_garbage_cidr_is_recorded_as_malformed_not_reclassified` assert the score** its own docstring promises. *Payoff:* removes a test that currently passes while the failure it names is live — false confidence is worse than no test.

---

## 8. Findings register

> **Scope note.** The full adjudicated register for this round is 132 confirmed findings, each of which survived an adversarial verifier instructed to refute it. Reproduced below in full are the findings whose complete dossiers — reproduction, refutation attempts, executed evidence, and fix — were available at writing time, plus every additional defect for which I hold executed probe output. Where the verifier's adjudicated severity differed from the filing auditor's, **the verifier's severity governs and both are shown**; that disagreement is itself signal about calibration. Line references were re-checked against the working tree at the time of writing.

### Blockers

<details>
<summary><b>B1 — Cross-tool path tracing only fires when the export literally spells the internet <code>0.0.0.0/0</code>; <code>any</code> / <code>ANY-EXTERNAL</code> / <code>INTERNET</code> yield zero paths — and the same literal disarms the change gate</b></summary>

**File:** `backend/src/graph/reachability.py:188-191` (called from `backend/src/analyzers/path_trace.py:16`); also `backend/src/graph/reachability.py:333-334` and `backend/src/change/simulate.py:53`
**Severity:** blocker (auditor) / blocker (verifier)

**Why it matters.** `cross_tool_path` is the product's stated differentiator — "the exposure no single console can see" (`README.md:3`, `docs/FEATURES.md:41`, `ENGINE.md` §6.4) — and its findings are the demo's money shot. The entry node is looked up by **string** (`source: str = INTERNET_CIDR`; `if source not in g: return []`) even though `zones.zone_of` was explicitly rewritten so a named object resolving to `0.0.0.0/0` classifies as `ZONE_INTERNET`. Real AlgoSec / Palo / Check Point exports write the internet source as `any` or as a named object in the overwhelming majority of rules — `backend/src/normalizers/algosec.py:12-15` asserts this itself. For those customers the analyzer returns an empty list, and an empty list renders as "no internet-to-crown-jewel path exists." This is the exact class of defect (*"the internet was a string, not a place"*) that `ENGINE.md:669` lists under **"Fixed, and no longer gaps."**

**Failure scenario.** AlgoSec rule `allow ANY-EXTERNAL -> app-server-07 tcp/443` (`ANY-EXTERNAL` is a group object whose catalog value is `0.0.0.0/0`) plus Guardicore policy `allow app-server-07 -> db-prod-01 tcp/5432`, db tagged `pci`. The graph is built **correctly**: node `ANY-EXTERNAL` has `zone == "internet"` and `ip_set == ["0.0.0.0/0"]`. `cross_tool_paths` still returns `[]` because the literal key `0.0.0.0/0` is not a node.

**Evidence — executed**, full pipeline `normalize → resolve_identities → build_graph → path_trace.analyze`:

```
entry spelled '0.0.0.0/0'    -> node='0.0.0.0/0'    zone=internet  cross_tool_path findings=1
     100 critical forced=True Cross-tool path: Internet can reach db-prod-01 through 2 tools
entry spelled 'any'          -> node='any'          zone=internet  cross_tool_path findings=0
entry spelled 'ANY-EXTERNAL' -> node='ANY-EXTERNAL' zone=internet  cross_tool_path findings=0
entry spelled 'INTERNET'     -> node='INTERNET'     zone=internet  cross_tool_path findings=0

entry '0.0.0.0/0'    who_can_reach('db-prod-01').internet_exposed = True
entry 'ANY-EXTERNAL' who_can_reach('db-prod-01').internet_exposed = False
```

**The verifier found it is worse than filed — the change-approval gate is affected too.** Estate has `<entry> -> app-server-07 tcp/443`; operator proposes the *internal* rule `app-server-07 -> db-prod-01 tcp/5432`:

```
entry='0.0.0.0/0'    forced_escalate=True,  reasons=['opens 1 new internet path(s) reaching sensitive asset(s): db-prod-01']
entry='any'          forced_escalate=False, reasons=[], new_exposed=[]
entry='ANY-EXTERNAL' forced_escalate=False, reasons=[], new_exposed=[]
```

The gate's other arm (`is_internet_source(proposed.source, ...)`, `simulate.py:293`) does **not** cover this — the proposal's own source is an internal host. `advisory/classify_change.py:170` short-circuits to escalate on `forced_escalate` *before* any model call, so with it `False` the decision is handed to the LLM with a delta that says "no new internet paths."

**Refutations attempted and failed.** (a) Does the identity layer alias the named object onto `0.0.0.0/0` when both spellings appear? No — `alias_map` keeps them separate, both nodes coexist with `zone=internet`, total findings still 0. (b) Does another analyzer compensate? Only for the single-hop case: `<entry> -> db-prod-01 tcp/3389` yields over_permissive 60/critical/forced for all spellings. The two-hop cross-tool chain drops the whole engine to zero. (c) Does a normalizer canonicalize the node key? No — `algosec.py` deliberately keeps the NAME as the key.

**Dead code confirmed.** `severity.py:342` anticipates named entries via `path.get("entry_cidrs")`, but `reachability.describe_path` (`:118-131`) never emits that key. `grep -rn entry_cidrs src/ tests/` shows the only producer is a hand-built dict at `tests/test_severity.py:783`.

**Test hole confirmed.** The Phase-1 exit-criterion test `tests/test_analyzers.py:291-340` ("the four encodings of one policy score identically") calls **only** `over_permissive.analyze`. The only `cross_tool_path` tests (`tests/test_engine_invariants.py:225-247`) use a synthetic estate whose entry is a literal `0.0.0.0/0`. The differentiator is tested with exactly the one spelling that works. The shipped demo hides it: `data/mock/algosec_export.json` srcs are literal CIDRs.

**Fix.** In `cross_tool_paths`, replace `if source not in g: return []` with an entry **set**: `entries = [n for n, d in g.nodes(data=True) if d.get("zone") == ZONE_INTERNET]`, iterate `all_simple_paths` from each, dedupe by path tuple. Same for `who_can_reach`'s `internet_exposed`/`internet_path` and for `simulate.py:53`. Have `describe_path` populate `entry_cidrs` from `g.nodes[entry]["ip_set"]`. Extend `FOUR_ENCODINGS` to run `path_trace` and `simulate_change`.
</details>

<details>
<summary><b>B2 — The over-permissive analyzer's reason gate (<code>E &gt;= 1.0</code>) discards findings the published guardrail floor forces critical</b></summary>

**File:** `backend/src/analyzers/over_permissive.py:68`
**Severity:** blocker (auditor) / blocker (verifier)

**Why it matters.** `ENGINE.md` §5.4 sells the guardrail floor as the safety net: "categorically-unacceptable patterns are **force-flagged critical** regardless of the computed number, so no downstream model error can bury a true emergency," and states the internet test is `is_internet_source` (netaddr `is_public`), explicitly *not* `E >= 1.0`. But `_reasons()` — which runs **before** `score_over_permissive` and `continue`s when it returns `[]` — still uses `is_internet = E >= 1.0`, and `E == 1.0` only for a `/0`. Any public source narrower than `/23` (E < 0.5) carrying an admin/lateral port, and any public source narrower than `/27` (E < 0.3) reaching a regulated asset, produces a rule the floor would force critical and that the analyzer never scores at all. The finding is not down-ranked; **it does not exist.**

**Failure scenario.** `allow 52.20.10.0/24 -> app-01 tcp/3389` — a partner/vendor public `/24` with RDP to a prod host, the single most common real over-permissive shape. E = 0.3, P = 1.0, `is_internet_source` = True, guardrail clause 2 fires (severity 52, `forced_critical=True`) — and `over_permissive.analyze` emits **zero** findings, because clause 2's analyzer twin needs E ≥ 0.5 and clause 3's needs E ≥ 0.3 *and* a sensitive tag.

**Evidence — executed**, real AlgoSec export through `algosec.normalize → build_graph → over_permissive.analyze`:

```
partner /24 -> app-01 tcp/3389    E=0.3 P=1.0 internet=True forced=True sev=52 EMITTED=False
routable /29 -> pci-db tcp/443    E=0.1 P=0.4 internet=True forced=True sev=43 EMITTED=False
routable /30 -> crown tcp/3389    E=0.1 P=1.0 internet=True forced=True sev=69 EMITTED=False
routable /26 -> untagged tcp/22   E=0.3 P=1.0 internet=True forced=True sev=35 EMITTED=False
0.0.0.0/0   -> app-01 tcp/3389    E=1.0 P=1.0 internet=True forced=True sev=90 EMITTED=True
```

**It is a whole-engine false all-clear, not just an analyzer gap.** The verifier ran all five analyzers via `run_all._run_analyzers`, not just `over_permissive.analyze`:

```
partner public /24 -> prod app tcp/3389        findings=0 [] degraded=[]
partner public /29 -> PCI db tcp/443           findings=0 [] degraded=[]
partner public /24 -> PCI db tcp/3389          findings=1 [('over_permissive', 78, 'critical')]
named obj ANY-EXTERNAL(/0) -> app tcp/3389     findings=1 [('over_permissive', 90, 'critical')]
```

And through the full real pipeline on a hand-built AlgoSec export (raw CIDR source **and** named object source):

```
REC ALGO-900 52.20.10.0/24 cidr ['52.20.10.0/24'] tcp/3389 ['prod']
REC ALGO-901 PARTNER-A     identity ['52.20.10.0/24'] tcp/22 ['prod']
TOTAL FINDINGS: 0 []   degraded: []
GUARDRAIL ALGO-900: internet->internal forced=True sev=52 ['admin/lateral-movement port exposed to the internet']
GUARDRAIL ALGO-901: internet->internal forced=True sev=52 ['admin/lateral-movement port exposed to the internet']
```

`path_trace` is not a backstop — it requires ≥ 2 tools and a sensitive terminal, so a single-tool AlgoSec estate has none.

**Refutations attempted and failed.** (a) Another control catches it — no; the only other caller of `score_over_permissive` is `change/simulate.py:267`, the *proposal* gate, which is correct but does nothing for already-ingested rules. (b) Unreachable input — no; it arrives through the real `algosec.normalize` as both a raw CIDR and a named object. (c) Documented as intended — partially; `ENGINE.md` §6.1 prints `E >= 1.0` in the reason list, but §5.4 and `is_internet_source`'s own docstring claim the opposite, the docstring naming "a partner's public `/24`" as "a multi-address block [that] still fires." The docs contradict each other and the shipped behaviour is the unsafe reading.

**A test actively pins the defect.** `tests/test_mutation_guards.py:740-775` (M56) asserts `E >= 1.0` in `_reasons` is "display-only and must stay pinned to its boundary" on the rationale that "the finding survives (the broad-source arm still fires)" — false for E < 0.5, which is precisely the gap. Also, `tests/test_engine_invariants.py` uses `partner-net = 141.101.0.0/16` (E = 0.7), just wide enough to clear the broad-source arm, which is why the synthetic estate never exposed this.

**Fix.** Replace the predicate with `severity.is_internet_source(rec.source, rec.source_kind, rec.source_cidrs)`; better, invert the control flow so `forced_critical` emits unconditionally and `_reasons` only decides whether a non-forced rule is worth reporting. Keep `_is_wildcard_source` for the display label. Add a test driving `analyze`, not `score_over_permissive`, and correct M56.
</details>

<details>
<summary><b>B3 — <code>path_trace</code> takes 21 minutes on a 5,000-rule realistic export, synchronously on the request path, and returns zero findings</b></summary>

**File:** `backend/src/analyzers/path_trace.py`, `backend/src/graph/reachability.py` (`_PATH_SCAN_CAP` applied as `islice(nx.all_simple_paths(...), cap)`)
**Severity:** blocker

**Why it matters.** `backend/src/db.py:206` names 5,000 rules as the target scale. At that size the engine is not slow, it is unusable — and it produces nothing to show for the wait.

**Evidence — executed**, realistic multi-tool estate (60% AlgoSec with named objects and groups, 25% Guardicore, 15% Wiz), seconds per stage:

| rules | assets | nodes/edges | normalize | identity | graph | over_perm | cidr_overlap | shadowing | **path_trace** | total | peak RSS |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 200 | 85 | 85 / 173 | 0.005 | 0.001 | 0.001 | 0.002 | 0.001 | 0.006 | 0.001 | 0.02 s | 46 MB |
| 1,000 | 224 | 224 / 886 | 0.022 | 0.002 | 0.002 | 0.007 | 0.006 | 0.127 | 0.094 | 0.26 s | 51 MB |
| 2,000 | 401 | 401 / 1,813 | 0.049 | 0.004 | 0.009 | 0.016 | 0.014 | 0.538 | **7.83** | 8.5 s | 58 MB |
| 3,000 | 573 | 573 / 2,747 | 0.080 | 0.006 | 0.005 | 0.024 | 0.020 | 1.234 | **40.9** | 42.3 s | 64 MB |
| 5,000 | 926 | 926 / 4,645 | 0.113 | 0.008 | 0.007 | 0.038 | 0.030 | 3.13 | **1,265.7** | **1,269 s (21 min)** | 78 MB |
| 10,000 | 1,821 | 1,821 / 9,322 | 0.251 | 0.019 | 0.025 | 0.085 | 0.085 | 14.08 | **aborted at 900 s** | — | 112 MB |
| 20,000 | 3,583 | 3,583 / 18,773 | 0.460 | 0.049 | 0.043 | 0.167 | 0.173 | 53.10 | not attempted | — | 181 MB |

`path_trace` returned **0 findings at every one of those sizes** while consuming 99.7% of the runtime at 5,000 rules. Per-target breakdown at 5,000 rules (18 internet-reachable sensitive targets): 9 hit the 4,000-path cap in 0.2–2.5 s each; the other 9 yielded **zero** paths in a 20 s budget each and never reached the cap. One of those, given 600 s, took **142.9 s to yield its first path**. The BFS reachability closure over the same graph: **0.000 s**.

**The product's own scale dataset does not exercise this.** At identical rule count:

| dataset | rules | engine wall | findings | cross_tool_path |
|---|---|---|---|---|
| `scenarios._scale` / `scripts/seed_scale.py` | 5,000 | **0.51 s** | 5,030 | 0 |
| realistic multi-tool | 5,000 | **1,269 s** | 880 | 0 |

**2,480× apart at identical rule count.** The demo fixture (27 rules, 25 assets) is two to three orders of magnitude below the cliff, and `scripts/verify_engine.py` passes in 0.34 s while asserting nothing about it.

**How it fails.** No timeout, no progress, no partial result, no lock, and for half the targets not even the truncation warning — because the cap counts *yields*, and a target that never yields never trips it. `ENGINE.md` §10.3 concedes the cap bounds paths yielded rather than search performed (measured there at ~117 s on a 34-node mesh); it does not concede that the analyzer therefore becomes unusable at the stated target scale.

**Fix.** Phase C1 above: a per-target wall-clock budget alongside the cap, exhaustion surfaced as a degraded marker, and a longer-term move to k-shortest-paths or witness-plus-reconstruct, since `_bfs_witnesses` already answers the underlying question in 0.000 s.
</details>

<details>
<summary><b>B4 — On a meshed segment the cross-tool finding count is arithmetically <code>cap × targets</code>, and the change gate reports "no new sensitive reachability" while a new internet→PCI path is opened</b></summary>

**File:** `backend/src/graph/reachability.py` (`_PATH_SCAN_CAP`), `backend/src/change/simulate.py`
**Severity:** blocker

**Evidence — executed**, dense mesh where every path is cross-tool by construction:

| nodes | edges | sensitive targets | path_trace | cross_tool_path findings | = cap × targets? | signals payload | persist | peak RSS |
|---|---|---|---|---|---|---|---|---|
| 21 | 122 | 2 | 0.36 s | 7,922 | partial | — | — | 102 MB |
| 31 | 182 | 3 | 0.70 s | 11,923 | partial | — | — | 130 MB |
| 51 | 402 | 5 | 1.33 s | **20,000** | **5 × 4,000 exactly** | 54.7 MB | 2.25 s | 333 MB |
| 121 | 1,202 | 12 | 4.35 s | **48,000** | **12 × 4,000 exactly** | 132.3 MB | 5.94 s | 615 MB |

From 51 nodes upward the reported finding count is the constant `_PATH_SCAN_CAP` times the number of sensitive targets. It carries **no information about the estate**. `degraded_analyzers` was `[]` in every run.

**~50 nodes in one genuinely meshed segment is enough to defeat the change-approval gate**: it reports `no_new_sensitive_reachability: true`, `forced_escalate: false`, `forced_reasons: []`, `notes: []`, `delta_is_clean: true` for a change that opens a new internet→PCI path, because the truncated "before" scan and the truncated "after" scan are both capped and the delta between them is empty.

**Why it is a blocker rather than a scale nuisance.** `reachable()`'s `truncated` flag *is* correctly implemented and correctly plumbed into `agent/tools.py:60,72` — I confirmed it returns `True` on a truncated 6×5 mesh with a real `path_scan_truncated` WARNING carrying src/dst/cap. The design is sound. The gap is that the two consumers that matter most, `cross_tool_paths` (the snapshot findings) and `find_paths` (the change gate), do not carry it. So the one mechanism built to tell a proven "no path" from an exhausted budget is absent from both places where the distinction is load-bearing.

**Fix.** Carry `truncated` out of `cross_tool_paths` and `find_paths`; make any truncated scan force-escalate in `simulate_change` rather than compare two truncated sets; surface it in `degraded_analyzers` and `/api/health`.
</details>

<details>
<summary><b>B5 — <code>cidr_overlap</code> emits O(n²) findings, not just O(n²) work: 12.5 M findings and 12 GB RSS at 5,000 rules on an ordinary AlgoSec shape</b></summary>

**File:** `backend/src/analyzers/cidr_overlap.py`
**Severity:** blocker

**Evidence — executed.** Shape B is "every branch office to the DC on 443": nested sources, one destination group, one service — a completely ordinary enterprise rulebase shape.

| rules | cidr_overlap | findings | peak RSS |
|---|---|---|---|
| 1,000 | 5.5 s | 499,500 | 1,254 MB |
| 2,000 | 22.2 s | 1,999,000 | 4,870 MB |
| 5,000 | 201.6 s | 12,497,500 | **12,075 MB** |

Full `run()` on shape B, through the analyzer-isolation layer:

| rules | wall | findings | `degraded_analyzers` | peak RSS | persist to real PG |
|---|---|---|---|---|---|
| 1,000 | 4.3 s | 501,499 | `[]` | 2,195 MB | 38.3 s |
| 1,500 | 9.7 s | 1,127,249 | `[]` | 2,881 MB | — |

**~1,000 rules is enough** if a meaningful slice share a destination group and a service. `degraded_analyzers: []` throughout — the engine reports full health while producing half a million findings, and persistence dutifully writes all of them.

**How it fails on a memory-limited host.** An uncatchable SIGKILL from the OS OOM killer, which analyzer isolation cannot help against (that is a limit of the mechanism, not a defect in it), leaving `_ENGINE` unset so the next request repeats the work.

**Secondary, and related:** finding *volume* on a realistic shape is already a usability problem before the pathological one — 1,000 rules → 243 findings; 2,000 → 901; 4,000 → **3,415**, of which 95% are low-severity `cidr_overlap`.

**Fix.** Aggregate to one finding per (destination, service) cluster with a member count and the widest/narrowest pair named, rather than one per pair. Cap emission and mark truncation.
</details>

<details>
<summary><b>B6 — Persistence overwrites rules and criticals on a multi-device export; the console's maximum displayable severity drops from 100 to 80</b></summary>

**File:** `backend/src/persist.py` (canonical rule identity), `backend/src/normalizers/*`
**Severity:** blocker

**Why it matters.** Every firewall numbers its own rules from 1. A 4-device estate is the *normal* case, not an edge case.

**Evidence — executed** against the real Postgres, 12 rules across 4 devices, each numbering rules 1..3:

| | engine | database | claimed by `snapshots.notes` / `audit_log` |
|---|---|---|---|
| canonical rules | 12 | **3** | 12 |
| findings | 11 | **6** | 11 |
| graph edges | 4 | **3** | 4 |
| criticals ≥ 90 | 4 | **0** | — |

Overwritten and never persisted: `SSH open from the internet to PCI-DB` (100), `RDP open from the internet to PCI-DB` (100), `PostgreSQL open from the internet to PCI-DB` (100), `RDP open from the internet to APP-SEG` (90), `SSH open from CORP to PCI-DB` (85). **The highest severity the console can show on that estate is 80.**

The failure is doubly bad because the audit trail asserts the correct numbers: `snapshots.notes` says 12 rules and 11 findings while the tables hold 3 and 6. An auditor reconciling the two would conclude the database was tampered with.

**Fix.** Include the emitting device in the canonical rule key (Phase B5). Add a DB-backed test asserting persisted counts equal the projection for a multi-device fixture — the projection-vs-rows check already exists for single-device snapshots and passes, so the harness is there.
</details>

<details>
<summary><b>B7 — A differently-shaped export produces a completely clean estate: 0 records, 0 findings, <code>health: ok</code>, <code>degraded_reasons: []</code></b></summary>

**File:** `backend/src/normalizers/profile.py` (`require_rows` / `require_mapping`)
**Severity:** blocker · **introduced by remediation**

**Why it matters.** The validation layer added in remediation to answer "the normalizers validate nothing" returns *empty* for an absent key rather than raising. A wrong field name, a vendor variant, or an AlgoSec AFA multi-device `devices[]` wrapper therefore reads as "this customer has no policy," and every downstream signal agrees.

**Evidence — executed**, failure-loudness matrix:

| input | outcome |
|---|---|
| byte-truncated JSON | **loud** — `JSONDecodeError` → 422 → health 503 ✅ |
| one row missing `action` in 40 k | **loud, but total** — whole export aborts |
| one row with list-valued `src` | **loud, but total** — whole export aborts |
| Guardicore `action: "alert"` | **loud, but total** |
| Wiz `kind: "egress"` | **loud, but total** |
| array-truncated export (200 of 400 rows) | **silent** — half the estate, no signal |
| top-level keys named differently | **silent** — 0 records, health `ok` |
| AFA multi-device `devices[]` shape | **silent** — 0 records, 0 findings, health `ok`, `degraded_reasons: []` |
| all three exports empty | **silent** — 0 findings, health `ok` |

The asymmetry is the defect: the loud cases are loud but *total* (one bad row in 40,000 aborts everything), and the silent cases are the ones that produce a plausible-looking clean report.

**Fix.** Phase B3 + B4: `require_rows`/`require_mapping` raise on an absent key; a zero-record normalize is a non-`ok` health condition; per-rule isolation so one malformed row degrades one rule rather than the export.
</details>

<details>
<summary><b>B8 — Nested address groups, range objects and wildcard masks still resolve to <code>source_cidrs: []</code>, score E=0.1, and produce zero findings on internet→PCI RDP</b></summary>

**File:** `backend/src/normalizers/profile.py` (`object_cidrs`, `token_cidrs`), `backend/src/normalizers/algosec.py:123-150`
**Severity:** blocker · **regression: "fix narrowed to the probe"**

**Why it matters.** This was the previous audit's most damaging finding. The remediation validated the fix against a constructed export of nine **flat** named objects and declared it closed. Group-of-groups — the normal structure of a real firewall catalog — was not covered.

**Evidence — executed.** Ground truth in every row: **RDP (3389) from the whole internet to one host**, destination *not* tagged sensitive so the sensitive-dest rule cannot mask the defect.

| how a real export writes it | reported |
|---|---|
| `src: "0.0.0.0/0"`, `service: "tcp/3389"` | critical 90 ✅ |
| `src: "any"` / `"Any"` / `"ANY-EXTERNAL"` group / `"INTERNET"` group | critical 90 ✅ |
| address-group with `0.0.0.0/0` among members | critical 90 ✅ |
| `src: "0.0.0.0/1"` | critical 85 ✅ |
| `src: "10.0.0.0/8"` + `src_negate: true` (≡ the internet) | **medium 56**, titled "from 10.0.0.0/8" |
| `src: ["0.0.0.0/0"]` (list) | **aborts the whole export** |
| Check Point range object `0.0.0.0-255.255.255.255` | **NO FINDING** |
| nested group (group of groups) | **NO FINDING** |
| ASA wildcard mask `10.0.0.0 0.255.255.255` | **NO FINDING** |
| separate `netmask` field | **NO FINDING** |
| `service: "RDP"` (in the 25-token L7 table) | critical 90 ✅ |
| `service: "MS-WBT-Server"` (Check Point's own name) | **NO FINDING** |
| `service: "ms-rdp"` (Palo App-ID) | **NO FINDING** |
| `service: "application-default"` | **NO FINDING** |
| `service: ["tcp/3389"]` | **NO FINDING** |
| `service: {proto, port}` | **NO FINDING** |
| `port: 3389, protocol: "tcp"` columns, no `service` | **NO FINDING** |
| no `service` field at all | **NO FINDING**, and **zero warnings** |
| `service: "tcp/3389,1433"` (comma) | critical 90 ✅ |
| `service: "tcp/3380-3400"` (range) | critical 90 ✅ |
| `service: "tcp/443,udp/443"` | **NO FINDING** (`udp/443` alone: critical 78 QUIC) |
| `disabled: true` (grants nothing) | **critical 90** (false positive) |
| `action: "Allow"` / `"accept"` | critical 90 ✅ |

**Aggregate on a 300-rule export built only from spellings real exports use:** 50% of rules resolved to no source address space at all, 20% decoded to no port, and **45% of ground-truth internet→admin/data grants (54 of 120) produced no over-permissive finding.**

**Fix.** Phase B1 (recursive group resolution with cycle detection, range objects, wildcard masks, `netmask` field, vendor service vocabularies) and Phase B2 (unresolvable ⇒ conservative floor + a reported condition, not silence).
</details>

### High

<details>
<summary><b>H1 — <code>tcp/any</code> / <code>tcp/all</code> / <code>tcp/*</code> decodes to "port unknown" (P=0.5) instead of all ports; the same grant as <code>tcp/1-65535</code> produces zero findings instead of 90/critical</b></summary>

**File:** `backend/src/normalizers/common.py:306-352` (`_parse_port_spec`)
**Severity:** high (auditor) / high (verifier)

**Why it matters.** `tcp/any` is the standard Palo Alto / Check Point / AlgoSec spelling for "TCP, every port." The codebase deliberately built **one** wildcard vocabulary (`netaddr.is_any` → `any`/`all`/`*`/`0.0.0.0/0`) and applied it in three places — the whole-service token (`common.py:425`), src/dst tokens (`common.py:475`) and `_PROTOCOL_ALIASES` (`common.py:33`) — but never inside the port half. So `any` falls through to `int("any")`, is rejected, and the record carries `port=None` → `P_UNKNOWN` (0.5) with an empty interval set. Empty intervals also mean guardrail clause 2 (`_intersects(intervals, ADMIN_LATERAL_PORTS)`) cannot fire.

The inconsistency is sharp and in the wrong direction: `parse_service("all")` → `protocol=any`, P=1.0, forced critical; `parse_service("tcp/all")` → `port=None`, P=0.5, **no finding at all**. *Narrowing* the grant from "every protocol" to "every TCP port" makes the engine go silent.

**Evidence — executed**, full engine, all five analyzers, `allow ANY-EXTERNAL(0.0.0.0/0) -> app-01`:

```
tags=['prod']  svc=tcp/any        -> *** NO FINDINGS ***
tags=['prod']  svc=tcp/*          -> *** NO FINDINGS ***
tags=['prod']  svc=tcp/1-65535    -> over_permissive:90/critical/FORCED
tags=['prod']  svc=tcp/3389       -> over_permissive:90/critical/FORCED
tags=[]        svc=tcp/any        -> *** NO FINDINGS ***
tags=[]        svc=tcp/1-65535    -> over_permissive:60/critical/FORCED
```

Decode table:

```
'tcp/any'   proto=tcp port=None end=None warn=["unparseable port 'any'"]
'tcp/ALL'   proto=tcp port=None end=None warn=["unparseable port 'ALL'"]
'udp/any'   proto=udp port=None end=None warn=["unparseable port 'any'"]
'tcp/*'     proto=tcp port=None end=None warn=["unparseable port '*'"]
```

**Broader than AlgoSec service strings.** The Wiz and Guardicore normalizers call `parse_service(None, port, protocol)`, routing a separate `port` field through the same function: `port="*"` → `port=None, warn=["unparseable port '*'"]`. `"*"` is exactly how an Azure NSG writes `destinationPortRange` for all ports, and Wiz ingests Azure.

**Bounded blast radius (why high, not blocker).** With a sensitive-tagged destination the `sensitive` branch of `_reasons` still fires and `tcp/any` scores 100/critical/forced. And the change gate is **not** defeated for internet sources: `simulate.py:293-295` appends "creates new internet→internal exposure" from `is_internet_source`, independent of P — verified against the live demo engine (`0.0.0.0/0 -> app-server-07 tcp/any` gives `forced=True`). The false-negative bites when the destination is untagged or merely `prod`.

**No control surfaces the warning.** `profile.service_audit` does emit an audit row carrying `warnings: ["unparseable port 'any'"]`, but `grep -rn "warnings" app/main.py` returns only an unrelated comment and `grep -rln "warnings"` over `frontend/app` + `frontend/components` returns nothing. It survives only as raw JSON inside `/api/ingest`'s `resolved_objects` blob.

**Test hole.** `tests/test_parse_service.py::SERVICE_CASES` covers `tcp/abc`, `tcp/70000`, `tcp/500-100`, `tcp/`, `ip`, `all`, `*`, `ANY`, `tcp/1-65535` — and **no `<proto>/<wildcard>` case at all.**

**Fix.** Test each token with the existing `netaddr.is_any` before `_decode_port` and expand a wildcard to `(_PORT_MIN, _PORT_MAX)`; the full-range path already scores correctly via `PORT_SPAN_ANY`. Add `<proto>/<wildcard>` rows and a `parse_service(None, "*", "tcp")` row, plus an invariant that `parse_service("tcp/all")` and `parse_service("tcp/0-65535")` produce the same `port_score`.
</details>

<details>
<summary><b>H2 — Destination sensitivity (D) reads only the destination node's own tags: writing the destination as the subnet that contains a regulated asset drops the score two bands and escapes guardrail clause 3</b></summary>

**File:** `backend/src/analyzers/severity.py:175-179` (`dest_score`), with no membership expansion in `backend/src/graph/build.py`
**Severity:** high (auditor) / high (verifier, "at the ceiling of high")

**Why it matters.** Phase 1 resolved the **source** side (`source_cidrs` beats the label, `is_public` beats the string) and left the destination side purely label-driven. Real rulebases target network objects and groups far more often than individual hosts, so the *wider* — and therefore more dangerous — a destination is written, the **lower** it scores. That is a monotonicity violation in the under-reporting direction, and it silently escapes guardrail clause 3 ("a regulated/crown-jewel asset reachable from the internet"), which is port-independent by design and is the clause a compliance buyer relies on.

**Failure scenario.** `db-prod-01` = 10.10.5.9, tagged `crown-jewel` + `pci`. `DC-SUBNETS` is a network object = 10.10.0.0/16 which contains it. `allow 0.0.0.0/0 -> DC-SUBNETS tcp/1433` grants MSSQL from the whole internet to 65,534 addresses **including the crown jewel**, and scores 57/medium, not forced. The strictly narrower `allow 0.0.0.0/0 -> db-prod-01 tcp/1433` scores 100/critical/forced.

**Evidence — executed**, identical rule, three destination spellings:

```
dst=db-prod-01   dest_cidrs=['10.10.5.9/32'] dest_tags=['pci','crown-jewel']
   sev=100 band=critical forced=True  vec={'E':1.0,'P':0.9,'D':1.0,'B':1.5}
dst=DC-SUBNETS   dest_cidrs=['10.10.0.0/16'] dest_tags=[]
   sev=57  band=medium   forced=False vec={'E':1.0,'P':0.9,'D':0.4,'B':1.5}
dst=10.10.0.0/16 dest_cidrs=['10.10.0.0/16'] dest_tags=[]
   sev=57  band=medium   forced=False vec={'E':1.0,'P':0.9,'D':0.4,'B':1.5}
```

**Executed false all-clear.** `advisory/report.py:build_summary` gates `internet_reaches_regulated_data` on `forced_critical AND dest_tags & SENSITIVE_TAGS`, or a cross-tool path. With the subnet spelling both arms are dead:

```
dst=db-prod-01: by_band {'critical':1,'low':1} forced_critical=1 internet_reaches_regulated_data=True  sensitive_assets=['db-prod-01']
dst=DC-SUBNETS: by_band {'medium':1}           forced_critical=0 internet_reaches_regulated_data=False sensitive_assets=['db-prod-01']
```

The compliance report says *no* while simultaneously listing `db-prod-01` as a sensitive asset, and `_fallback` drops the "reaches regulated data" sentence from the executive summary.

**The engine internally proves the containment and ignores it.** With the broad rule ordered first, `shadowing` fires: `shadowed_rule sev=10 low — "Dead allow on db-prod-01: redundant rule never adds anything"`. `shadowing._covers` establishes destination-CIDR containment from `dest_cidrs` — the machinery for the fix already exists one module over. Far from compensating, that finding reads as *reassurance* about the very host now exposed.

**Bigger root cause than filed.** `dest_tags` is the **emitting tool's** tag list, not the merged asset's. An AlgoSec rule `0.0.0.0/0 -> db-prod-01 tcp/1433` where AlgoSec's catalog is untagged and Wiz classifies the same host `crown-jewel`+`pci` merges correctly (`g.nodes["db-prod-01"]["tags"] == ['crown-jewel','pci']`) and *still* scores D=0.4, sev 57, not forced — a directly-named crown jewel, no subnet involved. That defeats the flagship cross-tool-identity claim, not just the containment case.

**The team already considers this property load-bearing — for proposals only.** `change/simulate.resolve_dest_tags` aggregates by containment and `test_change_simulate.py::test_a_wider_cidr_never_narrows_the_tag_set` pins the exact inverse invariant ("A caller cannot dilute a regulated destination by aiming at its whole subnet"). It is enforced for proposed rules and never for ingested ones. Note it is half-open even there: `resolve_dest_tags("DC-SUBNETS")` returns `[]` while `resolve_dest_tags("10.10.0.0/16")` returns `['crown-jewel','pci','prod']`, so it is not a drop-in lift.

**Disclosure gap.** `ENGINE.md` §10.2 discloses "No CIDR-membership expansion" but scopes it to `_valid_traversal` and to *paths* being under-counted. Nothing discloses that D and the guardrail floor are containment-blind.

**Correction to the filed finding.** The third data point — destination written as `0.0.0.0/0` scoring 38 — reproduces but is *not* a defect: that is an egress/pseudo-node endpoint with an explicit, documented and defensible exemption (`test_the_internet_pseudo_node_is_the_only_exemption`). Aggregating the whole estate into `0.0.0.0/0` would mislabel every egress rule as crown-jewel.

**Fix.** Phase B6.
</details>

<details>
<summary><b>H3 — L7 app inference reads only the first port interval, and an <code>any/any</code> rule produces no transport finding at all: widening a rule removes the QUIC blind-spot finding</b></summary>

**File:** `backend/src/normalizers/common.py:273-278` (`_infer_l7`) and `backend/src/analyzers/transport_exposure.py:128`
**Severity:** high (auditor) / high (verifier)

**Why it matters.** `transport_exposure` is the fifth analyzer and the differentiator `ENGINE.md` §6.5 is built around. `_infer_l7(protocol, port)` takes one scalar and is called with `pstart` — the start of the **first interval only** — which is the exact "scored as its start port" defect the codebase says it eliminated for `port_score`. Separately, `transport_exposure.py:128` filters `r.port is not None`, so a true `any/any` rule is excluded from both checks even though `_opens`'s own docstring and `ENGINE.md:468-471` state that "a rule whose protocol is `any` opens the port on every transport."

**Evidence — executed**, end-to-end on the shipped demo export through the real normalizers (only `ALGO-080`'s `service` mutated in an in-memory copy):

```
service='udp/443'     -> 8 transport findings; transport_exposure 78 critical FORCED "QUIC (udp/443) reachable from the internet to app-server-09" + 40 medium fallback pair
service='udp/1-65535' -> 7 transport findings; QUIC blind spot GONE
service='udp/400-500' -> 7 transport findings; QUIC blind spot GONE
service='any'         -> 6 transport findings; BOTH transport findings GONE
service='udp/80,443'  -> 8; blind spot fires but titled "HTTP3-DISCOVERY (udp/80,443) ..."
```

Decode table: `'udp/443'` → `l7='quic'`; `'udp/400-500'` → `l7=None`; `'udp/1-65535'` → `l7=None`; `'udp/443-8443'` → `l7='quic'` *only because 443 is first*; `'udp/80,443'` → `l7='http3-discovery'`, named after port 80.

**A true silent all-clear the filed finding missed.** In the auditor's two scenarios `over_permissive` still fires at 90/critical, so those were a lost *risk class*, not a blanket all-clear. But below `over_permissive`'s thresholds, widening takes the finding count from 1 to 0:

```
src=10.20.5.0/24 -> app-01 (prod):
  udp/443      -> 1 finding (39 medium quic_blind_spot)
  udp/440-450  -> 0 findings   *** NOTHING REPORTED ***
  udp/1-65535  -> 0 findings   *** NOTHING REPORTED ***
```

That is exactly the "lateral QUIC" case `docs/FEATURES.md:170-173, 217` advertises.

**It propagates.** `graph/reachability.py:82` answers an app-scoped query (`app="quic"`) by `grant["l7_app"] == app`, so "what can reach X over QUIC?" also misses a `udp/1-65535` grant. `grep -rn l7_app backend/src` confirms it is set in exactly one place and never enriched later.

**A test currently locks the defect in.** `backend/tests/test_parse_service.py:55` pins the row with the comment "l7 is inferred from the FIRST interval's start port (pre-existing behaviour)."

**Fix.** Infer L7 over `DecodedService.intervals()` rather than `pstart`, returning the blind-app match if any interval hits one; treat `protocol == "any"` as matching both tcp and udp `APP_BY_PORT` keys; drop the `r.port is not None` filter at `transport_exposure.py:128`. Update the test row and add a monotonicity test: widening a service must never reduce the finding set for that rule.
</details>

<details>
<summary><b>H4 — A malformed address object collapses exposure to E=0.1 and the finding disappears entirely: bad input lowers reported risk</b></summary>

**File:** `backend/src/normalizers/profile.py:169-190` (`object_cidrs`) feeding `backend/src/analyzers/severity.py:97-101` (`exposure_score`)
**Severity:** medium (auditor) / **high (verifier — raised)**

**Why it matters.** `object_cidrs`'s own docstring states the problem it exists to fix: "`10.0.0.0/33` and `300.1.1.1/24` are typos in what is usually a BROAD rule, and today they quietly become single-host identity assets — i.e. bad input LOWERS the reported risk, which is the worst failure direction available to a security tool." The remediation added a warning row and an `abstract` flag but **did not change the scoring outcome**: the object still resolves to `cidrs == []`, the record still carries `source_cidrs == []`, and `exposure_score` still falls back to `E_IDENTITY = 0.1`.

**Failure scenario.** AlgoSec catalog object `BAD-OBJ = {"type": "network", "value": "10.0.0.0/33"}` — a fat-finger for `/3`, a broad grant — used as the source of `allow BAD-OBJ -> db-prod-01 tcp/22`, db tagged `pci`+`prod`. E = 0.1 clears none of `sensitive_dest_min_E` (0.3) or `broad_source_E` (0.5): **SSH to a PCI database produces no finding at all.**

**Evidence — executed**, all five analyzers:

```
R6 src=BAD-OBJ  kind=identity scidrs=[]            svc=tcp/22 act=allow dtags=['pci','prod']
R7 src=GOOD-OBJ kind=identity scidrs=['0.0.0.0/3'] svc=tcp/22 act=allow dtags=['pci','prod']
object_cidrs bad: ([], ["unresolvable object value '10.0.0.0/33'"])
E(BAD-OBJ): 0.1     E(GOOD): 0.9     P tcp/22: (1.0, 'admin / lateral-movement')
--- total findings: 1
   over_permissive | R7 | 100 critical
```

R6 produces no finding of any type. `degraded_analyzers` empty. `is_internet_source('10.0.0.0/33','identity',[])` → `False`, so no guardrail floor either.

**Broader than filed.** A raw malformed *token* in the src column, no catalog involved, has the identical outcome: `src="10.0.0.0/33"` → `source_cidrs=[]` → 0 findings, 0 degraded. `token_cidrs`'s own docstring names the failure verbatim — "the rule then scores as a single host (E=0.1) and vanishes from every piece of subnet math" — while the code still produces exactly that.

**An internal inconsistency, not a considered tradeoff.** `object_is_abstract` (`profile.py:145-150`) says of the identical warning: "FAIL CLOSED: we have no evidence it is a host, and calling it one is precisely how a typo'd broad rule came to score as a single host." Abstractness fails closed; exposure fails open on the same signal.

**The guarding test buys false confidence.** `tests/test_normalizers.py:150-168` `test_a_garbage_cidr_is_recorded_as_malformed_not_reclassified` opens with "It must not quietly become a single-host asset with E=0.1" and then asserts only `source_cidrs == []` — precisely the input that yields E=0.1. It never asserts a score. It passes today while the failure it names is live:

```
$ pytest tests/test_normalizers.py -q -k "garbage_cidr or malformed_object_value"
4 passed, 77 deselected
```

(To be fair, the "single-host *asset*" half **is** genuinely fixed — the entity is `abstract=True` with no fabricated `/32`. Only the E=0.1 half is unmet.)

**The audit trail records it but nothing surfaces it.** `res.resolved` gets `{"malformed": true, "fields": {"src": [...]}}` on `rule:R6`, rendered as a truncated `JSON.stringify(o.resolved)` in `IngestInspector.tsx:127-134` — no badge, no count, no filter, no health signal.

**Fix.** Phase B2 — carry a `source_unresolved` flag onto the record and have `exposure_score` return a conservative floor for a malformed *network* object; at minimum emit a first-class `ingest_defect` finding so it appears in the findings list, not only the inspector. Add the assertion the existing test's docstring already promises.
</details>

<details>
<summary><b>H5 — <code>shadowing</code> is clean O(n²): 27 s at 8,000 rules, ≈11 minutes extrapolated at 40,000</b></summary>

**File:** `backend/src/analyzers/shadowing.py`
**Severity:** high

**Evidence — executed**, single process, warm:

| rules | normalize | identity | graph | over_perm | cidr_overlap | **shadowing** | total |
|---|---|---|---|---|---|---|---|
| 1,000 | 27 ms | 11 ms | 2 ms | 8 ms | 4 ms | **401 ms** | 473 ms |
| 2,000 | 56 ms | 34 ms | 4 ms | 16 ms | 9 ms | **1.62 s** | 1.77 s |
| 4,000 | 123 ms | 63 ms | 8 ms | 30 ms | 17 ms | **6.82 s** | 6.90 s |
| 8,000 | — | — | — | — | — | **27.0 s** | — |
| 40,000 (extrapolated) | — | — | — | — | — | **≈ 11.3 min** | — |

Three independent extrapolations agree (11.0 / 11.1 / 11.3 min). Peak RSS is modest (78 MB at 2,000 rules) — this is CPU, not memory. A second measurement series on a different shape gives 0.127 s / 0.538 s / 1.234 s / 3.13 s / 14.08 s / 53.10 s at 1k/2k/3k/5k/10k/20k, the same curve.

Note this is the *correct* analyzer being expensive, not a broken one — `shadowing` scored 5/5 on mutation testing and its directional-coverage property is genuinely tested. It simply does not bucket before the ordered-pair scan.

**Fix.** Phase C3 — bucket by destination and service before pairing. Exit criterion: 8,000 rules in < 5 s.
</details>

<details>
<summary><b>H6 — Normalizers are all-or-nothing per export: one malformed row in 40,000 aborts everything</b></summary>

**File:** `backend/src/normalizers/*`, `backend/src/normalizers/profile.py` (`require_token`, `require_rule`)
**Severity:** high

One row missing `action`, one row with a list-valued `src`, one Guardicore `action: "alert"`, one Wiz `kind: "egress"` — each aborts the entire export with a `NormalizeError`. The refusal is *diagnosable*, which is the right instinct and better than silent coercion, but the granularity is wrong: a 40,000-rule production export will contain at least one row the adapter does not model, and the customer gets nothing rather than 39,999 rules and one audit entry.

Paired with B7, the ingest layer has both failure modes at once and each in the wrong place: total-abort where it should degrade one row, and silence where it should abort.

**Fix.** Phase B4 — per-rule isolation with a named audit entry and a partial-ingest health signal.
</details>

<details>
<summary><b>H7 — The role boundary ships OFF (<code>sync:false</code>) while health reports <code>ok</code></b></summary>

**File:** `backend/app/main.py` (role guards / capability sync)
**Severity:** high · partial regression from previous blocker B6/B16/B18

The guards themselves are real and correct — the scanner provably fails on an injected unguarded route, which is the right kind of test. But the default deployment ships with the boundary disabled, and `/api/health` reports `ok` in that state, so nothing tells an operator that `x-npr-role` is being trusted. A control that is correct but off by default, with no signal that it is off, is not a control.

**Fix.** Phase D4 — on by default, and `sync:false` becomes a non-`ok` health condition.
</details>

<details>
<summary><b>H8 — A degraded analyzer run is persisted as authoritative under the same snapshot id and published as <code>status:"ok"</code></b></summary>

**File:** `backend/src/analyzers/run_all.py`, `backend/src/persist.py`, `backend/app/main.py`
**Severity:** high · **introduced by remediation** (self-reported by the remediation log as blocker-class, shipped anyway)

The isolation mechanism is well built — 9/9 mutations killed, both isolation behaviours guarded (`test_a_failing_analyzer_leaves_the_other_four_intact`, `test_reanalyze_never_swallows_an_analyzer_failure`), and it never fired spuriously across every adversarial export I built. The defect is entirely in what happens *after*: the partial result overwrites the good rows under the same snapshot id, and is served as `status:"ok"` / `served_from:"database"`. A loud crash was converted into a quiet, durable, authoritative under-report.

**Fix.** Phase D1 — never overwrite good rows with a degraded run; propagate `degraded_analyzers` to health and to the findings payload.
</details>

<details>
<summary><b>H9 — The change pipeline is the least-tested code in the repo: 6 of 20 injected defects killed (30%)</b></summary>

**File:** `backend/src/change/simulate.py`, `staging.py`, `apply.py`, `backend/src/normalizers/profile.py`, `backend/src/analyzers/path_trace.py`
**Severity:** high

**Method.** 112 single-line defects injected one at a time at HEAD `473609c`; for each: apply → run the full 1,297-test suite → run `verify_engine.py` → revert → confirm green. All 28 survivors were re-run with `PYTHONDONTWRITEBYTECODE=1` after I found a same-size/same-second `.pyc` staleness trap in my own harness; all 28 survived again. Every survivor then got a purpose-built probe on a pristine `git archive HEAD` copy showing the exact baseline-vs-mutant behaviour change.

**Kill rate by file** (worst end):

| file | injected | killed | survived | kill % |
|---|---:|---:|---:|---:|
| `analyzers/path_trace.py` | 1 | 0 | 1 | **0%** |
| `change/apply.py` | 2 | 0 | 2 | **0%** |
| `normalizers/profile.py` | 6 | 2 | 4 | 33% |
| `change/simulate.py` | 6 | 2 | 4 | 33% |
| `change/staging.py` | 5 | 2 | 3 | 40% |
| `analyzers/over_permissive.py` | 4 | 2 | 2 | 50% |
| `analyzers/transport_exposure.py` | 5 | 3 | 2 | 60% |
| `analyzers/cidr_overlap.py` | 5 | 3 | 2 | 60% |
| `identity.py` | 12 | 8 | 4 | 67% |
| **TOTAL (all 20 files)** | **112** | **84** | **28** | **75%** |

Four survivors are equivalent mutants I proved rather than reported (M34, M64, X12, N18), so the real rate is **84 / 108 non-equivalent = 78%**.

**Verified survivor consequences** (each measured, not assumed):

| id | site | mutation | consequence |
|---|---|---|---|
| M63 | `simulate.py:293` | drop the internet→internal force-escalate clause | escalate → **LLM `auto_approve`**, end to end |
| N20 | `simulate.py:195` | `_granted_intervals` ignores the service label | `tcp/80,3389` from `0.0.0.0/0` loses the admin guardrail and both op reasons |
| M62 | `simulate.py:173` | `resolve_cidrs` stops resolving the token | `proposed.source_cidrs` reported `[]` for a `0.0.0.0/1` request |
| X01 / M58 / N28 / N27 | `profile.py:99,113,117` | four ways to misclassify abstract vs concrete | a `/31`, a `/24`, a 2-member group or a 1-member `address-group` reads as a host → **fabricated** internet→PCI path |
| M33 | `identity.py:523` | `all(e.abstract)` → `any(...)` | the 100/critical cross-tool path **disappears** |
| M51 | `path_trace.py:16` | `SENSITIVE_TAGS - {"pci"}` | internet→PCI chain with a pci-only terminal disappears |
| N12 / N13 / N14 | `staging.py:106,121,160` | three coverage/equality defects | a real push becomes `duplicate_staged` → `no_op` |
| N17 | `apply.py:80` | `order - 1` → `+ 1` | the shadowing finding **survives** the applied fix |
| M42 | `over_permissive.py:77` | `E >= 0.5` → `>` | `/23` + RDP finding **vanishes entirely** |
| M08 | `severity.py:514` | drop `sorted()` in `_canonical_intervals` | 90/forced-critical → 86/not-forced |
| X08 | `transport_exposure.py:78` | drop the protocol-`any` arm | `any/443` → PCI DB produces no fallback finding |
| N09 | `transport_exposure.py:141` | vector from the tcp side | published vector E 1.0→0.1, B 1.5→1.0 |
| N05 / N06 | `cidr_overlap.py:94,145` | containment direction / outer-rule naming | title claims a `/24` covers a `/8` |
| X04 | `classify_change.py:198` | omitted criterion defaults False | audit-trail criteria contradict the engine |

**Two calibration observations about the suite itself.** (1) `verify_engine.py` contributed **zero independent detection power** — across all 84 kills, `mutants whose ONLY killer was verify_engine: []`, because `test_demo_golden.py::test_every_verify_engine_check_passes` runs the same check set in-process. (2) Kill power is concentrated: `test_severity.py` 189 mutation-failures, `test_demo_golden.py` 91, `test_analyzers.py` 68, `test_zones.py` 36, `test_identity.py` 31, then a long tail. `test_mutation_guards.py` — written specifically to close the previous round's survivors — contributed 8 and was the *sole* killer for 3, so it does real work but is narrow by construction: it guards named historical mutants, not classes of them. **18 mutants were killed by exactly one test**, i.e. one deletion from surviving — notably M40/M41 (analyzer isolation and `reanalyze` fail-closed) and M48 (the fallback-pair range match).

**Fix.** Phase D3. The specs and probe scripts already exist; this is a well-defined day of work per file.
</details>

<details>
<summary><b>H10 — <code>/api/findings</code> returns 57.8 MB and <code>/api/graph</code> 50.1 MB with no pagination</b></summary>

**File:** `backend/app/main.py`
**Severity:** high

**Evidence — executed**, real API over a 51-node mesh (TestClient + real Postgres):

| endpoint | status | time | body |
|---|---|---|---|
| `/api/health` | 200 | 3.54 s | 456 B — `"status":"ok"`, `degraded_reasons: []` |
| `/api/findings` | 200 | 3.90 s | **57.8 MB** |
| `/api/graph` | 200 | 3.64 s | **50.1 MB** |
| `/api/assets` | 200 | 0.01 s | 21 KB |
| process peak RSS | | | **975 MB** |

Note `/api/health` takes 3.54 s and still says `ok` on an estate where the findings payload is 57.8 MB of `cap × targets` arithmetic.

**Fix.** Phase C5.
</details>

### Medium

<details>
<summary><b>M1 — <code>protocol == "any"</code> with an explicit port is treated as "every port": a vendor's "ALL protocols on 443" becomes an any/any rule and marks a live deny dead</b></summary>

**File:** `backend/src/analyzers/severity.py:547-556` (`_class_applies`) and `backend/src/analyzers/shadowing.py:82-90` (`_service_covers`)
**Severity:** medium

**Why it matters.** `_PROTOCOL_ALIASES` maps `ip`/`all`/`*`/`ip-any` to canonical protocol `any`, which is right for a bare service token. But when a row carries a **separate port column** — the shape most cloud/SD-WAN/CSV exports use, where `protocol: "ALL"` means "TCP and UDP", not "all ports" — the decoded record is `protocol="any", port=443`. `_class_applies` short-circuits `return protocol == "any" or span > PORT_SPAN_ANY` regardless of the interval set, and `_service_covers` returns `True` unconditionally when the earlier rule's protocol is `any`. Both directions are wrong: the rule is over-reported as "any protocol/port", **and** a genuinely live deny below it is declared dead.

**Failure scenario.** Guardicore/SD-WAN policy `{"src_label":"web","dst_label":"db","protocol":"ip","port":443,"action":"allow"}` followed by `{"protocol":"tcp","port":3389,"action":"deny"}`.

**Evidence — executed**, through `guardicore.normalize → shadowing / over_permissive`:

```
  G1 proto=any port=443  svc='any/443'  act=allow
  G2 proto=tcp port=3389 svc='tcp/3389' act=deny
SHADOW:   41 Dead deny on db: blocked traffic is actually allowed
          | deny web -> db (tcp/3389) never fires; earlier allow G1 (web) already permits it
OVERPERM: 41 any protocol/port open from web to db  P-class: any-port
```

The dead-deny half is the expensive one: an operator told a working RDP block is dead will remove it.

**Fix.** In `_class_applies`, only take the `protocol == "any"` short-circuit when the interval set is genuinely unbounded (`intervals is None` or spans the full range); otherwise fall through to `_intersects`. In `_service_covers`, when `earlier.protocol == "any"` but `earlier` names port intervals, require interval containment rather than returning `True`. Add a Guardicore fixture with `protocol: "ip"` and an explicit port to `test_shadowing.py`.
</details>

<details>
<summary><b>M2 — Vendor service vocabularies and non-string service shapes silently produce no finding, several with zero warnings</b></summary>

**File:** `backend/src/normalizers/common.py` (`parse_service`), `backend/src/normalizers/*`
**Severity:** medium (a constituent of B8, listed separately because the fix is independent)

`service: "MS-WBT-Server"` (Check Point's own name for RDP), `service: "ms-rdp"` (Palo App-ID), `service: "application-default"`, `service: ["tcp/3389"]`, `service: {proto, port}`, separate `port`/`protocol` columns with no `service`, and **no `service` field at all** each produce no finding. The last case produces **zero warnings** — the record is simply portless and the engine treats "port unknown" as mid-risk, which as `severity.py:150-152` intends is "a mid-risk fact, not a safe one" — except at P=0.5 it is not mid-risk, it is invisible, because every reason arm needs P ≥ 0.85.

The 25-token L7 table handles `RDP`, `SSH`, `HTTPS` etc., so the *concept* is implemented; it is the vendor spelling coverage that is thin.

**Fix.** Extend the L7 token table with Check Point and Palo App-ID vocabularies; accept list- and dict-valued `service` where the vendor emits them; make "no service field at all" a warned condition rather than a silent portless record.
</details>

<details>
<summary><b>M3 — Ingest warnings and malformed-field markers are recorded but effectively invisible</b></summary>

**File:** `frontend/components/IngestInspector.tsx:127-134`, `backend/app/main.py`
**Severity:** medium

The remediation correctly added per-object `warnings` and per-rule `{"malformed": true, "fields": {...}}` audit rows. They render as `JSON.stringify(o.resolved)` inside a `truncate max-w-[45%]` span — no badge, no count, no filter — and `/api/health` and the snapshot payload carry no ingest-warning signal at all (`grep -rn "warnings" app/main.py` returns only an unrelated comment; `grep -rln "warnings"` over `frontend/app` + `frontend/components` returns nothing).

The data is there and correct. Nobody will see it.

**Fix.** Phase D2 — a count and a filter in the inspector, and a warning count in the health payload.
</details>

<details>
<summary><b>M4 — <code>scripts/verify_engine.py</code> is a duplicate CI step, not a second opinion</b></summary>

**File:** `backend/scripts/verify_engine.py`, `backend/tests/test_demo_golden.py`
**Severity:** medium

Across all 84 mutation kills there is not one mutant `verify_engine` caught that `pytest` did not — the set of mutants whose only killer was `verify_engine` is empty. It failed independently on 11 mutants, always alongside the suite. That is expected, since `test_demo_golden.py::test_every_verify_engine_check_passes` runs the same check set in-process, but it means the separate CI step buys nothing and creates the impression of independent verification. It also runs in 0.34 s and asserts nothing about any of the three scale cliffs.

**Fix.** Phase D5 — give it at least one property the suite does not assert (a scale bound would be the obvious candidate), or delete the step.
</details>

<details>
<summary><b>M5 — Finding volume on a realistic estate is 95% low-severity <code>cidr_overlap</code> noise</b></summary>

**File:** `backend/src/analyzers/cidr_overlap.py`
**Severity:** medium

1,000 rules → 243 findings; 2,000 → 901; 4,000 → **3,415**, of which ~95% are low `cidr_overlap`. This is the non-pathological version of B5 and it matters independently: a reviewer facing 3,415 findings on a 4,000-rule estate will not read them, which undermines the ranking layer the product is sold on.

**Fix.** Cluster and rank overlaps rather than emitting per pair; consider making low-severity overlaps a *count* on the parent rule rather than individual findings.
</details>

### Low

<details>
<summary><b>L1 — IPv4-mapped IPv6 is unwrapped by <code>is_public</code> but not by <code>exposure_score</code>: <code>::ffff:0.0.0.0/96</code> scores E=0.1</b></summary>

**File:** `backend/src/analyzers/severity.py:471-479` (`_exposure_of`), also `prefixlen_of` at `:416`
**Severity:** medium (auditor) / **low (verifier — downgraded on reachability)**

**Why it matters.** `netaddr.py`'s module docstring makes unwrapping an explicit published decision — "IPv4-mapped v6 is UNWRAPPED to its embedded v4 network and classified as v4 ... `::ffff:10.0.0.0/104` is therefore 10/8" — with the stated reason that not doing so "would silently hide an internet-facing v6 rule written in mapped form." `_unwrap_mapped` is applied inside `is_public` only; `_exposure_of` calls `_band_for(net.version, net.prefixlen)` on the raw network, and every mapped block lands at prefixlen ≥ 96, so the v6 table always returns 0.1. The two halves of the same documented rule disagree.

**Evidence — executed:**

```
0.0.0.0/0        E=1.0 public=True   |  ::ffff:0.0.0.0/96      E=0.1 public=True  SAME=False
10.0.0.0/8       E=0.9 public=False  |  ::ffff:10.0.0.0/104    E=0.1 public=False SAME=False
1.0.0.0/8        E=0.9 public=True   |  ::ffff:1.0.0.0/104     E=0.1 public=True  SAME=False
52.20.10.0/24    E=0.3 public=True   |  ::ffff:52.20.10.0/120  E=0.1 public=True  SAME=False
::ffff:8.8.8.8   E=0.1 public=True   |  8.8.8.8                E=0.1  SAME=True   (hosts agree)
```

**The verifier found it worse than filed within the analyzer**, and then downgraded the severity anyway. The filed finding says the guardrail floor still fires on a sensitive destination. It does not: `over_permissive.analyze` drops the record when `_reasons` is empty and all four arms are E-gated, so `::ffff:0.0.0.0/96 -> pci-host tcp/3389` yields **no finding at all** while the plain `0.0.0.0/0` spelling yields 100/critical/forced. Only an `any/any` rule survives, via the one E-independent arm. `path_trace` cannot catch it either (see B1).

**Why low.** There is no customer-export ingest path today, the one user-supplied source string (`/api/change/classify`) is independently protected — mapped sources still force-escalate with the identical three guardrail reasons, because that path calls `is_internet_source`/`zone_of`, which unwrap — and no supported vendor emits IPv4-mapped CIDR *blocks*. The mapped spelling that does occur in the wild is a single **host**, and for hosts both spellings agree. **Caveat for the reader: if any real export is ever observed carrying a mapped block, this becomes high immediately**, because the failure is total silence in the flagship analyzer with no second net.

**Fix.** Export `_unwrap_mapped` (drop the underscore) and apply it in `_exposure_of` before `_band_for` and in `prefixlen_of` (which today prints 96). Cleaner: unwrap once in `netaddr.parse_net` so `_exposure_of`, `cidr_overlap.source_nets`, `PolicyRecord._canonicalize_cidrs` and `zones.zone_of` all see one canonical form. Add a spelling-invariance test: for every band row, `exposure_score("::ffff:X/(N+96)") == exposure_score("X/N")`.
</details>

<details>
<summary><b>L2 — Disabled/inactive rules and negated source/destination fields are silently dropped</b></summary>

**File:** `backend/src/normalizers/algosec.py:170-196`, `guardicore.py:135-152`, `profile.py`
**Severity:** high (auditor) / **low (verifier — downgraded; Phase-3 scope, no reachable input path)**

**The code fact is true and reproduces.** No normalizer reads `disabled`/`enabled` or any `negate` flag, and `require_token`/`require_rule` do not refuse them, so both are silently dropped. `grep -rniE "negate|disabled|enabled|inactive" backend/src/` returns no normalizer hit.

Executed:

```
== (a) DISABLED broad allow + live deny below   (input carried "disabled": true, "enabled": false)
    100 critical forced=True  over_permissive :: tcp/1-65535 open from the internet to db-prod-01
    100 critical forced=False shadowed_rule   :: Dead deny on db-prod-01: blocked traffic is actually allowed
== (b) negated source (allow NOT 10/8 -> db 3389)
     85 critical forced=False over_permissive :: RDP open from INTERNAL to db-prod-01
```

**Why the verifier downgraded it to low.** Reachability is nil, not merely privileged. There is no upload endpoint and no API client: `normalize_all()` reads three fixed files from `backend/data/mock/`, the only input control is `POST /api/admin/dataset` over a fixed enum of code-generated builders, and none of the generated fixtures contains a `disabled` or `negate` key. Decisively, `main.py:389` and `main.py:574` call `write_scenario(_ACTIVE_SCENARIO)` **before** every lazy engine build and every `/api/recompute`, overwriting `data/mock` from code — so even hand-editing the fixture is regenerated away before it is read. The behaviour is observable only by importing the module and calling `normalize()` on a dict you wrote yourself.

It is also not hidden: `README.md:68`, `DEMO.md:51` and `docs/FEATURES.md:22` all state there is no upload path, and `docs/REQUIREMENTS.md` schedules the exact fix as FUT-P3-2 ("honour `enabled`/`disabled`") with the Phase-3 exit criterion written out as "a rule marked disabled produces no allow edge," and FUT-P3-4 names the fabricated "traffic is actually allowed" deny case verbatim. The branch under audit is Phase 2. Two details of the filing are also off: half the claim fails toward **over**-reporting (the less-bad direction), and case (b) scores 85, not 94. The `persist.py:140 "enabled": True` sub-claim collapses entirely — `PolicyRecord` has no `enabled` field and `db/schema.sql:150` declares `enabled boolean NOT NULL DEFAULT true`, so the hardcode restates the schema default for a concept the canonical model deliberately does not carry.

**What survives is a genuine hygiene item.** The normalizers' own stated contract (`profile.py`'s `NormalizeError` docstring — "what it is never allowed to be is 'normalize something else and say nothing'") is honoured for list-valued src/dst, unmapped action verbs and malformed addresses, and not for `disabled`/`enabled`/`negate`.

**Fix.** Quick win #5 — a guard in `require_rule` that raises `NormalizeError` on a truthy `disabled`, a false `enabled`, or any negation key, so the unmodelled semantics fail loud on the day a real export first arrives.
</details>

<details>
<summary><b>L3 — Identity-layer determinism and hygiene survivors</b></summary>

**File:** `backend/src/identity.py:520-523, 611`
**Severity:** low

Three surviving mutations that are not correctness defects but are unpinned contracts: sorting assets by `kind` changes asset order everywhere downstream with no test noticing (M35); keeping `None` identifiers persists `{...,'mac': None}` (N24); and dropping the lexicographic tiebreak at `:520` is provably equivalent today only because `sorted` is stable and `members` happens to be pre-sorted (M34) — a latent coupling that will break silently if either premise changes.

**Fix.** Pin the asset ordering contract and the identifier-pruning contract in `test_mutation_guards.py`; make the `:520` tiebreak explicit rather than relying on upstream ordering.
</details>

<details>
<summary><b>L4 — <code>npm audit</code> reports high-severity transitive advisories in the frontend toolchain</b></summary>

**File:** `frontend/package.json` / lockfile
**Severity:** low

`npm audit` reports high-severity advisories reachable only through the build/lint toolchain (`@next/eslint-plugin-next` → `glob`; `browserslist` unbounded memory growth, GHSA-c83g-rgw3-j3cx, CVSS 7.5). These are dev-dependency paths, not runtime exposure, and the fix is a semver-major bump of `eslint-config-next`.

**Fix.** Schedule the major bump; not urgent, but it will show up in any customer's supply-chain review.
</details>

---

## Appendix — how to reproduce

- Python: `/Users/mehulpuri/Projects/ztpa/backend/.venv/bin/python`
- Offline suite: `… -m pytest` (1,297 collected)
- Full suite: `NPR_TEST_DATABASE_URL='postgresql://npr:nprdev@localhost:55433/npr' … -m pytest`
- Engine self-check: `… backend/scripts/verify_engine.py`
- Probe scripts, mutation harness (`harness.py`, `muts*.json`, `*.results.json`, `probe_*.py`) and raw output are under the audit scratchpad; every table in this document is regenerable from them.
- The working tree was restored after every mutation and every probe: `git status --porcelain` is empty, `pytest` is green, `verify_engine.py` prints `ALL CHECKS PASSED`.
