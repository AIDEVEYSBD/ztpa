# Test backlog

Everything that is built but not yet tested the way it ultimately has to be. Each line says
what is untested, why it matters, and what unblocks it. Updated as work lands; when an item
is tested, move it to **Done** with the date and the evidence.

Feature status lives in [TRACKER.md](TRACKER.md); this file is only about verification.

## Needs a person (UI and review quality)

| # | What | Why it matters | Unblocked by |
|---|---|---|---|
| T1 | Every FRR screen judged by a person in a real browser: Exports, Context data, Rule review, Change package, Approvers, Knowledge | Automated part done 2026-10-30 (`scripts/ui_walkthrough.py`: headless Chromium signs in, uploads, visits every screen, runs the agents; 0 console errors / failed requests at 1440, 1280 and 1024 px; screenshots reviewed and 6 defects fixed). Still needs a person to use it and judge it | A tester with the UAT script (docs/frr/UAT.md) |
| T2 | Narrow-screen / small-laptop layout of the register and package screens | Checked at 1024 px in screenshots: register scrolls horizontally, its row detail now stacks below 1280 px, bulk-decision buttons wrap as a pair. Below 1024 px and on real devices not checked | T1 |
| T3 | The two-stage approval with two different people end to end in the UI | Staging proved owner validation and the four-eyes refusal via the API, not a second person approving | Two testers, each granted a duty |
| T4 | Narrative quality judged by network owners on real rules | Model output was checked for schema and citations, not for usefulness to an owner | Real export + client standards loaded |
| T21 | NAT semantics confirmed with a Check Point engineer: whether access rules match pre- or post-NAT on the client's gateways, and whether NAT-rule shadowing matches Check Point's own NAT order (manual vs automatic sections) | The review deliberately does not rewrite grants through NAT; if the gateways match post-NAT, internet exposure via NAT could be under-reported | A Check Point engineer + one real NAT rulebase |
| T5 | `mgmt_cli` commands and rollbacks executed on a lab Check Point management server | The commands follow the documented syntax but have never been run; a wrong rollback is worse than none | A Check Point lab / test management server and an engineer |

## Needs real client data

| # | What | Why it matters | Unblocked by |
|---|---|---|---|
| T6 | Check Point parser on a real, sanitised export (with hit counts, NAT, sections, inline layers) | Only synthetic exports have been parsed | Sanitised export from the client |
| T7 | Stealthwatch flow export and CMDB/IPAM extract in their real column layouts | Column aliases are guesses from typical exports | Sample files |
| T8 | Skybox export | Parser not built: format unknown | A sample export (01.1b) |
| T9 | Evaluation on the reviewers' labelled rulebase; decide the severity-tuning signal (broad internal admin, internet-exposed DB ports) | Current eval set is labelled by construction | Labelled rulebase (FRR-01.5) |
| T22 | Narrative eval on the client's own rules and documents | Live runs so far (Vertex gemini-2.5-pro, Azure gpt-4.1-mini, both clean) used the synthetic rulebase and two sample excerpts | T6, T10 |
| T25 | Review comparison on two real, successive exports of the same rulebase; CSV opened in the reviewers' spreadsheet tool | Rule uids are assumed stable across exports (Check Point uids are); verified only on synthetic pairs | Two real exports some weeks apart (T6) |
| T10 | Knowledge base with the client's standards, exceptions and runbooks; check retrieval picks the right passages | Retrieval tested on a two-section sample | Client documents |

## Needs a deployment or environment

| # | What | Why it matters | Unblocked by |
|---|---|---|---|
| T11 | SSO with the client's identity provider: login, role map, logout | Staging uses break-glass | IdP app registration (docs/SSO.md) |
| T12 | Azure Front Door + WAF + edge lock in front of the frontend | Staging runs without Front Door (no domain) | A domain for Azure staging |
| T13 | GCP edge: HTTPS load balancer + managed certificate + Cloud Armor + IAP | Staging uses the run.app URL through the IAM proxy | A domain for staging |
| T14 | GitHub Actions: CI (`ci.yml`) and both deploy workflows on GitHub | Linted with actionlint, never run | Push the branch; configure environments |
| T15 | Autoscaling under load at production size, from inside the VNet; Cloud SQL / Flexible Server connection budget at max instances | Run at staging size on Azure (2026-10-30, below): API 1→4 replicas, frontend 1→3, 160 clients, 125 req/s, 99.99% success after four fixes. Not yet at production size (D2ds database, 10 API replicas) or on GCP | A production-sized environment; GCP needs `gcloud auth login` |
| T27 | Vertex BYOK from a secret store | Unit-tested with a generated key; never with a real key from Key Vault / Secret Manager | On Azure staging, put a Vertex service-account key in `byok_secrets` as `GOOGLE_APPLICATION_CREDENTIALS_JSON`, set `ADVISORY_PROVIDER=vertex`, run the narrative eval |
| T17 | Alerts reach a real channel (5xx, worker down, DB CPU) | Policies exist, no channel attached | A notification channel |

## Done

| # | What | When | Evidence |
|---|---|---|---|
| T16 | Large upload in the cloud: 36.1 MiB / 70,000-rule export through the staging frontend | 2026-10-29 | Single request refused 413 by Cloud Run (cap confirmed); multipart 5 parts in 20 s, finalized in 24.5 s, accepted and reviewed 88 s after start. Found: register pages 1.5–2.5 s on large reviews (whole-document load per process) → moved to indexed rows |
| T16b | Register pages at 70,000 rules in staging, after moving to rows + summarised effective policy + gzip | 2026-10-29 | Server-side p50 178 ms (was ~2 s); end-user 470–650 ms over a ~365 ms network floor (was 1.3–2.5 s) |
| T12a | Azure staging end to end: Terraform apply (55 resources), migrations on Flexible Server, in-VNet smoke test, break-glass through the public frontend, FRR flow, AI Foundry narratives via managed identity, Key Vault references, Application Insights | 2026-10-29 | Export accepted 5.5 s; agent run 12 s, 7/7 narrated on gpt-4.1-mini; 40k-rule export reviewed 32 s, register page 290 ms. Found: `az containerapp job start --args` mangles command lines → `scripts/azure/start-job.sh` |
| T12b | KEDA PostgreSQL scaler scales workers on queue depth | 2026-10-29 | Burst of 20 × 8,000-rule exports: workers 1 → 2 (staging max) within ~45 s; all 20 reviewed in 53 s |
| T24 | Multipart on Azure Blob staged blocks (and GCS compose, T16) against the real services | 2026-10-29 | 20.5 MiB in 3 parts committed as blocks, finalized and reviewed |
| T18 | Point-in-time restore and secret rotation rehearsed (Azure staging) | 2026-10-30 | Restore to a point 10 min back: ~10 min, same VNet; in-network check showed 24 of 27 exports (the 3 later uploads absent), register and audit rows cut at the same point; restored server deleted. Proxy-secret rotation: the first attempt showed that restarts keep the cached secret (a later revision of one app then broke frontend to API with 401s); rebuilt as a three-step zero-downtime rotation (API accepts the previous secret) and rehearsed under a once-a-second probe: 330+ probes, 0 failures. GCP rehearsal still to do |
| T19 | Model provider failure in the cloud (Azure staging) | 2026-10-30 | Worker pointed at a nonexistent deployment: run succeeded, all 40 narratives fell back to engine text with the provider's reason (404 deployment not found), summary marked engine_fallback; restored by Terraform. Gotcha: during a revision switch the draining revision still takes jobs |
| T15a | Load at staging size (Azure, 160 concurrent clients through the frontend, 110k-rule export, 5 min) | 2026-10-30 | Run 1: 4.5% success (PoolTimeout after 30 s; database idle). After index-only paging + fail-fast pools: 36.9 req/s, 99.7%. After the slim review head: 87.4 req/s. After cached totals: 124.8 req/s (~145 sustained), 37,443/37,446 OK, p50 953 ms incl. ~365 ms network; bound by the 1-vCore B1ms database (83% CPU) |
| T20 | Rate limit holds across replicas (Azure staging) | 2026-10-30 | API at 3 replicas, 90 parallel model-route requests from one identity: exactly 30 admitted (per-identity limit 30/min), 60 answered 429; logs show all three replicas served (10–12 admitted each) |
| T23 | Largest single export on a real worker (Azure staging, 4 GiB) | 2026-10-30 | 110,000 rules / 426,235 grants (36.7 MiB): multipart upload 17.5 s, accepted in ~5.5 min, worker working set peak 1.78 GiB (1-min sampling; 2.4 GiB measured locally), no restarts. 125,000 rules / 484,198 grants refused in 47 s with the count and advice. Package for the 110k export (54,806 items) drafted in the background in 34 s after the API's synchronous path answered 413. Found and fixed on the way: two heavy jobs per worker would OOM (now one per process); drafting in the API would OOM (now compact input + worker) |
| T26 | Eval ledger on both clouds | 2026-10-30 | Vertex gemini-2.5-pro: 20 items, fallback 0, ungrounded 0, contradictions 0, citation 0.8, package summary clean; Azure gpt-4.1-mini recorded for the same fingerprints. CI now requires both (`NPR_PROMPT_GATE_MIN_MODELS=2`) |
| T22a | Narrative eval on Azure gpt-4.1-mini | 2026-10-29 | 20 items: fallback 0, ungrounded 0, contradictions 0, citation 1.0 |
| — | GCP staging deploy, migrations, smoke test, end-to-end FRR flow, Vertex narratives, tracing, staging load test | 2026-10-29 | [TRACKER.md](TRACKER.md) changelog; REMEDIATION-LOG "First real deployment" |
