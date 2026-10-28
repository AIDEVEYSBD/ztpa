# Firewall Rule Review (FRR) — build tracker

What exists, what is partial, what is still to build. Updated after every feature lands.
Bar: **production grade** — scalable, load-tested, no per-request slow paths.
Approach: **additive** — existing product capabilities stay; FRR is built alongside them.
Where an existing behaviour conflicts with an FRR rule (device push, auto-approve), it is
disabled by an FRR policy switch, not deleted.

Status: ✅ done · 🟡 partial · ⬜ not started · 🔧 in progress

_Last updated: 2026-10-28_

## Changelog

| Date | Item(s) | Change |
|---|---|---|
| 2026-10-28 | PLAT-7 | Shared rate limits on model-backed routes; request body and field caps |
| 2026-10-28 | PLAT-4 | Replicas serve one published snapshot: active pointer + signed artifacts; cold start loads rather than rebuilds; fixed artifact publish that could keep a corrupted object |
| 2026-10-28 | PLAT-5 | Durable Postgres job queue + worker process + job status API |
| 2026-10-28 | PLAT-3 | Object storage interface (local / GCS / Azure Blob) |
| 2026-10-28 | PLAT-6, 01.3 | Production fail-closed boot checks; `docs/frr/ARCHITECTURE.md` |
| 2026-10-28 | PLAT-12, PLAT-13 | `auto` prefers the host cloud's own AI service; BYOK keys reported by name; failed Vertex credential lookups cached 30s so they are not re-probed per request |
| 2026-10-28 | PLAT-1 | Live Vertex call verified via ADC; default model set to `google/gemini-2.5-pro` (2.5-flash not enabled on the sandbox project) |
| 2026-10-28 | PLAT-2 | Live call verified against the sandbox Azure AI Foundry account (`gpt-4.1-mini`, identity auth) |
| 2026-10-28 | PLAT-1 | Google Vertex AI provider (ADC auth, OpenAI-compatible endpoint, never chosen by `auto`), migration 0008, Configuration-page option, 11 offline tests |

## FRR-01 · Requirements, exports and evaluation rulebase

| ID | Item | Status | Where / note |
|---|---|---|---|
| 01.1a | Check Point rulebase/objects/NAT parser | ⬜ | Only comment mentions today |
| 01.1b | Skybox export parser | ⬜ | |
| 01.1c | Cisco flow / Stealthwatch ingestion | ⬜ | Catalyst/Meraki inventory only |
| 01.1d | CMDB / IPAM import (owner, app, zone tags) | ⬜ | Tags currently from mock exports |
| 01.2 | Role-to-approver matrix (network owner, network security approver) | 🟡 | admin/analyst/viewer + `require_approver` (`backend/app/main.py`); no owner/approver split |
| 01.3 | Process, integrations and data-flow documentation | 🟡 | Platform architecture and data flow: `docs/frr/ARCHITECTURE.md`. Client process walkthrough still to capture |
| 01.4 | RAG sources: network standards, exceptions, change/rollback runbooks | ⬜ | No vector store or corpus |
| 01.5 | Labelled test rulebase + metrics (check accuracy, severity agreement, time / 1,000 rules) | 🟡 | One golden fixture (`backend/scripts/verify_engine.py`), scale bench; no labels or metrics |

## FRR-02 · Effective-policy reconstruction and risk workflow

| ID | Item | Status | Where / note |
|---|---|---|---|
| 02.1 | Five agents + handoffs: orchestrator, intake parser, effective-policy checker, risk & impact assessor, change-package drafter | ⬜ | Existing agents (remediation, campaign, classify, authoring, ask) do other jobs |
| 02.2a | Rule / object normalisation | ✅ | `backend/src/models.py`, `backend/src/normalizers/` |
| 02.2b | NAT parsing | ⬜ | |
| 02.2c | Intake integrity: checksum, export age, schema validation, fail closed on wrong shape | ⬜ | Wrong-shaped export currently reads as clean (`normalizers/profile.py`) |
| 02.2d | Export upload + object storage (GCS / Blob) | ⬜ | Engine reads `backend/data/mock` only |
| 02.3a | Effective policy: first-match per device/package, deny subtraction | 🟡 | Union-of-allows graph (`backend/src/graph/build.py`) |
| 02.3b | Checks: any-any, exposed admin ports, broad sources | ✅ | `analyzers/over_permissive.py`, `analyzers/severity.py` |
| 02.3c | Check: shadowed rules (per rulebase, bucketed) | 🟡 | Per source tool, O(n²) (`analyzers/shadowing.py`) |
| 02.3d | Check: expired rules | ⬜ | No schedule/expiry field |
| 02.3e | Check: unused rules via hit counts | ⬜ | |
| 02.3f | Change recommendation workflow with rollback | 🟡 | Remediation loop exists; rollback is a status flip |
| 02.4a | LLM for impact narrative only; engine decides | 🟡 | LLM currently classifies auto-approve/escalate and ranks |
| 02.4b | Versioned system prompts | ⬜ | `advisory/prompts/*.txt` + inline, unversioned |
| 02.4c | Schema-validated model output | ⬜ | `parse_json` + hand checks |
| 02.5 | Configuration smoke test + initial benchmark | 🟡 | `/api/admin/ai/test`; no benchmark on labelled data |

## FRR-03 · Screens, HITL gates and change package

| ID | Item | Status | Where / note |
|---|---|---|---|
| 03.1a | Effective-policy model view | 🟡 | Explorer/graph UI; inherits 02.3a limit |
| 03.1b | Rule-risk register with evidence | 🟡 | `/api/findings`, `RiskTodo.tsx`; not FRR-shaped |
| 03.1c | Narrowed or time-bound rule proposals | ⬜ | |
| 03.1d | Rollback plan artefact | ⬜ | |
| 03.1e | Limitations section per review | 🟡 | Integrity/degraded markers only |
| 03.2a | Two-stage HITL: owner validates findings + availability impact → approver reviews change package | 🟡 | Single approver stage |
| 03.2b | FRR policy switch: no device write, no auto-approve, no automatic ITSM change | ⬜ | Push simulated (`change/staging.py`); auto-approve path exists |

## FRR-04 · Evaluation, UAT and finetuning

| ID | Item | Status | Where / note |
|---|---|---|---|
| 04.1 | UAT scenarios + expected outcomes | ⬜ | |
| 04.2 | Internal functional + integration testing | 🟡 | 2,065 backend tests green against real Postgres 16 + pgvector locally; DB tests still skip in CI; 0 frontend tests |
| 04.3 | Re-runnable eval suite incl. live-model evals | ⬜ | Agent tests stub the model |
| 04.4 | False-positive / false-negative measurement and tuning | ⬜ | |
| 04.5 | Eval gate in CI before UAT / release | ⬜ | |

## FRR-05 · Release and continuous finetuning

| ID | Item | Status | Where / note |
|---|---|---|---|
| 05.1 | CI builds images once, deploys by digest | ⬜ | CI tests only; laptop deploys |
| 05.2 | Post-deploy smoke test | 🟡 | `/api/live`, `/api/health` |
| 05.3 | Runtime telemetry (OpenTelemetry export) | 🟡 | `ztpa.ai_metrics`, `advisory/trace.py`; no OTel |
| 05.4 | Structured reviewer feedback (agree/disagree on severity) | 🟡 | Comment threads only |
| 05.5 | Versioned, eval-gated prompt / retrieval / agent tuning | ⬜ | |

## Platform (GCP + Azure multi-cloud)

| ID | Item | Status | Where / note |
|---|---|---|---|
| PLAT-1 | Vertex AI (Gemini) provider via ADC | ✅ | `backend/src/advisory/client.py`, `db/migrations/0008_vertex_provider.sql`, `backend/tests/test_advisory_vertex.py`. Live-verified 2026-10-28 on the sandbox project: `gemini-2.5-pro` (default) and `gemini-3-flash-preview` answer with native JSON; `gemini-2.5-flash` and the other 3.x names 404 there |
| PLAT-2 | Azure OpenAI / Foundry provider | ✅ | Pre-existing (`advisory/client.py`). Live-verified 2026-10-28: sandbox Foundry account, `gpt-4.1-mini`, managed-identity/`az login` auth, native JSON mode |
| PLAT-12 | Native-platform AI by default: `auto` picks Vertex on GCP, AI Foundry on Azure (platform auto-detected, `NPR_PLATFORM` override) | ✅ | `backend/src/settings.py` (`platform`, `active_provider`); tests in `backend/tests/test_advisory_vertex.py` |
| PLAT-13 | BYOK: OpenAI / Anthropic / Azure key / GCP service-account file, from the platform secret store, never the DB | 🟡 | Env-based keys work and are reported by name in `/api/health` (`byok_keys`); Secret Manager / Key Vault wiring is PLAT-3 |
| PLAT-14 | Cross-cloud identity federation (e.g. GCP workload calling Azure OpenAI without a key) | ⬜ | Later; designed-for, not built |
| PLAT-3 | Storage / secrets / identity interfaces (GCS + Blob, Secret Manager + Key Vault) | 🟡 | Storage done: `backend/src/storage.py` (`file://`, `gs://`, `az://`, workload identity, streamed, atomic local writes), `tests/test_storage.py`. Secrets: injected as env by Cloud Run / Container Apps (deploy wiring, PLAT-9/10). Live bucket test pending deploy |
| PLAT-4 | Stateless backend: engine state out of process memory and local disk | 🟡 | Done: `ztpa.active_snapshot` pointer (migration 0010) + HMAC-signed engine artifacts in object storage (`backend/src/snapshot_artifacts.py`); every publish site moves the pointer in its own transaction; replicas poll it (`NPR_SNAPSHOT_POLL_S`) and LOAD instead of rebuild (~0.1s vs ~2s at 2,000 assets); concurrent cold requests build once. 7 real-DB tests. Remaining: move recompute / dataset / merge rebuilds onto jobs (202 + polling) and replace `data/mock` inputs with uploaded exports (02.2d) |
| PLAT-5 | Job worker for recompute / review runs | ✅ | Postgres queue `db/migrations/0009_jobs.sql`, `backend/src/jobs/` (SKIP LOCKED claim, heartbeat lease, backoff retries, dead state, idempotency keys, per-kind stats); worker `python -m src.jobs.worker`; inline in API for dev; `/api/jobs/{id}`, `/api/admin/jobs/{stats,ping}`. 19 real-Postgres tests incl. 8-worker contention. Existing endpoints not yet moved onto it (PLAT-4) |
| PLAT-6 | Fail-closed proxy auth when `NPR_PROXY_SECRET` unset | ✅ | `settings.production_startup_errors()`: staging/prod refuses to boot without proxy secret, DATABASE_URL or cloud storage; localhost CORS dev-only. `tests/test_production_startup.py` |
| PLAT-7 | Rate limits + LLM input size caps | ✅ | `backend/src/ratelimit.py` + migration 0011: per-identity and per-deployment per-minute ceilings on all 11 model-backed routes, shared across replicas (in-process fallback in dev), 429 + Retry-After, fails open loudly. `backend/app/limits.py`: 1 MB body cap incl. chunked bodies (413); field caps on ask/intake/connector sample. `tests/test_limits.py` |
| PLAT-8 | Pinned dependencies / lockfile; test deps out of prod image | ⬜ | |
| PLAT-9 | Terraform: GCP (Cloud Run, Cloud SQL, GCS, Secret Manager, Artifact Registry) | ⬜ | |
| PLAT-10 | Terraform: Azure (Container Apps, private PG, Blob, Key Vault, ACR) | ⬜ | `scripts/azure/deploy.sh` exists (CLI, public DB) |
| PLAT-15 | Load-test suite (`loadtest/`) gating releases | ⬜ | |
| PLAT-16 | One-step schema bootstrap for the migrate job (`schema.sql` + `auth_schema.sql` + `sso_schema.sql` + migrations) | ⬜ | Today three files must be applied in order by hand |
| PLAT-11 | Deployment docs: `docs/frr/DEPLOY-GCP.md`, `docs/frr/DEPLOY-AZURE.md`, runbook, prod checklist | ⬜ | |
