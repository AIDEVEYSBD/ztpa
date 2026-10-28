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
| 2026-10-28 | 05.3 | OpenTelemetry tracing to each cloud's native backend |
| 2026-10-28 | 04.1 | UAT scenario script |
| 2026-10-28 | PLAT-18 | Azure Front Door Premium WAF with origin lock |
| 2026-10-28 | 01.1c, 01.1d, 03.1c | CMDB/IPAM and flow datasets; owners on every package item; flow-observed sources prefill narrowing; Context data screen |
| 2026-10-28 | 03.1a, 05.4 (UI) | Effective-policy view and per-check reviewer feedback (agree / disagree / report missed) on the Rule review screen |
| 2026-10-28 | UI-1, 03.1b, 03.1e | FRR screens in the console |
| 2026-10-28 | 02.3a, 02.3c, 03.1a | Shadowing computed per (layer, gateway); per-gateway effective-policy model served with the register |
| 2026-10-28 | PLAT-15 | Load test suite and first measured baseline; immutable review documents cached per process |
| 2026-10-28 | 05.4 | Reviewer feedback with false-positive / missed-finding semantics; reviews export as eval labels |
| 2026-10-28 | 01.5, 04.3-04.5 | Labelled evaluation suite, metrics and CI gate; first severity-tuning signal recorded |
| 2026-10-28 | 02.1, 02.4a-c, 01.4 | Five-agent orchestrated review run; validated, cited, versioned impact narratives (live on Vertex); knowledge base with full-text retrieval |
| 2026-10-28 | 01.2, 03.1c, 03.1d, 03.2a, 03.2b | Change-package drafter with rollback, approver matrix, two-stage owner → approver review with four eyes, runbook export, FRR mode switch; shadowing refuted by install targets or recent hits |
| 2026-10-28 | 01.1a, 02.2b-d, 02.3b-e, 03.1b, 03.1e | Check Point parser, export upload + intake job with checksum/age/shape checks, deterministic rule-risk register API; shadowing bucketed (~8x faster at 1k rules, near-linear to 20k); `migrate.py --check` made read-only |
| 2026-10-28 | PLAT-11 | Deployment guides for both clouds, runbook, production checklist |
| 2026-10-28 | PLAT-10, 05.1, 05.2 | Azure Terraform (planned against sandbox: 56 resources); deploy pipelines for both clouds; in-network smoke test; CI runs real-DB tests as the runtime role |
| 2026-10-28 | PLAT-9, PLAT-17 | GCP Terraform (validated + planned against sandbox); runtime DB role without DDL rights; worker health port for Cloud Run |
| 2026-10-28 | PLAT-8, PLAT-16 | Hash-pinned lockfile, multi-process image with preflight, shared JSON logging; one-command database bootstrap with advisory lock |
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
| 01.1a | Check Point rulebase/objects/NAT parser | ✅ | `backend/src/normalizers/checkpoint.py`: Management API JSON (`show-access-rulebase` / `show-nat-rulebase`, objects dictionary, sections, hits). Hosts, networks, ranges, nested groups, service groups, time objects, negation (read as any, limited), app-sites (broadened, limited), disabled/expired rules kept in inventory but not as grants, unknown hits ≠ zero. 24 tests on a synthetic export. **Needs validating against a real sanitised export** |
| 01.1b | Skybox export parser | ⬜ | |
| 01.1c | Cisco flow / Stealthwatch ingestion | ✅ | `backend/src/frr/context.py`: flow CSV (Stealthwatch column names recognised, `443/TCP` ports, epoch/ISO/US times), aggregated per conversation, COPY-loaded into `ztpa.flows` (migration 0016, gist + btree indexes). Narrowing proposals get observed sources (90-day window, grouped /24) as a prefill the owner confirms. **Needs validating against a real export** |
| 01.1d | CMDB / IPAM import (owner, app, zone tags) | ✅ | CMDB/IPAM CSV (CIDR, host or range; owner, application, environment, zone, criticality) into `ztpa.cmdb_assets`; destination owners attached to every package item; `GET /api/context/owners`. Rejects missing columns or > 1 % unreadable rows with the first bad lines |
| 01.2 | Role-to-approver matrix (network owner, network security approver) | ✅ | `ztpa.frr_approvers` (migration 0013): duty `network_owner` / `security_approver` per principal (email or SSO subject) and scope (layer or `*`), admin-managed via `/api/admin/frr/approvers`, separate from product roles; every grant/revoke audited |
| 01.3 | Process, integrations and data-flow documentation | 🟡 | Platform architecture and data flow: `docs/frr/ARCHITECTURE.md`. Client process walkthrough still to capture |
| 01.4 | RAG sources: network standards, exceptions, change/rollback runbooks | 🟡 | Knowledge base built: `backend/src/frr/knowledge.py` + migration 0014 (heading-aware chunking, Postgres full-text retrieval, identical on both clouds), `/api/knowledge` add/list/search/delete (admin), citations checked against what was retrieved. **The client's actual documents still to be loaded**; pgvector hybrid retrieval later |
| 01.5 | Labelled test rulebase + metrics (check accuracy, severity agreement, time / 1,000 rules) | ✅ | `backend/src/frr/evals.py`: synthetic labelled Check Point rulebase (labels by construction; bands from a written v1 reviewer policy), per-check precision/recall/F1, exact band agreement + Cohen's kappa, time per 1,000 rules; `--export/--labels` for the client's labelled set. Latest (2,000 rules): P = R = 1.0 on 560+ pairs; band agreement 0.91, κ 0.85; 0.17 s / 1k rules |

## FRR-02 · Effective-policy reconstruction and risk workflow

| ID | Item | Status | Where / note |
|---|---|---|---|
| 02.1 | Five agents + handoffs: orchestrator, intake parser, effective-policy checker, risk & impact assessor, change-package drafter | ✅ | `backend/src/frr/agents.py`: `frr.review_run` job sequences the five agents, records each step (inputs' identity, counts, prompt version, model) in `ztpa.frr_runs`, restarts idempotently, never replaces a package under review. `POST /api/exports/{id}/review-runs`, `GET /api/frr/runs/{id}`, `GET /api/frr/agents`. 12 tests incl. real-DB orchestrated run |
| 02.2a | Rule / object normalisation | ✅ | `backend/src/models.py`, `backend/src/normalizers/` |
| 02.2b | NAT parsing | 🟡 | Check Point NAT rules parsed with resolved original/translated address space (`NatRule`); not yet applied to effective policy |
| 02.2c | Intake integrity: checksum, export age, schema validation, fail closed on wrong shape | ✅ | `backend/src/frr/intake.py`: sha256 recorded at upload and re-verified in the worker; export time required (file or declared), rejected if > `NPR_EXPORT_MAX_AGE_DAYS` (30) or in the future; non-rulebase / paginated-incomplete / rule-missing-fields exports rejected with a reason. Rejection is an outcome on the export row, never an empty estate. (The older `profile.py` path is unchanged) |
| 02.2d | Export upload + object storage (GCS / Blob) | ✅ | `POST /api/exports` streams to storage (100 MB cap, content-addressed, duplicate = same export), `ztpa.exports` (migration 0012), `export.ingest` job; `GET /api/exports[/{id}[/review]]`. 11 end-to-end tests as the runtime role. Uploaded exports do not yet feed the main console engine (they feed the FRR register) |
| 02.3a | Effective policy: first-match per device/package, deny subtraction | 🟡 | Per (layer, gateway) model in the review: rules installed on each gateway in order → effective allows, shadowed, denies, inactive (`effective_policy` in `GET /api/exports/{id}/review`). Partitions with identical rule sets computed once. Full packet-space subtraction (partial overlaps) and NAT application not done |
| 02.3b | Checks: any-any, exposed admin ports, broad sources | ✅ | Engine `over_permissive` run over the uploaded rulebase; classified per FRR check in `backend/src/frr/review.py` |
| 02.3c | Check: shadowed rules (per rulebase, bucketed) | ✅ | Bucketed index (identical to the O(n²) scan on randomised rulebases) and now computed per (layer, gateway): a rule is shadowed only when covered on every gateway it is installed on; recent hit counts still refute. 20,000 rules reviewed in 11 s |
| 02.3d | Check: expired rules | ✅ | Time-object expiry in `RuleMeta.expires_at`; `expired` and `expiring_soon` (`NPR_FRR_EXPIRING_DAYS`) checks |
| 02.3e | Check: unused rules via hit counts | ✅ | `unused` = zero hits or last hit older than `NPR_FRR_UNUSED_DAYS` (90); only when the export carries hits, else a limitation; plus `disabled` |
| 02.3f | Change recommendation workflow with rollback | 🟡 | Remediation loop exists; rollback is a status flip |
| 02.4a | LLM for impact narrative only; engine decides | ✅ | FRR path: model writes prose through a schema with no band/proposal/command/impact field (test proves injected fields are dropped); live-verified on Vertex `gemini-2.5-pro` (grounded, cited). Older console features still use the LLM for classify/rank (behind FRR mode, classify can no longer auto-approve) |
| 02.4b | Versioned system prompts | ✅ | `backend/src/frr/prompts/impact.v1.md`, `package.v1.md`; version = name@sha256 recorded on every narrative and run step |
| 02.4c | Schema-validated model output | ✅ | pydantic `ImpactNarrative` / `PackageNarrative` with length caps; invented citations, schema failures and provider errors fall back to labelled engine text (`by: engine_fallback`, `fallback_reason`). Top-N narration (`NPR_FRR_NARRATE_TOP`, 40) bounds cost |
| 02.5 | Configuration smoke test + initial benchmark | 🟡 | `/api/admin/ai/test`; no benchmark on labelled data |

## FRR-03 · Screens, HITL gates and change package

| ID | Item | Status | Where / note |
|---|---|---|---|
| 03.1a | Effective-policy model view | ✅ | API: per-gateway effective policy with the register; UI `components/frr/EffectivePolicy.tsx` on the Rule review screen (per gateway: installed, effective allow, deny, shadowed here, inactive) |
| 03.1b | Rule-risk register with evidence | ✅ | API `GET /api/exports/{id}/review`; UI `components/frr/ReviewScreen.tsx` + `RegisterTable.tsx`: KPIs, always-visible limitations, band/check filters, pagination, expandable evidence, hits shown as unknown (never 0) when absent |
| 03.1c | Narrowed or time-bound rule proposals | ✅ | Deterministic proposals per check with availability impact; narrowing items now carry flow-observed sources and services as an owner prefill (owner still confirms; flows show use, not need). Outage guards: never moves a cleanup rule, never removes a rule shadowed by one being narrowed |
| 03.1d | Rollback plan artefact | ✅ | Every item carries Check Point `mgmt_cli` change and exact rollback (restores rule as exported); `GET /api/change-packages/{id}/runbook` (approved only) emits accepted items with rollback under the approval record |
| 03.1e | Limitations section per review | ✅ | Review-level and per-rule limitations produced, served and shown in the register UI |
| 03.2a | Two-stage HITL: owner validates findings + availability impact → approver reviews change package | ✅ | `backend/src/frr/workflow.py` + `app/packages_api.py`: owner decides each item (accept/reject-with-note/modify-with-input) then validates; a different security approver approves/rejects (four eyes enforced in code and as a DB CHECK); state-conditional updates; all transitions audited. 6 end-to-end tests as the runtime role |
| 03.2b | FRR policy switch: no device write, no auto-approve, no automatic ITSM change | ✅ | `NPR_FRR_MODE` (on by default in both Terraform roots): the older change gate escalates everything, staging needs explicit approval, simulated push refused (403). FRR packages have no device or ITSM code path at all (test asserts no network client imports). 3 tests |

## FRR-04 · Evaluation, UAT and finetuning

| ID | Item | Status | Where / note |
|---|---|---|---|
| 04.1 | UAT scenarios + expected outcomes | ✅ | `docs/frr/UAT.md`: 30 scenarios across intake, register, package/agents, two-stage review and controls, per role, with pass criteria and a results sheet. The labelled test rulebase itself comes from the client (FRR-01.5) |
| 04.2 | Internal functional + integration testing | 🟡 | 2,065 backend tests green against real Postgres 16 + pgvector locally; DB tests still skip in CI; 0 frontend tests |
| 04.3 | Re-runnable eval suite incl. live-model evals | 🟡 | Deterministic eval suite re-runnable (`python -m src.frr.evals`). Live-model narrative checked manually on Vertex; automated narrative eval (groundedness / citation rate) not yet built |
| 04.4 | False-positive / false-negative measurement and tuning | 🟡 | FP/FN measured per check with misses listed. Tuning signal found, **not applied pending reviewer labels**: engine rates broad internal admin access low (policy says medium) and internet-exposed database ports medium (policy says high) |
| 04.5 | Eval gate in CI before UAT / release | ✅ | CI step `FRR evaluation gate` (2,000 rules): fails on precision/recall < 0.98, any check recall < 0.95, or > 3 s per 1,000 rules; band agreement enforced when `NPR_EVAL_MIN_BAND_AGREEMENT` is set; report kept as a build artifact |

## FRR-05 · Release and continuous finetuning

| ID | Item | Status | Where / note |
|---|---|---|---|
| 05.1 | CI builds images once, deploys by digest | ✅ | `.github/workflows/deploy-gcp.yml`, `deploy-azure.yml`: manual per-environment, workload identity federation (no stored cloud keys), build+push once with provenance/SBOM, digests flow to migrate -> terraform -> smoke. CI (`ci.yml`) adds real-Postgres tests as the runtime role, image builds, prod-boot refusal, no-pytest-in-image, `terraform validate`, `next build`. actionlint clean. Not yet run on GitHub |
| 05.2 | Post-deploy smoke test | ✅ | `python -m src.smoke`: runs inside the private network as a one-off of the migrate job; checks API liveness, migrations current, and a worker completing a `system.ping` job. 2 real-DB tests |
| 05.3 | Runtime telemetry (OpenTelemetry export) | ✅ | `backend/src/telemetry.py`: FastAPI + psycopg spans, parent-based sampling (`NPR_OTEL_SAMPLE`, 0.1), request id on each span; Azure → Application Insights (connection string from Terraform), GCP → Cloud Trace (`NPR_OTEL=gcp` in Terraform, ADC), else OTLP; never fatal. Plus `ztpa.ai_metrics` for model calls. Verified exporters import in the image; live traces to verify after first deploy |
| 05.4 | Structured reviewer feedback (agree/disagree on severity) | ✅ | `ztpa.frr_feedback` (migration 0015), `PUT /api/exports/{id}/review/{rule}/feedback`: agree / disagree (false positive) / disagree naming an unraised check (missed finding, needs a band), suggested band, required comment on disagreement; `GET .../feedback` agreement per check + suggested band shifts; `GET .../labels` (admin) turns reviews into eval labels for `src.frr.evals --labels`. 2 tests |
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
| PLAT-8 | Pinned dependencies / lockfile; test deps out of prod image | ✅ | `backend/requirements.lock` (59 hash-pinned packages, linux/amd64 py3.12, via `uv pip compile`); image installs `--require-hashes`; pytest moved to `requirements-dev.txt` (verified absent from image); image runs `$WEB_CONCURRENCY` uvicorn processes on `$PORT`; `src.preflight` makes a refused boot exit 1; API and worker share JSON logs with Cloud Logging `severity`. Image built and smoke-tested: API + separate worker container round-tripped a job |
| PLAT-9 | Terraform: GCP (Cloud Run, Cloud SQL, GCS, Secret Manager, Artifact Registry) | ✅ | `infra/gcp/`: private VPC + Cloud NAT; Cloud SQL PG16 private IP, PITR, optional HA; GCS (versioned, no public access); Secret Manager with generated internal secrets; per-role service accounts, no keys; Cloud Run API (internal-only), worker (always-on), frontend, migrate job; images by digest only (validated); optional HTTPS LB + managed cert + Cloud Armor; baseline alerts. `terraform validate` clean; read-only `plan` against the sandbox project: 68 resources, no errors. Not yet applied |
| PLAT-10 | Terraform: Azure (Container Apps, private PG, Blob, Key Vault, ACR) | ✅ | `infra/azure/`: VNet + private endpoints/DNS; PG Flexible private access (optional ZR HA, pgvector allowed); Blob with shared keys and public access off; Key Vault (RBAC, purge protection) via managed identities; ACR; Container Apps API (internal), worker (KEDA PostgreSQL queue-depth scaling), frontend; migrate job as its own identity; alerts. Validated; read-only plan against the sandbox: 56 resources, no errors. Not yet applied |
| PLAT-15 | Load-test suite (`loadtest/`) gating releases | ✅ | `loadtest/run.py`: ingest burst + multi-process read mix (register, exports, package, findings, live), p50/p95/p99 and error-rate thresholds, exit 1 on breach. Local run (one instance, 4 API processes, 2 workers, runtime DB role, laptop): **1,129 req/s, 0 errors, p95 84–103 ms**; 30 exports ingested in 1.5 s; a 10,000-rule export (5.3 MB) uploaded in 0.03 s and reviewed in 4.6 s, register pages p50 1 ms. To repeat against staging after first deploy |
| PLAT-16 | One-step schema bootstrap for the migrate job (`schema.sql` + `auth_schema.sql` + `sso_schema.sql` + migrations) | ✅ | `python db/migrate.py --bootstrap`; advisory lock serialises concurrent runs; verified on an empty database, re-run is a no-op, full suite (2,082) green against it |
| UI-1 | FRR screens: Exports, Context data, Rule review (register + effective policy + reviewer feedback), Change package (agent run steps, AI/engine summary, items with commands + rollback, owner decisions, validate, approve, runbook), Approvers and Knowledge (admin) | 🟡 | `frontend/components/frr/*`, `lib/frr.ts`, `lib/frrTypes.ts`; typecheck, lint, `next build` and the swallowed-catch grep clean. **Not yet exercised in a browser** (needs an SSO session) |
| PLAT-17 | Least-privilege runtime DB role | ✅ | `db/migrate.py --ensure-app-role`: runtime role has row access to `ztpa` only (CREATE/ALTER/DROP and ledger writes refused, verified); migrate runs as owner. Full suite (2,083) passes connecting as the restricted role |
| PLAT-18 | Azure Front Door + WAF in Terraform | ✅ | `infra/azure/front_door.tf`: Front Door Premium, managed DRS 2.1 + bot rules in Prevention, per-IP rate limit, HTTPS only, managed certificate; origin locked by `NPR_EDGE_ID` (frontend middleware 404s requests without this profile's `X-Azure-FDID`). Planned read-only against the sandbox: 65 resources |
| PLAT-11 | Deployment docs: `docs/frr/DEPLOY-GCP.md`, `docs/frr/DEPLOY-AZURE.md`, runbook, prod checklist | ✅ | `docs/frr/DEPLOY-GCP.md`, `DEPLOY-AZURE.md` (one-time setup with keyless CI identity, GitHub environment config, release flow, first-release checks, capacity and connection budget), `RUNBOOK.md`, `PRODUCTION-CHECKLIST.md` |
