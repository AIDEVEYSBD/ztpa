# Firewall Rule Review — production architecture

How the product is built to run on **Google Cloud or Azure** (one cloud per deployment),
scale horizontally, and stay correct under load. Status of every piece is in
[TRACKER.md](TRACKER.md); deployment steps are in [DEPLOY-GCP.md](DEPLOY-GCP.md) and
[DEPLOY-AZURE.md](DEPLOY-AZURE.md).

## 1. Principles

1. **The engine decides, the model narrates.** Rule matching, effective policy and every
   risk check are deterministic. An LLM writes impact narrative and drafts wording; it never
   decides severity, approval or a rule change.
2. **Fail closed.** A wrong-shaped export, a missing secret, a degraded analysis or an
   unreachable model never reads as "clean". It is refused, or served with the gap stated.
3. **Stateless request path.** API replicas hold only caches they can rebuild from Postgres
   and object storage. Any replica can serve any request; any replica can die.
4. **Heavy work is a job.** Parsing exports, rebuilding the engine and running review
   pipelines happen in workers, never inside an HTTP request.
5. **One codebase, two clouds.** Cloud services sit behind four narrow interfaces
   (object storage, secrets, AI provider, identity). Postgres is the common denominator.
6. **No device writes.** The product produces a change package for humans. It never pushes
   to a firewall or opens an ITSM change by itself.

## 2. Components

```
                 ┌──────────────── edge: HTTPS LB + WAF (Cloud Armor / Front Door) ──────────┐
 browser ──TLS──▶│  frontend  (Next.js, SSO via OIDC, session cookie)                          │
                 └──────┬──────────────────────────────────────────────────────────────────────┘
                        │ private network, x-npr-proxy-secret + signed identity headers
                        ▼
                 ┌──────────────┐    enqueue     ┌──────────────┐
                 │  api (N)     │──────────────▶ │  worker (M)  │  parse · build engine · review
                 │  FastAPI     │◀── results ─── │  same image  │  pipeline · LLM narrative
                 └──┬───────┬───┘                └──┬────────┬──┘
                    │       │                       │        │
          SQL (pooled)   read snapshot          SQL │        │ read/write exports + artifacts
                    ▼       ▼ artifact              ▼        ▼
            ┌──────────────────┐            ┌──────────────────────┐   ┌──────────────────┐
            │ Postgres 16      │            │ Object storage       │   │ AI provider       │
            │ + pgvector       │            │ GCS / Azure Blob     │   │ Vertex / Foundry  │
            │ system of record │            │ exports, artifacts   │   │ or BYOK           │
            └──────────────────┘            └──────────────────────┘   └──────────────────┘
                         secrets: Secret Manager / Key Vault  →  env at container start
```

| Component | Runs as | Scales on | State |
|---|---|---|---|
| `frontend` | Next.js standalone container | request concurrency | none (signed session cookie) |
| `api` | FastAPI under gunicorn + uvicorn workers | request concurrency / CPU | per-replica snapshot cache only |
| `worker` | same image, `python -m src.jobs.worker` | queue depth | none |
| `migrate` | same image, one-shot job per release | — | — |
| Postgres | Cloud SQL / Azure Database for PostgreSQL Flexible | vertical + read replica | everything durable |
| Object storage | GCS / Blob | managed | uploaded exports, snapshot artifacts, reports |

## 3. Request and data flow

### 3.1 Review run (the core FRR flow)

1. **Upload.** A network owner uploads a policy export (Check Point, Skybox, CMDB/IPAM CSV…).
   The API streams it to object storage under `exports/<sha256>`, records an `exports` row
   (checksum, size, source type, declared export time, uploader) and enqueues an `ingest` job.
   Request returns `202 {job_id}` in milliseconds regardless of file size.
2. **Intake job.** Validates schema, export age and checksum; rejects wrong-shaped input with
   a reason instead of producing an empty estate. Normalises rules, objects and NAT into the
   canonical model.
3. **Engine job.** Reconstructs effective policy per device/package and runs every
   deterministic check. Publishes a **snapshot**: rows in Postgres plus a signed, compressed
   engine artifact in object storage, then flips the **active-snapshot pointer**.
4. **Review pipeline job.** The five FRR agents (orchestrator → intake parser → effective-policy
   checker → risk & impact assessor → change-package drafter) run as a recorded state machine
   over the snapshot. Each step's input/output is persisted, so a run is resumable and auditable.
5. **Human gates.** Network owner validates findings and availability impact; network security
   approver reviews the change package. Both are server-enforced roles with an audit trail.

### 3.2 How a replica serves a snapshot without building it

- `ztpa.active_snapshot` is a single row: `snapshot_id`, `artifact_uri`, `generation`.
- Each API replica caches the loaded engine artifact keyed by `generation` and re-reads the
  pointer at most every few seconds. On change it downloads and verifies the artifact
  (HMAC-SHA256 over the bytes, key from the secret store) and swaps the cache atomically.
- A replica never runs the engine on the request path. Cold start = one artifact download.
- Local development keeps the current behaviour (build in-process from `backend/data/mock`)
  behind `NPR_JOBS_INLINE=true`, so the demo and the test suite are unchanged.

### 3.3 Job queue

Postgres-backed (`ztpa.jobs`), claimed with `SELECT … FOR UPDATE SKIP LOCKED`. Chosen over
Pub/Sub / Service Bus because it is identical on both clouds, transactional with the data it
produces, and needs no extra service. Properties:

- **Lease + heartbeat**: a claimed job has `locked_until`; a crashed worker's job is reclaimed.
- **Retries** with exponential backoff and a max-attempts dead state.
- **Idempotency key** per job (e.g. export checksum), so a double upload is one job.
- **Per-kind concurrency limits** so a burst of engine builds cannot starve narrative jobs.
- **Metrics**: queue depth, age of oldest job and failure rate are exported for autoscaling
  (KEDA PostgreSQL scaler on Azure; custom metric or min-instance worker pool on GCP).

Throughput ceiling is high for this workload (jobs are seconds-to-minutes, not per-request);
if it is ever reached the interface allows swapping in Pub/Sub or Service Bus.

## 4. Scale and load

| Concern | Design |
|---|---|
| API horizontal scale | Stateless; snapshot cache per replica; sticky sessions not required |
| Large rulebases | Parsing and analysis in workers; shadowing bucketed by device/package and port range (not O(n²) across the estate); path search capped by count **and** wall-clock |
| Uploads | Streamed to object storage with a size cap; never held whole in API memory |
| Database connections | Per-process pool; `replicas × workers × pool_max ≤ DB limit − headroom`; managed pooling (Cloud SQL Managed Connection Pooling / Flexible Server PgBouncer) in production |
| Read-heavy screens | Paginated, indexed queries (cursor pagination on findings already in place) |
| LLM cost and latency | LLM calls only in jobs or bounded endpoints; per-request input caps; per-identity rate limit; daily token budget per deployment; deterministic fallback on timeout |
| Abuse | Edge WAF + per-identity rate limits in the API; body size caps on every endpoint |
| Long requests | None by design: anything over ~2s becomes a job with progress polling |

Load is validated, not assumed: a load-test suite (`loadtest/`, tracker PLAT-15) drives the
read API and the review pipeline with generated rulebases, and its results gate releases.
Target figures are set from those measurements, starting with the FRR evaluation metric
"time to review 1,000 rules".

## 5. Security

- **Identity**: OIDC SSO at the frontend; the API trusts identity headers only with a valid
  proxy secret, and **refuses to start in production without one** (no fail-open).
- **Roles**: viewer, analyst, network owner, network security approver, admin, enforced on
  the server for every route.
- **Network**: API, worker, database and storage on private networking only; the frontend is
  the single public entry, behind the edge WAF.
- **Secrets**: Secret Manager / Key Vault, read via workload identity; never in the database,
  images or logs. BYOK keys live there too.
- **Cloud identity**: service account (GCP) / managed identity (Azure) per component, least
  privilege; no long-lived cloud keys in the default setup.
- **Supply chain**: pinned dependencies with a lockfile; images built once in CI, scanned,
  and deployed **by digest**; test tooling excluded from production images.
- **Audit**: every approval, rule-change proposal and configuration change is an append-only
  audit row with actor and request id.

## 6. AI providers

| Deployment | Default (`ADVISORY_PROVIDER=auto`) | Auth | Alternatives |
|---|---|---|---|
| GCP | Vertex AI (Gemini) in the deployment's project | runtime service account (ADC) | BYOK: Azure OpenAI key, OpenAI, Anthropic |
| Azure | Azure AI Foundry deployment in the subscription | managed identity | BYOK: OpenAI, Anthropic, GCP service-account file |
| Local | Ollama if running, else any configured key | developer login / key | — |

Cross-cloud keyless access (for example a GCP workload calling Azure OpenAI through workload
identity federation) is a planned extension (tracker PLAT-14); the provider layer already
separates "which provider" from "how it authenticates", so it is additive.

## 7. Observability

- Structured JSON logs to stdout with request id, actor and job id (Cloud Logging / Log Analytics).
- OpenTelemetry traces and metrics exported to Cloud Trace / Application Insights.
- `/api/live` for liveness, `/api/health` for readiness (503 with reasons when degraded).
- Every model call metered (`ztpa.ai_metrics`: tokens, latency, cost, outcome).
- Alerts: readiness failing, queue age, job failure rate, 5xx rate, LLM fallback rate, DB CPU
  and connections.

## 8. Environments and release

`dev` (local), `staging` (per cloud) and `prod` (per cloud), each with its own project /
subscription or resource group, database and secrets. CI on every change: tests, lint,
type check, `next build`, image build, vulnerability scan. On merge: push to Artifact Registry
and ACR, run migrations as a job, deploy services by digest, run a post-deploy smoke test,
and keep the previous revision for instant rollback. The evaluation suite gates promotion to
production.
