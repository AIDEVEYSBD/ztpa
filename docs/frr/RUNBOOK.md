# Runbook

Day-two operations for a Firewall Rule Review deployment on either cloud. Commands are shown
for GCP (`gcloud`) and Azure (`az`); `<env>` is `staging` or `prod`.

## Health at a glance

| Question | Where |
|---|---|
| Is the API up? | `/api/live` (liveness; process only) |
| Is it serving correct data? | `/api/health` as admin: 503 with `degraded_reasons` when the DB, snapshot or analysis is not authoritative |
| Are jobs flowing? | `GET /api/admin/jobs/stats`: `ready`, `running`, `dead`, `oldest_ready_s` per kind |
| Is the model provider working? | Admin → AI configuration → Test; `ztpa.ai_metrics` for failure rate and latency |
| Logs | Cloud Logging / Log Analytics; every line is JSON with `event`, `request_id`, `actor`, `job_id` |

## Common incidents

**Readiness failing (`/api/health` 503)**
Read `degraded_reasons`. *Database unreachable:* check the instance status and connection
count (pool exhaustion shows as `PoolTimeout` in API logs). *Snapshot not persisted /
degraded analysis:* the API keeps serving the last complete snapshot; find the failing
analyzer in logs by `event=engine_build_failed` or `snapshot_publication_refused`.

**Jobs not starting (`oldest_ready_s` climbing)**
No worker is consuming. GCP: `gcloud run services describe frr-<env>-worker` (min instances
≥ 1, latest revision ready). Azure: `az containerapp replica list -n ca-frr-<env>-worker -g rg-frr-<env>`.
Worker logs: `event=worker_db_lost` means it cannot reach the database.

**Jobs dying (`dead` rising)**
`SELECT kind, last_error, count(*) FROM ztpa.jobs WHERE status='dead' GROUP BY 1,2 ORDER BY 3 DESC;`
A `PermanentError` is bad input (the message says what); anything else exhausted its retries.
After fixing the cause, requeue:
`UPDATE ztpa.jobs SET status='queued', attempts=0, run_after=now(), finished_at=NULL WHERE job_id = '<id>';`

**Export rejected for size, or worker restarted mid-ingest (OOM)**
Ingest memory follows grants (rules × sources × destinations × services), ~5.4 KiB each
at peak; a 40,000-rule export with ~4 grants a rule peaks near 1 GiB. Above
`NPR_MAX_GRANTS` (450,000, sized to the 4 GiB worker) the export is rejected with the count
before the review runs. To accept larger: raise the worker's memory and the limit together
(roughly 1 GiB per 150,000 grants above the default), or have the owner export each access
layer separately. `NPR_MAX_PARSE_BYTES` (300 MB) still bounds the raw JSON. Each worker process
runs at most `NPR_WORKER_HEAVY_CONCURRENCY` (1) rulebase-sized jobs (ingest, agent runs) at once —
two at the limit would not fit 4 GiB — while its other slots take light jobs; more heavy
throughput comes from more worker replicas, not more slots.

**Replicas serving different snapshots**
They converge within `NPR_SNAPSHOT_POLL_S` (5 s). If one does not, its logs show
`event=snapshot_sync_failed` with the reason (missing artifact, signature failure). A
signature failure after rotating `NPR_ARTIFACT_KEY` is expected once: trigger a recompute
to republish under the new key.

**429s from the API**
Model-backed routes are limited per identity (`NPR_RATE_LLM_PER_IDENTITY`, 30/min) and per
deployment (`NPR_RATE_LLM_PER_DEPLOYMENT`, 600/min). The response names which ceiling was
hit. Raise the env var on the API service if the limit is wrong for the workload.

**Model provider failing**
Capabilities fall back to deterministic output and say so; nothing breaks. Logs:
`event=llm_call_failed` with provider, model and error. GCP: the backend service account
needs `roles/aiplatform.user` and the model must be enabled in the project/location. Azure:
the backend identity needs *Cognitive Services OpenAI User* on the AI account.

## Routine tasks

**Rollback**
GCP: `gcloud run services update-traffic frr-<env>-api --to-revisions=<previous>=100 --region <region>`
(same for `-web`, `-worker`). Azure: `az containerapp revision list` then
`az containerapp ingress traffic set --revision-weight <previous>=100`. Migrations are
forward-only, so a rollback runs older code on the newer schema. That is safe only for
additive migrations, which is the rule from 0008 on: add columns and tables in one
release, remove what is no longer read in a later one (expand, then contract). Check the
migrations between the two revisions before rolling back.

**Change a prompt, retrieval setting or model**
Prompts live in `backend/src/frr/prompts/`; sampling and retrieval settings at the top of
`src/frr/agents.py`. Any change alters the agent's fingerprint, and CI's prompt gate fails until
a passing evaluation of it is recorded. Against each provider you ship on (Vertex, Foundry):
`python -m src.frr.narrative_eval --items 20 --gate --record` (about 21 model calls), then commit
`src/frr/prompts/eval-ledger.json`. A failing run is never recorded. A model change (new
deployment or version) does not alter the fingerprint: re-run the evaluation on the new model
before switching production to it. `GET /api/frr/agents` shows, per agent, the running
fingerprint and the models it passed on. `NPR_PROMPT_GATE_MIN_MODELS=2` requires both clouds.

**Rotate a secret**
Add a new version in Secret Manager / Key Vault, then roll the services (re-run the deploy,
or `gcloud run services update … --update-secrets` / `az containerapp update`).
- `NPR_PROXY_SECRET` (frontend to API), with no refused request. A restart is NOT enough: Container
  Apps and Cloud Run read a secret when a *revision* starts, and a restart keeps the cached value, so
  "rotate then restart" silently leaves the old secret in use and the next new revision of one app
  breaks the pair. Rehearsed on Azure staging with a probe once a second, zero failures:
  1. `export TF_VAR_proxy_secret_previous="$(az keyvault secret show --vault-name <kv> -n proxy-secret
     --query value -o tsv)"` (GCP: `gcloud secrets versions access latest --secret frr-<env>-proxy-secret`),
     then `terraform apply -replace='random_password.internal["proxy"]'`. The API and worker get a new
     revision accepting both secrets; the frontend still sends the old one.
  2. New frontend revision: `az containerapp update -n ca-frr-<env>-web -g <rg> --revision-suffix rot<date>`
     (GCP: `gcloud run services update frr-<env>-web --region <region> --update-labels rotated=<date>`).
  3. `unset TF_VAR_proxy_secret_previous; terraform apply` drops the old secret from the vault and the API.
- Database app password (`app-db-password` plus `database-url`): update both, run the migrate
  job (it resets the role's password), then roll the services.
- `NPR_ARTIFACT_KEY`: roll, then trigger one recompute.

**Restore the database**
GCP: point-in-time clone (`gcloud sql instances clone <src> <dst> --point-in-time <ts>`), then
switch `database-url`. Azure: `az postgres flexible-server restore -g <rg> -n <new> --source-server <src>
--restore-time <ts>`, then switch `database-url`. Rehearse quarterly.

Rehearsed on Azure staging (2026-10-30): the restore took ~10 minutes and joined the same private
VNet; verified from a job inside the network (`scripts/azure/start-job.sh … python -c …`) that it held
exactly the exports uploaded before `<ts>` (24 of 27; register and audit rows cut at the same point),
then deleted. The roles and their passwords come back with the data, so the existing `database-url`
works once its host is changed.

**Scale**
Raise `*_max_instances` / `*_max_replicas` and redeploy. Check the connection budget in the
deploy guide first; the database is the shared limit.

## Pausing a non-production environment

The services already scale to zero; the database and the always-on worker are what cost money
while idle.

| | Pause | Resume |
|---|---|---|
| GCP | `gcloud run services update frr-<env>-worker --region <region> --min-instances 0`; `gcloud sql instances patch frr-<env> --activation-policy NEVER` | `gcloud sql instances patch frr-<env> --activation-policy ALWAYS`, then redeploy (restores the worker minimum) |
| Azure | `az containerapp update -n ca-frr-<env>-worker -g rg-frr-<env> --min-replicas 0`; `az postgres flexible-server stop -g rg-frr-<env> -n <server>` | `az postgres flexible-server start …`, then redeploy |

Azure starts a stopped Flexible Server again automatically after 7 days. Pausing is drift
from Terraform; the next apply restores the worker minimum. Never pause production.

## Escalation data to collect

Request id from the UI error, the time window, `/api/health` payload, `jobs/stats`, and the
log lines for that `request_id` / `job_id`.
