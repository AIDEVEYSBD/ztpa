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

**Rotate a secret**
Add a new version in Secret Manager / Key Vault, then roll the services (re-run the deploy,
or `gcloud run services update … --update-secrets` / `az containerapp update`).
- `NPR_PROXY_SECRET`: roll frontend and API together.
- Database app password (`app-db-password` plus `database-url`): update both, run the migrate
  job (it resets the role's password), then roll the services.
- `NPR_ARTIFACT_KEY`: roll, then trigger one recompute.

**Restore the database**
GCP: point-in-time clone (`gcloud sql instances clone <src> <dst> --point-in-time <ts>`), then
switch `database-url`. Azure: `az postgres flexible-server restore --restore-time <ts>`, then
switch `database-url`. Rehearse quarterly.

**Scale**
Raise `*_max_instances` / `*_max_replicas` and redeploy. Check the connection budget in the
deploy guide first; the database is the shared limit.

## Escalation data to collect

Request id from the UI error, the time window, `/api/health` payload, `jobs/stats`, and the
log lines for that `request_id` / `job_id`.
