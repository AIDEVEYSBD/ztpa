# Production readiness checklist

Go-live gate for an environment. ✅ = enforced in code or CI; ☐ = to verify per environment.

## Platform (enforced)

- ✅ Production refuses to boot without `NPR_PROXY_SECRET`, `DATABASE_URL`, a 32+ char
  `NPR_ARTIFACT_KEY` and cloud object storage (`src/preflight.py`, exit 1; CI asserts it).
- ✅ API, worker, database and storage are private; the frontend is the only public entry.
- ✅ Runtime connects as a role with row access only (no DDL, no ledger writes); migrations
  run as a separate identity (`migrate.py --ensure-app-role`; CI runs the suite as that role).
- ✅ Secrets come from Secret Manager / Key Vault via workload identity; none in images,
  the database or the repo.
- ✅ Images are hash-pinned (`requirements.lock`), contain no test tooling, are built once in
  CI and deployed by digest; Terraform rejects tags.
- ✅ Migrations run before each rollout; a post-deploy smoke test runs inside the network.
- ✅ Stateless API: replicas serve the published snapshot; heavy work runs in workers via a
  durable queue with leases and retries.
- ✅ Shared rate limits on model-backed routes; 1 MB request cap; field caps.
- ✅ Structured JSON logs; liveness and readiness are separate endpoints.

## Per environment (verify)

- ☐ Terraform state bucket/account is versioned and readable only by deployers.
- ☐ SSO redirect URI registered; role mapping tested for every product role.
- ☐ Break-glass procedure tested and its secret held offline ([../BREAKGLASS.md](../BREAKGLASS.md)).
- ☐ Database HA on (prod); a point-in-time restore rehearsed (procedure measured on Azure
  staging, RUNBOOK "Restore the database"; repeat it for this environment).
- ☐ Alerts route to a monitored channel; a test alert received.
- ☐ Custom domain with TLS; WAF in front of the frontend (GCP: Cloud Armor, Azure: Front Door
  Premium WAF — both via `domain`).
- ☐ Model provider test passes from Admin → AI configuration; data-residency of the chosen
  provider/location accepted by the security owner.
- ☐ Load test run against this environment's size (tracker PLAT-15; staging-size results in
  TEST-BACKLOG T15a). The connection budget is checked by Terraform at plan time.
- ☐ Proxy-secret rotation rehearsed with the three-step procedure (RUNBOOK "Rotate a secret").
- ☐ FRR evaluation suite passed on the labelled test rulebase (tracker 04.5) before UAT.

## Not yet in place (tracked)

See [TRACKER.md](TRACKER.md): Skybox ingestion (01.1b), NAT
applied to effective policy (02.2b), and validation against real client exports.
