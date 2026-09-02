# Deploying Network Policy Reviewer (free tier)

Three hosts, all free:

| Layer | Host | Notes |
|---|---|---|
| Frontend (Next.js + Auth.js) | **Vercel** (Hobby) | Non-commercial only — use Pro for real EY business use. |
| Backend (FastAPI + engine) | **Render** (Free web service) | Sleeps after 15 min idle → ~50 s cold start. |
| Database (Postgres) | **Neon** (existing) | Reused as-is; already schema-applied and seeded. |

> **Secret handling.** The OpenAI key and the database URL are **never committed**.
> On Render they are `sync: false` variables in `render.yaml` (values typed into the
> dashboard, encrypted at rest). On Vercel they are Environment Variables (encrypted).
> `.env` is gitignored and untracked — keep it that way.

---

## Order of operations

Deploy the **backend first** (the frontend needs its URL), then the frontend.

```
1. Render  → backend  → get https://ztpa-backend.onrender.com
2. Vercel  → frontend → set BACKEND_URL to the Render URL → get https://<app>.vercel.app
3. Render  → set FRONTEND_ORIGIN = the Vercel URL → restart (optional hardening)
```

---

## 0. Database migrations — the step that is no longer optional

**The schema now only ever changes through `db/migrate.py`.** It used to change
three ways: `db/schema.sql`, this runner, and four `ensure_*` helpers in
`backend/src/persist.py` that ran `ALTER TABLE` / `CREATE TABLE` **from the
request path** behind module-level "already done" flags. That meant the live
schema depended on which endpoints had happened to be hit since the last process
restart, one table (`asset_merges`) existed in no `.sql` file at all, and the
application's database role had to keep DDL privileges forever. Those helpers are
deleted. A missing column is now a failed write with a clear error, not a
silently self-healing one — which is the correct trade, but it does mean **a
deploy that skips the migration step will fail loudly instead of limping.**

`render.yaml` runs it for you in `buildCommand`, so a normal Blueprint deploy
needs nothing extra. Run it by hand when you provision a database, when you point
the app at a different one, or when a deploy failed before the migration:

```bash
export DATABASE_URL="postgresql://…"          # the same value Render/Vercel hold

python db/migrate.py            # baseline schema.sql, then every pending migration
python db/migrate.py --status   # report applied vs pending, change nothing
python db/migrate.py --check    # same, but exit 1 if anything is pending (CI gate)
python db/migrate.py --migrations-only        # skip the baseline
python db/migrate.py db/auth_schema.sql       # a different baseline file, then migrations
```

**What the runner guarantees**

| Property | How |
|---|---|
| Applied in order | Numeric filename prefix (`0002_…`), sorted numerically, not by string |
| Exactly once | Recorded in `ztpa.schema_migrations`; an already-recorded version is skipped |
| One transaction each | The file and its ledger row commit together, so they can never disagree |
| Idempotent | Re-running prints `no pending migrations`; the baseline is all `IF NOT EXISTS` |
| Forward-only | Editing an applied migration is refused (exit 3) — add a new numbered file |

**Adding a migration.** Create `db/migrations/NNNN_short_name.sql`, make every
statement re-runnable (`IF NOT EXISTS`, or `DROP … IF EXISTS` paired with the
`ADD` after it), and change `db/schema.sql` in the same commit so a fresh install
and an existing one converge on the same schema. A migration may not contain DDL
Postgres refuses inside a transaction block (`CREATE INDEX CONCURRENTLY`,
`ALTER TYPE … ADD VALUE`). Never write a `schema_migrations` row by hand: the
migration it names will be skipped forever.

**Verifying a deployment.** `python db/migrate.py --check` against the deployed
`DATABASE_URL` answers "is this database up to date with this checkout" with an
exit code. `backend/tests/test_db_governance.py` asserts the same thing plus the
governance behaviour end to end — see *Testing against a real database* below.

---

## 1. Backend → Render

Uses the committed `render.yaml` blueprint.

1. Push `render.yaml` (already on `main`).
2. Render dashboard → **New +** → **Blueprint** → connect the GitHub repo
   `AIDEVEYSBD/ztpa` (one-time GitHub authorization).
3. Render reads `render.yaml` and creates the `ztpa-backend` web service. When
   prompted, fill the `sync: false` secret values:
   - `DATABASE_URL` = your Neon connection string (the one from `.env`).
   - `OPENAI_API_KEY` = your OpenAI key.
   - `NPR_PROXY_SECRET` = a fresh random string. **Not optional in practice** — it is
     what stops anyone who can reach the Render URL from sending `x-npr-role: admin`
     and bypassing every role guard. Set the *same* value on Vercel (step 2).
     Generate one with
     `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`.
   - `FRONTEND_ORIGIN` = leave blank for now; set in step 3 above.
4. Deploy. Confirm health:
   ```
   https://ztpa-backend.onrender.com/api/live     →  liveness only, always 200 while up
   https://ztpa-backend.onrender.com/api/health   →  {"status":"ok","db":true,"proxy_auth":true,...}
   ```
   `proxy_auth: false` means `NPR_PROXY_SECRET` is unset — fix that before the URL is
   shared. `/api/health` is the readiness/status view and answers **503** when a
   dependency is down; `/api/live` is what `render.yaml` uses as `healthCheckPath`, so a
   sleeping Neon does not restart-loop the process.

**Notes**
- Native Python runtime (no Docker). Start command binds `$PORT`.
- `buildCommand` is `pip install -r requirements.txt && python ../db/migrate.py`
  (`rootDir` is `backend`, hence the `../`). Render exposes `envVars` to the build,
  so `DATABASE_URL` is available there. **If the build fails on the migrate step,
  the database is unreachable or the URL is wrong — fix that rather than removing
  the step.** On a paid instance type, move it to `preDeployCommand`
  (`python ../db/migrate.py --migrations-only`), which runs after the build and
  before traffic shifts; pre-deploy commands are not available on the free plan.
- `render.yaml` pins **`ADVISORY_PROVIDER=openai`** (there is no Ollama on Render), so
  **this deployment sends finding text, rule text and asset names to OpenAI**. The header's
  AI residency chip will read *"Hosted — data leaves this host"*. That is a deliberate
  trade for the hosted demo, but it is not the local-first configuration the README
  describes — do not present it as one.
- On first boot the engine builds in a background thread and self-seeds its
  snapshot into Postgres if missing — so a clean Neon DB is fine too, **provided
  the migrations have run** (step 0). The application no longer creates any part
  of its own schema.

## 2. Frontend → Vercel

1. Vercel dashboard → **Add New… → Project** → import `AIDEVEYSBD/ztpa`.
2. **Root Directory = `frontend`** (critical — the Next.js app is not at repo root).
   Framework preset auto-detects Next.js.
3. Add Environment Variables (Production):

   | Name | Value |
   |---|---|
   | `DATABASE_URL` | Neon **pooled** string (host contains `-pooler`) |
   | `AUTH_SECRET` | generate: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"` |
   | `AUTH_TRUST_HOST` | `true` |
   | `BACKEND_URL` | `https://ztpa-backend.onrender.com` (from step 1) |
   | `APP_URL` | leave blank (auto-derives from request host) |
   | `ADMIN_EMAIL` | your admin email |
   | `RESEND_API_KEY` | *(optional — magic/reset links print to logs without it)* |
   | `EMAIL_FROM` | *(optional, if Resend is set)* |
   | `SSO_CLIENT_ID` | from the AutoX SSO admin — **setting this turns SSO on and local password login off** |
   | `SSO_CLIENT_SECRET` | from the AutoX SSO admin |
   | `SSO_SESSION_MAX_AGE` | `3600` (absolute session seconds = role-change pickup interval) |
   | `NPR_PROXY_SECRET` | the **same** value set on Render — the middleware sends it alongside the `x-npr-*` actor headers, and without it the backend cannot tell a real proxy request from a forged one |

   > **SSO.** Register `https://<app>.vercel.app/api/auth/callback/autox` as a
   > redirect URI and `https://<app>.vercel.app/login` as a post-logout redirect URI
   > *before* setting `SSO_CLIENT_ID` — they must match byte-for-byte. Preview
   > deployments have different hostnames and will not work unless also registered.
   > Full setup, including the `npr_admin` / `npr_analyst` / `npr_viewer` app roles,
   > is in [SSO.md](SSO.md).

   > Use the Neon **pooled** endpoint for the frontend: Auth.js opens `pg` pools
   > inside serverless functions, and the pooled endpoint prevents connection
   > exhaustion. `BACKEND_URL` is read at build time by `next.config.mjs` rewrites,
   > so a change to it requires a redeploy.

4. Deploy. Open `https://<app>.vercel.app`.

## 3. Harden CORS (optional)

On Render, set `FRONTEND_ORIGIN` to the Vercel URL and restart. The normal request
path is server-to-server (Next.js proxies `/api/*` to Render), so the browser never
calls Render cross-origin — this is defense-in-depth.

---

## Testing against a real database

The backend unit suite is deliberately offline: `backend/conftest.py` blanks
`DATABASE_URL` at import so CI can never reach a server, and `pytest` runs in
~2s. The governance tests in `backend/tests/test_db_governance.py` are the
exception — they prove, on real rows, that **all four** of a recompute, a dataset
switch, an asset merge and a reset leave `change_requests`, `change_decisions`
and `audit_log` intact, that every column the persist layer writes exists, that
`audit()` records who acted, and that a snapshot too wide for one `INSERT` still
persists.

The reset is the one that needs a sentence of its own. `/api/admin/reset-demo`
**retires** the change trail — it stamps `archived_at` and every read that feeds
a screen filters `archived_at IS NULL` — instead of deleting it, so the console
still resets to a clean slate while the record of who asked for what survives
(`db/migrations/0003`). What a reset really deletes is the working set and the
cache: `staged_changes`, `remediation_revisions`, `campaign_plans`. Re-running
the demo revives the retired rows, because request ids are deterministic content
hashes and the persist helpers clear the stamp on the way in.

They read a **separate** variable, so setting it cannot accidentally point the
unit suite at a real database, and they **skip** when it is absent:

```bash
# any throwaway Postgres with db/schema.sql + db/migrate.py applied
NPR_TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/npr pytest
```

Setting it **wrongly** is a hard failure, not a skip: an unreachable database
fails collection with the connection error, because a run that was asked for a
database and did not get one has proved nothing and must not exit 0. Unset the
variable to run offline on purpose. (`backend/tests/dbharness.py` holds that
decision; `test_persist_snapshot.py` tests it, offline.)

Every test runs in one transaction and rolls it back, so nothing is committed —
but point it at a scratch database anyway, never at production.

---

## Operational caveats

- **Cold starts.** Render free sleeps after 15 min idle. To keep the demo snappy,
  ping `/api/health` every ~10 min (e.g. a free cron-job.org monitor or a GitHub
  Actions scheduled `curl`).
- **Long AI calls through the proxy.** Report/ask calls proxied via Vercel's
  rewrite are subject to Vercel's gateway timeout; with `gpt-4o` they normally
  return well within it.
- **First admin.** After deploy, create the first admin with
  `node frontend/scripts/create-admin.mjs` (run locally against the same Neon DB),
  or set `ADMIN_EMAIL` and follow the app's invite flow.
- **Backend is public — the shared secret is what makes that safe.** It authorizes on
  the `x-npr-role` / `x-npr-email` / `x-npr-sub` headers the Vercel middleware injects.
  `NPR_PROXY_SECRET` is now enforced: with it set, a request carrying those headers
  without the secret is rejected **401**, so the Render URL cannot be used to
  self-assign a role. **Leave it unset and the old exposure is back in full** — the
  headers are then trusted unconditionally. Confirm `proxy_auth: true` on
  `/api/health` after every deploy, and keep `FRONTEND_ORIGIN` set as
  defense-in-depth on top.
