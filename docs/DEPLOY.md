# Deploying ZeroTrust Policy Advisor (free tier)

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

## 1. Backend → Render

Uses the committed `render.yaml` blueprint.

1. Push `render.yaml` (already on `main`).
2. Render dashboard → **New +** → **Blueprint** → connect the GitHub repo
   `AIDEVEYSBD/ztpa` (one-time GitHub authorization).
3. Render reads `render.yaml` and creates the `ztpa-backend` web service. When
   prompted, fill the two secret values:
   - `DATABASE_URL` = your Neon connection string (the one from `.env`).
   - `OPENAI_API_KEY` = your OpenAI key.
   - `FRONTEND_ORIGIN` = leave blank for now; set in step 3 above.
4. Deploy. Confirm health:
   ```
   https://ztpa-backend.onrender.com/api/health   →  {"status":"ok","db":true,...}
   ```

**Notes**
- Native Python runtime (no Docker). Start command binds `$PORT`.
- On first boot the engine builds in a background thread and self-seeds its
  snapshot into Postgres if missing — so a clean Neon DB is fine too (as long as
  the `ztpa` schema exists; run `python tasks.py db` once if it does not).

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
- **Backend is public.** It trusts `x-ztpa-role`/`x-ztpa-email` headers injected by
  the Vercel middleware. Anyone hitting the Render URL directly could forge these.
  Fine for a demo; before anything real, add a shared secret the backend requires
  (reject requests from clients that don't present it).
