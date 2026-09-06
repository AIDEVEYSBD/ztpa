# Break-glass: getting back in when SSO is broken

> **Read this before you need it.** This application has no password directory,
> no magic links, no invite flow and no "forgot password". AutoX SSO is the only
> way in. That is a deliberate decision, and its consequence is that a broken SSO
> configuration locks **everyone** out of a running deployment — including the
> person who would fix it.
>
> This document is the way back. It has been executed end to end, twice: once
> against the application (the code path) and once against the live Azure
> Container App (the operational path). The transcripts are in §7.

---

## 1. Is this actually your problem?

Work down this list before opening the emergency door. Most "locked out" is not.

| Symptom | What it means | Fix |
|---|---|---|
| `/login` says **"Sign-in is not configured"** | `SSO_CLIENT_ID` is unset. The app has no identity provider at all. | §3, then configure SSO properly (docs/SSO.md) |
| `/login` shows the AutoX button, but sign-in returns `?error=OAuthCallbackError` | The redirect URI is not registered byte-for-byte, or the client secret is wrong | Fix the registration; no break-glass needed |
| You reach **`/no-access`** | You *are* signed in. AutoX granted you no application role. | Ask an AutoX admin for `npr_admin`; press retry. **Not** a lockout |
| `/no-access` says **"SSO misconfiguration … opaque"** | `resource` is not reaching both legs of the code flow | docs/SSO.md §3; sign-in works, authorization does not |
| AutoX itself is down / unreachable / the tenant is gone | Nobody can authenticate | **This is the case break-glass exists for** |
| `SSO_ISSUER` points somewhere wrong, or the client was deleted in AutoX | Discovery fails; sign-in cannot start | **Break-glass** |

Break-glass is for *"the identity provider cannot authenticate anyone, and I need
into the admin console now"*. It is not a convenience login.

## 2. What it is, precisely

A single credential, held **in the platform's secret store and nowhere else**,
that mints an `admin` session without contacting AutoX.

- **It is off by default and cannot turn itself on.** The provider is registered
  only when `AUTH_LOCAL_LOGIN` is exactly the string `true` **and** a credential
  is configured. With the flag unset, `/api/auth/providers` returns `{}` and
  `POST /api/auth/callback/breakglass` reaches no provider.
- **Nothing about it lives in the database.** `ztpa.app_users.password_hash` was
  dropped by `db/migrations/0005_drop_local_auth.sql`; `ztpa.auth_tokens` is
  gone. So break-glass still works when the **database** is the thing that is
  broken (verified — §7.3), and a database compromise yields no login.
- **It is loud.** Every attempt, success and failure, is written to the container
  log with the `[breakglass]` prefix.
- **It is attributable.** The session carries `sub = breakglass:<email>`, which
  `middleware.ts` forwards to the backend as `x-npr-sub` and `db.audit()` writes
  to `audit_log.actor_sub`. Every action taken through the emergency door is
  distinguishable in the audit trail from every action taken through SSO.
- **It expires on its own.** A break-glass session has a 15-minute absolute
  deadline (`BREAKGLASS_SESSION_MAX_AGE`), not extended by activity. Forgetting
  to close the door does not leave a permanent session open.
- **It rate-limits.** Five failed attempts lock that container instance for five
  minutes. In-process and per-replica: it is defence in depth on top of a strong
  password, not a substitute for one. Restarting the revision clears it.

### Configuration

| Variable | Required | Notes |
|---|---|---|
| `AUTH_LOCAL_LOGIN` | yes | Must be exactly `true`. Anything else = off |
| `BREAKGLASS_EMAIL` | yes | The one identity that can sign in. Appears in the audit trail |
| `BREAKGLASS_PASSWORD_HASH` | preferred | bcrypt hash. Store as a **secret**, not a plain env var |
| `BREAKGLASS_PASSWORD` | fallback | Plaintext. Accepted so a recovery never fails for want of a hashing tool; logs a warning on every use |
| `BREAKGLASS_SESSION_MAX_AGE` | no | Seconds, default `900` |

## 3. Opening the door (Azure Container Apps)

Generate the hash first — off the deployment, on your own machine:

```bash
cd frontend
node -e "console.log(require('bcryptjs').hashSync(process.argv[1],10))" 'a-long-random-password-you-just-made-up'
# -> $2a$10$....
```

No repo checked out? Any bcrypt will do (`htpasswd -bnBC 10 "" pw | tr -d ':\n'`),
or fall back to `BREAKGLASS_PASSWORD` with the plaintext and rotate afterwards.

Then, two commands:

```bash
RG=npr-demo-rg
APP=npr-frontend

# 1. the credential goes in the secret store, never in an env var
az containerapp secret set -n "$APP" -g "$RG" \
  --secrets 'breakglass-password-hash=$2a$10$....'

# 2. arm it — this creates a new revision
az containerapp update -n "$APP" -g "$RG" \
  --set-env-vars AUTH_LOCAL_LOGIN=true \
                 BREAKGLASS_EMAIL=you@yourcompany.com \
                 BREAKGLASS_PASSWORD_HASH=secretref:breakglass-password-hash
```

> **Quoting.** A bcrypt hash contains `$`. Single-quote it, or your shell will
> eat `$2a`, `$10` and everything after the next `$` and store a truncated hash
> that will never match.

**How long it takes: about 90 seconds** from the `update` command returning to
the new revision taking traffic (measured: `az` returns in ~14 s, the revision
reports `Healthy` at ~t+58 s, and traffic moves at ~t+93 s). The app keeps
serving throughout — the old revision drains, so `/login` never stops answering.

Then open `https://<app>/login`. The AutoX button is still there if SSO is
configured; underneath it is a **Break-glass sign-in** disclosure. Open it, enter
the `BREAKGLASS_EMAIL` and the password, and you are an `admin`.

If `SSO_CLIENT_ID` is unset entirely, `/login` shows the "Sign-in is not
configured" panel instead — which names these same variables — until you arm it.

## 4. Closing it again

**This is the half people forget.** The door has no automatic timeout; only the
*sessions* it mints do.

```bash
az containerapp update -n "$APP" -g "$RG" \
  --remove-env-vars AUTH_LOCAL_LOGIN BREAKGLASS_EMAIL BREAKGLASS_PASSWORD_HASH

az containerapp secret remove -n "$APP" -g "$RG" \
  --secret-names breakglass-password-hash
```

Same ~95 seconds for the new revision to take traffic. Confirm:

```bash
# must print nothing
az containerapp show -n "$APP" -g "$RG" \
  --query "properties.template.containers[0].env[?name=='AUTH_LOCAL_LOGIN']" -o tsv
# must print {}
curl -s https://<app>/api/auth/providers
```

Sessions minted before you closed the door survive until their 15-minute
deadline. To end them immediately, rotate `AUTH_SECRET` — that invalidates every
session cookie in the app, SSO ones included.

Then, in the audit trail (admin console → **Audit trail**, or SQL):

```sql
SELECT ts, action, actor_email, actor_sub, actor_role
  FROM ztpa.audit_log
 WHERE actor_sub LIKE 'breakglass:%'
 ORDER BY ts DESC;
```

Every action taken through the door, in order. Review it, and record why the door
was opened.

## 5. Other platforms

Nothing about the mechanism is Azure-specific — it is three environment
variables. On Render, Vercel, Fly or plain Docker, set the same three, restart,
and remove them afterwards. Only §3's commands and the ~90 s are Container
Apps-specific.

## 6. What was deliberately NOT chosen, and why

**A SQL insert into `ztpa.app_users`.** This was the obvious candidate — the
table is still there — and it is wrong. `app_users` is a *mirror*: nothing reads
it to authorize anything (`db/sso_schema.sql`, `lib/users.ts`), so a hand-written
row grants nothing. Making it grant something would mean reintroducing a
password column and a code path that trusts the database for authentication, at
which point a database compromise is an admin session, and the emergency path
stops working in the case where the database is what failed.

**Redeploying an older image.** "Roll back to the build that still had password
login" is slower (an image pull and a full deploy), needs a build that may no
longer exist, and reverts every other fix in the current image.

**Deleting the password path outright and recovering by re-provisioning.** The
alternative the workstream brief posed. Rejected: on this deployment "re-provision"
means a new container revision at minimum, and if AutoX is the thing that is
broken there is nothing to re-provision *to*. A dormant, off-by-default,
audited, self-expiring credential is a smaller risk than having no way in.

**Keeping `AUTH_LOCAL_LOGIN`'s old meaning.** It used to be `AUTH_LOCAL_LOGIN=true
|| !ssoEnabled()` — password login was **on by default** whenever SSO was not
configured, which is the state a fresh clone and the current live deployment are
both in. The name was kept (`scripts/azure/deploy.sh` already plumbs it, so this
procedure needs no deploy-script change), but the fallback is gone: only the
literal string `true` arms it.

## 7. Proof — the transcripts

### 7.1 The application: nothing configured

Built frontend, `SSO_CLIENT_ID` unset, `AUTH_LOCAL_LOGIN` unset.

```
### GET /login  (SSO unset, break-glass NOT armed)
Sign-in is not configured
No identity provider is configured
SSO_CLIENT_ID
AUTH_LOCAL_LOGIN=true
BREAKGLASS_PASSWORD_HASH
docs/SSO.md
docs/BREAKGLASS.md
  status=200 bytes=8791          <- a panel that names the fix, not an empty box

### removed routes (anonymous)
  GET /forgot                -> 307   Location: /login?callbackUrl=%2Fforgot
  GET /reset                 -> 307   Location: /login?callbackUrl=%2Freset
  GET /this-path-never-existed -> 307 Location: /login?callbackUrl=%2Fthis-path-never-existed
  GET /login/magic?token=x   -> 404
     (identical treatment: not special-cased auth routes -- just gone)

### the credential providers are gone from Auth.js
{}
  POST /api/auth/callback/password   -> /api/auth/error?error=Configuration
  POST /api/auth/callback/magic      -> /api/auth/error?error=Configuration
  POST /api/auth/callback/breakglass -> /api/auth/error?error=Configuration
```

### 7.2 The application: armed, and the sign-in

```
### providers now registered
{"breakglass":{"id":"breakglass","name":"Break-glass","type":"credentials", ...}}

### 1. WRONG password -> refused
  HTTP/1.1 302 Found
  location: .../login?error=CredentialsSignin&code=credentials

### 2. RIGHT password -> signed in
  HTTP/1.1 302 Found
  location: http://localhost:3111

### 3. the session it minted
{"user":{"name":"Break-glass operator","email":"oncall@example.com",
         "id":"breakglass:oncall@example.com","role":"admin"},
 "sso":{"provider":"breakglass","sub":"breakglass:oncall@example.com",
        "appRoles":["breakglass"],"misconfigured":false,"reauthAt":1788698336}}
   reauthAt = sign-in + 15 minutes exactly

### 4. authorization
  GET /console -> 200
  GET /forgot  -> 404      (authenticated: the route is genuinely gone)
  GET /reset   -> 404

### 5. the mirror row
('oncall@example.com', 'Break-glass operator', 'admin', 'active',
 'breakglass:oncall@example.com', ['breakglass'], 'breakglass', 2026-09-06 12:23:56+00)

### 6. an admin write through the break-glass session, and the audit row it left
POST /api/admin/tools/explain -> 200
('set_tool_roles', 'user', 'oncall@example.com', 'breakglass:oncall@example.com',
 'admin', 2026-09-06 12:24:49+00)

### 7. brute force
  attempt 1..5 (wrong)  -> error=CredentialsSignin
  attempt 6  (CORRECT)  -> error=CredentialsSignin      <- locked out
  [breakglass] FAILED sign-in; locking this instance out for 5 minutes
  [breakglass] REFUSED (locked out for another 300s after 5 failed attempts)

### 8. the session expires on its own (BREAKGLASS_SESSION_MAX_AGE=5 for the test)
  t+0s  session -> {... "role":"admin", "reauthAt":1788698409}
  t+0s  GET /console -> 200
  t+7s  session -> null
  t+7s  GET /console -> 307 -> /login?callbackUrl=%2Fconsole
```

### 7.3 The application: with the database unreachable

`DATABASE_URL` pointed at a dead port.

```
  HTTP/1.1 302 Found          <- signed in anyway
  location: http://localhost:3111
  GET /console -> 200
  [breakglass] SUCCESSFUL sign-in as oncall@example.com with role=admin.
  [breakglass] could not mirror the sign-in into app_users (sign-in still allowed):
               Error: connect ECONNREFUSED 127.0.0.1:1
```

The mirror write failed and the recovery still worked. That is the property that
makes this the right mechanism.

### 7.4 The live Azure Container App: open, then closed

Run against `npr-frontend` in `npr-demo-rg` on 2026-09-06. **The image was not
changed and the app never stopped answering.**

```
### BEFORE
  GET /login -> 200
  env: DATABASE_URL AUTH_SECRET NPR_PROXY_SECRET AUTH_TRUST_HOST BACKEND_URL APP_URL
  secrets: database-url npr-proxy-secret auth-secret
  active revision: npr-frontend--0000001

### STEP 1 - az containerapp secret set ...        done in 17s
### STEP 2 - az containerapp update --set-env-vars ...   az returned after 14s
### STEP 3 - waiting for the revision to take traffic
  t+24s  active=0000001,0000002(Healthy)  GET /login=200
  t+58s  active=0000001,0000002(Healthy)  GET /login=200
  t+93s  active=npr-frontend--0000002     GET /login=200   >>> live
  env now: AUTH_LOCAL_LOGIN=true
           BREAKGLASS_EMAIL=oncall@example.com
           BREAKGLASS_PASSWORD_HASH -> secretRef: breakglass-password-hash

### STEP 4 - CLOSE IT AGAIN
  az containerapp update --remove-env-vars ...   returned after 15s
  az containerapp secret remove ...              returned after 28s
  t+95s  active=npr-frontend--0000003            GET /login=200   >>> closed

### AFTER - restored exactly
  GET /login -> 200
  env: DATABASE_URL AUTH_SECRET NPR_PROXY_SECRET AUTH_TRUST_HOST BACKEND_URL APP_URL
  secrets: database-url npr-proxy-secret auth-secret
  image: npracrf312c545.azurecr.io/npr-frontend:dd51ccf-dirty-20260906112112 (unchanged)
```

## 8. Before you deploy the SSO-only build

The live deployment has **no `SSO_*` variable set today**. Under the previous
build that was survivable, because local login was on by default. Under this one
it is not: deploy as-is and `/login` will render "Sign-in is not configured" and
nobody will get in.

- [ ] `SSO_CLIENT_ID` / `SSO_CLIENT_SECRET` set, and redirect URIs registered
      byte-for-byte (docs/SSO.md §1)
- [ ] Signed in once and reached `/console` — before you rely on it
- [ ] `AUTH_LOCAL_LOGIN` **unset** in steady state
- [ ] This document reachable by whoever holds the Azure subscription — not only
      by whoever has the repo
