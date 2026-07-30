# AutoX SSO integration (OIDC)

Reference: <https://sso.autogrc.cloud/integration.md>

Network Policy Reviewer authenticates against **AutoX SSO** using OpenID Connect,
authorization code + PKCE (S256). Authorization is driven by the **`autox:app_roles`**
claim — the roles a user holds *in this application*.

---

## 1. What to register in the AutoX SSO admin

There is no self-service registration; an AutoX admin creates the client at
<https://sso.autogrc.cloud/admin>.

**Client**

| Field | Value |
|---|---|
| Client type | Confidential (server-side Next.js) |
| Grant | `authorization_code` + PKCE (S256) |
| ID token alg | `ES256` |
| Redirect URI (prod) | `https://<app-domain>/api/auth/callback/autox` |
| Redirect URI (local) | `http://localhost:3000/api/auth/callback/autox` |
| Post-logout redirect URI (prod) | `https://<app-domain>/login` |
| Post-logout redirect URI (local) | `http://localhost:3000/login` |
| Scopes | `openid profile email orgs roles` |
| Resource / audience | `https://sso.autogrc.cloud/api` |

Redirect URIs must match **byte-for-byte** (including trailing slashes). Register
every origin the app is served from — a Vercel preview URL will not work unless it
is registered too.

`offline_access` is **not** requested: no refresh tokens means no rotation /
reuse-detection races. Role freshness is handled by capping the session instead
(see §4).

### Application roles — create these three

`autox:app_roles` values, assigned per user for this application:

| SSO app role | App role | Grants |
|---|---|---|
| `npr_admin` | `admin` | Everything, plus the admin console: users, snapshots, per-role tool toggles, usage metrics |
| `npr_analyst` | `analyst` | Full read + AI advisory, submit **and** approve/reject change requests, run remediation campaigns |
| `npr_viewer` | `viewer` | Read-only: findings, graph, reports, evidence. Cannot approve or apply changes |

Notes:

- A user with **no** role from this list is authenticated but not entitled — they
  land on `/no-access` with a retry button. There is no implicit `viewer`.
- Multiple roles resolve to the **highest**: `admin` > `analyst` > `viewer`.
- The bare names `admin` / `analyst` / `viewer` are also accepted, so the prefix is
  a convention, not a hard requirement.
- To use different names in the SSO without a code change, set `SSO_ROLE_MAP`:
  ```
  SSO_ROLE_MAP={"npr-platform-owner":"admin","npr-network-reviewer":"analyst","npr-read":"viewer"}
  ```
- `autox:roles` (the global directory role) is read for display/audit only and
  **never** used for authorization — it is identical across every AutoX app.

---

## 2. Environment variables

```ini
SSO_CLIENT_ID=            # from the AutoX admin — turns SSO on
SSO_CLIENT_SECRET=        # confidential clients only
SSO_ISSUER=https://sso.autogrc.cloud
SSO_RESOURCE=https://sso.autogrc.cloud/api
SSO_SCOPE=openid profile email orgs roles
SSO_SESSION_MAX_AGE=3600  # absolute session seconds; role-change pickup interval
SSO_POST_LOGOUT_REDIRECT_URI=   # default: <origin>/login (must be registered)
SSO_ROLE_MAP=             # optional JSON override of SSO role -> app role
AUTH_LOCAL_LOGIN=         # "true" keeps password/magic-link login alive during cutover
```

`ssoEnabled()` is simply "is `SSO_CLIENT_ID` set". Setting it:

- registers the `autox` provider,
- **unregisters** the password and magic-link credential providers (so they cannot
  be used as an SSO bypass) unless `AUTH_LOCAL_LOGIN=true`,
- disables local invite / reset / magic-link server actions.

Apply the schema change once:

```
psql "$DATABASE_URL" --single-transaction -v ON_ERROR_STOP=1 -f db/sso_schema.sql
```

---

## 3. How app roles reach the app

The one non-obvious part of the AutoX contract:

> The access token is **opaque by default**. It is only a JWT — and only then
> carries `autox:app_roles` — when `resource=https://sso.autogrc.cloud/api` is sent
> on **both** the `/auth` request **and** the `/token` exchange. Sending it on only
> one leg yields an opaque token *silently*.

Auth.js has a config hook for the first leg but not the second, so:

| Leg | Where it is set |
|---|---|
| `/auth` | `authorization.params.resource` in [auth.autox.ts](../frontend/auth.autox.ts) |
| `/token` | `fetchWithResource` (the provider's `customFetch`), which appends `resource` to the token request body |

If the token ever comes back opaque, `readAppRoles()` returns `{ kind: "opaque" }`,
the session is flagged `misconfigured`, and `/no-access` says so explicitly rather
than reporting a phantom "no roles".

Flow:

```
/auth (PKCE+state+nonce, scope, resource)
   -> /token (code_verifier, resource)          <- both legs carry `resource`
   -> id_token   (ES256, JWKS-verified)         -> identity: sub, email, name, org
   -> access_token (JWT)                        -> autox:app_roles
   -> resolveRole(app_roles)                    -> admin | analyst | viewer | null
   -> Auth.js session cookie (httpOnly, encrypted)
   -> middleware forwards x-npr-role / x-npr-email / x-npr-sub to FastAPI
```

The backend reads those headers in `request_ctx` for per-role AI-tool gating and
usage attribution. It strips any client-supplied `x-npr-*` header first, but it
still trusts the proxy — the backend must stay reachable only through it.

---

## 4. Role and access changes

AutoX role grants and revocations appear **only in newly minted tokens**; an issued
token stays valid until it expires. So:

- No allow/deny verdict is persisted anywhere that outlives the token. The
  `role` column on `ztpa.app_users` is a mirror for audit/reporting, never an
  authorization input.
- The session has an **absolute** deadline (`SSO_SESSION_MAX_AGE`, default 1 h) — it
  is not extended by activity. On expiry the session cookie is dropped and the next
  navigation runs a fresh authorization request, silently while the AutoX session is
  alive, picking up any role change.
- `/no-access` is a **real retry**: its button calls `signIn("autox")`, i.e. a new
  authorization request. It never re-renders a cached session. (The integration guide
  calls getting this wrong the most common mistake.)

## 5. Users

- Local rows are keyed on `sso_sub` (the AutoX `sub`), never email: a deleted and
  re-created AutoX account keeps the email but gets a **new** `sub`.
- Provisioning is a side effect of successful authentication — a failed upsert logs
  and sign-in continues. Local state never denies sign-in.
- Migration adoption: an existing unlinked local row is claimed by matching email
  **only** when `email_verified === true`, and its local password is cleared.

## 6. Logout

`GET /sso/logout` clears the local session, then redirects to
`https://sso.autogrc.cloud/session/end` with `id_token_hint` and
`post_logout_redirect_uri`. Without `id_token_hint` the SSO cannot identify the
client, cannot validate the redirect URI, and will not come back.

## 7. Cold start

AutoX can scale to zero. The sign-in screen probes `GET /sso/health` (which proxies
`https://sso.autogrc.cloud/health`) and polls until the SSO returns its own JSON
`{"status":"ok"}` before redirecting. Status code alone is not enough: Render's
cold-start page is an HTML `503`, and Cloud Run queues the request and answers
slowly with `200`.

---

## Checklist

- [ ] Client registered; `client_id` / `client_secret` in the app's environment
- [ ] Redirect URIs registered for every origin, incl. `/api/auth/callback/autox`
- [ ] Post-logout redirect URIs registered
- [ ] `npr_admin`, `npr_analyst`, `npr_viewer` created and assigned to users
- [ ] `resource=https://sso.autogrc.cloud/api` confirmed on both legs — sign in and
      check the session is not flagged `misconfigured`
- [ ] `db/sso_schema.sql` applied
- [ ] `AUTH_LOCAL_LOGIN` unset in production (local login off)
