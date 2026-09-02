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
| `npr_admin` | `admin` | Everything, plus the admin console: users, snapshots, per-role tool toggles, usage metrics. The only role that may mutate the system of record — recompute, merge/unmerge identities, push to a data source |
| `npr_analyst` | `analyst` | Full read + AI advisory; propose, approve/reject, stage and withdraw change requests; run remediation campaigns |
| `npr_viewer` | `viewer` | Read-only: findings, graph, reports, evidence. Cannot submit, approve, stage, push or withdraw a change, cannot merge identities, and cannot recompute a snapshot |

### What the backend actually enforces

The role in the table is not a UI convention: three FastAPI dependencies in
`backend/app/main.py` reject the request with **403** before the handler body runs.

| Dependency | Roles | Routes it protects |
|---|---|---|
| `require_admin` | `admin` | `GET /api/admin/tools`, `POST /api/admin/tools/{key}`, `GET /api/admin/metrics`, `POST /api/admin/dataset`, `POST /api/admin/reset-demo`, `DELETE /api/snapshots/{id}` |
| `require_approver` | `admin`, `analyst` | `POST /api/change/classify`, `POST /api/change/submit`, `POST /api/change/reject`, `POST /api/staging`, `DELETE /api/staging/{id}`, `POST /api/campaign/plan`, `POST /api/campaign/submit`, `POST /api/findings/{id}/remediate`, `POST /api/findings/{id}/remediate/refine` |
| `require_operator` | `admin` | `POST /api/recompute`, `POST /api/actions/recompute`, `POST /api/staging/{id}/push`, `POST /api/assets/merge`, `POST /api/assets/unmerge` |

`require_approver` is drawn at *governance* actions — proposing, drafting a remediation,
classifying, approving, staging, withdrawing — and `require_operator` at actions that
**change the system of record or reach for a data source**. A viewer holds neither, so the
read-only promise above is enforced server-side on **every** route in that table, not merely
hidden in the UI. That is the full set of mutating endpoints; none is left unguarded.

Four `POST` routes are deliberately **not** role-gated, because they mutate nothing in the
governance pipeline and a viewer is entitled to them — they are POST only because they carry
a request body: `POST /api/findings/{id}/explain` (returns the finding's explanation, writing
only the explanation cache), `POST /api/agent/ask`, `POST /api/intake` (parses free text into
a structured rule and returns it — it does not submit one) and `POST /api/connectors/propose`
(returns a draft `SourceProfile`; nothing is registered). Each is still subject to
`_require_capability`, the per-role AI feature flag — see the second bullet below for why
that is not an authorization boundary.

Two boundaries this depends on, both worth stating plainly:

- **The role arrives in a header, and the header is only as trustworthy as the proxy.**
  `middleware.ts` forwards `x-npr-role` / `x-npr-email` / `x-npr-sub` and the backend strips
  any client-supplied copy before reading them (§3). When `NPR_PROXY_SECRET` is configured,
  a request may claim an identity **only** if it also presents that secret, so a direct
  caller cannot self-assign `admin`. **Leave `NPR_PROXY_SECRET` unset and that protection is
  off** — anyone who can reach the backend URL can send `x-npr-role: admin`. `/api/health`
  reports `proxy_auth: false` when it is unset; treat that as a deployment defect, not a
  warning.
- **The per-role AI *capability* toggles are a different mechanism, and are not an
  authorization boundary.** `_require_capability` (admin Tools screen → `ztpa.tool_settings`)
  is **default-on**: an absent row enables the capability for every role. It is a feature
  flag. Never reason about who can write from it — the `require_*` dependencies above are the
  boundary. (An *unreadable* settings table is the opposite case and is fail-closed: it
  resolves every AI capability to nobody, admin included, so breaking the store cannot
  re-enable a capability an operator killed.)

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

The backend reads those headers in `request_ctx` — for route authorization (§1),
per-role AI-tool gating and usage attribution. It strips any client-supplied
`x-npr-*` header first, then enforces the trust boundary: with
**`NPR_PROXY_SECRET`** set on both the proxy and the backend, a request may claim
an identity only if it also presents that secret, and otherwise gets **401**.
Unset, the headers are trusted unconditionally and the backend must be reachable
only through the proxy — `/api/health` reports `proxy_auth: false` so you can tell
which regime you are in.

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
- [ ] `NPR_PROXY_SECRET` set to the **same** value on the backend and the frontend, and
      `/api/health` reports `proxy_auth: true` — without it the role headers are
      unauthenticated and every role guard in §1 can be bypassed by calling the backend
      directly
