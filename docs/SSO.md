# AutoX SSO integration (OIDC)

Reference: <https://sso.autogrc.cloud/integration.md>

Network Policy Reviewer authenticates against **AutoX SSO** using OpenID Connect,
authorization code + PKCE (S256). Authorization is driven by the **`autox:app_roles`**
claim — the roles a user holds *in this application*.

> **AutoX SSO is the ONLY way in.** There is no password directory, no magic
> link, no invite, no "forgot password" and no Manage-users screen. Password and
> magic-link sign-in, `ztpa.auth_tokens` and `app_users.password_hash` were
> removed (`db/migrations/0005_drop_local_auth.sql`), and membership and roles are
> granted in the AutoX admin.
>
> The consequence is stated plainly because it is real: **a broken SSO
> configuration locks everyone out of a running deployment.** The recovery is a
> single, off-by-default, audited credential — **[docs/BREAKGLASS.md](BREAKGLASS.md)**.
> Read it before you deploy, not after.

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
| `npr_admin` | `admin` | Everything, plus the admin console: snapshots, per-role tool toggles, usage metrics, the audit trail. The only role that may mutate the system of record — recompute, merge/unmerge identities, push to a data source. (There is no *users* screen: see §5) |
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
```

`ssoEnabled()` is simply "is `SSO_CLIENT_ID` set", and it registers the `autox`
provider. It no longer *unregisters* anything, because there is nothing left to
unregister: the password and magic-link providers are deleted, not disabled.

**With `SSO_CLIENT_ID` unset there is no sign-in method at all.** `/login` then
renders an explicit "Sign-in is not configured" panel naming the variables that
fix it and pointing at the break-glass procedure — not an empty login box — and
the server logs `[auth] NO SIGN-IN METHOD IS CONFIGURED` at start-up. This is a
change of default worth noticing: local login used to be **on** whenever SSO was
off, so a deployment with no `SSO_*` variables was previously usable.

The emergency path has its own three variables and its own document; they are not
part of a normal deployment and must be **unset** in steady state:

```ini
AUTH_LOCAL_LOGIN=         # exactly "true" arms the break-glass credential
BREAKGLASS_EMAIL=         # the one identity it can authenticate
BREAKGLASS_PASSWORD_HASH= # bcrypt; store as a platform SECRET
```

See **[docs/BREAKGLASS.md](BREAKGLASS.md)**.

Apply the schema, in this order:

```
python db/migrate.py                     # engine schema + numbered migrations
python db/migrate.py db/auth_schema.sql  # ztpa.app_users
python db/migrate.py db/sso_schema.sql   # the sso_* columns
```

`0005_drop_local_auth` drops `ztpa.auth_tokens` and `app_users.password_hash`.
It is order-independent: on a fresh database it runs before `app_users` exists,
finds nothing to do, and says so in a NOTICE.

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

## 5. Users — `ztpa.app_users` is a mirror, not a directory

There is no user management in this application. Membership and roles are granted
in the AutoX admin; the **Manage users** screen, the invite flow and the
`create-admin.mjs` / `send-reset.mjs` bootstrap scripts are gone, because under
SSO they could only create rows nobody can sign in as.

`ztpa.app_users` survives, and **must not be dropped**. It is the projection that
gives the audit trail a *who*: `0002_audit_identity` made
`audit_log.actor_email` / `actor_sub` / `actor_role` plain text so the trail
outlives the account, and this table is what resolves a historical `actor_sub`
back to a person. `frontend/lib/users.ts:provisionSsoUser` writes it on every
authentication.

- Rows are keyed on `sso_sub` (the AutoX `sub`), never email: a deleted and
  re-created AutoX account keeps the email but gets a **new** `sub`.
- Provisioning is a side effect of successful authentication — a failed upsert logs
  and sign-in continues. Local state never denies sign-in, and never grants it.
- Migration adoption: an existing unlinked local row is claimed by matching email
  **only** when `email_verified === true`. (Its password used to be cleared here;
  the column no longer exists.)
- `email_verified` is now stamped from the AutoX `email_verified` claim, forward
  only — it used to be written by a consumed magic link.
- A break-glass sign-in is mirrored too, as `sso_sub = breakglass:<email>` with
  `created_by = 'breakglass'`, so "did anyone use the emergency door" is one query.
- `status` and `role` on this table are reporting fields. Setting `status` to
  `disabled` here does **not** stop anyone signing in — revoke the AutoX app role.

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
- [ ] `db/auth_schema.sql` and `db/sso_schema.sql` applied, and `python db/migrate.py --check` clean
- [ ] `AUTH_LOCAL_LOGIN`, `BREAKGLASS_EMAIL`, `BREAKGLASS_PASSWORD_HASH` all unset
      in production — `curl /api/auth/providers` returns **only** `autox`
- [ ] Somebody has actually signed in and reached `/console` on this deployment.
      With SSO as the only door, "the config looks right" is not evidence
- [ ] [docs/BREAKGLASS.md](BREAKGLASS.md) is reachable by whoever holds the
      hosting subscription, not only by whoever has the repo
- [ ] `NPR_PROXY_SECRET` set to the **same** value on the backend and the frontend, and
      `/api/health` reports `proxy_auth: true` — without it the role headers are
      unauthenticated and every role guard in §1 can be bypassed by calling the backend
      directly
