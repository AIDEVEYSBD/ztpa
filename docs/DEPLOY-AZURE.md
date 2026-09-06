# Deploying Network Policy Reviewer on Azure Container Apps

One command, one resource group, no VMs:

```bash
az login
bash scripts/azure/deploy.sh
```

| Layer | Azure service | Notes |
|---|---|---|
| Frontend (Next.js + Auth.js) | **Container Apps** — external ingress | The only thing with a public address. Also the authorization proxy. |
| Backend (FastAPI + engine) | **Container Apps** — **internal** ingress | Reachable only from inside the managed environment. |
| Database | **PostgreSQL Flexible Server** (Burstable `Standard_B1ms`, PG 16) | TLS enforced server-side; `sslmode=require` in the connection string. |
| Images | **Azure Container Registry** (Basic) | Built server-side with `az acr build`, pulled with a managed identity. |
| Schema + demo data | **Container Apps job** (`npr-migrate`) | `db/migrate.py` → `seed_demo.py` → `precompute.py`, with an exit code. |
| Logs | **Log Analytics workspace** | Wired into the managed environment. |

Region defaults to `centralindia`; everything lands in one resource group
(`npr-demo-rg`) so teardown is a single delete.

---

> ## Read this before you show it to anyone
>
> **This is a demo / staging environment carrying the seeded demo dataset.** It is
> not a production deployment of this product, and the reason is the product, not
> the infrastructure. The independent round-2 audit —
> [`PROD-READINESS-AUDIT-2.md`](PROD-READINESS-AUDIT-2.md) — leaves **8 open
> blockers** and its verdict is unambiguous:
>
> > *"The core engine is not production-ready, and I would not put this in front of
> > a client yet… the maths is trustworthy, the plumbing between the maths and the
> > answer is not, and every gap I found fails toward 'you're clean.'"*
>
> The sharpest of them (B1) is that cross-tool path tracing only fires when an
> export spells the internet literally `0.0.0.0/0`; `any` or a named group yields
> **zero** paths and renders as *"no internet-to-crown-jewel path exists."* On a
> demo dataset built to say `0.0.0.0/0`, the product looks like it works. On a
> real export it can be silently, confidently wrong in the safe-looking direction.
>
> So: **seeded demo data only.** Do not load a customer's export into this
> environment, do not treat anything it prints as an assessment, and do not
> present the deployment as evidence that the product is ready. It is evidence
> that the product *runs*, which is a different claim.

---

## What the script actually creates

| # | Resource | Default name | Why |
|---|---|---|---|
| 1 | Resource group | `npr-demo-rg` | One delete tears everything down. |
| 2 | Container registry | `npracr<hash>` | Basic. Name derived from subscription + group, so a re-run finds the same one. |
| 3 | PostgreSQL Flexible Server | `npr-pg-<hash>` | Burstable B1ms, 32 GB, PG 16, database `npr`. |
| 4 | Log Analytics workspace | `npr-logs` | Log sink for the environment. |
| 5 | Container Apps environment | `npr-env` | The private network both apps share. |
| 6 | Managed identity | `npr-acr-pull` | Holds `AcrPull` on the registry. Nothing else. |
| 7 | Job | `npr-migrate` | migrate → seed → precompute, re-runnable by hand. |
| 8 | Container app (backend) | `npr-backend` | Internal ingress, port 8000, liveness on `/api/live`. |
| 9 | Container app (frontend) | `npr-frontend` | External ingress, port 3000. **The public URL.** |

The `<hash>` is the first 8 hex characters of `sha256(subscriptionId/resourceGroup)`.
Both of those names are global DNS labels, so they cannot just be `npr-acr`;
deriving them means a re-run always lands on the same resources, and two people
deploying this repo into two subscriptions never collide.

---

## Architecture, and the one decision that matters

```
                    ┌───────────────────────── Container Apps environment ─────────────────────────┐
                    │                                                                              │
  internet ───────► │  npr-frontend                          npr-backend                           │
   (443)            │  EXTERNAL ingress :3000  ──────────►   INTERNAL ingress :8000                │
                    │  Next.js + Auth.js                     FastAPI + deterministic engine        │
                    │  middleware.ts:                        trusts x-npr-* IF x-npr-proxy-secret  │
                    │   • strips client x-npr-*              matches its own NPR_PROXY_SECRET      │
                    │   • sets role/email/sub                                                      │
                    │   • signs with proxy secret                                                  │
                    │         │                                        │                           │
                    │  npr-migrate (job, manual trigger) ──────────────┤                           │
                    └──────────┼────────────────────────────────────────┼───────────────────────────┘
                               │                                        │
                               └────────────► PostgreSQL Flexible Server ◄──────────
                                              sslmode=require, Azure-services firewall rule
```

**The backend has no public address, and that is the point.**

The frontend is not a UI in front of an API — it is the *authorization proxy*.
`frontend/middleware.ts` strips every client-supplied `x-npr-*` header, then sets
`x-npr-role` / `x-npr-email` / `x-npr-sub` from the Auth.js session and signs
them with `x-npr-proxy-secret`. FastAPI reads those headers to decide who you
are and what you may do. That design is sound only if two things hold:

1. **Nobody else can send those headers to the backend.** On the previous
   (Render + Vercel) topology the backend was on the public internet and the
   shared secret was the *only* thing standing between a curl command and
   `x-npr-role: admin`. An independent audit rated the secret shipping unset a
   blocker, and it was right to. Here the backend's ingress is `internal`: its
   FQDN (`npr-backend.internal.<env-domain>`) resolves only inside the managed
   environment, so the header-trust surface is not exposed at all. The shared
   secret becomes defence in depth instead of the entire defence.

2. **`NPR_PROXY_SECRET` is identical on both containers.** The script generates
   it once with `openssl rand -hex 32`, stores it as a Container Apps secret on
   both apps, and on every re-run **reads the existing value back out** rather
   than minting a new one. A fresh value on one side only would 401 every
   proxied request in the console — which is exactly the failure a "safe to
   re-run" script must not be able to cause. Verify it after every deploy:
   `/api/health` must report `"proxy_auth": true`.

Same-environment apps reach each other by FQDN with no VNet, no peering and no
private DNS zone to configure. Internal ingress costs nothing and removes an
entire class of exposure, which is why it is the default here and why
`FRONTEND_ORIGIN` (CORS) is set as well: the browser never talks to FastAPI
directly, so CORS is belt to the internal-ingress braces.

### Every secret is a Container Apps secret

| Secret | Backend | Frontend | Job |
|---|---|---|---|
| `database-url` | ✓ | ✓ | ✓ |
| `npr-proxy-secret` | ✓ | ✓ | |
| `auth-secret` | | ✓ | |
| `model-api-key` | ✓ (if supplied) | | |
| `sso-client-secret` | | ✓ (if supplied) | |

Environment variables reference them as `secretref:<name>`. No secret is ever a
plaintext env var, a container build arg (recoverable from `docker history`), or
a file in the repo. The one honest caveat: `az` takes secret values as
command-line arguments, so they are briefly visible to `ps` on the machine
running the deploy. Key Vault references are the production answer to that; they
are not wired up here.

---

## Prerequisites

- **Azure CLI 2.90+** and `az login`. The script installs the `containerapp`
  extension if it is missing.
- **openssl** (for the generated secrets) and **git** (for the image tag). Both
  ship with macOS and any Linux you would run this from.
- Permissions in the target subscription to create a resource group and the
  resources above. **Ideally** also `Microsoft.Authorization/roleAssignments/write`,
  so the managed identity can be granted `AcrPull` — see *Registry authentication*
  below for what happens when you do not have it.
- **No Docker.** Images are built server-side by ACR Tasks. This is not just
  convenience: the dev machines here are arm64, Container Apps runs amd64, and a
  locally built image would start and immediately die with `exec format error`.
  `az acr build --platform linux/amd64` removes the cross-compilation problem
  rather than solving it.

---

## One-command deploy

```bash
az login
az account set --subscription "F-S-CONSULTING-SBP10F-WFT22C3H"   # or set NPR_SUBSCRIPTION
bash scripts/azure/deploy.sh
```

First run takes roughly **20–30 minutes**, most of it the Postgres server (~10
min) and the managed environment (~5 min). The script prints the frontend URL
and the next steps when it finishes.

### It is idempotent — that is the whole design

Re-run it. After a failure, after a code change, after someone edits something in
the portal. Every resource is checked before it is created, and every setting is
converged rather than assumed:

| On a re-run | What happens |
|---|---|
| Resources | `show` first; create only what is missing. |
| `NPR_PROXY_SECRET`, `AUTH_SECRET` | Read back out of the deployed app and reused. Never regenerated. |
| `DATABASE_URL` | Recovered from the app's secret. Rebuilt only if it no longer points at this server — and *then* the admin password is reset, because Azure will not hand a password back. |
| Images | Skipped if the tag is already in the registry (`NPR_FORCE_BUILD=1` overrides). |
| Migration job | Re-run every time. All three steps are idempotent: `migrate.py` skips applied migrations, `seed_demo.py` rewrites the same deterministic fixtures, `precompute.py` persists the same snapshot id. |
| App templates | Converged from one source of truth. Container Apps only cuts a new revision when the template actually changed, so a no-op re-run is free. |

The image tag is the short commit sha, plus `-dirty-<timestamp>` when
`git status --porcelain` is not empty — so an uncommitted change can never
silently redeploy the previous image, and two dirty trees can never collide on
one tag.

---

## Configuration

Everything is an environment variable with a working default. The ones you are
most likely to touch:

| Variable | Default | What it does |
|---|---|---|
| `NPR_RESOURCE_GROUP` | `npr-demo-rg` | Target group. Changing it gives you a whole second environment. |
| `NPR_LOCATION` | `centralindia` | Region for everything. |
| `NPR_SUBSCRIPTION` | *(current)* | Selects the subscription before anything is created. |
| `NPR_MIN_REPLICAS` | `1` | `0` scales to zero — near-free when idle, at the price of cold starts (see *Cost*). |
| `NPR_IMAGE_TAG` | commit sha | Pin or roll back to a tag already in the registry. |
| `NPR_FORCE_BUILD` | `0` | Rebuild even when the tag exists. |
| `NPR_SKIP_MIGRATE` | `0` | Skip the migrate/seed job (you are certain the schema is current). |
| `NPR_ALLOW_CLIENT_IP` | `0` | `1` adds a Postgres firewall rule for your public IP — needed for the local-login admin bootstrap. |
| `NPR_PG_VERSION` | `16` | Drop to `15` if 16 is unavailable in your region. |
| `NPR_BACKEND_SCHEME` | `https` | `http` is the escape hatch if TLS on the internal FQDN misbehaves; traffic still never leaves the environment. |
| `NPR_YES` | `0` | `1` skips the "create the resource group?" confirmation (CI). |
| `NPR_ROLE_WAIT` | `30` | Seconds to wait for the `AcrPull` grant to propagate before the first pull. |

Optional passthrough, read from your shell and wired into the frontend if set:
`SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`, `SSO_ISSUER`, `SSO_RESOURCE`, `SSO_SCOPE`,
`SSO_SESSION_MAX_AGE`, `SSO_ROLE_MAP`, `SSO_POST_LOGOUT_REDIRECT_URI`,
`ADMIN_EMAIL`, `EMAIL_FROM`, `RESEND_API_KEY`, `AUTH_LOCAL_LOGIN`.

### Registry authentication — managed identity, with a fallback

The script creates a **user-assigned managed identity** (`npr-acr-pull`), grants
it `AcrPull` scoped to this registry, and attaches it to both apps and the job.
That is the better practice, and user-assigned rather than system-assigned for a
specific reason: a system identity does not exist until the app exists, so its
grant necessarily lands *after* the first image pull has been attempted. This one
exists before anything needs it.

Creating a role assignment needs `Microsoft.Authorization/roleAssignments/write`,
which sandbox subscriptions often withhold. If the grant fails the script says so
loudly, enables the ACR admin user, stores those credentials as a secret and
carries on — a real downgrade (one static credential, registry-wide, valid for
push as well as pull) that is reported in the final summary rather than hidden.
The warning includes the exact `az role assignment create` command for someone
with the rights; run it, re-run the deploy, and the script switches back.

### Migrations — a job, not an exec

`az containerapp exec` opens an interactive shell against a serving replica. It
needs a TTY, it competes with traffic, and — the disqualifier — **it does not
return the command's exit code**, so a failed migration and a successful one look
identical to a script. The job is a first-class resource with an execution
record, an exit status, its own logs and a retry limit, and it is re-runnable
from a runbook without redeploying anything:

```bash
az containerapp job start -n npr-migrate -g npr-demo-rg
az containerapp job execution list -n npr-migrate -g npr-demo-rg -o table
az containerapp job logs show -n npr-migrate -g npr-demo-rg --container migrate --format text
```

The deploy script polls it to completion and **refuses to deploy the apps if it
did not succeed** — shipping a console on top of a database whose schema was
never applied is the outcome worth preventing.

> The job's `command`/`args` are set through the YAML surface, not CLI flags,
> and that is not a style choice. `az containerapp job create --args "-c" "…"`
> fails with `ERROR: unrecognized arguments: -c` — argparse resolves the
> leading-dash token to an option rather than a value. Verified against
> azure-cli 2.90.0 / containerapp 1.3.0b5.

### Health probes

The backend gets **one liveness probe, on `/api/live`**, and no readiness probe.
Both halves of that are deliberate:

- `/api/health` is the readiness *and honesty* endpoint: it answers **503**
  whenever the database is unreachable, the active snapshot is missing, or the
  engine came back degraded. Pointing a restart-triggering probe at it turns a
  briefly-away Burstable database into an endless restart loop of a process that
  is working perfectly and that a restart cannot fix. `/api/live` touches nothing
  but the process itself, which is the question a liveness probe is actually
  asking.
- A **readiness** probe that fails during a rollout stops traffic ever shifting to
  the new revision — so a transient database blip during a deploy would present
  as a failed deploy. Not worth it here.

The frontend's liveness probe is `/`, which is a public route (`auth.config.ts`),
so it needs no session.

---

## Setting the AI provider key

The product runs end-to-end **without any model key** — explain, rank, classify
and report all have deterministic fallbacks, and that is the configuration you
get by default. To turn the advisory layer on:

```bash
OPENAI_API_KEY=sk-... bash scripts/azure/deploy.sh
# or
ANTHROPIC_API_KEY=sk-ant-... bash scripts/azure/deploy.sh
```

The key is stored as the `model-api-key` secret on the backend, referenced by
`secretref`, and never printed. `ADVISORY_PROVIDER` is pinned to match, and
`OPENAI_MODEL` / `ADVISORY_MODEL` are overridable the same way.

> **This sends data off the host.** With a key set, finding text, rule text and
> asset names go to the provider, and the header's AI residency chip reads
> *"Hosted — data leaves this host."* There is no Ollama in Container Apps, so
> the local-first configuration the README describes is not available here. That
> is a deliberate trade for a hosted demo; do not present it as the local-first
> posture.

To remove a key later, delete the secret and the env var — the deploy script
preserves an existing key on a re-run, so simply not passing it again does not
unset it:

```bash
az containerapp update -n npr-backend -g npr-demo-rg --remove-env-vars OPENAI_API_KEY ADVISORY_PROVIDER
az containerapp secret remove -n npr-backend -g npr-demo-rg --secret-names model-api-key
```

---

## Creating the first admin

A fresh database has no users, and the frontend fails closed: no session sends
you to `/login`, and a session with no recognised role sends you to `/no-access`.
There is no implicit `viewer`. Pick one of two paths.

**a. AutoX SSO (what a real deployment uses).** Register these two URLs in the
AutoX admin, byte for byte, *before* setting `SSO_CLIENT_ID`:

```
redirect URI          https://<frontend-fqdn>/api/auth/callback/autox
post-logout redirect  https://<frontend-fqdn>/login
```

then re-run the deploy with `SSO_CLIENT_ID` and `SSO_CLIENT_SECRET` set. Setting
`SSO_CLIENT_ID` turns SSO **on** and local password/magic-link login **off**.
Roles come from the `npr_admin` / `npr_analyst` / `npr_viewer` app roles; full
setup is in [SSO.md](SSO.md).

**b. Local login (fastest for a demo).** The bootstrap script is a Node script
that talks to Postgres directly, so it needs your IP through the firewall:

```bash
NPR_ALLOW_CLIENT_IP=1 bash scripts/azure/deploy.sh        # adds a rule for your public IP

export DATABASE_URL="$(az containerapp secret show -n npr-frontend -g npr-demo-rg \
  --secret-name database-url --query value -o tsv)"
node frontend/scripts/create-admin.mjs you@example.com    # prints a single-use sign-in link
```

Remove the rule when you are done:

```bash
az postgres flexible-server firewall-rule list -g npr-demo-rg -s <pg-server> -o table
az postgres flexible-server firewall-rule delete -g npr-demo-rg -s <pg-server> -n deployer-<your-ip>
```

---

## Verifying a deployment

```bash
FE=$(az containerapp show -n npr-frontend -g npr-demo-rg \
       --query properties.configuration.ingress.fqdn -o tsv)

curl -s "https://$FE/api/health" | head -c 400
```

Read it for three things:

| Field | Must be | If it is not |
|---|---|---|
| `"proxy_auth"` | `true` | **Stop.** The backend is trusting `x-npr-*` headers unconditionally. Re-run the deploy; it sets the same secret on both apps. |
| `"db"` | `true` | The connection string or the firewall rule is wrong. Check the migrate job's logs. |
| `"status"` | `"ok"` | `"degraded"` names its own reasons in `degraded_reasons`. A missing snapshot means the job did not run — start it by hand. |

`/api/health` is proxied through the frontend because that is the only way in:
the backend has no public address. There is no URL you can curl that reaches
FastAPI directly, which is the intended state.

```bash
az containerapp logs show -n npr-backend  -g npr-demo-rg --follow
az containerapp logs show -n npr-frontend -g npr-demo-rg --follow
az containerapp revision list -n npr-backend -g npr-demo-rg -o table
```

---

## Cost

List prices, `centralindia`, USD, at the time of writing. **Treat this as an
order of magnitude, not a quote** — the only number that matters is what Cost
Management shows after a week.

| Line | Assumption | Rough monthly |
|---|---|---|
| Container Apps | 1.5 vCPU + 3 GiB always allocated (`min-replicas 1`), mostly idle, minus the monthly free grant | **$30–45** |
| PostgreSQL B1ms | 1 vCore burstable + 32 GB storage + backups | **$18–22** |
| Container Registry | Basic | **$5** |
| Log Analytics | two low-traffic containers | **$0–8** |
| | | **≈ $55–80 / month** |

Two levers:

- **`NPR_MIN_REPLICAS=0`** drops the Container Apps line to roughly the cost of
  the requests you actually make. The price is a cold start on the first request
  after idle — and the backend rebuilds its deterministic engine on startup, so
  that first page is slow *and* `/api/health` is honestly degraded for a few
  seconds. Fine for a link you send occasionally; wrong for a live demo.
- **`bash scripts/azure/teardown.sh`** between demos. The script is idempotent,
  so standing it back up is one command and ~25 minutes.

Container Apps' consumption plan bills idle replicas at a much lower rate than
active ones, which is why an always-on demo is affordable at all. The Postgres
server is the one line that bills the same whether or not anyone visits.

---

## Teardown

```bash
bash scripts/azure/teardown.sh
```

It prints the group's actual inventory, spells out what is lost, and asks you to
**type the resource group name** — not press `y`, because the gesture has to be
proportional to deleting a database and its backups. `NPR_FORCE_TEARDOWN=1`
skips the prompt for CI; it is deliberately *not* the same variable as the deploy
script's `NPR_YES`, so a variable left exported in a shell that was deploying can
never end up deleting.

This is irreversible. There is no soft delete for a resource group, and the
Postgres server's automated backups go with it.

---

## Troubleshooting

**The app shows `ImagePullBackOff` / `UNAUTHORIZED` right after the first deploy.**
The `AcrPull` role assignment had not propagated when the pull was attempted.
Wait a minute and restart the revision, or re-run the deploy with
`NPR_ROLE_WAIT=90`.

**Every page in the console 401s.** `NPR_PROXY_SECRET` differs between the two
apps. Confirm with `/api/health` (`proxy_auth`) and re-run the deploy — it reads
the existing value and writes it to both. Never set it by hand on one app only.

**The frontend's `/api/*` calls fail with a TLS error.** The internal FQDN's
certificate is not being trusted by the Node proxy. Re-run with
`NPR_BACKEND_SCHEME=http`: the last hop drops to HTTP but never leaves the
environment's private network. Say so in any security review rather than leaving
it undocumented.

**`ERROR: unrecognized arguments: -c`.** Someone converted the migration job's
`command`/`args` back to CLI flags. They have to go through `--yaml`; see
*Migrations* above.

**The migrate job fails on `db/migrate.py`.** Read its logs
(`az containerapp job logs show -n npr-migrate -g npr-demo-rg --container migrate
--format text`). Almost always the database is unreachable: check that the
`AllowAllAzureServices` firewall rule exists and that the connection string
carries `sslmode=require` — `require_secure_transport` is ON, so a connection
without it is refused outright.

**`az acr build` seems to hang before it starts.** It uploads the build context
first. The repo's `.dockerignore` excludes `node_modules`, `.venv` and `.git`; if
it is missing or has been edited, you are uploading ~500 MB.

**PostgreSQL 16 is not available in the region.** `NPR_PG_VERSION=15` and re-run;
the server is only created once, so this must be right the first time or the
server has to be deleted.

**The registry name is not available.** ACR names are global. `NPR_ACR_NAME=<something>`
and re-run.

**Deploying to the wrong subscription.** The script prints the subscription name
and id in its first five lines and asks before creating the resource group. If
that prompt has already gone by, `bash scripts/azure/teardown.sh` is the undo.

---

## What this deployment is not

Honest list of the distance between this and a production environment, separate
from the product's own 8 blockers:

- **No network isolation for the database.** Postgres is reachable from any
  Azure-hosted source (the `0.0.0.0` firewall rule), because Container Apps
  consumption workloads have no stable outbound IP. Production wants a VNet-
  integrated environment and a private endpoint. What stands in for it here: TLS
  is enforced server-side and the password is 28 random characters from a
  62-character alphabet.
- **The application connects as the Postgres server admin.** A least-privilege
  role that owns nothing and can only DML is a production requirement and is not
  set up here.
- **Secrets live in Container Apps, not Key Vault.** No rotation, no audit trail
  on access, and the values pass through `az` command lines at deploy time.
- **No custom domain, no WAF, no Front Door.** The public URL is the
  platform-generated `*.azurecontainerapps.io` name with its managed certificate.
- **No CI/CD.** Deploys happen from a laptop by running this script. There is no
  gate that stops a dirty working tree from reaching the demo — only a tag that
  makes it obvious afterwards.
- **Backups are the Postgres default (7 days, same region) and have never been
  restored.** An untested backup is a hypothesis.
- **Single region, single replica of everything.** No HA on the database
  (`Burstable` cannot do zone-redundant HA anyway), no multi-region anything.
- **Log retention is the workspace default** and nothing is alerting on anything.

None of that matters for a demo carrying seeded data. All of it matters before a
customer's export goes anywhere near it — and by then
[`PROD-READINESS-AUDIT-2.md`](PROD-READINESS-AUDIT-2.md) has to be closed out
first, because the infrastructure being sound would not make a silently wrong
answer any less wrong.

---

## Related

- [DEPLOY.md](DEPLOY.md) — the earlier Render + Vercel + Neon deployment, and the
  migration runner's contract (`db/migrate.py`), which is unchanged here.
- [SSO.md](SSO.md) — AutoX OIDC setup, app roles, and the role-mapping override.
- [PROD-READINESS-AUDIT-2.md](PROD-READINESS-AUDIT-2.md) — what is actually wrong
  with the product, in detail, with reproductions.
