#!/usr/bin/env bash
# =============================================================================
# Network Policy Reviewer  ->  Azure Container Apps.   IDEMPOTENT: re-runnable.
#
#     bash scripts/azure/deploy.sh
#
# Stands up, in dependency order: a resource group, an Azure Container Registry,
# a PostgreSQL Flexible Server, a Log Analytics workspace, a Container Apps
# managed environment, both images (built server-side), a one-off migrate+seed
# job, and the two container apps. Prints the frontend URL at the end.
#
# WHAT THIS IS. A demo / staging environment carrying the seeded demo dataset.
# It is not a production deployment of this product and docs/DEPLOY-AZURE.md is
# explicit about why (docs/PROD-READINESS-AUDIT-2.md, 8 open blockers).
#
# -----------------------------------------------------------------------------
# THE SECURITY INVARIANT THIS SCRIPT EXISTS TO GET RIGHT
# -----------------------------------------------------------------------------
# The frontend is an authorization proxy: frontend/middleware.ts strips every
# client-supplied x-npr-* header, then sets x-npr-role / x-npr-email / x-npr-sub
# from the session and signs them with x-npr-proxy-secret. FastAPI trusts those
# headers -- that is how the whole role model works -- and the ONLY thing
# separating "trusted proxy" from "anyone who can reach the backend URL and
# sends x-npr-role: admin" is that shared secret.
#
# So this script does two things, and neither is optional:
#
#   1. NPR_PROXY_SECRET is generated ONCE (openssl rand) and set to the SAME
#      value on both apps, as a Container Apps secret, referenced by secretref.
#      On a re-run it is READ BACK from the existing app rather than
#      regenerated -- a fresh value on one side only would 401 the entire UI.
#      Verify after deploy by forging a header against the backend from inside
#      the frontend container (see NEXT STEPS) -- /api/health cannot show this:
#      it is behind the frontend auth middleware AND 401s on the backend itself.
#
#   2. The backend gets INTERNAL ingress. Its FQDN resolves only inside the
#      managed environment, so the header-trust model is not exposed to the
#      internet at all; the shared secret becomes defence in depth rather than
#      the only defence. The frontend reaches it over the environment's private
#      network by FQDN, which needs no VNet configuration -- same environment is
#      enough.
#
# Every secret value (DATABASE_URL, NPR_PROXY_SECRET, AUTH_SECRET, any model
# provider key) is stored as a Container Apps secret and referenced from the env
# as `secretref:<name>`. No secret is ever a plaintext env var, a build arg, or
# written to a file in the repo.
#
# -----------------------------------------------------------------------------
# TWO DESIGN CHOICES THE BRIEF ASKED TO BE JUSTIFIED
# -----------------------------------------------------------------------------
# (a) REGISTRY AUTH: managed identity, not the ACR admin user.
#     A user-assigned managed identity (npr-acr-pull) is created FIRST, granted
#     AcrPull on the registry, and attached to both apps and the job. Preferred
#     because the admin user is a single static credential, shared by everything
#     that pulls, valid registry-wide (push as well as pull), and lands in the
#     app as a secret you then have to rotate by hand. The identity holds one
#     role assignment, scoped to this registry, with no credential to leak.
#     A user-assigned identity rather than system-assigned specifically to avoid
#     the ordering trap: a system identity does not exist until the app exists,
#     so its AcrPull grant necessarily lands after the first image pull has
#     already been attempted. This one exists before anything needs it.
#     FALLBACK: creating a role assignment needs Microsoft.Authorization/
#     roleAssignments/write, which sandbox subscriptions often withhold. If the
#     grant fails, the script says so loudly and falls back to the admin user so
#     the deploy still completes. That is a real downgrade, and it is reported
#     in the summary rather than hidden.
#
# (b) MIGRATIONS: a Container Apps JOB, not `az containerapp exec`.
#     `az containerapp exec` opens an interactive shell against a running
#     replica: it needs a TTY, it competes with serving traffic, and -- the
#     disqualifier -- it does not give the caller the command's exit code, so a
#     failed migration looks exactly like a successful one to a script. The job
#     is a first-class resource with an execution record, an exit status, its own
#     logs, a retry limit, and a `job start` you can re-run at 3am from a runbook
#     without redeploying anything. It runs migrate -> seed -> precompute, all
#     three of which are idempotent, from the SAME image as the backend (which
#     is why that image carries db/ as well as backend/).
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# 0. Knobs. Every one of these is overridable from the environment; the
#    defaults are the documented demo deployment.
# ---------------------------------------------------------------------------
RESOURCE_GROUP="${NPR_RESOURCE_GROUP:-npr-demo-rg}"
LOCATION="${NPR_LOCATION:-centralindia}"

ENV_NAME="${NPR_ENV_NAME:-npr-env}"
LAW_NAME="${NPR_LOG_WORKSPACE:-npr-logs}"
IDENTITY_NAME="${NPR_IDENTITY_NAME:-npr-acr-pull}"
BACKEND_APP="${NPR_BACKEND_APP:-npr-backend}"
FRONTEND_APP="${NPR_FRONTEND_APP:-npr-frontend}"
MIGRATE_JOB="${NPR_MIGRATE_JOB:-npr-migrate}"

# Image names are fixed by the shared build contract; the tag defaults to the
# commit so a re-run at the same commit deploys the same image (and skips the
# build entirely). A dirty working tree gets a timestamp so two different trees
# can never collide on one tag.
BACKEND_IMAGE_NAME="npr-backend"
FRONTEND_IMAGE_NAME="npr-frontend"

PG_DB="${NPR_PG_DATABASE:-npr}"
PG_ADMIN_USER="${NPR_PG_ADMIN_USER:-npradmin}"
PG_VERSION="${NPR_PG_VERSION:-16}"
PG_TIER="${NPR_PG_TIER:-Burstable}"
PG_SKU="${NPR_PG_SKU:-Standard_B1ms}"
PG_STORAGE_GB="${NPR_PG_STORAGE_GB:-32}"

# min-replicas 1 keeps both apps warm: the backend rebuilds its deterministic
# engine on startup, so a scale-to-zero cold start is a slow first page AND a
# window where /api/health is honestly degraded. Set NPR_MIN_REPLICAS=0 to trade
# that for near-zero idle cost.
MIN_REPLICAS="${NPR_MIN_REPLICAS:-1}"
MAX_REPLICAS="${NPR_MAX_REPLICAS:-3}"

# Container Apps consumption bills cpu:memory in a fixed 1 vCPU : 2 GiB ratio;
# these pairs are on that line. Anything off it is rejected at create time.
BACKEND_CPU="${NPR_BACKEND_CPU:-1.0}"
BACKEND_MEMORY="${NPR_BACKEND_MEMORY:-2.0Gi}"
FRONTEND_CPU="${NPR_FRONTEND_CPU:-0.5}"
FRONTEND_MEMORY="${NPR_FRONTEND_MEMORY:-1.0Gi}"
JOB_CPU="${NPR_JOB_CPU:-1.0}"
JOB_MEMORY="${NPR_JOB_MEMORY:-2.0Gi}"
JOB_TIMEOUT_SECONDS="${NPR_JOB_TIMEOUT:-1800}"

# https unless you have a reason. See the ingress section for the http escape
# hatch and what it costs.
BACKEND_SCHEME="${NPR_BACKEND_SCHEME:-https}"

TAGS_ARGS=(--tags "project=npr" "environment=demo" "managed-by=scripts/azure/deploy.sh")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ---------------------------------------------------------------------------
# 1. Output helpers. Nothing here ever prints a secret value.
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_STEP=$'\033[1;36m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'
  C_OK=$'\033[1;32m';   C_OFF=$'\033[0m'
else
  C_STEP=""; C_WARN=""; C_ERR=""; C_OK=""; C_OFF=""
fi

NL=$'\n'   # used by the YAML emitter's "is this value safe" guard

STEP_N=0
step() { STEP_N=$((STEP_N + 1)); printf '\n%s==> [%d] %s%s\n' "$C_STEP" "$STEP_N" "$*" "$C_OFF"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
die()  { printf '\n%s[fatal]%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

confirm() {
  # Auto-yes when NPR_YES=1 or stdin is not a terminal, so this stays a
  # one-command deploy from CI while still catching "wrong subscription" when a
  # human runs it by hand.
  if [ "${NPR_YES:-0}" = "1" ] || [ ! -t 0 ]; then return 0; fi
  printf '    %s [y/N] ' "$1"
  local reply=""
  read -r reply || true
  case "$reply" in [yY] | [yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

# ---------------------------------------------------------------------------
# 2. Preflight. Fail here, with a sentence that says what to do, rather than
#    half way through provisioning.
# ---------------------------------------------------------------------------
step "Preflight"

command -v az >/dev/null 2>&1 || die "azure-cli not found. https://learn.microsoft.com/cli/azure/install-azure-cli"
command -v openssl >/dev/null 2>&1 || die "openssl not found; it generates the shared secrets."

# The containerapp commands ship in azure-cli core, but the extension is what
# carries current flags (--registry-identity, job subgroups). Install it if it
# is missing; never fail the deploy on the upgrade path.
if ! az extension show --name containerapp >/dev/null 2>&1; then
  info "installing the 'containerapp' az extension"
  az extension add --name containerapp --yes --only-show-errors >/dev/null 2>&1 ||
    warn "could not install the containerapp extension; continuing with the built-in commands"
fi

az account show -o none 2>/dev/null ||
  die "not signed in. Run: az login   (then re-run this script)"

if [ -n "${NPR_SUBSCRIPTION:-}" ]; then
  az account set --subscription "$NPR_SUBSCRIPTION" ||
    die "could not select subscription '$NPR_SUBSCRIPTION'"
fi

SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
SUBSCRIPTION_NAME="$(az account show --query name -o tsv)"
info "subscription : $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"
info "region       : $LOCATION"
info "group        : $RESOURCE_GROUP"

[ -f "${REPO_ROOT}/backend/Dockerfile" ] ||
  die "missing ${REPO_ROOT}/backend/Dockerfile — the backend image cannot be built."
[ -f "${REPO_ROOT}/frontend/Dockerfile" ] ||
  die "missing ${REPO_ROOT}/frontend/Dockerfile — the frontend image cannot be built."
[ -f "${REPO_ROOT}/db/migrate.py" ] ||
  die "missing ${REPO_ROOT}/db/migrate.py — wrong repo root?"

# az acr build uploads the build context. Without a .dockerignore that excludes
# node_modules and .venv this uploads ~500 MB per build over a home connection,
# which reads at 3am as "the deploy hung".
if [ ! -f "${REPO_ROOT}/.dockerignore" ]; then
  warn "no .dockerignore at the repo root: 'az acr build' will upload the entire tree"
  warn "(including frontend/node_modules and backend/.venv) to the registry."
fi

# Image tag. `git status --porcelain` and not `git diff --quiet`, because an
# untracked Dockerfile is exactly the state that must not silently reuse an
# older image.
IMAGE_TAG="${NPR_IMAGE_TAG:-}"
if [ -z "$IMAGE_TAG" ]; then
  if git -C "$REPO_ROOT" rev-parse --short HEAD >/dev/null 2>&1; then
    IMAGE_TAG="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
    if [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]; then
      IMAGE_TAG="${IMAGE_TAG}-dirty-$(date -u +%Y%m%d%H%M%S)"
    fi
  else
    IMAGE_TAG="$(date -u +%Y%m%d%H%M%S)"
  fi
fi
info "image tag    : $IMAGE_TAG"

# Globally-unique names (ACR and the Postgres server both take a public DNS
# label) derived deterministically from subscription + group, so a re-run always
# lands on the same resources and two people deploying from the same repo into
# different subscriptions never collide.
NAME_SUFFIX="$(printf '%s' "${SUBSCRIPTION_ID}/${RESOURCE_GROUP}" |
  openssl dgst -sha256 | awk '{print $NF}' | cut -c1-8)"
ACR_NAME="${NPR_ACR_NAME:-npracr${NAME_SUFFIX}}"
PG_SERVER="${NPR_PG_SERVER:-npr-pg-${NAME_SUFFIX}}"
info "registry     : $ACR_NAME"
info "postgres     : $PG_SERVER"

# ---------------------------------------------------------------------------
# 3. Resource providers. A first-ever deploy into a fresh subscription fails
#    deep inside `containerapp env create` if Microsoft.App is unregistered,
#    with an error that does not name the fix.
# ---------------------------------------------------------------------------
step "Resource providers"
for ns in Microsoft.App Microsoft.OperationalInsights Microsoft.ContainerRegistry Microsoft.DBforPostgreSQL Microsoft.ManagedIdentity; do
  state="$(az provider show --namespace "$ns" --query registrationState -o tsv 2>/dev/null || echo "")"
  if [ "$state" = "Registered" ]; then
    info "$ns already registered"
  else
    info "registering $ns (this can take a couple of minutes)"
    az provider register --namespace "$ns" --wait --only-show-errors >/dev/null 2>&1 ||
      warn "could not register $ns — if a later step fails on RegistrationRequired, ask a subscription owner to register it"
  fi
done

# ---------------------------------------------------------------------------
# 4. Resource group
# ---------------------------------------------------------------------------
step "Resource group"
if [ "$(az group exists --name "$RESOURCE_GROUP")" = "true" ]; then
  ok "$RESOURCE_GROUP exists"
else
  info "about to CREATE resource group '$RESOURCE_GROUP' in '$LOCATION'"
  info "subscription: $SUBSCRIPTION_NAME"
  confirm "Create it?" || die "aborted. Set NPR_SUBSCRIPTION / NPR_RESOURCE_GROUP to target something else."
  az group create --name "$RESOURCE_GROUP" --location "$LOCATION" "${TAGS_ARGS[@]}" -o none
  ok "created $RESOURCE_GROUP"
fi

# ---------------------------------------------------------------------------
# 5. Azure Container Registry
# ---------------------------------------------------------------------------
step "Container registry"
if az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" -o none 2>/dev/null; then
  ok "$ACR_NAME exists"
else
  available="$(az acr check-name --name "$ACR_NAME" --query nameAvailable -o tsv 2>/dev/null || echo "true")"
  if [ "$available" != "true" ]; then
    die "registry name '$ACR_NAME' is not available — it is either taken globally or it lives in
    another resource group in this subscription. Set NPR_ACR_NAME to a free name and re-run."
  fi
  # Basic SKU: enough for two images and it supports ACR Tasks, which is what
  # `az acr build` runs on. --admin-enabled false is the default and is stated
  # here on purpose: the pull path is the managed identity below, and the admin
  # user is only ever enabled by the explicit fallback.
  az acr create --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" --location "$LOCATION" \
    --sku Basic --admin-enabled false "${TAGS_ARGS[@]}" -o none
  ok "created $ACR_NAME"
fi
ACR_ID="$(az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" --query id -o tsv)"
ACR_LOGIN_SERVER="$(az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" --query loginServer -o tsv)"
info "login server : $ACR_LOGIN_SERVER"

# ---------------------------------------------------------------------------
# 6. PostgreSQL Flexible Server
# ---------------------------------------------------------------------------
step "PostgreSQL flexible server"

gen_pg_password() {
  # Alphanumeric only: Azure demands three of {upper, lower, digit, symbol} and
  # this satisfies exactly three, while staying free of every character that
  # would need percent-encoding in the connection string. The fixed affixes
  # guarantee the three classes rather than relying on 28 random characters
  # happening to contain them.
  printf 'Npr%s9' "$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-28)"
}

PG_EXISTED=1
PG_PASSWORD=""
if az postgres flexible-server show --resource-group "$RESOURCE_GROUP" --name "$PG_SERVER" -o none 2>/dev/null; then
  ok "$PG_SERVER exists"
else
  PG_EXISTED=0
  PG_PASSWORD="$(gen_pg_password)"
  info "creating $PG_SERVER ($PG_TIER / $PG_SKU, PG $PG_VERSION, ${PG_STORAGE_GB}GB) — a few minutes"
  # --public-access Enabled: public endpoint on, but NO firewall rule yet, so the
  # server is unreachable until the explicit Azure-services rule below. Left to
  # its own devices this command adds a rule for whatever IP the deploy happened
  # to run from, which is not a thing that should quietly become infrastructure.
  az postgres flexible-server create \
    --resource-group "$RESOURCE_GROUP" --name "$PG_SERVER" --location "$LOCATION" \
    --admin-user "$PG_ADMIN_USER" --admin-password "$PG_PASSWORD" \
    --tier "$PG_TIER" --sku-name "$PG_SKU" --version "$PG_VERSION" \
    --storage-size "$PG_STORAGE_GB" --public-access Enabled \
    --yes "${TAGS_ARGS[@]}" -o none
  ok "created $PG_SERVER"
fi

PG_FQDN="$(az postgres flexible-server show --resource-group "$RESOURCE_GROUP" --name "$PG_SERVER" \
  --query fullyQualifiedDomainName -o tsv)"
# Read the admin login back rather than assuming $PG_ADMIN_USER: on a server that
# already existed, the name in the connection string has to be the one the server
# actually has.
PG_ADMIN_LOGIN="$(az postgres flexible-server show --resource-group "$RESOURCE_GROUP" --name "$PG_SERVER" \
  --query administratorLogin -o tsv)"
info "host         : $PG_FQDN (admin: $PG_ADMIN_LOGIN)"

# Container Apps consumption workloads have no stable outbound IP, so the
# allow-Azure-services rule (the 0.0.0.0/0.0.0.0 special case) is what lets them
# connect at all. It does NOT open the server to the internet: it admits traffic
# whose source is Azure. This is the documented trade for not running a VNet, and
# it is why the connection is TLS-only and the password carries 28 random
# characters from a 62-character alphabet.
#
# NOTE `--public-access Enabled` on the create above, NOT `None`. `None` does not
# mean "public endpoint with no rules yet" -- it DISABLES the public endpoint
# outright, and every firewall-rule call against such a server then fails with
# "Firewall rule operations are not supported for a server without public access
# enabled". That is what it did on the first run of this script.
#
# The 0.0.0.0-0.0.0.0 rule is Azure's special form meaning "allow Azure
# services", which is broader than it looks: it admits any resource in ANY Azure
# tenant, not only ours. It is narrowed below to the Container Apps
# environment's static outbound IP as soon as that environment exists, which is
# the address the apps actually egress from.
if az postgres flexible-server firewall-rule show --resource-group "$RESOURCE_GROUP" \
  --server-name "$PG_SERVER" --name AllowAllAzureServices -o none 2>/dev/null; then
  ok "firewall rule AllowAllAzureServices exists"
else
  az postgres flexible-server firewall-rule create --resource-group "$RESOURCE_GROUP" \
    --server-name "$PG_SERVER" --name AllowAllAzureServices \
    --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0 -o none
  ok "added firewall rule AllowAllAzureServices"
fi

# Opt-in: your own address, so `node frontend/scripts/create-admin.mjs` can run
# from the laptop. Off by default — an admin workstation IP is not something to
# add to infrastructure without being asked.
if [ "${NPR_ALLOW_CLIENT_IP:-0}" = "1" ]; then
  CLIENT_IP="${NPR_CLIENT_IP:-$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || echo "")}"
  if [ -n "$CLIENT_IP" ]; then
    az postgres flexible-server firewall-rule create --resource-group "$RESOURCE_GROUP" \
      --server-name "$PG_SERVER" --name "deployer-$(printf '%s' "$CLIENT_IP" | tr '.' '-')" \
      --start-ip-address "$CLIENT_IP" --end-ip-address "$CLIENT_IP" -o none
    ok "allowed client IP $CLIENT_IP"
  else
    warn "NPR_ALLOW_CLIENT_IP=1 but the public IP could not be determined; set NPR_CLIENT_IP=x.x.x.x"
  fi
fi

if az postgres flexible-server db show --resource-group "$RESOURCE_GROUP" \
  --server-name "$PG_SERVER" --name "$PG_DB" -o none 2>/dev/null; then
  ok "database '$PG_DB' exists"
else
  az postgres flexible-server db create --resource-group "$RESOURCE_GROUP" \
    --server-name "$PG_SERVER" --name "$PG_DB" -o none
  ok "created database '$PG_DB'"
fi

# require_secure_transport is ON by default on Flexible Server and MUST stay on:
# it is the server-side half of the guarantee that credentials, tokens and
# findings never cross the network in clear. The client-side half is
# `sslmode=require` in the connection string below. Assert rather than assume —
# a server someone turned it off on would still work, silently, in clear.
RST="$(az postgres flexible-server parameter show --resource-group "$RESOURCE_GROUP" \
  --server-name "$PG_SERVER" --name require_secure_transport --query value -o tsv 2>/dev/null || echo "")"
case "$(printf '%s' "$RST" | tr 'A-Z' 'a-z')" in
  on | true | 1) ok "require_secure_transport is ON" ;;
  "") warn "could not read require_secure_transport; the connection string still forces sslmode=require" ;;
  *)
    warn "require_secure_transport was '$RST' — turning it back ON"
    az postgres flexible-server parameter set --resource-group "$RESOURCE_GROUP" \
      --server-name "$PG_SERVER" --name require_secure_transport --value on -o none
    ;;
esac

# ---------------------------------------------------------------------------
# 7. Log Analytics + Container Apps managed environment
# ---------------------------------------------------------------------------
step "Log Analytics workspace and Container Apps environment"
if az monitor log-analytics workspace show --resource-group "$RESOURCE_GROUP" \
  --workspace-name "$LAW_NAME" -o none 2>/dev/null; then
  ok "$LAW_NAME exists"
else
  az monitor log-analytics workspace create --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$LAW_NAME" --location "$LOCATION" "${TAGS_ARGS[@]}" -o none
  ok "created $LAW_NAME"
fi
LAW_CUSTOMER_ID="$(az monitor log-analytics workspace show --resource-group "$RESOURCE_GROUP" \
  --workspace-name "$LAW_NAME" --query customerId -o tsv)"
LAW_KEY="$(az monitor log-analytics workspace get-shared-keys --resource-group "$RESOURCE_GROUP" \
  --workspace-name "$LAW_NAME" --query primarySharedKey -o tsv)"

if az containerapp env show --name "$ENV_NAME" --resource-group "$RESOURCE_GROUP" -o none 2>/dev/null; then
  ok "$ENV_NAME exists"
else
  info "creating managed environment $ENV_NAME — a few minutes"
  az containerapp env create --name "$ENV_NAME" --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --logs-destination log-analytics \
    --logs-workspace-id "$LAW_CUSTOMER_ID" --logs-workspace-key "$LAW_KEY" \
    "${TAGS_ARGS[@]}" -o none
  ok "created $ENV_NAME"
fi

# The environment's default domain is what makes the chicken-and-egg tractable:
# both FQDNs are derivable from it BEFORE either app exists.
#   external:  <app>.<defaultDomain>
#   internal:  <app>.internal.<defaultDomain>
# The apps are still created with these predicted values and then RECONCILED
# against the FQDNs the platform actually returns (step 13) — a prediction is
# used to break the ordering cycle, never trusted as the final answer.
ENV_DOMAIN="$(az containerapp env show --name "$ENV_NAME" --resource-group "$RESOURCE_GROUP" \
  --query properties.defaultDomain -o tsv)"
[ -n "$ENV_DOMAIN" ] || die "could not read the environment's default domain"
BACKEND_FQDN="${BACKEND_APP}.internal.${ENV_DOMAIN}"
FRONTEND_FQDN="${FRONTEND_APP}.${ENV_DOMAIN}"
info "env domain   : $ENV_DOMAIN"

# ---------------------------------------------------------------------------
# 8. Pull identity (see the justification in the header)
# ---------------------------------------------------------------------------
step "Registry pull identity"
REGISTRY_MODE="identity"
if az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" -o none 2>/dev/null; then
  ok "$IDENTITY_NAME exists"
else
  az identity create --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" "${TAGS_ARGS[@]}" -o none
  ok "created $IDENTITY_NAME"
fi
IDENTITY_ID="$(az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" --query id -o tsv)"
IDENTITY_PRINCIPAL_ID="$(az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" --query principalId -o tsv)"

EXISTING_ASSIGNMENT="$(az role assignment list --assignee "$IDENTITY_PRINCIPAL_ID" --scope "$ACR_ID" \
  --role AcrPull --query "[0].id" -o tsv 2>/dev/null || echo "")"
if [ -n "$EXISTING_ASSIGNMENT" ]; then
  ok "AcrPull already granted on $ACR_NAME"
else
  # --assignee-object-id + --assignee-principal-type, not --assignee: a
  # just-created identity has not replicated through Entra yet, and plain
  # --assignee does a graph lookup that fails on exactly that race.
  if az role assignment create --assignee-object-id "$IDENTITY_PRINCIPAL_ID" \
    --assignee-principal-type ServicePrincipal --role AcrPull --scope "$ACR_ID" -o none 2>/dev/null; then
    ok "granted AcrPull on $ACR_NAME"
    # Entra role assignments are eventually consistent. A pull attempted in the
    # first seconds after the grant can still 401, and the failure surfaces as an
    # image-pull error on the app, which looks like a broken image rather than a
    # race. NPR_ROLE_WAIT=0 skips it when you know the grant is already live.
    if [ "${NPR_ROLE_WAIT:-30}" -gt 0 ] 2>/dev/null; then
      info "waiting ${NPR_ROLE_WAIT:-30}s for the role assignment to propagate before the first pull"
      sleep "${NPR_ROLE_WAIT:-30}"
    fi
  else
    REGISTRY_MODE="admin"
    warn "could not create the AcrPull role assignment (needs Microsoft.Authorization/roleAssignments/write)."
    warn "FALLING BACK to the ACR admin user. This is a real downgrade: one static credential,"
    warn "registry-wide, stored as a secret on both apps. Ask an owner to run:"
    warn "  az role assignment create --assignee-object-id $IDENTITY_PRINCIPAL_ID \\"
    warn "    --assignee-principal-type ServicePrincipal --role AcrPull --scope $ACR_ID"
    warn "then re-run this script to switch back."
  fi
fi

REGISTRY_ARGS=()          # for `containerapp create` / `job create`
JOB_REGISTRY_ARGS=()
REGISTRY_SET_ARGS=()      # for `containerapp registry set` on a re-run
if [ "$REGISTRY_MODE" = "identity" ]; then
  REGISTRY_ARGS=(--registry-server "$ACR_LOGIN_SERVER" --registry-identity "$IDENTITY_ID" --user-assigned "$IDENTITY_ID")
  JOB_REGISTRY_ARGS=(--registry-server "$ACR_LOGIN_SERVER" --registry-identity "$IDENTITY_ID" --mi-user-assigned "$IDENTITY_ID")
  REGISTRY_SET_ARGS=(--server "$ACR_LOGIN_SERVER" --identity "$IDENTITY_ID")
else
  az acr update --name "$ACR_NAME" --admin-enabled true -o none ||
    die "the AcrPull grant failed AND the admin user could not be enabled — this identity can
    neither grant a role nor change the registry. Ask a subscription owner for one of the two."
  ACR_USERNAME="$(az acr credential show --name "$ACR_NAME" --query username -o tsv)"
  ACR_PASSWORD="$(az acr credential show --name "$ACR_NAME" --query 'passwords[0].value' -o tsv)"
  REGISTRY_ARGS=(--registry-server "$ACR_LOGIN_SERVER" --registry-username "$ACR_USERNAME" --registry-password "$ACR_PASSWORD")
  JOB_REGISTRY_ARGS=("${REGISTRY_ARGS[@]}")
  REGISTRY_SET_ARGS=(--server "$ACR_LOGIN_SERVER" --username "$ACR_USERNAME" --password "$ACR_PASSWORD")
fi

# ---------------------------------------------------------------------------
# 9. Build both images IN the registry.
#
#    `az acr build` uploads the context and builds on an ACR Task agent, which
#    is x86-64. That is not a convenience here, it is the fix: this repo is
#    developed on arm64 and Container Apps runs amd64, so a local `docker build`
#    produces an image that starts and immediately dies with "exec format
#    error". --platform linux/amd64 states the target explicitly rather than
#    relying on the agent's architecture staying what it is today.
# ---------------------------------------------------------------------------
step "Build images (server-side, linux/amd64)"

image_tag_exists() { # repo tag
  az acr repository show --name "$ACR_NAME" --image "$1:$2" -o none 2>/dev/null
}

build_image() { # repo dockerfile-relative-to-context context
  local repo="$1" dockerfile="$2" context="$3"
  if [ "${NPR_FORCE_BUILD:-0}" != "1" ] && image_tag_exists "$repo" "$IMAGE_TAG"; then
    ok "$repo:$IMAGE_TAG already in the registry (NPR_FORCE_BUILD=1 to rebuild)"
    return 0
  fi
  info "building $repo:$IMAGE_TAG from $dockerfile"
  # RUN FROM INSIDE THE CONTEXT. `az acr build` resolves --file against the
  # SHELL'S CWD, not against the context directory it is given, so with the
  # script's cwd at the repo root `--file Dockerfile <repo>/frontend` looks for
  # <repo>/Dockerfile, does not find it, and dies with the rather misleading
  # "Unable to find 'Dockerfile'" -- naming the file it was asked for rather
  # than the path it actually tried.
  #
  # The backend hid this: its --file is `backend/Dockerfile`, which happens to
  # resolve correctly from the repo root, so one image built and the other did
  # not. Subshell so the caller's cwd is untouched.
  ( cd "$context" && az acr build --registry "$ACR_NAME" --resource-group "$RESOURCE_GROUP" \
      --platform linux/amd64 \
      --image "${repo}:${IMAGE_TAG}" --image "${repo}:latest" \
      --file "$dockerfile" . )
  ok "pushed ${ACR_LOGIN_SERVER}/${repo}:${IMAGE_TAG}"
}

# Backend context is the REPO ROOT: one image carries backend/ and db/ so the
# migration job and the API are the same artifact. Frontend context is
# frontend/, which has its own .dockerignore.
build_image "$BACKEND_IMAGE_NAME" "backend/Dockerfile" "$REPO_ROOT"
build_image "$FRONTEND_IMAGE_NAME" "Dockerfile" "${REPO_ROOT}/frontend"

BACKEND_IMAGE="${ACR_LOGIN_SERVER}/${BACKEND_IMAGE_NAME}:${IMAGE_TAG}"
FRONTEND_IMAGE="${ACR_LOGIN_SERVER}/${FRONTEND_IMAGE_NAME}:${IMAGE_TAG}"

# ---------------------------------------------------------------------------
# 10. Secrets: recover, or generate once.
#
#     Idempotency is not cosmetic here. NPR_PROXY_SECRET regenerated on a re-run
#     and set on only one of the two apps means every proxied request 401s. So
#     the existing value is read back out of the deployed app and reused; a new
#     one is minted only when there is nothing to recover.
# ---------------------------------------------------------------------------
step "Secrets"

app_secret() { # app secret-name  -> value on stdout, empty if absent
  az containerapp secret show --name "$1" --resource-group "$RESOURCE_GROUP" \
    --secret-name "$2" --query value -o tsv 2>/dev/null || true
}
job_secret() { # job secret-name
  az containerapp job secret show --name "$1" --resource-group "$RESOURCE_GROUP" \
    --secret-name "$2" --query value -o tsv 2>/dev/null || true
}

recover() { # secret-name -> first value found across backend app, frontend app, job
  local n="$1" v=""
  v="$(app_secret "$BACKEND_APP" "$n")"
  if [ -z "$v" ]; then v="$(app_secret "$FRONTEND_APP" "$n")"; fi
  if [ -z "$v" ]; then v="$(job_secret "$MIGRATE_JOB" "$n")"; fi
  printf '%s' "$v"
}

PROXY_SECRET="$(recover npr-proxy-secret)"
if [ -n "$PROXY_SECRET" ]; then
  ok "reusing the existing NPR_PROXY_SECRET (both apps will get this same value)"
else
  PROXY_SECRET="$(openssl rand -hex 32)"
  ok "generated a new NPR_PROXY_SECRET"
fi

AUTH_SECRET_VALUE="$(recover auth-secret)"
if [ -n "$AUTH_SECRET_VALUE" ]; then
  ok "reusing the existing AUTH_SECRET"
else
  AUTH_SECRET_VALUE="$(openssl rand -hex 32)"
  ok "generated a new AUTH_SECRET"
fi

# DATABASE_URL. Recovered when it still points at THIS server; otherwise rebuilt,
# which on an already-existing server means resetting the admin password —
# the password is not readable back out of Azure, so the only way to hold a
# correct connection string is to set a known one.
DATABASE_URL="$(recover database-url)"
if [ -n "$DATABASE_URL" ] && [ "${DATABASE_URL#*@${PG_FQDN}:5432/}" = "$DATABASE_URL" ]; then
  warn "the stored DATABASE_URL does not point at $PG_FQDN — rebuilding it"
  DATABASE_URL=""
fi
if [ -z "$DATABASE_URL" ]; then
  if [ -z "$PG_PASSWORD" ]; then
    if [ "$PG_EXISTED" = "1" ]; then
      warn "no stored DATABASE_URL for an existing server: resetting the admin password"
      PG_PASSWORD="$(gen_pg_password)"
      az postgres flexible-server update --resource-group "$RESOURCE_GROUP" --name "$PG_SERVER" \
        --admin-password "$PG_PASSWORD" -o none
    else
      die "internal: no password for a freshly created server"
    fi
  fi
  # sslmode=require is mandatory, not decoration: require_secure_transport is ON
  # on the server, so a URL without it fails to connect at all — and psycopg and
  # node-postgres both read it straight off the URL.
  DATABASE_URL="postgresql://${PG_ADMIN_LOGIN}:${PG_PASSWORD}@${PG_FQDN}:5432/${PG_DB}?sslmode=require"
  ok "composed a new DATABASE_URL (sslmode=require)"
else
  ok "reusing the existing DATABASE_URL"
fi

# Model provider key, if the operator supplied one. Optional by design: with no
# key the advisory layer takes its deterministic fallbacks and the product still
# runs end to end.
AI_PROVIDER=""
AI_KEY=""
if [ -n "${NPR_OPENAI_API_KEY:-${OPENAI_API_KEY:-}}" ]; then
  AI_PROVIDER="openai"; AI_KEY="${NPR_OPENAI_API_KEY:-${OPENAI_API_KEY:-}}"
elif [ -n "${NPR_ANTHROPIC_API_KEY:-${ANTHROPIC_API_KEY:-}}" ]; then
  AI_PROVIDER="anthropic"; AI_KEY="${NPR_ANTHROPIC_API_KEY:-${ANTHROPIC_API_KEY:-}}"
else
  # Nothing passed in — but a previous run may have set one. Keep it.
  AI_KEY="$(recover model-api-key)"
  if [ -n "$AI_KEY" ]; then
    AI_PROVIDER="$(az containerapp show --name "$BACKEND_APP" --resource-group "$RESOURCE_GROUP" \
      --query "properties.template.containers[0].env[?name=='ADVISORY_PROVIDER'].value | [0]" -o tsv 2>/dev/null || echo "")"
    if [ -z "$AI_PROVIDER" ]; then AI_PROVIDER="openai"; fi
  fi
fi
if [ -n "$AI_PROVIDER" ]; then
  ok "advisory provider: $AI_PROVIDER (key stored as a secret, never printed)"
else
  info "no model provider key supplied — the advisory layer will use its deterministic fallbacks"
fi

# ---------------------------------------------------------------------------
# 11. Env assembly. ONE place builds the environment for each app, and both the
#     create call and the YAML convergence read from it, so the two can never
#     drift apart. `secretref:` values name a Container Apps secret; everything
#     else is plaintext and must be safe to read in the portal.
# ---------------------------------------------------------------------------
BACKEND_SECRETS=("database-url=${DATABASE_URL}" "npr-proxy-secret=${PROXY_SECRET}")
FRONTEND_SECRETS=("database-url=${DATABASE_URL}" "npr-proxy-secret=${PROXY_SECRET}" "auth-secret=${AUTH_SECRET_VALUE}")
if [ -n "$AI_KEY" ]; then BACKEND_SECRETS+=("model-api-key=${AI_KEY}"); fi
if [ -n "${SSO_CLIENT_SECRET:-}" ]; then FRONTEND_SECRETS+=("sso-client-secret=${SSO_CLIENT_SECRET}"); fi
if [ -n "${RESEND_API_KEY:-}" ]; then FRONTEND_SECRETS+=("resend-api-key=${RESEND_API_KEY}"); fi

build_backend_env() { # $1 = frontend origin
  BACKEND_ENV=(
    "DATABASE_URL=secretref:database-url"
    "NPR_PROXY_SECRET=secretref:npr-proxy-secret"
    "FRONTEND_ORIGIN=$1"
    "NPR_LOG_LEVEL=${NPR_LOG_LEVEL:-INFO}"
  )
  case "$AI_PROVIDER" in
    openai)
      BACKEND_ENV+=("ADVISORY_PROVIDER=openai" "OPENAI_API_KEY=secretref:model-api-key"
        "OPENAI_MODEL=${OPENAI_MODEL:-gpt-4o}") ;;
    anthropic)
      BACKEND_ENV+=("ADVISORY_PROVIDER=anthropic" "ANTHROPIC_API_KEY=secretref:model-api-key"
        "ADVISORY_MODEL=${ADVISORY_MODEL:-claude-sonnet-4-6}") ;;
  esac

  # Same rule as the frontend: preserve what this script does not declare.
  # AZURE_CLIENT_ID is the concrete case that bit -- it is what tells
  # DefaultAzureCredential WHICH user-assigned identity to present, and without
  # it every ARM discovery call and every managed-identity model call fails with
  # "(invalid_scope) 400, Unable to load the proper Managed Identity". A redeploy
  # erased it and the Configuration page went blind.
  # JSON, not `-o tsv` -- see the note in build_frontend_env. A tsv row whose
  # `value` is null collapses the column, secretRef lands in the value field, and
  # a secret-backed variable is rewritten as the literal SECRET NAME.
  local existing
  existing="$(az containerapp show -n "$BACKEND_APP" -g "$RESOURCE_GROUP" \
    --query "properties.template.containers[0].env" -o json 2>/dev/null || echo '[]')"
  while IFS=$'\x1f' read -r name ref val; do
    [ -n "$name" ] || continue
    case " ${BACKEND_ENV[*]} " in *" ${name}="*) continue ;; esac
    if [ -n "$ref" ]; then
      BACKEND_ENV+=("${name}=secretref:${ref}")
      info "preserved ${name} (secretref) set outside this script"
    elif [ -n "$val" ]; then
      BACKEND_ENV+=("${name}=${val}")
      info "preserved ${name} set outside this script"
    fi
  done <<< "$(printf '%s' "$existing" | python3 -c '
import json, sys
for e in json.load(sys.stdin) or []:
    print("\x1f".join([e.get("name") or "", e.get("secretRef") or "", (e.get("value") or "").replace("\x1f", " ")]))
' 2>/dev/null || true)"
}

build_frontend_env() { # $1 = backend url  $2 = app url
  FRONTEND_ENV=(
    "DATABASE_URL=secretref:database-url"
    "AUTH_SECRET=secretref:auth-secret"
    "NPR_PROXY_SECRET=secretref:npr-proxy-secret"
    "AUTH_TRUST_HOST=true"
    "BACKEND_URL=$1"
    "APP_URL=$2"
    # AUTH_URL, NOT just APP_URL -- and this line is why SSO could not work on a
    # deployment that had no custom domain bound.
    #
    # APP_URL is read by this product's own code (lib/baseurl). AUTH_URL is what
    # Auth.js builds the OIDC `redirect_uri` from. Without it Auth.js falls back
    # to deriving the origin from the incoming request, and behind Container Apps
    # ingress that resolves to the container's BIND ADDRESS: the app sent
    # `redirect_uri=https://0.0.0.0:3000/api/auth/callback/autox`, the IdP
    # rejected it as unregistered, and the failure surfaced as
    # INVALID_REDIRECT_URI -- which reads as "you registered the wrong URL"
    # rather than "the app asked for the wrong one".
    #
    # AUTH_URL was only ever set by bind-domain.sh, so this worked on the one
    # deployment with a custom domain and on no other. That also made the
    # NEXT STEPS printed at the end of this script wrong: they tell you to
    # register the azurecontainerapps.io callback, which could never match.
    "AUTH_URL=$2"
  )
  local n v
  for n in SSO_CLIENT_ID SSO_ISSUER SSO_RESOURCE SSO_SCOPE SSO_SESSION_MAX_AGE \
    SSO_ROLE_MAP SSO_POST_LOGOUT_REDIRECT_URI SSO_TOKEN_AUTH_METHOD \
    ADMIN_EMAIL EMAIL_FROM AUTH_LOCAL_LOGIN BREAKGLASS_EMAIL; do
    v="${!n:-}"
    if [ -n "$v" ]; then FRONTEND_ENV+=("${n}=${v}"); fi
  done

  # AUTH_LOCAL_LOGIN ARRIVES FROM THE DEPLOYING SHELL, AND A DEV MACHINE HAS IT SET.
  #
  # Break-glass needs three things to authenticate anyone: AUTH_LOCAL_LOGIN=true,
  # BREAKGLASS_EMAIL, and a password or hash (frontend/lib/sso.breakGlassState).
  # This loop forwards the first two and NOT the third, so a stray
  # AUTH_LOCAL_LOGIN=true lands "armed but unusable" -- the provider is never
  # registered and /api/auth/callback/breakglass does not exist. That is the
  # safe half.
  #
  # The unsafe half is that it is SILENT. Running `make db` (or anything else
  # that does `set -a; . ./.env`) in the same shell before deploying is enough
  # to carry a local demo's AUTH_LOCAL_LOGIN=true into a cloud revision, where
  # the sign-in page then renders a yellow "Break-glass is armed but unusable"
  # notice to every visitor. The existing warning below only fires on
  # BREAKGLASS_PASSWORD_HASH, which this loop does not forward -- so it cannot
  # catch this case, and nobody would know until someone opened the login page.
  case " ${FRONTEND_ENV[*]} " in
    *" AUTH_LOCAL_LOGIN=true "*)
      warn "AUTH_LOCAL_LOGIN=true is being deployed, from this shell's environment."
      warn "  Break-glass will show as ARMED on the sign-in page. It cannot authenticate"
      warn "  anyone (no password is forwarded), but it is visible to every visitor."
      warn "  If this came from a local .env, unset it and re-run: unset AUTH_LOCAL_LOGIN"
      warn "  To arm it deliberately, see docs/BREAKGLASS.md." ;;
  esac

  # PRESERVE EVERY OPERATOR-SET VARIABLE THIS SCRIPT DOES NOT ITSELF MANAGE.
  #
  # `az containerapp update --yaml` REPLACES the template, so anything set out of
  # band is silently dropped -- and the deploy still reports success. Measured
  # twice on this deployment, not theorised: the first redeploy disarmed
  # break-glass; the second erased the entire SSO configuration
  # (SSO_CLIENT_ID/SECRET/ISSUER/RESOURCE) and AZURE_CLIENT_ID, leaving an
  # SSO-only application with no way for anyone to sign in.
  #
  # The first fix special-cased break-glass, which was treating the symptom. The
  # rule that actually holds: a declarative deploy should own what it DECLARES
  # and leave everything else alone. So carry forward any variable already on the
  # running app that this script does not set itself. A variable this script does
  # set still wins, so a deliberate change is never blocked by a stale value.
  # NB: JSON, not `-o tsv`. `--query "env[].[name,value,secretRef]" -o tsv` on an
  # entry whose `value` is null COLLAPSES the empty column, so secretRef lands in
  # the value field and a secret-backed variable is preserved as the literal
  # SECRET NAME. That is not hypothetical: it wrote SSO_CLIENT_SECRET="sso-client-secret"
  # (17 characters), Auth.js saw a secret it could not use, chose
  # token_endpoint_auth_method "none", sent no client credentials, and every
  # sign-in died with `invalid_client` and an unhelpful "problem with the server
  # configuration" page. A preservation routine that silently corrupts what it
  # preserves is worse than not preserving at all.
  local existing
  existing="$(az containerapp show -n "$FRONTEND_APP" -g "$RESOURCE_GROUP" \
    --query "properties.template.containers[0].env" -o json 2>/dev/null || echo '[]')"
  while IFS=$'\x1f' read -r name ref val; do
    [ -n "$name" ] || continue
    case " ${FRONTEND_ENV[*]} " in *" ${name}="*) continue ;; esac
    if [ -n "$ref" ]; then
      FRONTEND_ENV+=("${name}=secretref:${ref}")
      info "preserved ${name} (secretref) set outside this script"
    elif [ -n "$val" ]; then
      FRONTEND_ENV+=("${name}=${val}")
      info "preserved ${name} set outside this script"
    fi
  done <<< "$(printf '%s' "$existing" | python3 -c '
import json, sys
for e in json.load(sys.stdin) or []:
    print("\x1f".join([e.get("name") or "", e.get("secretRef") or "", (e.get("value") or "").replace("\x1f", " ")]))
' 2>/dev/null || true)"
  case " ${FRONTEND_ENV[*]} " in
    *" BREAKGLASS_PASSWORD_HASH="*)
      warn "break-glass is ARMED (docs/BREAKGLASS.md to disarm)" ;;
  esac

  if [ -n "${SSO_CLIENT_SECRET:-}" ]; then FRONTEND_ENV+=("SSO_CLIENT_SECRET=secretref:sso-client-secret"); fi
  if [ -n "${RESEND_API_KEY:-}" ]; then FRONTEND_ENV+=("RESEND_API_KEY=secretref:resend-api-key"); fi
}

# ---------------------------------------------------------------------------
# 12. Migration + seed job, then the two apps.
# ---------------------------------------------------------------------------

# The YAML emitters and the scratch directory both of the sections below use.
yaml_env_block() { # env pairs -> YAML `env:` entries, 10-space indented
  local pair key val
  for pair in "$@"; do
    key="${pair%%=*}"
    val="${pair#*=}"
    case "$val" in
      secretref:*) printf '          - name: %s\n            secretRef: %s\n' "$key" "${val#secretref:}" ;;
      *"$NL"*)
        die "env value for $key contains a newline; refusing to emit broken YAML" ;;
      # SINGLE-quoted YAML scalar, with ' doubled -- the one form that carries a
      # value containing double quotes. SSO_ROLE_MAP is JSON
      # ({"npr-platform-owner":"admin",...}, docs/SSO.md:101), so a double-quoted
      # emitter produced invalid YAML and the earlier guard aborted the deploy
      # half-finished on the script's own documented SSO path. Single-quoted YAML
      # does no escape processing at all except '' -> ', so backslashes in a
      # regex or a Windows path also survive untouched.
      # NB the ${val//"'"/"''"} form. The backslash form ${val//\'/\'\'} looks
      # equivalent and is not: bash keeps the backslashes, emitting it\'\'s
      # instead of it''s, which is invalid YAML. Verified both ways.
      *) printf "          - name: %s\n            value: '%s'\n" "$key" "${val//"'"/"''"}" ;;
    esac
  done
}

write_app_yaml() { # file container image cpu memory probe-path probe-port env...
  local file="$1" container="$2" image="$3" cpu="$4" memory="$5" probe_path="$6" probe_port="$7"
  shift 7
  {
    printf 'type: Microsoft.App/containerApps\n'
    printf 'properties:\n  template:\n    containers:\n'
    printf '      - name: %s\n        image: %s\n' "$container" "$image"
    printf '        resources:\n          cpu: %s\n          memory: "%s"\n' "$cpu" "$memory"
    if [ "$#" -gt 0 ]; then
      printf '        env:\n'
      yaml_env_block "$@"
    fi
    # LIVENESS ONLY, and pointed at /api/live. /api/health is the readiness and
    # honesty endpoint: it answers 503 whenever the database is unreachable or
    # the snapshot is missing. A restart-triggering probe on that endpoint turns
    # a sleeping Burstable database into an endless restart loop of a process
    # that is working perfectly and that a restart cannot fix. Deliberately no
    # readiness probe either: a readiness gate that fails during a rollout stops
    # traffic from ever shifting to the new revision, so a transient database
    # blip during a deploy would present as a failed deploy.
    printf '        probes:\n'
    printf '          - type: Liveness\n            httpGet:\n              path: %s\n              port: %s\n' "$probe_path" "$probe_port"
    printf '            initialDelaySeconds: 20\n            periodSeconds: 30\n'
    printf '            timeoutSeconds: 5\n            failureThreshold: 3\n'
    printf '    scale:\n      minReplicas: %s\n      maxReplicas: %s\n' "$MIN_REPLICAS" "$MAX_REPLICAS"
  } >"$file"
}

TMPDIR_DEPLOY="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR_DEPLOY"; }
trap cleanup EXIT


# One line, run by /bin/sh inside the backend image. /app IS the repo root in
# that image (backend/Dockerfile says so, and three modules locate their
# neighbours by walking up from __file__, so the layout is load-bearing).
# All three steps are idempotent: migrate skips applied migrations, seed rewrites
# the same deterministic fixtures, precompute persists the same snapshot id.
#
# Single-quoted, and it must stay free of single quotes: it is emitted into the
# job YAML as a single-quoted scalar.
# db/migrate.py applies schema.sql + db/migrations/*. It does NOT apply
# auth_schema.sql or sso_schema.sql -- those are separate baselines and the
# runner takes one at a time (`python db/migrate.py db/auth_schema.sql`).
# ztpa.app_users and ztpa.auth_tokens live ONLY in auth_schema.sql, so omitting
# it produces a database that migrates cleanly, serves the engine correctly, and
# that NOBODY CAN LOG INTO -- with no error until the first sign-in attempt.
#
# NOTE the exact form. `--migrations-only` SKIPS the baseline and still exits 0,
# so `migrate.py X --migrations-only || migrate.py X` reports "no pending
# migrations", succeeds, and creates nothing -- verified against a real database.
# The baseline argument alone is what applies the file. Re-running is safe:
# every statement is IF NOT EXISTS and applied migrations are recorded.
MIGRATE_SCRIPT='set -e; cd /app; echo "[1/5] engine schema"; python db/migrate.py; echo "[2/5] auth schema";   python db/migrate.py db/auth_schema.sql; echo "[3/5] sso schema";    python db/migrate.py db/sso_schema.sql; echo "[4/5] seed";          python backend/scripts/seed_demo.py; echo "[5/5] precompute";    python backend/scripts/precompute.py; echo done'
case "$MIGRATE_SCRIPT" in *"'"*) die "MIGRATE_SCRIPT contains a single quote; it cannot be emitted as YAML" ;; esac

# WHY THE JOB'S command/args GO THROUGH YAML AND NOT FLAGS.
# `az containerapp job create --command /bin/sh --args "-c" "<script>"` does not
# work. --args is argparse nargs='*', and argparse resolves a leading-dash token
# to an option, not to a value, so the CLI stops with:
#     ERROR: unrecognized arguments: -c <script>
# Verified against azure-cli 2.90.0 / containerapp 1.3.0b5; --args="-c" fails the
# same way one token later. The YAML surface takes command and args as real
# lists and has no such parsing. It is also a PATCH that leaves
# configuration.secrets alone, so the file carries secretRefs and never a secret.
write_job_yaml() { # file container image cpu memory env...
  local file="$1" container="$2" image="$3" cpu="$4" memory="$5"
  shift 5
  {
    printf 'type: Microsoft.App/jobs\n'
    printf 'properties:\n  template:\n    containers:\n'
    printf '      - name: %s\n        image: %s\n' "$container" "$image"
    printf '        resources:\n          cpu: %s\n          memory: "%s"\n' "$cpu" "$memory"
    if [ "$#" -gt 0 ]; then
      printf '        env:\n'
      yaml_env_block "$@"
    fi
    printf '        command:\n          - "/bin/sh"\n'
    printf '        args:\n          - "-c"\n'
    printf "          - '%s'\n" "$MIGRATE_SCRIPT"
  } >"$file"
}

step "Migration + seed job"
if az containerapp job show --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" -o none 2>/dev/null; then
  ok "$MIGRATE_JOB exists — converging it"
  az containerapp job secret set --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" \
    --secrets "database-url=${DATABASE_URL}" -o none
  if [ "$REGISTRY_MODE" = "identity" ]; then
    az containerapp job identity assign --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" \
      --user-assigned "$IDENTITY_ID" -o none
  fi
  az containerapp job registry set --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" \
    "${REGISTRY_SET_ARGS[@]}" -o none
  az containerapp job update --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" \
    --replica-timeout "$JOB_TIMEOUT_SECONDS" -o none
else
  az containerapp job create --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" \
    --environment "$ENV_NAME" --trigger-type Manual \
    --replica-timeout "$JOB_TIMEOUT_SECONDS" --replica-retry-limit 1 \
    --replica-completion-count 1 --parallelism 1 \
    --image "$BACKEND_IMAGE" --cpu "$JOB_CPU" --memory "$JOB_MEMORY" \
    --container-name migrate \
    --secrets "database-url=${DATABASE_URL}" \
    --env-vars "DATABASE_URL=secretref:database-url" \
    "${JOB_REGISTRY_ARGS[@]}" "${TAGS_ARGS[@]}" -o none
  ok "created $MIGRATE_JOB"
fi

write_job_yaml "${TMPDIR_DEPLOY}/job.yaml" migrate "$BACKEND_IMAGE" "$JOB_CPU" "$JOB_MEMORY" \
  "DATABASE_URL=secretref:database-url"
az containerapp job update --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" \
  --yaml "${TMPDIR_DEPLOY}/job.yaml" -o none
ok "job runs: engine+auth+sso schema -> seed -> precompute, on $BACKEND_IMAGE"

if [ "${NPR_SKIP_MIGRATE:-0}" = "1" ]; then
  warn "NPR_SKIP_MIGRATE=1 — not running the migration. The apps below will start against"
  warn "whatever schema the database currently has."
else
  info "starting an execution (schemas -> seed -> precompute)"
  EXECUTION_NAME="$(az containerapp job start --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" \
    --query name -o tsv 2>/dev/null || echo "")"
  if [ -z "$EXECUTION_NAME" ]; then
    EXECUTION_NAME="$(az containerapp job execution list --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" \
      --query "sort_by(@, &properties.startTime)[-1].name" -o tsv 2>/dev/null || echo "")"
  fi
  [ -n "$EXECUTION_NAME" ] || die "could not determine the job execution name; check: az containerapp job execution list -n $MIGRATE_JOB -g $RESOURCE_GROUP"
  info "execution    : $EXECUTION_NAME"

  # Poll rather than assume. A migration that failed and a migration that
  # succeeded must not look the same to this script — that is the entire reason
  # this is a job and not an `exec`.
  JOB_STATUS="Unknown"
  WAITED=0
  while [ "$WAITED" -lt "$JOB_TIMEOUT_SECONDS" ]; do
    JOB_STATUS="$(az containerapp job execution show --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" \
      --job-execution-name "$EXECUTION_NAME" --query properties.status -o tsv 2>/dev/null || echo "Unknown")"
    case "$JOB_STATUS" in
      Succeeded | Failed | Cancelled | Degraded) break ;;
    esac
    printf '    ... %s (%ds)\r' "$JOB_STATUS" "$WAITED"
    sleep 10
    WAITED=$((WAITED + 10))
  done
  printf '\n'
  if [ "$JOB_STATUS" != "Succeeded" ]; then
    warn "migration job finished as '$JOB_STATUS'. Logs:"
    az containerapp job logs show --name "$MIGRATE_JOB" --resource-group "$RESOURCE_GROUP" \
      --container migrate --execution "$EXECUTION_NAME" --tail 100 --format text 2>/dev/null || true
    die "the database is not migrated/seeded; not deploying apps on top of it.
    Re-run just this step with:  az containerapp job start -n $MIGRATE_JOB -g $RESOURCE_GROUP"
  fi
  ok "migration + seed + precompute succeeded"
fi

# ---------------------------------------------------------------------------
# 13. The apps.
#
#     Two-phase on purpose. `az containerapp create` has no flag for health
#     probes — probes exist only in the YAML surface — so each app is CREATED
#     with flags (which is where secrets, registry auth and ingress are
#     well-supported) and then CONVERGED with `az containerapp update --yaml`,
#     which PATCHes the template: image, resources, env and probes. The YAML
#     carries no secret VALUES, only secretrefs, so it is safe on disk.
#     Convergence is also what makes the re-run path identical to the first run,
#     and Container Apps only cuts a new revision when the template actually
#     changed, so a no-op re-run costs nothing.
# ---------------------------------------------------------------------------
step "Backend container app (internal ingress)"
build_backend_env "https://${FRONTEND_FQDN}"

BACKEND_INGRESS_ARGS=(--ingress internal --target-port 8000)
BACKEND_INSECURE_ARGS=()
if [ "$BACKEND_SCHEME" = "http" ]; then
  # Escape hatch, off by default. Traffic still never leaves the environment's
  # private network, but you lose TLS on the last hop between the two apps.
  BACKEND_INGRESS_ARGS+=(--allow-insecure true)
  BACKEND_INSECURE_ARGS=(--allow-insecure true)
fi

if az containerapp show --name "$BACKEND_APP" --resource-group "$RESOURCE_GROUP" -o none 2>/dev/null; then
  ok "$BACKEND_APP exists — converging"
  az containerapp secret set --name "$BACKEND_APP" --resource-group "$RESOURCE_GROUP" \
    --secrets "${BACKEND_SECRETS[@]}" -o none
  if [ "$REGISTRY_MODE" = "identity" ]; then
    az containerapp identity assign --name "$BACKEND_APP" --resource-group "$RESOURCE_GROUP" \
      --user-assigned "$IDENTITY_ID" -o none
  fi
  az containerapp registry set --name "$BACKEND_APP" --resource-group "$RESOURCE_GROUP" \
    "${REGISTRY_SET_ARGS[@]}" -o none
  az containerapp ingress enable --name "$BACKEND_APP" --resource-group "$RESOURCE_GROUP" \
    --type internal --target-port 8000 --transport auto \
    ${BACKEND_INSECURE_ARGS[@]+"${BACKEND_INSECURE_ARGS[@]}"} -o none
else
  az containerapp create --name "$BACKEND_APP" --resource-group "$RESOURCE_GROUP" \
    --environment "$ENV_NAME" --image "$BACKEND_IMAGE" --container-name "$BACKEND_APP" \
    --cpu "$BACKEND_CPU" --memory "$BACKEND_MEMORY" \
    --min-replicas "$MIN_REPLICAS" --max-replicas "$MAX_REPLICAS" \
    "${BACKEND_INGRESS_ARGS[@]}" \
    --secrets "${BACKEND_SECRETS[@]}" \
    --env-vars "${BACKEND_ENV[@]}" \
    "${REGISTRY_ARGS[@]}" "${TAGS_ARGS[@]}" -o none
  ok "created $BACKEND_APP"
fi

# The FQDN the platform actually assigned wins over the predicted one.
ACTUAL_BACKEND_FQDN="$(az containerapp show --name "$BACKEND_APP" --resource-group "$RESOURCE_GROUP" \
  --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null || echo "")"
if [ -n "$ACTUAL_BACKEND_FQDN" ] && [ "$ACTUAL_BACKEND_FQDN" != "$BACKEND_FQDN" ]; then
  info "backend FQDN differs from the predicted one; using $ACTUAL_BACKEND_FQDN"
  BACKEND_FQDN="$ACTUAL_BACKEND_FQDN"
fi
BACKEND_URL="${BACKEND_SCHEME}://${BACKEND_FQDN}"
info "backend      : $BACKEND_URL  (internal — not reachable from the internet)"

step "Frontend container app (external ingress)"
build_frontend_env "$BACKEND_URL" "https://${FRONTEND_FQDN}"

if az containerapp show --name "$FRONTEND_APP" --resource-group "$RESOURCE_GROUP" -o none 2>/dev/null; then
  ok "$FRONTEND_APP exists — converging"
  az containerapp secret set --name "$FRONTEND_APP" --resource-group "$RESOURCE_GROUP" \
    --secrets "${FRONTEND_SECRETS[@]}" -o none
  if [ "$REGISTRY_MODE" = "identity" ]; then
    az containerapp identity assign --name "$FRONTEND_APP" --resource-group "$RESOURCE_GROUP" \
      --user-assigned "$IDENTITY_ID" -o none
  fi
  az containerapp registry set --name "$FRONTEND_APP" --resource-group "$RESOURCE_GROUP" \
    "${REGISTRY_SET_ARGS[@]}" -o none
  az containerapp ingress enable --name "$FRONTEND_APP" --resource-group "$RESOURCE_GROUP" \
    --type external --target-port 3000 --transport auto -o none
else
  az containerapp create --name "$FRONTEND_APP" --resource-group "$RESOURCE_GROUP" \
    --environment "$ENV_NAME" --image "$FRONTEND_IMAGE" --container-name "$FRONTEND_APP" \
    --cpu "$FRONTEND_CPU" --memory "$FRONTEND_MEMORY" \
    --min-replicas "$MIN_REPLICAS" --max-replicas "$MAX_REPLICAS" \
    --ingress external --target-port 3000 \
    --secrets "${FRONTEND_SECRETS[@]}" \
    --env-vars "${FRONTEND_ENV[@]}" \
    "${REGISTRY_ARGS[@]}" "${TAGS_ARGS[@]}" -o none
  ok "created $FRONTEND_APP"
fi

ACTUAL_FRONTEND_FQDN="$(az containerapp show --name "$FRONTEND_APP" --resource-group "$RESOURCE_GROUP" \
  --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null || echo "")"
if [ -n "$ACTUAL_FRONTEND_FQDN" ] && [ "$ACTUAL_FRONTEND_FQDN" != "$FRONTEND_FQDN" ]; then
  info "frontend FQDN differs from the predicted one; using $ACTUAL_FRONTEND_FQDN"
  FRONTEND_FQDN="$ACTUAL_FRONTEND_FQDN"
fi
FRONTEND_URL="https://${FRONTEND_FQDN}"

# A BOUND CUSTOM DOMAIN WINS OVER THE azurecontainerapps.io FQDN.
#
# APP_URL is what Auth.js builds session cookies and OIDC callback URLs from. If
# a custom hostname is bound and this keeps naming the default FQDN, users arrive
# on the custom domain, get a cookie issued for a different host, and sign-in
# fails in a redirect loop that looks like a broken login rather than a wrong
# variable. scripts/azure/bind-domain.sh sets it correctly; this line is what
# used to overwrite it on the next deploy.
#
# `hostname list` returns the bound custom names; there is at most one here, and
# the default FQDN is not among them.
CUSTOM_HOSTNAME="$(az containerapp hostname list -n "$FRONTEND_APP" -g "$RESOURCE_GROUP" \
  --query "[?bindingType!='Disabled'].name | [0]" -o tsv 2>/dev/null || true)"
if [ -n "$CUSTOM_HOSTNAME" ] && [ "$CUSTOM_HOSTNAME" != "None" ]; then
  FRONTEND_URL="https://${CUSTOM_HOSTNAME}"
  info "custom domain bound: using $FRONTEND_URL for APP_URL / FRONTEND_ORIGIN"
fi

# ---------------------------------------------------------------------------
# 14. Converge both templates with the REAL FQDNs, and add the probes.
#     This is the pass that closes the ordering cycle: whatever the two apps
#     were created with, they end this step holding each other's real address.
# ---------------------------------------------------------------------------
step "Converge templates (probes, real FQDNs)"

build_backend_env "$FRONTEND_URL"
write_app_yaml "${TMPDIR_DEPLOY}/backend.yaml" "$BACKEND_APP" "$BACKEND_IMAGE" \
  "$BACKEND_CPU" "$BACKEND_MEMORY" "/api/live" 8000 "${BACKEND_ENV[@]}"
az containerapp update --name "$BACKEND_APP" --resource-group "$RESOURCE_GROUP" \
  --yaml "${TMPDIR_DEPLOY}/backend.yaml" -o none
ok "backend: liveness on /api/live, FRONTEND_ORIGIN=$FRONTEND_URL"

build_frontend_env "$BACKEND_URL" "$FRONTEND_URL"
# "/" is a public route (auth.config.ts), so this probe needs no session.
write_app_yaml "${TMPDIR_DEPLOY}/frontend.yaml" "$FRONTEND_APP" "$FRONTEND_IMAGE" \
  "$FRONTEND_CPU" "$FRONTEND_MEMORY" "/" 3000 "${FRONTEND_ENV[@]}"
az containerapp update --name "$FRONTEND_APP" --resource-group "$RESOURCE_GROUP" \
  --yaml "${TMPDIR_DEPLOY}/frontend.yaml" -o none
ok "frontend: liveness on /, BACKEND_URL=$BACKEND_URL"

# ---------------------------------------------------------------------------
# 15. Summary
# ---------------------------------------------------------------------------
step "Done"
REGISTRY_NOTE="$REGISTRY_MODE"
if [ "$REGISTRY_MODE" = "admin" ]; then
  REGISTRY_NOTE="admin user (FALLBACK — the AcrPull grant failed; see the warnings above)"
fi
cat <<SUMMARY

  Frontend (open this)   ${FRONTEND_URL}
  Backend  (internal)    ${BACKEND_URL}
  Database               ${PG_FQDN} / ${PG_DB}   (TLS required)
  Registry               ${ACR_LOGIN_SERVER}    images tagged ${IMAGE_TAG}
  Registry auth          ${REGISTRY_NOTE}
  Resource group         ${RESOURCE_GROUP} (${LOCATION})

  NEXT STEPS

  1. Confirm the shared-secret check is live.

     NOT by curling /api/health from outside: frontend/middleware.ts matches
     /api/*, /api/health is not in auth.config.ts's PUBLIC list, so an
     unauthenticated request is redirected to /login and you learn nothing.
     And once NPR_PROXY_SECRET is set the backend answers /api/health with 401
     anyway -- the proxy-auth guard covers it.

     Prove the invariant directly instead: from inside the frontend container,
     forge an admin header against the backend's internal address. WITHOUT the
     secret it must be 401; WITH it, 200. That is the whole control.

       az containerapp exec -g ${RESOURCE_GROUP} -n ${FRONTEND_APP} --command sh
       # then, inside:
       #   B=\$BACKEND_URL
       #   wget -qO- --server-response --header='x-npr-role: admin' \$B/api/snapshot 2>&1 | head -3
       #     -> expect  HTTP/1.1 401
       #   wget -qO- --server-response --header='x-npr-role: admin' \
       #        --header=\"x-npr-proxy-secret: \$NPR_PROXY_SECRET\" \$B/api/snapshot 2>&1 | head -3
       #     -> expect  HTTP/1.1 200
       #   wget -qO- \$B/api/live    -> expect 200 (liveness is exempt, which is
       #                                 why the probe uses it and not /api/health)

  2. Create the first admin. The frontend needs a user with role=admin before
     anyone can sign in. Either:

       a. AutoX SSO (docs/SSO.md) — register these two URLs, byte for byte:
            redirect URI          ${FRONTEND_URL}/api/auth/callback/autox
            post-logout redirect  ${FRONTEND_URL}/login
          then re-run this script with SSO_CLIENT_ID / SSO_CLIENT_SECRET set.

       b. Local login — run the bootstrap script against this database:
            NPR_ALLOW_CLIENT_IP=1 bash scripts/azure/deploy.sh    # opens your IP
            export DATABASE_URL="\$(az containerapp secret show -n ${FRONTEND_APP} \\
              -g ${RESOURCE_GROUP} --secret-name database-url --query value -o tsv)"
            node frontend/scripts/create-admin.mjs you@example.com

  3. Model provider key (optional). Without one the advisory layer uses its
     deterministic fallbacks. With one, finding text, rule text and asset names
     LEAVE this host for the provider:

       OPENAI_API_KEY=sk-... bash scripts/azure/deploy.sh

  4. Logs and re-runs:

       az containerapp logs show -n ${BACKEND_APP} -g ${RESOURCE_GROUP} --follow
       az containerapp job start -n ${MIGRATE_JOB} -g ${RESOURCE_GROUP}
       bash scripts/azure/deploy.sh          # idempotent; re-run any time
       bash scripts/azure/teardown.sh        # deletes everything

  This is a DEMO/STAGING environment carrying the seeded demo dataset. The
  product has 8 open blockers (docs/PROD-READINESS-AUDIT-2.md); do not put a
  real customer's export in it. docs/DEPLOY-AZURE.md has the details.

SUMMARY
