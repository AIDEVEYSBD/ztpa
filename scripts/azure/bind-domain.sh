#!/usr/bin/env bash
# Bind a custom domain to the deployed frontend Container App, with a free
# Azure-managed certificate, and repoint the app's own idea of its URL at it.
#
# WHY THIS IS A SEPARATE SCRIPT FROM deploy.sh
# --------------------------------------------
# The DNS for autogrc.cloud is hosted at Cloudflare, not Azure DNS, so `az`
# cannot create the records -- a human does, in the Cloudflare dashboard. And the
# records cannot be written until the Container App exists, because both values
# come out of it (the CNAME target is the app's FQDN; the TXT value is the app's
# domain verification id). So the sequence is necessarily:
#
#   deploy.sh          -> app exists on its azurecontainerapps.io FQDN
#   THIS SCRIPT, pass 1 -> prints the exact two records to paste into Cloudflare
#   (human adds them, DNS-only)
#   THIS SCRIPT, pass 2 -> binds the hostname, issues the managed cert, and
#                          updates APP_URL / FRONTEND_ORIGIN / AUTH_URL
#
# Re-running is safe at any point: every step checks before it acts.
#
# THE CLOUDFLARE PROXY MUST BE OFF (grey cloud, "DNS only")
# ---------------------------------------------------------
# Azure validates ownership by resolving the CNAME to the Container App and then
# issues the certificate. With Cloudflare proxying (orange cloud) the name
# resolves to Cloudflare's edge instead, validation fails, and the managed
# certificate is never issued. The Azure error does not mention Cloudflare or
# proxying -- it just says validation failed -- so this is worth getting right
# the first time. The proxy can be switched back on AFTER the certificate is
# issued, if you want Cloudflare in front.
#
# WHY APP_URL MATTERS AS MUCH AS THE BINDING
# ------------------------------------------
# Auth.js issues cookies and builds callback URLs from APP_URL. Left pointing at
# the azurecontainerapps.io FQDN while users arrive on the custom domain, the
# session cookie is issued for the wrong host and sign-in fails in a redirect
# loop that looks like a broken login rather than a misconfiguration. The SSO
# redirect URIs registered with AutoX must be for https://npr.autogrc.cloud, so
# this value must match them exactly.
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-npr-demo-rg}"
FRONTEND_APP="${FRONTEND_APP:-npr-frontend}"
ENVIRONMENT="${ENVIRONMENT:-npr-env}"
CUSTOM_DOMAIN="${CUSTOM_DOMAIN:-npr.autogrc.cloud}"

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; OFF=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$OFF"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$OFF" "$*"; }
info() { printf '  %s·%s %s\n' "$DIM" "$OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$OFF" "$*"; }
die()  { printf '  %s✗%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

command -v az >/dev/null || die "az CLI not found"
az account show -o none 2>/dev/null || die "not logged in — run 'az login'"

# --------------------------------------------------------------------------
step "Read the deployed app"
# --------------------------------------------------------------------------
APP_FQDN="$(az containerapp show -n "$FRONTEND_APP" -g "$RESOURCE_GROUP" \
  --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null || true)"
[ -n "$APP_FQDN" ] || die "frontend app '$FRONTEND_APP' not found in '$RESOURCE_GROUP' — run deploy.sh first"

VERIFICATION_ID="$(az containerapp show -n "$FRONTEND_APP" -g "$RESOURCE_GROUP" \
  --query properties.customDomainVerificationId -o tsv)"
[ -n "$VERIFICATION_ID" ] || die "could not read customDomainVerificationId"

SUBDOMAIN="${CUSTOM_DOMAIN%%.*}"
ok "app FQDN        $APP_FQDN"
ok "verification id $VERIFICATION_ID"

# --------------------------------------------------------------------------
step "Check DNS"
# --------------------------------------------------------------------------
CNAME_OK=false; TXT_OK=false
RESOLVED="$(dig +short CNAME "$CUSTOM_DOMAIN" 2>/dev/null | sed 's/\.$//' || true)"
[ "$RESOLVED" = "$APP_FQDN" ] && CNAME_OK=true
TXT_VALUE="$(dig +short TXT "asuid.${CUSTOM_DOMAIN}" 2>/dev/null | tr -d '"' || true)"
[ "$TXT_VALUE" = "$VERIFICATION_ID" ] && TXT_OK=true

if [ "$CNAME_OK" != true ] || [ "$TXT_OK" != true ]; then
  cat <<EOF

  ${BOLD}Add these two records in Cloudflare, then re-run this script.${OFF}

    Type   Name                  Value
    ----   ----                  -----
    TXT    asuid.${SUBDOMAIN}    ${VERIFICATION_ID}
    CNAME  ${SUBDOMAIN}          ${APP_FQDN}

  ${BOLD}${YELLOW}Set the CNAME to "DNS only" (grey cloud), NOT proxied.${OFF}
  Azure resolves this name to verify ownership before it will issue the
  certificate. Proxied, it resolves to Cloudflare and validation fails with an
  error that does not mention proxying.

  Current state:
    CNAME ${CUSTOM_DOMAIN} -> ${RESOLVED:-<unset>}   $([ "$CNAME_OK" = true ] && echo OK || echo "expected ${APP_FQDN}")
    TXT   asuid.${CUSTOM_DOMAIN} -> ${TXT_VALUE:-<unset>}   $([ "$TXT_OK" = true ] && echo OK || echo MISMATCH)

  If ${CUSTOM_DOMAIN} is already bound elsewhere, remove it there first or the
  CNAME cannot be repointed.

EOF
  exit 2
fi
ok "CNAME and TXT both resolve correctly"

# --------------------------------------------------------------------------
step "Bind the hostname and issue the managed certificate"
# --------------------------------------------------------------------------
if az containerapp hostname list -n "$FRONTEND_APP" -g "$RESOURCE_GROUP" -o tsv 2>/dev/null | grep -q "$CUSTOM_DOMAIN"; then
  ok "hostname already bound"
else
  # --validation-method CNAME is what makes Azure create the free managed
  # certificate; without it the bind expects a certificate you supply yourself.
  az containerapp hostname bind -n "$FRONTEND_APP" -g "$RESOURCE_GROUP" \
    --hostname "$CUSTOM_DOMAIN" --environment "$ENVIRONMENT" \
    --validation-method CNAME -o none
  ok "bound $CUSTOM_DOMAIN with a managed certificate"
fi

# --------------------------------------------------------------------------
step "Point the app at its own public URL"
# --------------------------------------------------------------------------
# See the header: Auth.js builds cookies and callbacks from these. If they keep
# naming the azurecontainerapps.io host while users arrive on the custom domain,
# sign-in fails in a redirect loop.
CUSTOM_URL="https://${CUSTOM_DOMAIN}"
az containerapp update -n "$FRONTEND_APP" -g "$RESOURCE_GROUP" \
  --set-env-vars "APP_URL=${CUSTOM_URL}" "AUTH_URL=${CUSTOM_URL}" "AUTH_TRUST_HOST=true" -o none
ok "frontend APP_URL / AUTH_URL -> ${CUSTOM_URL}"

BACKEND_APP="${BACKEND_APP:-npr-backend}"
if az containerapp show -n "$BACKEND_APP" -g "$RESOURCE_GROUP" -o none 2>/dev/null; then
  az containerapp update -n "$BACKEND_APP" -g "$RESOURCE_GROUP" \
    --set-env-vars "FRONTEND_ORIGIN=${CUSTOM_URL}" -o none
  ok "backend FRONTEND_ORIGIN -> ${CUSTOM_URL} (CORS allowlist)"
fi

# --------------------------------------------------------------------------
step "Verify"
# --------------------------------------------------------------------------
info "waiting for the certificate and the new revision (this can take a few minutes)"
for i in $(seq 1 30); do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$CUSTOM_URL/" 2>/dev/null || echo 000)"
  [ "$CODE" = "200" ] && { ok "$CUSTOM_URL responds 200"; break; }
  [ "$i" = 30 ] && warn "still $CODE after ~5 min — check 'az containerapp hostname list' and the cert state"
  sleep 10
done

CERT_SUBJECT="$(echo | openssl s_client -servername "$CUSTOM_DOMAIN" -connect "${CUSTOM_DOMAIN}:443" 2>/dev/null \
  | openssl x509 -noout -subject -issuer 2>/dev/null || true)"
[ -n "$CERT_SUBJECT" ] && info "certificate: $(echo "$CERT_SUBJECT" | tr '\n' ' ')"

cat <<EOF

  ${GREEN}${BOLD}${CUSTOM_URL}${OFF}

  If sign-in loops, APP_URL and the AutoX SSO redirect URI disagree — they must
  both be exactly ${CUSTOM_URL}.
EOF
