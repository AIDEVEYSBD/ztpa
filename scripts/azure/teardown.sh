#!/usr/bin/env bash
# =============================================================================
# Network Policy Reviewer — delete the Azure demo deployment.
#
#     bash scripts/azure/teardown.sh
#
# Deletes the whole resource group, which is everything scripts/azure/deploy.sh
# created: both container apps, the migrate job, the managed environment, the
# Log Analytics workspace, the container registry AND ITS IMAGES, the managed
# identity, and the PostgreSQL Flexible Server WITH ITS DATA AND BACKUPS.
#
# This is irreversible. There is no soft delete on a resource group, and the
# Postgres server's backups go with it, so the confirmation below asks you to
# type the group's name rather than press 'y' — the same gesture that protects
# against deleting the wrong group when two are open in two terminals.
#
# Non-interactive use (CI): NPR_FORCE_TEARDOWN=1. Deliberately NOT the same
# variable as the deploy script's NPR_YES, so a variable left exported in a
# shell that was deploying can never end up deleting.
# =============================================================================
set -euo pipefail

RESOURCE_GROUP="${NPR_RESOURCE_GROUP:-npr-demo-rg}"

if [ -t 1 ]; then
  C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'; C_OK=$'\033[1;32m'; C_OFF=$'\033[0m'
else
  C_WARN=""; C_ERR=""; C_OK=""; C_OFF=""
fi
info() { printf '    %s\n' "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
die()  { printf '\n%s[fatal]%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

command -v az >/dev/null 2>&1 || die "azure-cli not found."
az account show -o none 2>/dev/null || die "not signed in. Run: az login"

if [ -n "${NPR_SUBSCRIPTION:-}" ]; then
  az account set --subscription "$NPR_SUBSCRIPTION" || die "could not select subscription '$NPR_SUBSCRIPTION'"
fi

SUBSCRIPTION_NAME="$(az account show --query name -o tsv)"
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"

if [ "$(az group exists --name "$RESOURCE_GROUP")" != "true" ]; then
  printf '%s✓%s resource group "%s" does not exist — nothing to tear down.\n' "$C_OK" "$C_OFF" "$RESOURCE_GROUP"
  exit 0
fi

printf '\nAbout to DELETE resource group "%s"\n' "$RESOURCE_GROUP"
printf '  subscription : %s (%s)\n' "$SUBSCRIPTION_NAME" "$SUBSCRIPTION_ID"
printf '  location     : %s\n\n' "$(az group show --name "$RESOURCE_GROUP" --query location -o tsv)"

# Show the actual inventory rather than a promise about it. If this list has
# something in it you did not expect, that is the moment to stop.
printf 'It contains:\n\n'
az resource list --resource-group "$RESOURCE_GROUP" \
  --query "sort_by([].{name:name, type:type, location:location}, &type)" -o table 2>/dev/null ||
  warn "could not list the group's resources; it will still be deleted in full"

cat <<'CONSEQUENCES'

This deletes, permanently:
  - the PostgreSQL server, its 'npr' database, and its automated backups
  - the container registry and every image in it
  - both container apps, the migrate job, and the managed environment
  - the Log Analytics workspace and all retained logs

If any of that holds something you want, take it out FIRST. A resource group
delete cannot be undone and Azure keeps no copy.

CONSEQUENCES

if [ "${NPR_FORCE_TEARDOWN:-0}" = "1" ]; then
  warn "NPR_FORCE_TEARDOWN=1 — skipping the confirmation prompt"
else
  [ -t 0 ] || die "not a terminal: re-run with NPR_FORCE_TEARDOWN=1 if you really mean it."
  printf 'Type the resource group name to confirm: '
  CONFIRMATION=""
  read -r CONFIRMATION || true
  [ "$CONFIRMATION" = "$RESOURCE_GROUP" ] ||
    die "got '${CONFIRMATION}', expected '${RESOURCE_GROUP}' — nothing was deleted."
fi

DELETE_ARGS=(--name "$RESOURCE_GROUP" --yes)
if [ "${NPR_TEARDOWN_NO_WAIT:-0}" = "1" ]; then
  DELETE_ARGS+=(--no-wait)
  info "starting the delete and returning immediately (NPR_TEARDOWN_NO_WAIT=1)"
else
  info "deleting — this takes several minutes, mostly the Postgres server"
fi

az group delete "${DELETE_ARGS[@]}"

if [ "${NPR_TEARDOWN_NO_WAIT:-0}" = "1" ]; then
  printf '\n%s✓%s delete started. Track it with:\n    az group show --name %s\n\n' \
    "$C_OK" "$C_OFF" "$RESOURCE_GROUP"
else
  printf '\n%s✓%s "%s" deleted.\n\n' "$C_OK" "$C_OFF" "$RESOURCE_GROUP"
fi
