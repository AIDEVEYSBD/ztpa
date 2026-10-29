#!/usr/bin/env bash
# Start a Container Apps job execution with an exact command line.
#   start-job.sh <resource-group> <job> <image> <command> [args...]
# Prints the execution name. Uses the REST API rather than `az containerapp job
# start --args`, which hands a whole command line over as ONE argument and
# reads any argument starting with "-" as one of its own options.
# The execution template replaces the container definition, so the job's own
# env (including Key Vault secret references) and resources are carried over.
set -euo pipefail
rg="$1"; job="$2"; image="$3"; shift 3
sub=$(az account show --query id -o tsv)
base="https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$job"
current=$(az rest --method get --url "$base?api-version=2024-03-01" --query "properties.template.containers[0]" -o json)
body=$(python3 - "$image" "$current" "$@" <<'PY'
import json, sys
image, current, cmd = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3:]
c = {"name": current["name"], "image": image, "command": cmd[:1], "args": cmd[1:],
     "env": current.get("env") or [], "resources": current.get("resources") or {}}
print(json.dumps({"containers": [c]}))
PY
)
az rest --method post --url "$base/start?api-version=2024-03-01" --body "$body" --query name -o tsv
