#!/usr/bin/env bash
# Wait for a Container Apps job execution to finish; exit non-zero unless it succeeded.
#   wait-job.sh <resource-group> <job-name> <execution-name> [timeout-seconds]
set -euo pipefail
rg="$1"; job="$2"; exec_name="$3"; timeout="${4:-900}"
deadline=$(( $(date +%s) + timeout ))
while :; do
  status=$(az containerapp job execution show -g "$rg" -n "$job" --job-execution-name "$exec_name" \
             --query properties.status -o tsv 2>/dev/null || echo Unknown)
  echo "execution $exec_name: $status"
  case "$status" in
    Succeeded) exit 0 ;;
    Failed|Stopped|Degraded)
      echo "::error::job execution $exec_name ended $status"
      az containerapp job logs show -g "$rg" -n "$job" --execution "$exec_name" --container migrate 2>/dev/null | tail -50 || true
      exit 1 ;;
  esac
  [ "$(date +%s)" -lt "$deadline" ] || { echo "::error::timed out waiting for $exec_name"; exit 1; }
  sleep 10
done
