#!/usr/bin/env bash
# Run agentgateway from a git-ignored copy of a config template.
#   ./scripts/run_gateway.sh                     # gateway/config.yaml (experiment 1)
#   ./scripts/run_gateway.sh gateway/exp3.yaml   # experiment 3
# agentgateway writes an auto-generated session key into the config file it was
# started with; running a copy keeps that secret out of the tracked template.
set -euo pipefail
cd "$(dirname "$0")/.."

template=${1:-gateway/config.yaml}
mkdir -p gateway/.runtime
runtime=gateway/.runtime/$(basename "$template")
if [ ! -f "$runtime" ] || [ "$template" -nt "$runtime" ]; then
  # Keep a key the gateway already generated, so restarts don't invalidate it.
  key=$(grep -A2 '^  session:' "$runtime" 2>/dev/null | awk '/key:/{print $2}' || true)
  cp "$template" "$runtime"
  if [ -n "${key:-}" ]; then
    printf '\nconfig:\n  session:\n    key: %s\n' "$key" >> "$runtime"
  fi
fi

exec ./bin/agentgateway-bin -f "$runtime"
