#!/usr/bin/env bash
# Run agentgateway from a git-ignored copy of gateway/config.yaml.
# agentgateway writes an auto-generated session key into the config file it was
# started with; running a copy keeps that secret out of the tracked template.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p gateway/.runtime
runtime=gateway/.runtime/config.yaml
if [ ! -f "$runtime" ] || [ gateway/config.yaml -nt "$runtime" ]; then
  # Keep a key the gateway already generated, so restarts don't invalidate it.
  key=$(grep -A2 '^  session:' "$runtime" 2>/dev/null | awk '/key:/{print $2}' || true)
  cp gateway/config.yaml "$runtime"
  if [ -n "${key:-}" ]; then
    printf '\nconfig:\n  session:\n    key: %s\n' "$key" >> "$runtime"
  fi
fi

exec ./bin/agentgateway-bin -f "$runtime"
