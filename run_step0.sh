#!/usr/bin/env bash
# Step 0: the Tokyo demo on real MCP (SDK 2.3.0, protocol 2026-07-28, stateless).
# Starts both servers, runs the same attack against each, stops them.
set -euo pipefail
cd "$(dirname "$0")"
PY=.venv/bin/python
mkdir -p traces

$PY servers/vulnerable_server.py > traces/vuln.log 2>&1 & VULN=$!
$PY servers/hardened_server.py   > traces/hard.log 2>&1 & HARD=$!
trap 'kill $VULN $HARD 2>/dev/null || true' EXIT
sleep 2

echo "################ VULNERABLE :8181 ################"
$PY attacks/attack.py 8181
echo "################ HARDENED   :8282 ################"
$PY attacks/attack.py 8282
