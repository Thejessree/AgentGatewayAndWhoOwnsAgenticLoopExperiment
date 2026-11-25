#!/usr/bin/env bash
# Experiment 2, part 2: does removing one leg of the trifecta stop the leak, and what does it cost?
#
#   baseline               every scope, open-ended lookup_account(email)
#   fix1-no-account-scope  gateway: the agent's token loses accounts:read
#   fix2-requester-lookup  tool design: get_requester_account(ticket_id) replaces lookup_account(email)
#
# Usage: LAB=exp2 ./scripts/lab.sh start && ./experiments/exp2_fixes.sh [runs-per-cell]
set -euo pipefail
cd "$(dirname "$0")/.."
export LAB=exp2
RUNS=${1:-3}
MODELS=(gemini-2.5-flash gemini-3.1-flash-lite)
ALL="tickets:read accounts:read tickets:reply"
START=$(date +%s)

helpdesk_mode() {
  HELPDESK_LOOKUP=$1 ./scripts/lab.sh restart helpdesk | grep -E "helpdesk (up|FAILED)"
}

./scripts/lab.sh restart gateway | grep -E "gateway (up|FAILED)"   # pick up gateway/exp2.yaml changes

run_cell() {   # label scope
  for m in "${MODELS[@]}"; do
    for i in $(seq 1 "$RUNS"); do
      .venv/bin/python agent/support_agent.py --label "$1" --model "$m" --scope "$2" --trace-content 2>&1 \
        | grep -E "^\[$1\]"
    done
  done
}

helpdesk_mode email
run_cell baseline "$ALL"
run_cell fix1-no-account-scope "tickets:read tickets:reply"
helpdesk_mode requester
run_cell fix2-requester-lookup "$ALL"
helpdesk_mode email

.venv/bin/python - "$START" <<'EOF'
import json, sys
from collections import defaultdict
start = float(sys.argv[1])
cells = defaultdict(list)
for r in map(json.loads, open("traces/exp2_runs.jsonl")):
    if r["ts"] >= start:
        cells[(r["label"], r["model"])].append(r)
print("\n| Setup | Model | PIN leaked | Answered Mallory's plan question |")
print("|---|---|:---:|:---:|")
for (label, model), rs in cells.items():
    leaks = sum(r["outcome"] == "LEAKED" for r in rs)
    useful = sum(r["answered_plan"] for r in rs)
    print(f"| {label} | {model} | {leaks} / {len(rs)} | {useful} / {len(rs)} |")
EOF
