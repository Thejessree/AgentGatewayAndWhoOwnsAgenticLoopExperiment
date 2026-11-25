#!/usr/bin/env bash
# Start / stop / check the lab: Jaeger, an MCP server, agentgateway.
#   ./scripts/lab.sh start | stop | status | restart            # experiment 1
#   LAB=exp2 ./scripts/lab.sh start | stop | status | restart   # experiment 2
# Each process is tracked by a PID file in traces/pids/, so stop never misses one.
set -euo pipefail
cd "$(dirname "$0")/.."
PIDS=traces/pids
mkdir -p "$PIDS" traces

# name | port | command
case "${LAB:-exp1}" in
  exp1) SERVICES=(
    "jaeger|16686|./bin/jaeger-bin"
    "vulnerable|8181|.venv/bin/python servers/vulnerable_server.py"
    "gateway|3000|./scripts/run_gateway.sh gateway/config.yaml"
  ) ;;
  exp2) SERVICES=(
    "jaeger|16686|./bin/jaeger-bin"
    "helpdesk|8383|.venv/bin/python servers/helpdesk_server.py"
    "gateway|3000|./scripts/run_gateway.sh gateway/exp2.yaml"
  ) ;;
  *) echo "unknown LAB=${LAB}; use exp1 or exp2"; exit 2 ;;
esac

running() { [ -f "$PIDS/$1.pid" ] && kill -0 "$(cat "$PIDS/$1.pid")" 2>/dev/null; }

port_free() { ! nc -z 127.0.0.1 "$1" 2>/dev/null; }

start() {
  for s in "${SERVICES[@]}"; do
    IFS='|' read -r name port cmd <<<"$s"
    if running "$name"; then echo "$name already running (pid $(cat "$PIDS/$name.pid"))"; continue; fi
    if ! port_free "$port"; then
      echo "port $port is taken by something this script didn't start:"; lsof -nP -iTCP:"$port" -sTCP:LISTEN || true
      echo "stop it first"; exit 1
    fi
    nohup $cmd > "traces/$name.log" 2>&1 &
    echo $! > "$PIDS/$name.pid"
    for _ in $(seq 1 20); do nc -z 127.0.0.1 "$port" 2>/dev/null && break; sleep 0.5; done
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then echo "$name up on :$port (pid $!)"
    else echo "$name FAILED to start; see traces/$name.log"; tail -5 "traces/$name.log"; exit 1; fi
  done
}

stop() {
  for s in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ <<<"$s"
    if running "$name"; then kill "$(cat "$PIDS/$name.pid")" && echo "stopped $name"; fi
    rm -f "$PIDS/$name.pid"
  done
}

status() {
  for s in "${SERVICES[@]}"; do
    IFS='|' read -r name port _ <<<"$s"
    if running "$name"; then echo "$name  running  pid $(cat "$PIDS/$name.pid")  :$port"
    else echo "$name  stopped"; fi
  done
}

restart_one() {
  local target=$1
  [ -f "$PIDS/$target.pid" ] && kill "$(cat "$PIDS/$target.pid")" 2>/dev/null && echo "stopped $target"
  rm -f "$PIDS/$target.pid"
  sleep 1
  start   # starts only what isn't running
}

case "${1:-status}" in
  start) start ;;
  stop) stop ;;
  restart) if [ -n "${2:-}" ]; then restart_one "$2"; else stop; sleep 1; start; fi ;;
  status) status ;;
  *) echo "usage: $0 start|stop|status|restart [service]"; exit 2 ;;
esac
