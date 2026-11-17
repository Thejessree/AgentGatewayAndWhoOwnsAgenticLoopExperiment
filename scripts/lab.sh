#!/usr/bin/env bash
# Start / stop / check the lab: Jaeger, the vulnerable MCP server, agentgateway.
#   ./scripts/lab.sh start | stop | status | restart
# Each process is tracked by a PID file in traces/pids/, so stop never misses one.
set -euo pipefail
cd "$(dirname "$0")/.."
PIDS=traces/pids
mkdir -p "$PIDS" traces

# name | port | command
SERVICES=(
  "jaeger|16686|./bin/jaeger-bin"
  "vulnerable|8181|.venv/bin/python servers/vulnerable_server.py"
  "gateway|3000|./scripts/run_gateway.sh"
)

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

case "${1:-status}" in
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 1; start ;;
  status) status ;;
  *) echo "usage: $0 start|stop|status|restart"; exit 2 ;;
esac
