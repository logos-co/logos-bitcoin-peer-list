#!/usr/bin/env bash
# Stops our signet node: RPC stop first, then its own PID if it lingers.
set -euo pipefail
. "$(dirname "$0")/env.sh"

[ -s "$SIGNET_DIR/bitcoind.pid" ] || { echo "bitcoind: no pid file"; exit 0; }
pid=$(cat "$SIGNET_DIR/bitcoind.pid")
kill -0 "$pid" 2>/dev/null || { echo "bitcoind: pid $pid is not running"; exit 0; }
bitcoin_cli stop >/dev/null 2>&1 || true
for _ in $(seq 1 120); do
    kill -0 "$pid" 2>/dev/null || { echo "bitcoind stopped, pid $pid"; exit 0; }
    sleep 1
done
if tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q -- "-datadir=$SIGNET_DIR"; then
    kill "$pid"
    echo "bitcoind did not stop within 120 s; sent SIGTERM to pid $pid" >&2
fi
exit 1
