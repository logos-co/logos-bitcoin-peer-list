#!/usr/bin/env bash
# Stops our Tor by the PID it wrote; never by name, since other Tor instances share the host.
set -euo pipefail
. "$(dirname "$0")/env.sh"

[ -s "$TOR_DIR/tor.pid" ] || { echo "tor: no pid file"; exit 0; }
pid=$(cat "$TOR_DIR/tor.pid")
if ! kill -0 "$pid" 2>/dev/null; then
    echo "tor: pid $pid is not running"
    rm -f "$TOR_DIR/tor.pid"
    exit 0
fi
# The pid file is ours, but check the process really is our tor before signalling it.
if ! tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q -- "-f $TOR_DIR/torrc"; then
    echo "tor: pid $pid is not our tor; leaving it" >&2
    exit 1
fi
kill "$pid"
for _ in $(seq 1 30); do
    kill -0 "$pid" 2>/dev/null || { rm -f "$TOR_DIR/tor.pid"; echo "tor stopped, pid $pid"; exit 0; }
    sleep 1
done
echo "tor pid $pid did not stop within 30 s" >&2
exit 1
