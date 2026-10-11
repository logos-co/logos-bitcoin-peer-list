#!/usr/bin/env bash
# Starts our own Tor from nixpkgs as a daemon (own DataDirectory, PidFile) and waits for bootstrap.
set -euo pipefail
. "$(dirname "$0")/env.sh"

mkdir -p "$TOR_DIR/data"
chmod 700 "$TOR_DIR" "$TOR_DIR/data"
if [ -s "$TOR_DIR/tor.pid" ] && kill -0 "$(cat "$TOR_DIR/tor.pid")" 2>/dev/null; then
    echo "tor already running, pid $(cat "$TOR_DIR/tor.pid")"
    exit 0
fi

cat > "$TOR_DIR/torrc" <<EOF
DataDirectory $TOR_DIR/data
PidFile $TOR_DIR/tor.pid
RunAsDaemon 1
Log notice file $TOR_DIR/tor.log
SocksPort $BPL_SOCKS IsolateSOCKSAuth ExtendedErrors
SocksPort $BPL_SOCKS_ISO IsolateDestAddr ExtendedErrors
EOF

start_and_wait() {
    : > "$TOR_DIR/tor.log"
    rm -f "$TOR_DIR/tor.pid"
    nix shell "$BPL_NIXPKGS#tor" -c tor -f "$TOR_DIR/torrc" --quiet
    for _ in $(seq 1 300); do
        if grep -q "Bootstrapped 100%" "$TOR_DIR/tor.log"; then
            echo "tor bootstrapped, pid $(cat "$TOR_DIR/tor.pid")"
            return 0
        fi
        sleep 1
    done
    return 1
}

start_and_wait && exit 0
# Guards that stop answering circuit handshakes (seen 2026-10-11) block bootstrap for good:
# set the state aside once, so Tor picks new guards.
echo "tor did not bootstrap within 300 s; retrying with fresh guards" >&2
cp "$TOR_DIR/tor.log" "$TOR_DIR/tor.failed-bootstrap.log"
bash "$(dirname "$0")/tor-stop.sh" || true
[ -f "$TOR_DIR/data/state" ] && mv "$TOR_DIR/data/state" "$TOR_DIR/state.stuck-guards.$(date +%s)"
start_and_wait && exit 0
echo "tor did not bootstrap with fresh guards either; see $TOR_DIR/tor.log" >&2
exit 1
