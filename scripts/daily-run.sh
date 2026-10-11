#!/usr/bin/env bash
# One daily run: our Tor, our signet node, a crawl per network, then both stopped by PID.
# The systemd user timer in ../systemd runs this; it is not installed by anything here.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/env.sh"
mkdir -p "$LOG_DIR"

exec 9>"$BPL_HOME/run.lock"
if ! flock -n 9; then
    echo "$(utc_now) another run holds $BPL_HOME/run.lock" >&2
    exit 1
fi

cleanup() {
    bash "$here/signet-stop.sh" || true
    bash "$here/tor-stop.sh" || true
    echo "$(utc_now) daily run finished"
}
trap cleanup EXIT

echo "$(utc_now) daily run starting"
bash "$here/tor-start.sh"
bash "$here/signet-start.sh"

"$BIN_DIR/peer-list" crawl --network mainnet --home "$BPL_HOME" --socks "$BPL_SOCKS" || echo "$(utc_now) mainnet crawl failed"
"$BIN_DIR/peer-list" crawl --network testnet4 --home "$BPL_HOME" --socks "$BPL_SOCKS" || echo "$(utc_now) testnet4 crawl failed"
# The signet crawl needs our node at the tip; after a day off it catches up in minutes.
if bash "$here/signet-wait.sh" "${BPL_SIGNET_WAIT:-7200}"; then
    "$BIN_DIR/peer-list" crawl --network signet --home "$BPL_HOME" --socks "$BPL_SOCKS" \
        --rpc-port "$BPL_SIGNET_RPC" --rpc-cookie "$SIGNET_DIR/signet/.cookie" || echo "$(utc_now) signet crawl failed"
else
    echo "$(utc_now) signet node not at the tip: signet skipped"
fi
