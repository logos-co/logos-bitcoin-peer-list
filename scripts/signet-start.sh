#!/usr/bin/env bash
# Starts our signet reference node (nixpkgs bitcoind) with the compact filter index, every
# connection through our Tor: -proxy also carries the DNS seeds, as addrfetch connections.
set -euo pipefail
. "$(dirname "$0")/env.sh"

mkdir -p "$SIGNET_DIR"
chmod 700 "$SIGNET_DIR"
if [ -s "$SIGNET_DIR/bitcoind.pid" ] && kill -0 "$(cat "$SIGNET_DIR/bitcoind.pid")" 2>/dev/null; then
    echo "bitcoind already running, pid $(cat "$SIGNET_DIR/bitcoind.pid")"
    exit 0
fi

nix shell "$BPL_NIXPKGS#bitcoind" -c bitcoind -signet -datadir="$SIGNET_DIR" -daemon \
    -pid="$SIGNET_DIR/bitcoind.pid" \
    -proxy="$BPL_SOCKS" -listen=0 -discover=0 \
    -blockfilterindex=1 \
    -server=1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport="$BPL_SIGNET_RPC" \
    -disablewallet=1 -dbcache="${BPL_SIGNET_DBCACHE:-2000}" -par=4 -printtoconsole=0

for _ in $(seq 1 60); do
    if bitcoin_cli -rpcwait -rpcwaittimeout=1 getblockcount >/dev/null 2>&1; then
        echo "bitcoind up, pid $(cat "$SIGNET_DIR/bitcoind.pid")"
        exit 0
    fi
    sleep 1
done
echo "bitcoind RPC did not come up within 60 s; see $SIGNET_DIR/signet/debug.log" >&2
exit 1
