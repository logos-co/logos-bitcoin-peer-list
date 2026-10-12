#!/usr/bin/env bash
# One release crawl per network, at release time only: our Tor (and for signet our signet node),
# `peer-list release` for each network, then both stopped by PID. The signed lists land in
# $BPL_HOME/release; install-release.sh puts them in the node module.
# Usage: BPL_KEY=SECRET [BPL_RELEASE_RUNS=N] release.sh [mainnet] [signet] [testnet4]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/env.sh"
: "${BPL_KEY:?set BPL_KEY to the secret file of the signing key}"
runs=${BPL_RELEASE_RUNS:-1}
nets=${*:-mainnet signet testnet4}
mkdir -p "$LOG_DIR"

exec 9>"$BPL_HOME/run.lock"
if ! flock -n 9; then
    echo "$(utc_now) another run holds $BPL_HOME/run.lock" >&2
    exit 1
fi

cleanup() {
    bash "$here/signet-stop.sh" || true
    bash "$here/tor-stop.sh" || true
    echo "$(utc_now) release finished"
}
trap cleanup EXIT

echo "$(utc_now) release starting: $nets, peers that pass in each of the last $runs run(s)"
bash "$here/tor-start.sh"
# Our signet node catches up while the other networks crawl.
case " $nets " in *" signet "*) bash "$here/signet-start.sh" ;; esac

status=0
for net in $nets; do
    rpc=""
    if [ "$net" = signet ]; then
        if ! bash "$here/signet-wait.sh" "${BPL_SIGNET_WAIT:-7200}"; then
            echo "$(utc_now) signet node not at the tip: signet skipped" >&2
            status=1
            continue
        fi
        rpc="--rpc-port $BPL_SIGNET_RPC --rpc-cookie $SIGNET_DIR/signet/.cookie"
    fi
    # shellcheck disable=SC2086 # $rpc is two flag pairs, paths without spaces
    "$BIN_DIR/peer-list" release --network "$net" --home "$BPL_HOME" --socks "$BPL_SOCKS" \
        --key "$BPL_KEY" --runs "$runs" $rpc || { echo "$(utc_now) $net: no list" >&2; status=1; }
done
ls -l "$BPL_HOME/release"
exit $status
