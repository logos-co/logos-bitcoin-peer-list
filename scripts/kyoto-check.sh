#!/usr/bin/env bash
# Kyoto against a signed list: N starts of 8 random peers through Tor's IsolateDestAddr port,
# from a checkpoint BPL_KYOTO_BACK blocks (default 144) below the tip. BPL_KYOTO_RESPONSE_TIMEOUT
# (seconds) overrides Kyoto's 5 s response timeout, for diagnosis only: the plan keeps the default.
# Usage: kyoto-check.sh mainnet|signet LIST.json PUBKEY.json [starts, default 10]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/env.sh"
net=$1 list=$2 pubkey=$3 starts=${4:-10}
back=${BPL_KYOTO_BACK:-144}

"$BIN_DIR/peer-list" verify --pubkey "$pubkey" "$list"
case $net in
    mainnet)
        # Our proof-of-work-checked header chain, brought to the tip by the listed peers.
        read -r tip tiphash cp cphash < <("$BIN_DIR/peer-list" headers --home "$BPL_HOME" --socks "$BPL_SOCKS" --back "$back")
        ;;
    signet)
        tip=$(bitcoin_cli getblockcount)
        tiphash=$(bitcoin_cli getblockhash "$tip")
        cp=$((tip - back))
        cphash=$(bitcoin_cli getblockhash "$cp")
        ;;
    *)
        echo "network must be mainnet or signet" >&2
        exit 2
        ;;
esac
mkdir -p "$BPL_HOME/kyoto"
out="$BPL_HOME/kyoto/$net-$(date -u +%Y%m%dT%H%M%SZ).json"
echo "$(utc_now) $net: checkpoint $cp, tip $tip; report $out"
"$BIN_DIR/kyoto-check" --list "$list" --network "$net" --socks "$BPL_SOCKS_ISO" \
    --checkpoint "$cp:$cphash" --expect-tip "$tip:$tiphash" --starts "$starts" --out "$out" \
    ${BPL_KYOTO_RESPONSE_TIMEOUT:+--response-timeout "$BPL_KYOTO_RESPONSE_TIMEOUT"}
