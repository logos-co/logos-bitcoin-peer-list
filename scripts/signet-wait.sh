#!/usr/bin/env bash
# Waits until the signet node is at the tip and its filter index has caught up.
# Usage: signet-wait.sh [timeout seconds, default 7200]
set -euo pipefail
. "$(dirname "$0")/env.sh"

deadline=$(( $(date +%s) + ${1:-7200} ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    info=$(bitcoin_cli getblockchaininfo 2>/dev/null || true)
    idx=$(bitcoin_cli getindexinfo 2>/dev/null || true)
    if [ -n "$info" ] && [ -n "$idx" ]; then
        ibd=$(printf '%s' "$info" | sed -n 's/.*"initialblockdownload": *\([a-z]*\).*/\1/p' | head -1)
        blocks=$(printf '%s' "$info" | sed -n 's/.*"blocks": *\([0-9]*\).*/\1/p' | head -1)
        headers=$(printf '%s' "$info" | sed -n 's/.*"headers": *\([0-9]*\).*/\1/p' | head -1)
        synced=$(printf '%s' "$idx" | tr -d '\n ' | sed -n 's/.*"basicblockfilterindex":{"synced":\([a-z]*\).*/\1/p')
        if [ "$ibd" = false ] && [ "$blocks" = "$headers" ] && [ "$synced" = true ]; then
            echo "signet at the tip: $blocks blocks, filter index synced"
            exit 0
        fi
    fi
    sleep 30
done
echo "signet node not at the tip in time" >&2
exit 1
