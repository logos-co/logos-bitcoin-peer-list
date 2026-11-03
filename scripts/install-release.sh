#!/usr/bin/env bash
# Puts a release into the node module: each <network>.json and clearnet-<network>.json in LIST_DIR
# that `peer-list verify` finds well formed, for its own network and newer than the one shipped,
# then Bitcoin Core's fixed seeds. Nothing is copied unless every list passes.
# Usage: install-release.sh NODE_MODULE_DIR LIST_DIR
#   BPL_PEER_LIST  the peer-list binary (default $BIN_DIR/peer-list, from scripts/build.sh)
#   BPL_CORE_SRC   a Core source tree; default: bitcoin-core-src of BPL_CORE_NIX
#                  (default ~/repos/logos-bitcoin-core-nix), the source the wallet's Core builds from
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/env.sh"
[ $# -eq 2 ] || { echo "usage: $0 NODE_MODULE_DIR LIST_DIR" >&2; exit 2; }
module=$1 lists=$2
dest=$module/rust-lib/peer-lists
if [ ! -d "$dest" ]; then
    echo "$module: not a node module checkout" >&2
    exit 2
fi
peer_list=${BPL_PEER_LIST:-$BIN_DIR/peer-list}
[ -x "$peer_list" ] || { echo "$peer_list: build it with scripts/build.sh, or set BPL_PEER_LIST" >&2; exit 2; }

version_of() {
    [ -f "$1" ] || return 0
    sed -n 's/^ *"version": *"\([0-9]*\)".*/\1/p' "$1" | head -1
}

found=""
for net in mainnet signet testnet4; do
    for name in "$net" "clearnet-$net"; do
        f=$lists/$name.json
        [ -f "$f" ] || continue
        kind=onion
        [ "$name" = "$net" ] || kind=clearnet
        ok=$("$peer_list" verify "$f") || { echo "$ok" >&2; exit 1; }
        case $ok in "OK   $f: $net v"*" $kind peers") ;; *) echo "$f: not a $net $kind list ($ok)" >&2; exit 1 ;; esac
        new=$(version_of "$f") old=$(version_of "$dest/$name.json")
        if [ -n "$old" ] && [ "$new" -le "$old" ]; then
            echo "$f: version $new is not newer than the shipped $old" >&2
            exit 1
        fi
        echo "$ok"
        found="$found $name"
    done
done
[ -n "$found" ] || { echo "$lists: no <network>.json or clearnet-<network>.json" >&2; exit 1; }

core_src=${BPL_CORE_SRC:-}
if [ -z "$core_src" ]; then
    core_src=$(nix build --no-link --print-out-paths "${BPL_CORE_NIX:-$HOME/repos/logos-bitcoin-core-nix}#bitcoin-core-src")
fi
seeds=$(mktemp -d)
trap 'rm -rf "$seeds"' EXIT
"$peer_list" seeds --core-src "$core_src" --out "$seeds"
for name in $found; do
    cp "$lists/$name.json" "$dest/$name.json"
done
cp "$seeds"/seeds-*.json "$seeds"/clearnet-seeds-*.json "$dest/"
echo "installed:$found and the fixed seeds, in $dest"
echo "next: cd $module/rust-lib && cargo test --no-default-features, then commit both there"
