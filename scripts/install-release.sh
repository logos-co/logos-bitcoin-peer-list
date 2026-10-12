#!/usr/bin/env bash
# Puts a release into the node module: each <network>.json in LIST_DIR that a key the module
# compiles in (rust-lib/keys/) verifies, for its own network and newer than the one shipped,
# then Bitcoin Core's onion v3 fixed seeds. Nothing is copied unless every list passes.
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
if [ ! -d "$dest" ] || [ ! -d "$module/rust-lib/keys" ]; then
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
    f=$lists/$net.json
    [ -f "$f" ] || continue
    ok=""
    for key in "$module"/rust-lib/keys/*.pub.json; do
        out=$("$peer_list" verify --pubkey "$key" "$f" 2>/dev/null) || continue
        case $out in "OK   $f: $net "*) ok=$out; break ;; esac
    done
    [ -n "$ok" ] || { echo "$f: no key in $module/rust-lib/keys verifies it as a $net list" >&2; exit 1; }
    new=$(version_of "$f") old=$(version_of "$dest/$net.json")
    if [ -n "$old" ] && [ "$new" -le "$old" ]; then
        echo "$f: version $new is not newer than the shipped $old" >&2
        exit 1
    fi
    echo "$ok"
    found="$found $net"
done
[ -n "$found" ] || { echo "$lists: no mainnet.json, signet.json or testnet4.json" >&2; exit 1; }

core_src=${BPL_CORE_SRC:-}
if [ -z "$core_src" ]; then
    core_src=$(nix build --no-link --print-out-paths "${BPL_CORE_NIX:-$HOME/repos/logos-bitcoin-core-nix}#bitcoin-core-src")
fi
seeds=$(mktemp -d)
trap 'rm -rf "$seeds"' EXIT
"$peer_list" seeds --core-src "$core_src" --out "$seeds"
for net in $found; do
    cp "$lists/$net.json" "$dest/$net.json"
done
cp "$seeds"/seeds-*.json "$dest/"
echo "installed:$found and the fixed seeds, in $dest"
echo "next: cd $module/rust-lib && cargo test --no-default-features, then commit both there"
