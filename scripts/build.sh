#!/usr/bin/env bash
# Builds peer-list and kyoto-check out of tree with nixpkgs' Rust, at most 8 jobs, into $BIN_DIR.
set -euo pipefail
. "$(dirname "$0")/env.sh"
src=$(cd "$(dirname "$0")/.." && pwd)

mkdir -p "$BIN_DIR"
export CARGO_TARGET_DIR=$BPL_HOME/target
nix shell "$BPL_NIXPKGS#cargo" "$BPL_NIXPKGS#rustc" "$BPL_NIXPKGS#gcc" -c \
    cargo build --release --locked -j "${BPL_JOBS:-8}" --manifest-path "$src/Cargo.toml"
install -m 755 "$CARGO_TARGET_DIR/release/peer-list" "$CARGO_TARGET_DIR/release/kyoto-check" "$BIN_DIR/"
echo "built: $("$BIN_DIR/peer-list" 2>&1 | head -1 || true)"
ls -la "$BIN_DIR"
