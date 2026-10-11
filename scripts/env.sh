# Shared settings for the run scripts. Every value can be overridden from the environment.
: "${BPL_HOME:=$HOME/btc-peer-list}"
# IsolateSOCKSAuth: the crawler and bitcoind send fresh SOCKS credentials per connection.
: "${BPL_SOCKS:=127.0.0.1:29050}"
# IsolateDestAddr without auth, for Kyoto (which speaks unauthenticated SOCKS only).
: "${BPL_SOCKS_ISO:=127.0.0.1:29051}"
: "${BPL_SIGNET_RPC:=29332}"
: "${BPL_NIXPKGS:=nixpkgs}"

TOR_DIR=$BPL_HOME/tor
SIGNET_DIR=$BPL_HOME/signet
STATE_DIR=$BPL_HOME/state
RUNS_DIR=$BPL_HOME/runs
LOG_DIR=$BPL_HOME/logs
BIN_DIR=$BPL_HOME/bin

bitcoin_cli() {
    nix shell "$BPL_NIXPKGS#bitcoind" -c bitcoin-cli -signet -datadir="$SIGNET_DIR" -rpcport="$BPL_SIGNET_RPC" "$@"
}

utc_now() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}
