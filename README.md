# logos-bitcoin-peer-list

Curates the onion peers that the Logos Bitcoin wallet gives Kyoto (bip157, the BIP157/158 light
client) with `whitelist_only`, so Kyoto never resolves a name. It runs on our build
infrastructure, never on a user's device, and every connection it makes goes through Tor.
The output is a signed list per network that `bitcoin_node_module` ships and verifies.

Spike 5 of the Bitcoin wallet plan: at least 50 mainnet and 10 signet onion peers pass every
check on 6 of 7 days, the testnet4 count is reported, and Kyoto given 8 random listed peers
reaches the tip in 10 of 10 starts.

## What a run does

`peer-list crawl --network mainnet|signet|testnet4` writes `runs/<network>/<UTC stamp>.json`.

Candidates:

- **DNS seeds**, asked for `x49.<seed>` (network, witness and compact filters) through Tor's
  SOCKS RESOLVE. Tor answers one address per query, so each seed is asked 6 times, each on a
  fresh circuit. Seeds return IP addresses only; those peers are dialled through Tor exits for
  their gossip, never listed.
- **btcnodes.io**, `GET /api/v1/snapshots/latest/` over HTTPS through Tor (mainnet only). The
  site allows 10 requests a day per IP; a run makes one at most, we cap ourselves at 3 a day,
  and the last good snapshot stands in when a request fails (`--no-btcnodes` uses it outright).
- **addrv2 gossip**: one `getaddr` per peer per run, after `sendaddrv2` in the handshake.
  BIP155 TorV3 entries with bit 6 become candidates; clearnet x49 entries are dialled for their
  own gossip, up to 100 a run.
- **Our own node** (signet): `getnodeaddresses 0 onion`, entries with bit 6.
- **Earlier runs**: peers that answered in the last 7 runs are checked again, so every peer has
  a daily record.

Checks, all over Tor, one connection per peer:

1. a version handshake whose services include bits 0, 3 and 6;
2. `getcfheaders` for 1000 blocks ending 6 below the tip; the peer's filter hashes are folded
   into the filter headers at both ends and compared with the reference:
   - **signet**: our own Core node (`-blockfilterindex=1`, every connection through our Tor);
   - **mainnet**: *not checked against our own node*. Stop hashes come from a header chain
     checked for proof of work and difficulty from Kyoto's taproot checkpoint (709,631); the
     filter headers are the answer of a majority (at least 3, more than half) of the peers;
   - **testnet4**: handshake only; the count is reported, no reference.

Each peer's record has the connect, handshake and cfheaders latencies; the summary has their
spread over the peers that passed, and failures by kind.

Politeness: 32 connections at most, new Tor streams paced at 2 a second (`--stream-rate`),
RESOLVE 4 at a time, timeouts on every step, one `getaddr` per peer.

## The list

```bash
peer-list list --network mainnet --key /path/to/test-key.secret --last 7 --min-pass 6 --out mainnet.json
peer-list verify --pubkey keys/test-key.pub.json mainnet.json
```

A peer is listed when it passed every check in at least `--min-pass` of the last `--last` runs
(the plan's rule is 6 of 7). The list is the node module's format 1:

```json
{"format":1,"network":"mainnet","version":"202610181200","created":"2026-10-18T12:00:00Z",
 "date":"2026-10-18","note":"...","refreshUrl":null,"peers":["<56>.onion:8333"],
 "keyId":"test-d680f3cac9837bf9","signature":"<128 hex>"}
```

The signature is Ed25519 over the canonical bytes: `logos-bitcoin-peer-list/1\n`, then the
list as compact JSON in this field order with `signature` null. `version` defaults to the
creation time as `YYYYMMDDHHMM`, so a newer list always has a larger version.

**The key in `keys/` is a TEST key.** Its secret was generated locally and is kept outside this
repository; the release key, and where it lives, is still to be decided.

## Running it

On framework.lan, everything lives under `~/btc-peer-list` (`BPL_HOME`); see `scripts/env.sh`
for the ports (Tor 29050 with IsolateSOCKSAuth, 29051 with IsolateDestAddr for Kyoto, signet
RPC 29332).

```bash
scripts/build.sh            # nixpkgs Rust, out of tree in $BPL_HOME/target, -j 8
scripts/tor-start.sh        # our own Tor (nixpkgs), own DataDirectory, PidFile
scripts/signet-start.sh     # our signet node through that Tor; scripts/signet-wait.sh
scripts/daily-run.sh        # one full run, then Tor and bitcoind stopped by PID
scripts/kyoto-check.sh mainnet mainnet.json keys/test-key.pub.json   # 10 Kyoto starts
```

`kyoto-check` uses bip157 at the commit the plan pins (0.7.0 was published from it, untagged):
`whitelist_only`, 8 random listed peers, Tor's IsolateDestAddr port, a 30 s handshake timeout,
`required_peers` 3 on mainnet and 2 on signet, from a checkpoint 144 blocks below the tip. A
start counts when Kyoto reports `FiltersSynced` at or above the tip we saw before it began.

### The daily timer (not installed)

`systemd/` holds a user service and timer for one run a day at about 03:30 UTC. Installing
them is a decision for the machine's owner:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/logos-btc-peer-list.service systemd/logos-btc-peer-list.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now logos-btc-peer-list.timer
loginctl enable-linger "$USER"   # otherwise user timers run only while a session is open
```

The runs need the repository extracted at `~/btc-peer-list/src` and `scripts/build.sh` run
once. Signing stays a separate step where the key is.

## Development

```bash
CARGO_TARGET_DIR=/somewhere/outside cargo test -p peer-list
```
