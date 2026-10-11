//! kyoto-check: Kyoto (bip157 at the plan's pin) against the curated list. Each start takes 8
//! random onion peers, whitelist_only, through Tor's SOCKS port, a 30 s handshake timeout and
//! required_peers 3 on mainnet or 2 on signet, then times the start until FiltersSynced.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bip157::chain::checkpoints::HashCheckpoint;
use bip157::chain::ChainState;
use bip157::{AddrV2, BlockHash, Builder, Client, Event, Info, Network, ServiceFlags, TrustedPeer};
use rand::seq::SliceRandom;
use serde::Serialize;
use sha3::{Digest, Sha3_256};

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The service key of a v3 onion host, if its checksum checks.
fn onion_key(host: &str) -> Option<[u8; 32]> {
    let label = host.strip_suffix(".onion").filter(|l| l.len() == 56)?;
    let (mut raw, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in label.bytes() {
        buf = (buf << 5) | B32.iter().position(|&x| x == c)? as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            raw.push((buf >> bits) as u8);
        }
        buf &= (1 << bits) - 1;
    }
    if raw.len() != 35 || raw[34] != 3 {
        return None;
    }
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(&raw[..32]);
    h.update([3u8]);
    let cs = h.finalize();
    if cs[..2] != raw[32..34] {
        return None;
    }
    raw[..32].try_into().ok()
}

#[derive(Serialize, Default)]
struct Start {
    n: usize,
    peers: Vec<String>,
    ok: bool,
    seconds: f64,
    tip_height: Option<u32>,
    tip_hash: Option<String>,
    reached_expected: bool,
    expected_hash_matches: Option<bool>,
    handshakes: usize,
    warnings: BTreeMap<String, usize>,
    error: Option<String>,
}

#[derive(Serialize)]
struct Report {
    network: String,
    list: String,
    socks: String,
    checkpoint: String,
    expect_tip: u32,
    required_peers: u8,
    handshake_timeout_s: u64,
    /// Kyoto's default (5 s) unless set.
    response_timeout_s: Option<u64>,
    starts: Vec<Start>,
    reached: usize,
    seconds_p50: Option<f64>,
    seconds_p90: Option<f64>,
    seconds_max: Option<f64>,
}

fn arg(args: &[String], k: &str) -> Option<String> {
    args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned()
}

/// What every start shares.
struct Setup {
    network: Network,
    socks: SocketAddr,
    cp: HashCheckpoint,
    required: u8,
    expect: (u32, Option<BlockHash>),
    limit: Duration,
    response: Option<Duration>,
}

async fn one(n: usize, peers: &[String], c: &Setup) -> Start {
    let Setup { network, socks, cp, required, expect, limit, response } = *c;
    let mut s = Start { n, peers: peers.to_vec(), ..Start::default() };
    let x49 = ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::COMPACT_FILTERS;
    let trusted: Vec<TrustedPeer> = peers
        .iter()
        .filter_map(|p| {
            let (host, port) = p.rsplit_once(':')?;
            Some(TrustedPeer::new(AddrV2::TorV3(onion_key(host)?), port.parse().ok(), x49))
        })
        .collect();
    let mut builder = Builder::new(network)
        .add_peers(trusted)
        .whitelist_only()
        .required_peers(required)
        .socks5_proxy(socks)
        .handshake_timeout(Duration::from_secs(30))
        .chain_state(ChainState::Checkpoint(cp));
    if let Some(r) = response {
        builder = builder.response_timeout(r);
    }
    let (node, client) = builder.build();
    let Client { requester, mut info_rx, mut warn_rx, mut event_rx } = client;
    let t = Instant::now();
    let mut node = tokio::spawn(node.run());
    let deadline = tokio::time::sleep(limit);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            Some(i) = info_rx.recv() => if matches!(i, Info::SuccessfulHandshake) { s.handshakes += 1 },
            Some(w) = warn_rx.recv() => {
                let key = format!("{w}").split(':').next().unwrap_or("").chars().take(60).collect::<String>();
                *s.warnings.entry(key).or_default() += 1;
            }
            Some(e) = event_rx.recv() => if let Event::FiltersSynced(u) = e {
                s.seconds = t.elapsed().as_secs_f64();
                s.tip_height = Some(u.tip.height);
                s.tip_hash = Some(u.tip.hash.to_string());
                s.reached_expected = u.tip.height >= expect.0;
                if let Some(h) = expect.1 {
                    s.expected_hash_matches = u.recent_history().get(&expect.0).map(|hd| hd.block_hash() == h).or((u.tip.height == expect.0).then_some(u.tip.hash == h));
                }
                s.ok = s.reached_expected && s.expected_hash_matches != Some(false);
                break;
            },
            r = &mut node => {
                s.seconds = t.elapsed().as_secs_f64();
                s.error = Some(match r { Ok(Ok(())) => "node stopped".into(), Ok(Err(e)) => format!("{e}"), Err(e) => format!("node task: {e}") });
                return s;
            }
            _ = &mut deadline => {
                s.seconds = t.elapsed().as_secs_f64();
                s.error = Some(format!("no FiltersSynced within {} s", limit.as_secs()));
                break;
            }
        }
    }
    let _ = requester.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(10), node).await;
    s
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let need = |k: &str| arg(&args, k).unwrap_or_else(|| {
        eprintln!("usage: kyoto-check --list FILE --network mainnet|signet --checkpoint HEIGHT:HASH --expect-tip HEIGHT[:HASH] [--socks 127.0.0.1:29051] [--starts 10] [--peers 8] [--timeout 900] [--response-timeout S] [--out FILE]");
        std::process::exit(2)
    });
    let list_path = need("--list");
    let net_name = need("--network");
    let (network, required) = match net_name.as_str() {
        "mainnet" => (Network::Bitcoin, 3u8),
        "signet" => (Network::Signet, 2u8),
        _ => {
            eprintln!("--network must be mainnet or signet");
            std::process::exit(2)
        }
    };
    let cp_arg = need("--checkpoint");
    let (h, hash) = cp_arg.split_once(':').expect("--checkpoint HEIGHT:HASH");
    let cp = HashCheckpoint::new(h.parse().expect("height"), hash.parse().expect("block hash"));
    let exp_arg = need("--expect-tip");
    let expect: (u32, Option<BlockHash>) = match exp_arg.split_once(':') {
        Some((h, x)) => (h.parse().expect("height"), Some(x.parse().expect("block hash"))),
        None => (exp_arg.parse().expect("height"), None),
    };
    let socks: SocketAddr = arg(&args, "--socks").unwrap_or("127.0.0.1:29051".into()).parse().expect("--socks ip:port");
    let starts: usize = arg(&args, "--starts").map(|v| v.parse().expect("--starts")).unwrap_or(10);
    let pick: usize = arg(&args, "--peers").map(|v| v.parse().expect("--peers")).unwrap_or(8);
    let limit = Duration::from_secs(arg(&args, "--timeout").map(|v| v.parse().expect("--timeout")).unwrap_or(900));
    let response = arg(&args, "--response-timeout").map(|v| Duration::from_secs(v.parse().expect("--response-timeout")));

    let list: serde_json::Value = serde_json::from_slice(&std::fs::read(&list_path).expect("read --list")).expect("list JSON");
    assert_eq!(list["network"].as_str(), Some(net_name.as_str()), "the list is for another network");
    let all: Vec<String> = list["peers"].as_array().expect("peers").iter().filter_map(|p| p.as_str().map(String::from)).collect();
    eprintln!("{net_name}: {} listed peers; {starts} starts of {pick} random peers, required_peers {required}", all.len());

    let setup = Setup { network, socks, cp, required, expect, limit, response };
    let mut out = vec![];
    for n in 1..=starts {
        let mut chosen = all.clone();
        chosen.shuffle(&mut rand::thread_rng());
        chosen.truncate(pick);
        let s = one(n, &chosen, &setup).await;
        eprintln!("start {n}: ok {} in {:.1} s, tip {:?}, handshakes {}, warnings {:?}, error {:?}", s.ok, s.seconds, s.tip_height, s.handshakes, s.warnings, s.error);
        out.push(s);
    }
    let mut times: Vec<f64> = out.iter().filter(|s| s.ok).map(|s| s.seconds).collect();
    times.sort_by(|a, b| a.total_cmp(b));
    let pct = |p: usize| (!times.is_empty()).then(|| times[((p * times.len()).div_ceil(100)).clamp(1, times.len()) - 1]);
    let report = Report {
        network: net_name,
        list: list_path,
        socks: socks.to_string(),
        checkpoint: cp_arg,
        expect_tip: expect.0,
        required_peers: required,
        handshake_timeout_s: 30,
        response_timeout_s: response.map(|r| r.as_secs()),
        reached: out.iter().filter(|s| s.ok).count(),
        seconds_p50: pct(50),
        seconds_p90: pct(90),
        seconds_max: times.last().copied(),
        starts: out,
    };
    let body = serde_json::to_string_pretty(&report).expect("report JSON");
    match arg(&args, "--out") {
        Some(p) => std::fs::write(&p, &body).expect("write --out"),
        None => println!("{body}"),
    }
    println!("{}: reached the tip in {} of {} starts; p50 {:?} s, p90 {:?} s, max {:?} s", report.network, report.reached, report.starts.len(), report.seconds_p50, report.seconds_p90, report.seconds_max);
}
