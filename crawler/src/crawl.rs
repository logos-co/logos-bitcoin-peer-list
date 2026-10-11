//! One run for one network: candidates from the DNS seeds, btcnodes.io, our own node and peers'
//! addrv2 gossip; checks over Tor with bounded concurrency; the run's JSON file.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::bip158::FilterHeader;
use bitcoin::p2p::address::AddrV2;
use bitcoin::{BlockHash, Network};
use rand::seq::SliceRandom;
use serde_json::{json, Value};
use tokio::task::JoinSet;

use crate::headers::{self, Chain};
use crate::netcfg::NetCfg;
use crate::onion;
use crate::p2p::{Conn, X49};
use crate::results::*;
use crate::rpc::Rpc;
use crate::socks::{self, Target};
use crate::util::{isolation, percentiles, rfc3339, stamp, unix_now};

const BIT6: u64 = 1 << 6;

pub struct Opts {
    pub net: NetCfg,
    pub socks: SocketAddr,
    pub state_dir: PathBuf,
    pub runs_dir: PathBuf,
    pub concurrency: usize,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub cfheaders_timeout: Duration,
    pub getaddr_window: Duration,
    pub budget: usize,
    pub range: u32,
    pub depth: u32,
    pub btcnodes: bool,
    /// Our own node's RPC port and cookie (signet).
    pub rpc: Option<(u16, PathBuf)>,
    pub seed_queries: u32,
    /// Earlier runs whose peers are checked again.
    pub previous: usize,
    /// Clearnet x49 peers from gossip, dialled for their own gossip only, at most.
    pub gossip_clearnet: usize,
    /// Onion candidates learned from gossip this run, at most: most are dead, and each dead
    /// onion costs Tor several descriptor lookups.
    pub gossip_onion: usize,
    /// Gossip entries last seen longer ago than this are ignored.
    pub gossip_max_age: Duration,
}

/// What every peer is asked: filter headers for `start..=stop`, and our node's answer if we have one.
struct Expect {
    start: u32,
    stop: BlockHash,
    count: u32,
    own: Option<(FilterHeader, FilterHeader)>,
}

struct Ctx {
    socks: SocketAddr,
    network: Network,
    gossip_min_time: u32,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    cfheaders_timeout: Duration,
    getaddr_window: Duration,
    expect: Option<Expect>,
}

struct Checked {
    onion: bool,
    r: PeerResult,
    /// Onion v3 `host:port` with bit 6, from this peer's addrv2.
    gossip: Vec<String>,
    /// IPv4/IPv6 `host:port` with bits 0, 3 and 6, from the same answer.
    gossip_clear: Vec<String>,
    gossip_onion: usize,
}

fn ms(t: Instant) -> u64 {
    t.elapsed().as_millis() as u64
}

fn fmt_addr(ip: &IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(a) => format!("{a}:{port}"),
        IpAddr::V6(a) => format!("[{a}]:{port}"),
    }
}

async fn check(ctx: Arc<Ctx>, addr: String, is_onion: bool) -> Checked {
    let mut out = Checked { onion: is_onion, r: PeerResult { addr: addr.clone(), ..PeerResult::default() }, gossip: vec![], gossip_clear: vec![], gossip_onion: 0 };
    let r = &mut out.r;
    let Some((host, port)) = onion::split_host_port(&addr) else {
        r.failure = Some("address: not host:port".into());
        return out;
    };
    let target = if is_onion {
        Target::Name(host)
    } else {
        match host.parse::<IpAddr>() {
            Ok(ip) => Target::Ip(ip),
            Err(_) => {
                r.failure = Some("address: not an IP".into());
                return out;
            }
        }
    };
    let t = Instant::now();
    let tcp = match tokio::time::timeout(ctx.connect_timeout, socks::connect(ctx.socks, &target, port, &isolation())).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            r.failure = Some(format!("connect: {e}"));
            return out;
        }
        Err(_) => {
            r.failure = Some("connect: timeout".into());
            return out;
        }
    };
    r.connect_ms = Some(ms(t));
    let mut c = Conn::new(tcp, ctx.network);
    let t = Instant::now();
    let v = match tokio::time::timeout(ctx.handshake_timeout, c.handshake()).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            r.failure = Some(format!("handshake: {e}"));
            return out;
        }
        Err(_) => {
            r.failure = Some("handshake: timeout".into());
            return out;
        }
    };
    r.handshake_ms = Some(ms(t));
    let services = v.services.to_u64();
    r.version = Some(v.version);
    r.services = Some(format!("0x{services:x}"));
    r.user_agent = Some(v.user_agent.chars().take(80).collect());
    r.start_height = Some(v.start_height);
    r.services_ok = services & X49 == X49;
    if !r.services_ok {
        r.failure = Some("services: missing-bits (needs 0, 3 and 6)".into());
    }
    if let (true, true, Some(e)) = (is_onion, services & BIT6 != 0, &ctx.expect) {
        let t = Instant::now();
        match tokio::time::timeout(ctx.cfheaders_timeout, c.cfheaders(e.start, e.stop, e.count)).await {
            Ok(Ok((prev, last))) => {
                r.cfheaders_ms = Some(ms(t));
                r.prev_filter_header = Some(prev.to_string());
                r.stop_filter_header = Some(last.to_string());
                if let Some((p, s)) = e.own {
                    r.cfheaders_match = Some(prev == p && last == s);
                }
            }
            Ok(Err(err)) => {
                r.failure.get_or_insert(format!("cfheaders: {err}"));
            }
            Err(_) => {
                r.failure.get_or_insert("cfheaders: timeout".into());
            }
        }
    }
    // One getaddr per peer per run.
    if let Ok(Ok(entries)) = tokio::time::timeout(ctx.getaddr_window + Duration::from_secs(5), c.getaddr(ctx.getaddr_window)).await {
        r.gossip_addresses = Some(entries.len());
        for e in entries.into_iter().filter(|e| e.time >= ctx.gossip_min_time) {
            let svc = e.services.to_u64();
            match e.addr {
                AddrV2::TorV3(pk) => {
                    out.gossip_onion += 1;
                    if svc & BIT6 != 0 && e.port != 0 {
                        out.gossip.push(format!("{}:{}", onion::from_pubkey(&pk), e.port));
                    }
                }
                AddrV2::Ipv4(ip) if svc & X49 == X49 && e.port != 0 => out.gossip_clear.push(fmt_addr(&IpAddr::V4(ip), e.port)),
                AddrV2::Ipv6(ip) if svc & X49 == X49 && e.port != 0 => out.gossip_clear.push(fmt_addr(&IpAddr::V6(ip), e.port)),
                _ => {}
            }
        }
        r.gossip_onion_bit6 = Some(out.gossip.len());
    }
    out
}

/// Peers of the last `n` runs worth checking again: those that passed, then those that answered.
pub fn previous_peers(run_dir: &Path, n: usize) -> Vec<String> {
    let runs = load_runs(run_dir, n);
    let mut passed = BTreeSet::new();
    let mut answered = BTreeSet::new();
    for run in &runs {
        for p in &run.peers {
            if p.passed {
                passed.insert(p.addr.clone());
            } else if p.handshake_ms.is_some() {
                answered.insert(p.addr.clone());
            }
        }
    }
    let mut out: Vec<String> = passed.iter().cloned().collect();
    out.extend(answered.into_iter().filter(|a| !passed.contains(a)));
    out
}

/// The last `n` runs in a network's directory, oldest first.
pub fn load_runs(run_dir: &Path, n: usize) -> Vec<Run> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(run_dir)
        .map(|d| d.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect())
        .unwrap_or_default();
    files.sort();
    let skip = files.len().saturating_sub(n);
    files[skip..].iter().filter_map(|p| serde_json::from_slice::<Run>(&std::fs::read(p).ok()?).ok()).collect()
}

async fn signet_reference(rpc: &Rpc, range: u32, depth: u32, reference: &mut Reference) -> Result<Expect, String> {
    let info = rpc.call("getblockchaininfo", json!([])).await?;
    if info["initialblockdownload"] != Value::Bool(false) || info["blocks"] != info["headers"] {
        return Err(format!("our node is not at the tip: {} of {} blocks", info["blocks"], info["headers"]));
    }
    let idx = rpc.call("getindexinfo", json!(["basic block filter index"])).await?;
    if idx["basic block filter index"]["synced"] != Value::Bool(true) {
        return Err("our node's filter index is not synced".into());
    }
    let tip = info["blocks"].as_u64().ok_or("getblockchaininfo: no height")? as u32;
    let stop_h = tip - depth;
    let start = stop_h + 1 - range;
    let stop: BlockHash = rpc.block_hash(stop_h).await?.parse().map_err(|e| format!("block hash: {e}"))?;
    let prev: FilterHeader = rpc.filter_header(start - 1).await?.parse().map_err(|e| format!("filter header: {e}"))?;
    let last: FilterHeader = rpc.filter_header(stop_h).await?.parse().map_err(|e| format!("filter header: {e}"))?;
    *reference = Reference {
        kind: "own-node".into(),
        checked_against_own_node: true,
        tip_height: Some(tip),
        start_height: Some(start),
        stop_height: Some(stop_h),
        stop_hash: Some(stop.to_string()),
        prev_filter_header: Some(prev.to_string()),
        stop_filter_header: Some(last.to_string()),
        note: "filter headers from our own Core node (-blockfilterindex=1), reached over Tor".into(),
        ..Reference::default()
    };
    Ok(Expect { start, stop, count: range, own: Some((prev, last)) })
}

async fn mainnet_reference(o: &Opts, peers: &[String], range: u32, depth: u32, reference: &mut Reference) -> Result<Expect, String> {
    let path = o.state_dir.join("mainnet-headers.bin");
    let base: BlockHash = headers::BASE_HASH.parse().map_err(|e| format!("checkpoint: {e}"))?;
    let mut chain = Chain::load(&path, headers::BASE_HEIGHT, base);
    let before = chain.tip_height();
    let s = headers::sync(&mut chain, &path, o.net.network, o.socks, peers).await;
    let tip = chain.tip_height();
    reference.headers_note = Some(format!(
        "headers {before} -> {tip} (+{}) from {} peers, {} at their tip; highest peer start_height {}; errors: {}",
        s.fetched,
        s.tried,
        s.confirmed,
        s.max_peer_height,
        s.errors.len()
    ));
    if s.confirmed == 0 {
        return Err(format!("header sync: no peer confirmed a tip ({:?})", s.errors.iter().take(5).collect::<Vec<_>>()));
    }
    let stop_h = tip - depth;
    let start = stop_h + 1 - range;
    let stop = chain.hash_at(stop_h).ok_or("no stop hash")?;
    *reference = Reference {
        kind: "peer-agreement".into(),
        checked_against_own_node: false,
        tip_height: Some(tip),
        start_height: Some(start),
        stop_height: Some(stop_h),
        stop_hash: Some(stop.to_string()),
        headers_note: reference.headers_note.take(),
        note: "not checked against our own node: filter headers are the majority answer of independent onion peers; block hashes from a proof-of-work-checked header chain from Kyoto's taproot checkpoint".into(),
        ..Reference::default()
    };
    Ok(Expect { start, stop, count: range, own: None })
}

/// Majority answer among peers (mainnet): at least 3 peers and more than half of those that answered.
fn agreement(run: &mut Run) {
    let mut groups: HashMap<(String, String), usize> = HashMap::new();
    for p in &run.peers {
        if let (Some(a), Some(b)) = (&p.prev_filter_header, &p.stop_filter_header) {
            *groups.entry((a.clone(), b.clone())).or_default() += 1;
        }
    }
    let responding: usize = groups.values().sum();
    let best = groups.into_iter().max_by_key(|(_, n)| *n);
    run.reference.responding = Some(responding);
    match best {
        Some((pair, n)) if n >= 3 && n * 2 > responding => {
            run.reference.agreeing = Some(n);
            run.reference.prev_filter_header = Some(pair.0.clone());
            run.reference.stop_filter_header = Some(pair.1.clone());
            for p in &mut run.peers {
                if p.stop_filter_header.is_some() {
                    p.cfheaders_match = Some(p.prev_filter_header.as_ref() == Some(&pair.0) && p.stop_filter_header.as_ref() == Some(&pair.1));
                }
            }
        }
        _ => run.reference.error = Some(format!("no majority among {responding} answers")),
    }
}

fn latency(v: Vec<u64>) -> Latency {
    let mut v = v;
    let n = v.len();
    let p = percentiles(&mut v, &[10, 50, 90, 100]);
    let at = |k: u32| p.iter().find(|(q, _)| *q == k).map(|(_, x)| *x);
    Latency { n, p10: at(10), p50: at(50), p90: at(90), max: at(100) }
}

/// A failure's kind without the peer-specific detail: `step: first word`, or the Tor reply.
fn failure_kind(f: &str) -> String {
    let mut parts = f.splitn(3, ':').map(str::trim);
    let (a, b, c) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let first = |t: &str| t.split_whitespace().next().unwrap_or("").to_string();
    match (a, b) {
        ("connect", "tor") => format!("connect: tor: {}", first(c)),
        (_, "") => a.to_string(),
        _ => format!("{a}: {}", first(b)),
    }
}

pub async fn run(o: Opts) -> Result<(PathBuf, Run), String> {
    let started = unix_now();
    let t0 = Instant::now();
    let run_dir = o.runs_dir.join(o.net.name);
    std::fs::create_dir_all(&run_dir).map_err(|e| format!("{}: {e}", run_dir.display()))?;
    std::fs::create_dir_all(&o.state_dir).map_err(|e| format!("{}: {e}", o.state_dir.display()))?;
    let mut run = Run {
        format: RUN_FORMAT,
        tool: format!("peer-list {}", env!("CARGO_PKG_VERSION")),
        network: o.net.name.into(),
        started: rfc3339(started),
        started_unix: started,
        config: RunConfig {
            socks: o.socks.to_string(),
            concurrency: o.concurrency,
            connect_timeout_s: o.connect_timeout.as_secs(),
            handshake_timeout_s: o.handshake_timeout.as_secs(),
            cfheaders_timeout_s: o.cfheaders_timeout.as_secs(),
            getaddr_window_s: o.getaddr_window.as_secs(),
            budget: o.budget,
            range: o.range,
            depth: o.depth,
        },
        ..Run::default()
    };
    let log = |m: String| eprintln!("[{} {}] {m}", o.net.name, rfc3339(unix_now()));

    // Onion candidates in check order, each with every source that named it.
    let mut order: Vec<String> = vec![];
    let mut sources: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut add = |addr: String, src: &str, order: &mut Vec<String>| {
        let e = sources.entry(addr.clone()).or_default();
        if e.is_empty() {
            order.push(addr);
        }
        e.insert(src.to_string());
    };

    let prev = previous_peers(&run_dir, o.previous);
    run.sources.previous_runs = prev.len();
    for a in &prev {
        add(a.clone(), "previous-runs", &mut order);
    }

    let (seeds, ips) = crate::dns::query_all(o.socks, o.net.seeds, o.seed_queries, Duration::from_secs(60)).await;
    log(format!("DNS seeds: {} addresses from {} of {} seeds", ips.len(), seeds.iter().filter(|s| s.answers > 0).count(), seeds.len()));
    let mut seed_of: HashMap<IpAddr, Vec<String>> = HashMap::new();
    for s in &seeds {
        for a in &s.addresses {
            if let Ok(ip) = a.parse() {
                seed_of.entry(ip).or_default().push(format!("dns:{}", s.name));
            }
        }
    }
    run.sources.dns_seeds = seeds;

    if o.net.network == Network::Bitcoin {
        let (res, list) = crate::btcnodes::get(&o.state_dir, o.socks, o.btcnodes, Duration::from_secs(180)).await;
        log(format!("btcnodes: {} onion v3 with bit 6 (requested {}, from cache {}, error {:?})", list.len(), res.requested, res.from_cache, res.error));
        run.sources.btcnodes = Some(res);
        let mut list = list;
        list.shuffle(&mut rand::thread_rng());
        for a in list {
            add(a, "btcnodes", &mut order);
        }
    }

    let rpc = match &o.rpc {
        Some((port, cookie)) => Some(Rpc::from_cookie(*port, cookie)?),
        None => None,
    };
    if let Some(rpc) = &rpc {
        let mut own = OwnNodeResult::default();
        match rpc.call("getnodeaddresses", json!([0, "onion"])).await {
            Ok(Value::Array(v)) => {
                for e in v {
                    let (Some(host), Some(port)) = (e["address"].as_str(), e["port"].as_u64()) else { continue };
                    if onion::to_pubkey(host).is_none() {
                        continue;
                    }
                    own.onion_v3 += 1;
                    if e["services"].as_u64().unwrap_or(0) & BIT6 != 0 {
                        own.onion_v3_bit6 += 1;
                        add(format!("{host}:{port}"), "own-node", &mut order);
                    }
                }
            }
            Ok(other) => own.error = Some(format!("getnodeaddresses: {other}")),
            Err(e) => own.error = Some(e),
        }
        log(format!("own node: {} onion v3, {} with bit 6", own.onion_v3, own.onion_v3_bit6));
        run.sources.own_node = Some(own);
    }

    let expect = match o.net.network {
        Network::Signet => match &rpc {
            Some(rpc) => signet_reference(rpc, o.range, o.depth, &mut run.reference).await,
            None => Err("no RPC to our own signet node".into()),
        },
        Network::Bitcoin => {
            let mut peers: Vec<String> = prev.iter().take(8).cloned().collect();
            let mut rest: Vec<String> = order.iter().filter(|a| !prev.contains(a)).cloned().collect();
            rest.shuffle(&mut rand::thread_rng());
            peers.extend(rest.into_iter().take(16));
            log(format!("header sync from {} candidate peers", peers.len()));
            mainnet_reference(&o, &peers, o.range, o.depth, &mut run.reference).await
        }
        _ => {
            run.reference = Reference { kind: "none".into(), note: "testnet4: peers are counted (handshake with bits 0, 3 and 6); no filter-header reference".into(), ..Reference::default() };
            Err(String::new())
        }
    };
    let expect = match expect {
        Ok(e) => Some(e),
        Err(e) if e.is_empty() => None,
        Err(e) => {
            log(format!("no reference: {e}"));
            if run.reference.kind.is_empty() {
                run.reference.kind = "none".into();
            }
            run.reference.error = Some(e);
            None
        }
    };
    log(format!("reference {:?}: stop {:?} at {:?}", run.reference.kind, run.reference.stop_hash, run.reference.stop_height));

    let ctx = Arc::new(Ctx {
        socks: o.socks,
        network: o.net.network,
        gossip_min_time: unix_now().saturating_sub(o.gossip_max_age.as_secs()) as u32,
        connect_timeout: o.connect_timeout,
        handshake_timeout: o.handshake_timeout,
        cfheaders_timeout: o.cfheaders_timeout,
        getaddr_window: o.getaddr_window,
        expect,
    });

    // Gossip-only clearnet peers first: their addrv2 can add onion candidates early.
    let mut queue: VecDeque<(String, bool)> = ips.iter().map(|ip| (fmt_addr(ip, o.net.port), false)).collect();
    let mut seen: HashSet<String> = queue.iter().map(|(a, _)| a.clone()).collect();
    let mut queued = 0usize;
    let mut over = 0usize;
    let mut clear_queued = 0usize;
    let mut gossip_queued = 0usize;
    // SIGTERM or SIGINT: stop starting checks, finish those running, write the run.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for kind in [tokio::signal::unix::SignalKind::terminate(), tokio::signal::unix::SignalKind::interrupt()] {
        if let Ok(mut sig) = tokio::signal::unix::signal(kind) {
            let stop = stop.clone();
            tokio::spawn(async move {
                sig.recv().await;
                stop.store(true, std::sync::atomic::Ordering::SeqCst);
            });
        }
    }
    for a in &order {
        if seen.insert(a.clone()) {
            if queued < o.budget {
                queue.push_back((a.clone(), true));
                queued += 1;
            } else {
                over += 1;
            }
        }
    }
    let gs = &mut run.sources.gossip;
    let mut gossip_seen: HashSet<String> = HashSet::new();
    let mut set = JoinSet::new();
    let mut done = 0usize;
    loop {
        while set.len() < o.concurrency && !stop.load(std::sync::atomic::Ordering::SeqCst) {
            let Some((addr, is_onion)) = queue.pop_front() else { break };
            set.spawn(check(ctx.clone(), addr, is_onion));
        }
        let Some(res) = set.join_next().await else { break };
        let Ok(c) = res else { continue };
        done += 1;
        gs.peers_asked += usize::from(c.r.handshake_ms.is_some());
        if let Some(n) = c.r.gossip_addresses {
            gs.peers_answered += usize::from(n > 0);
            gs.addresses += n;
            gs.onion_v3 += c.gossip_onion;
        }
        for a in c.gossip {
            if gossip_seen.insert(a.clone()) {
                gs.onion_v3_bit6 += 1;
            }
            let e = sources.entry(a.clone()).or_default();
            e.insert("gossip".into());
            if seen.insert(a.clone()) {
                if queued < o.budget && gossip_queued < o.gossip_onion {
                    queue.push_back((a, true));
                    queued += 1;
                    gossip_queued += 1;
                    gs.new_candidates += 1;
                } else {
                    over += 1;
                }
            }
        }
        for a in c.gossip_clear {
            if clear_queued < o.gossip_clearnet && seen.insert(a.clone()) {
                queue.push_back((a, false));
                clear_queued += 1;
            }
        }
        if c.onion {
            run.peers.push(c.r);
            // A Tor that builds no circuits would record a false failure for every peer.
            if run.peers.len() == 64 && run.peers.iter().all(|p| p.connect_ms.is_none()) {
                return Err("the first 64 onion peers all failed to connect: Tor is not building circuits; no run file written".into());
            }
        } else {
            let mut r = c.r;
            let ip: Option<IpAddr> = onion::split_host_port(&r.addr).and_then(|(h, _)| h.parse().ok());
            r.sources = ip.and_then(|ip| seed_of.get(&ip).cloned()).unwrap_or_else(|| vec!["gossip".into()]);
            run.gossip_peers.push(r);
        }
        if done % 100 == 0 {
            log(format!("{done} done, {} queued, {} running, {} answered cfheaders", queue.len(), set.len(), run.peers.iter().filter(|p| p.stop_filter_header.is_some()).count()));
        }
    }
    gs.over_budget = over;
    run.summary.stopped_early = stop.load(std::sync::atomic::Ordering::SeqCst);
    run.summary.not_checked = queue.len();

    for p in &mut run.peers {
        p.sources = sources.get(&p.addr).map(|s| s.iter().cloned().collect()).unwrap_or_default();
    }
    if run.reference.kind == "peer-agreement" {
        agreement(&mut run);
    }
    let handshake_only = o.net.network == Network::Testnet4;
    for p in &mut run.peers {
        p.passed = if handshake_only { p.services_ok } else { p.services_ok && p.cfheaders_match == Some(true) };
        if p.cfheaders_match == Some(false) {
            p.failure.get_or_insert("cfheaders: differs-from-reference".into());
        }
        if !p.passed && p.failure.is_none() {
            p.failure = Some(if run.reference.error.is_some() { "reference: none-this-run".into() } else { "cfheaders: not-served".into() });
        }
    }

    let s = &mut run.summary;
    s.candidates = queued + over;
    s.checked = run.peers.len();
    s.connected = run.peers.iter().filter(|p| p.connect_ms.is_some()).count();
    s.handshake_ok = run.peers.iter().filter(|p| p.handshake_ms.is_some()).count();
    s.services_ok = run.peers.iter().filter(|p| p.services_ok).count();
    s.cfheaders_answered = run.peers.iter().filter(|p| p.stop_filter_header.is_some()).count();
    s.passed = run.peers.iter().filter(|p| p.passed).count();
    for p in &run.peers {
        for src in &p.sources {
            *s.candidates_by_source.entry(src.clone()).or_default() += 1;
        }
        if let Some(f) = &p.failure {
            *s.failures.entry(failure_kind(f)).or_default() += 1;
        }
    }
    s.candidates_by_source.insert("dns-seed-addresses".into(), ips.len());
    let passed: Vec<&PeerResult> = run.peers.iter().filter(|p| p.passed).collect();
    s.latency_ms = BTreeMap::from([
        ("connect".to_string(), latency(passed.iter().filter_map(|p| p.connect_ms).collect())),
        ("handshake".to_string(), latency(passed.iter().filter_map(|p| p.handshake_ms).collect())),
        ("cfheaders".to_string(), latency(passed.iter().filter_map(|p| p.cfheaders_ms).collect())),
    ]);
    s.duration_s = t0.elapsed().as_secs();
    run.finished = rfc3339(unix_now());
    let path = run_dir.join(format!("{}.json", stamp(started)));
    let body = serde_json::to_vec_pretty(&run).map_err(|e| e.to_string())?;
    std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
    log(format!("wrote {}: {} checked, {} passed in {} s", path.display(), run.summary.checked, run.summary.passed, run.summary.duration_s));
    Ok((path, run))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_kinds() {
        assert_eq!(failure_kind("connect: tor: onion-descriptor-not-found"), "connect: tor: onion-descriptor-not-found");
        assert_eq!(failure_kind("connect: timeout"), "connect: timeout");
        assert_eq!(failure_kind("handshake: p2p recv: early eof"), "handshake: p2p");
        assert_eq!(failure_kind("cfheaders: timeout"), "cfheaders: timeout");
    }

    fn peer(addr: &str, prev: &str, stop: &str) -> PeerResult {
        PeerResult { addr: addr.into(), services_ok: true, prev_filter_header: Some(prev.into()), stop_filter_header: Some(stop.into()), ..PeerResult::default() }
    }

    #[test]
    fn majority_needs_three_and_more_than_half() {
        let mut run = Run { peers: vec![peer("a", "p", "s"), peer("b", "p", "s"), peer("c", "p", "s"), peer("d", "p", "x")], ..Run::default() };
        agreement(&mut run);
        assert_eq!((run.reference.agreeing, run.reference.responding), (Some(3), Some(4)));
        assert_eq!(run.peers.iter().map(|p| p.cfheaders_match).collect::<Vec<_>>(), [Some(true), Some(true), Some(true), Some(false)]);
        let mut tie = Run { peers: vec![peer("a", "p", "s"), peer("b", "p", "s"), peer("c", "q", "s"), peer("d", "q", "s")], ..Run::default() };
        agreement(&mut tie);
        assert!(tie.reference.error.is_some() && tie.peers.iter().all(|p| p.cfheaders_match.is_none()));
    }
}
