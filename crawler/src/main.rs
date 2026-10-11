//! peer-list: curates onion peers that serve BIP157 compact filters, for Kyoto's whitelist.
//! Every connection goes through Tor's SOCKS port; only our own node's RPC stays on loopback.

mod btcnodes;
mod crawl;
mod dns;
mod headers;
mod http;
mod keys;
mod list;
mod netcfg;
mod onion;
mod p2p;
mod results;
mod rpc;
mod socks;
mod util;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

const USAGE: &str = "usage:
  peer-list crawl   --network mainnet|signet|testnet4 [--home DIR] [--socks ADDR] [--concurrency N]
                    [--budget N] [--no-btcnodes] [--rpc-port N --rpc-cookie FILE] [--seed-queries N]
                    [--range N] [--depth N] [--connect-timeout S] [--handshake-timeout S]
                    [--cfheaders-timeout S] [--getaddr-window S] [--previous N] [--gossip-clearnet N]
                    [--gossip-onion N] [--gossip-max-age-days N] [--stream-rate PER_SECOND]
  peer-list list    --network NET --key SECRET [--home DIR] [--last 7] [--min-pass 6]
                    [--version N] [--note TEXT] [--out FILE]
  peer-list verify  --pubkey FILE LIST...
  peer-list keygen  --secret FILE --pubkey FILE [--label test]
  peer-list summary RUN.json...
  peer-list headers [--home DIR] [--socks ADDR] [--back N]   (mainnet: sync, print tip and tip-N)";

struct Args {
    flags: HashMap<String, String>,
    pos: Vec<String>,
}

impl Args {
    fn parse(v: Vec<String>) -> Result<Self, String> {
        let (mut flags, mut pos) = (HashMap::new(), vec![]);
        let mut it = v.into_iter();
        while let Some(a) = it.next() {
            if let Some(k) = a.strip_prefix("--") {
                if k.starts_with("no-") {
                    flags.insert(k.to_string(), "true".into());
                } else {
                    flags.insert(k.to_string(), it.next().ok_or(format!("--{k} needs a value"))?);
                }
            } else {
                pos.push(a);
            }
        }
        Ok(Args { flags, pos })
    }

    fn get(&self, k: &str) -> Option<&str> {
        self.flags.get(k).map(String::as_str)
    }

    fn req(&self, k: &str) -> Result<&str, String> {
        self.get(k).ok_or(format!("--{k} is required"))
    }

    fn num<T: std::str::FromStr>(&self, k: &str, d: T) -> Result<T, String> {
        self.get(k).map(|v| v.parse().map_err(|_| format!("--{k}: not a number"))).unwrap_or(Ok(d))
    }

    fn home(&self) -> PathBuf {
        self.get("home").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("btc-peer-list"))
    }

    fn socks(&self) -> Result<SocketAddr, String> {
        self.get("socks").unwrap_or("127.0.0.1:29050").parse().map_err(|_| "--socks: not ip:port".into())
    }
}

async fn crawl(a: &Args) -> Result<(), String> {
    let net = netcfg::by_name(a.req("network")?).ok_or("--network must be mainnet, signet or testnet4")?;
    util::set_stream_rate(a.num("stream-rate", 2.0)?);
    let home = a.home();
    let rpc = match (a.get("rpc-port"), a.get("rpc-cookie")) {
        (Some(p), Some(c)) => Some((p.parse().map_err(|_| "--rpc-port: not a port")?, PathBuf::from(c))),
        _ => None,
    };
    let secs = |k: &str, d: u64| a.num(k, d).map(Duration::from_secs);
    let o = crawl::Opts {
        net,
        socks: a.socks()?,
        state_dir: home.join("state"),
        runs_dir: home.join("runs"),
        concurrency: a.num("concurrency", 32)?,
        connect_timeout: secs("connect-timeout", 60)?,
        handshake_timeout: secs("handshake-timeout", 30)?,
        cfheaders_timeout: secs("cfheaders-timeout", 45)?,
        getaddr_window: secs("getaddr-window", 15)?,
        budget: a.num("budget", net.budget)?,
        range: a.num("range", 1000)?,
        depth: a.num("depth", 6)?,
        btcnodes: a.get("no-btcnodes").is_none(),
        rpc,
        seed_queries: a.num("seed-queries", 6)?,
        previous: a.num("previous", 7)?,
        gossip_clearnet: a.num("gossip-clearnet", 100)?,
        gossip_onion: a.num("gossip-onion", 500)?,
        gossip_max_age: Duration::from_secs(a.num("gossip-max-age-days", 3u64)? * 86_400),
    };
    let (path, run) = crawl::run(o).await?;
    println!("{}", path.display());
    print_summary(&run);
    Ok(())
}

fn print_summary(r: &results::Run) {
    let s = &r.summary;
    println!("{} {} ({} s): candidates {} | checked {} connected {} handshake {} services {} cfheaders {} PASSED {}", r.network, r.started, s.duration_s, s.candidates, s.checked, s.connected, s.handshake_ok, s.services_ok, s.cfheaders_answered, s.passed);
    println!("  by source: {:?}", s.candidates_by_source);
    if let Some(b) = &r.sources.btcnodes {
        println!("  btcnodes: requested {} status {:?} cache {} snapshot {:?} onion_v3 {} bit6 {} x49 {} err {:?}", b.requested, b.status, b.from_cache, b.snapshot_timestamp, b.onion_v3, b.onion_v3_bit6, b.onion_v3_x49, b.error);
    }
    let seeds: Vec<String> = r.sources.dns_seeds.iter().map(|d| format!("{}={}/{}", d.name, d.addresses.len(), d.answers)).collect();
    println!("  dns: {}", seeds.join(" "));
    let g = &r.sources.gossip;
    println!("  gossip: asked {} answered {} addrs {} onion {} onion+bit6 {} new {} over-budget {}", g.peers_asked, g.peers_answered, g.addresses, g.onion_v3, g.onion_v3_bit6, g.new_candidates, g.over_budget);
    let f = &r.reference;
    println!("  reference: {} own-node {} stop {:?}@{:?} agree {:?}/{:?} err {:?}", f.kind, f.checked_against_own_node, f.stop_hash, f.stop_height, f.agreeing, f.responding, f.error);
    if let Some(h) = &f.headers_note {
        println!("  headers: {h}");
    }
    for (k, l) in &s.latency_ms {
        println!("  latency {k}: n {} p10 {:?} p50 {:?} p90 {:?} max {:?} ms", l.n, l.p10, l.p50, l.p90, l.max);
    }
    println!("  failures: {:?}", s.failures);
}

fn list_cmd(a: &Args) -> Result<(), String> {
    let network = a.req("network")?;
    netcfg::by_name(network).ok_or("--network must be mainnet, signet or testnet4")?;
    let key = keys::SecretKey::load(&PathBuf::from(a.req("key")?))?;
    let rule = list::Rule { last: a.num("last", 7)?, min_pass: a.num("min-pass", 6)? };
    let runs = crawl::load_runs(&a.home().join("runs").join(network), rule.last);
    let created = util::unix_now();
    let version: u64 = a.num("version", util::stamp(created)[..13].replace('T', "").parse().unwrap_or(1))?;
    let checked = match runs.last().map(|r| r.reference.kind.as_str()) {
        Some("own-node") => "checked against our own Core node's filter headers",
        Some("peer-agreement") => "not checked against our own node: filter headers agreed by a majority of independent peers",
        _ => "handshake only",
    };
    let default_note = format!(
        "Onion v3 peers serving BIP157 compact filters that passed every check over Tor in {} of the last {} runs ({checked}). Signed with a TEST key: not a release.",
        rule.min_pass, rule.last
    );
    let note = a.get("note").map(String::from).unwrap_or(default_note);
    let mut built = list::build(&runs, network, &rule, version, created, &note)?;
    built.list.sign(&key);
    let body = serde_json::to_string_pretty(&built.list).map_err(|e| e.to_string())? + "\n";
    match a.get("out") {
        Some(p) => std::fs::write(p, &body).map_err(|e| format!("{p}: {e}"))?,
        None => print!("{body}"),
    }
    eprintln!("{network}: {} peers from {} runs ({:?}); {} peers passed at least once", built.list.peers.len(), built.runs.len(), built.runs, built.counts.len());
    let mut hist: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for (_, n) in &built.counts {
        *hist.entry(*n).or_default() += 1;
    }
    eprintln!("passes -> peers: {hist:?}");
    Ok(())
}

fn verify_cmd(a: &Args) -> Result<(), String> {
    let key = keys::PublicKey::load(&PathBuf::from(a.req("pubkey")?))?;
    let mut bad = 0;
    for f in &a.pos {
        let r = std::fs::read(f).map_err(|e| e.to_string()).and_then(|b| serde_json::from_slice::<list::PeerList>(&b).map_err(|e| e.to_string())).and_then(|l| l.verify(&key).map(|_| l));
        match r {
            Ok(l) => println!("OK   {f}: {} v{} {} peers, key {}", l.network, l.version, l.peers.len(), key.key_id),
            Err(e) => {
                bad += 1;
                println!("FAIL {f}: {e}");
            }
        }
    }
    if bad > 0 {
        return Err(format!("{bad} list(s) failed"));
    }
    Ok(())
}

fn keygen(a: &Args) -> Result<(), String> {
    let label = a.get("label").unwrap_or("test");
    let k = keys::SecretKey::generate(label)?;
    let secret = PathBuf::from(a.req("secret")?);
    k.save(&secret, label)?;
    let public = serde_json::to_string_pretty(&k.public()).map_err(|e| e.to_string())? + "\n";
    std::fs::write(a.req("pubkey")?, public).map_err(|e| e.to_string())?;
    println!("{} written; secret at {}", k.key_id, secret.display());
    Ok(())
}

async fn headers_cmd(a: &Args) -> Result<(), String> {
    let home = a.home();
    let path = home.join("state").join("mainnet-headers.bin");
    let base: bitcoin::BlockHash = headers::BASE_HASH.parse().map_err(|e| format!("{e}"))?;
    let mut chain = headers::Chain::load(&path, headers::BASE_HEIGHT, base);
    let peers = crawl::previous_peers(&home.join("runs").join("mainnet"), 7);
    let s = headers::sync(&mut chain, &path, bitcoin::Network::Bitcoin, a.socks()?, &peers).await;
    if s.confirmed == 0 {
        return Err(format!("no peer confirmed a tip: {:?}", s.errors));
    }
    let back: u32 = a.num("back", 144)?;
    let tip = chain.tip_height();
    let cp = tip - back;
    println!("{tip} {} {cp} {}", chain.hash_at(tip).ok_or("no tip")?, chain.hash_at(cp).ok_or("no checkpoint")?);
    Ok(())
}

#[tokio::main]
async fn main() {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }
    let cmd = argv.remove(0);
    let r = match Args::parse(argv) {
        Err(e) => Err(e),
        Ok(a) => match cmd.as_str() {
            "crawl" => crawl(&a).await,
            "list" => list_cmd(&a),
            "verify" => verify_cmd(&a),
            "keygen" => keygen(&a),
            "headers" => headers_cmd(&a).await,
            "summary" => {
                for f in &a.pos {
                    match std::fs::read(f).ok().and_then(|b| serde_json::from_slice::<results::Run>(&b).ok()) {
                        Some(r) => print_summary(&r),
                        None => eprintln!("{f}: not a run file"),
                    }
                }
                Ok(())
            }
            _ => Err(USAGE.into()),
        },
    };
    if let Err(e) = r {
        eprintln!("peer-list {cmd}: {e}");
        std::process::exit(1);
    }
}
