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
mod seeds;
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
  peer-list release --network NET --key SECRET [--runs 1] [--no-crawl] [--out DIR]
                    [crawl options]   (one budgeted crawl, then a signed list of the peers that
                    passed every check in each of the last --runs runs: DIR/<network>.json,
                    DIR defaults to HOME/release)
  peer-list seeds   --core-src DIR --out DIR   (Core's onion v3 fixed seeds, per network)
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
    let (path, run) = crawl::run(crawl_opts(a)?).await?;
    println!("{}", path.display());
    print_summary(&run);
    Ok(())
}

fn crawl_opts(a: &Args) -> Result<crawl::Opts, String> {
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
    Ok(o)
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

/// The signed list under `rule` from the network's runs, as pretty JSON.
fn signed_list(a: &Args, network: &str, rule: &list::Rule, key: &keys::SecretKey) -> Result<(list::PeerList, String), String> {
    let runs = crawl::load_runs(&a.home().join("runs").join(network), rule.last);
    let created = util::unix_now();
    let version: u64 = a.num("version", util::stamp(created)[..13].replace('T', "").parse().unwrap_or(1))?;
    let checked = match runs.last().map(|r| r.reference.kind.as_str()) {
        Some("own-node") => "checked against our own Core node's filter headers",
        Some("peer-agreement") => "not checked against our own node: filter headers agreed by a majority of independent peers",
        _ => "handshake only",
    };
    let test = if key.key_id.starts_with("test-") { " Signed with a TEST key: not a release." } else { "" };
    let default_note = format!(
        "Onion v3 peers serving BIP157 compact filters that passed every check over Tor in {} of the last {} runs ({checked}).{test}",
        rule.min_pass, rule.last
    );
    let note = a.get("note").map(String::from).unwrap_or(default_note);
    let mut built = list::build(&runs, network, rule, version, created, &note)?;
    built.list.sign(key);
    eprintln!("{network}: {} peers from {} runs ({:?}); {} peers passed at least once", built.list.peers.len(), built.runs.len(), built.runs, built.counts.len());
    let mut hist: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for (_, n) in &built.counts {
        *hist.entry(*n).or_default() += 1;
    }
    eprintln!("passes -> peers: {hist:?}");
    let body = serde_json::to_string_pretty(&built.list).map_err(|e| e.to_string())? + "\n";
    Ok((built.list, body))
}

fn list_cmd(a: &Args) -> Result<(), String> {
    let network = a.req("network")?;
    netcfg::by_name(network).ok_or("--network must be mainnet, signet or testnet4")?;
    let key = keys::SecretKey::load(&PathBuf::from(a.req("key")?))?;
    let rule = list::Rule { last: a.num("last", 7)?, min_pass: a.num("min-pass", 6)? };
    let (_, body) = signed_list(a, network, &rule, &key)?;
    match a.get("out") {
        Some(p) => std::fs::write(p, &body).map_err(|e| format!("{p}: {e}"))?,
        None => print!("{body}"),
    }
    Ok(())
}

/// One budgeted crawl (unless --no-crawl), then the peers that passed every check in each of
/// the last `--runs` runs, signed. scripts/install-release.sh puts it in the node module.
async fn release(a: &Args) -> Result<(), String> {
    let network = a.req("network")?;
    netcfg::by_name(network).ok_or("--network must be mainnet, signet or testnet4")?;
    let key = keys::SecretKey::load(&PathBuf::from(a.req("key")?))?;
    let dir = a.get("out").map(PathBuf::from).unwrap_or_else(|| a.home().join("release"));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let runs: usize = a.num("runs", 1)?;
    if runs == 0 {
        return Err("--runs must be at least 1".into());
    }
    if a.get("no-crawl").is_none() {
        let (path, run) = crawl::run(crawl_opts(a)?).await?;
        println!("{}", path.display());
        print_summary(&run);
        // Interrupted: nothing signed, though `--no-crawl` may still sign from the run kept.
        if run.summary.stopped_early {
            return Err(format!("the {network} crawl stopped early; nothing signed"));
        }
    }
    let (list, body) = signed_list(a, network, &list::Rule { last: runs, min_pass: runs }, &key)?;
    if list.peers.is_empty() {
        return Err(format!("no {network} peer passed every check in the last {runs} runs; nothing written"));
    }
    let out = dir.join(format!("{network}.json"));
    std::fs::write(&out, body).map_err(|e| format!("{}: {e}", out.display()))?;
    println!("{}: {} peers, version {}, key {}", out.display(), list.peers.len(), list.version, key.key_id);
    Ok(())
}

fn seeds_cmd(a: &Args) -> Result<(), String> {
    let out = PathBuf::from(a.req("out")?);
    for s in seeds::extract(&PathBuf::from(a.req("core-src")?))? {
        let path = out.join(format!("seeds-{}.json", s.network));
        let body = serde_json::to_string_pretty(&s).map_err(|e| e.to_string())? + "\n";
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("{}: {} onion seeds ({})", path.display(), s.peers.len(), s.source);
    }
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
            "release" => release(&a).await,
            "seeds" => seeds_cmd(&a),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results::{PeerResult, Run};
    use std::path::Path;

    fn args(v: &[&str]) -> Args {
        Args::parse(v.iter().map(|s| s.to_string()).collect()).unwrap()
    }

    #[tokio::test]
    async fn a_release_keeps_peers_that_passed_every_run() {
        let home = tempfile::tempdir().unwrap();
        let runs = home.path().join("runs/signet");
        std::fs::create_dir_all(&runs).unwrap();
        let (a, b) = (format!("{}:38333", onion::from_pubkey(&[1; 32])), format!("{}:38333", onion::from_pubkey(&[2; 32])));
        // a passes both runs, b only the newer one.
        for (i, passed) in [vec![a.clone()], vec![a.clone(), b.clone()]].into_iter().enumerate() {
            let t = 1_791_000_000 + i as u64 * 86_400;
            let peers = passed.into_iter().map(|addr| PeerResult { addr, passed: true, ..PeerResult::default() }).collect();
            let run = Run { network: "signet".into(), started_unix: t, started: util::rfc3339(t), peers, ..Run::default() };
            std::fs::write(runs.join(format!("{i}.json")), serde_json::to_vec(&run).unwrap()).unwrap();
        }
        let key = keys::SecretKey::generate("test").unwrap();
        let secret = home.path().join("test.secret");
        key.save(&secret, "test").unwrap();
        let (h, k) = (home.path().to_str().unwrap(), secret.to_str().unwrap());
        let read = |p: &Path| serde_json::from_slice::<list::PeerList>(&std::fs::read(p).unwrap()).unwrap();

        release(&args(&["--network", "signet", "--key", k, "--home", h, "--no-crawl"])).await.unwrap();
        let one = read(&home.path().join("release/signet.json"));
        assert_eq!(one.peers, vec![a.clone(), b.clone()], "one run: everything that passed it");
        one.verify(&key.public()).unwrap();
        assert!(one.note.contains("TEST key"), "{}", one.note);

        let out = home.path().join("two");
        release(&args(&["--network", "signet", "--key", k, "--home", h, "--no-crawl", "--runs", "2", "--out", out.to_str().unwrap()])).await.unwrap();
        assert_eq!(read(&out.join("signet.json")).peers, vec![a], "two runs: only the peer that passed both");

        let e = release(&args(&["--network", "signet", "--key", k, "--home", h, "--no-crawl", "--runs", "3"])).await.unwrap_err();
        assert!(e.contains("2 signet runs, and the rule needs 3 passes"), "{e}");
        assert!(release(&args(&["--network", "mainnet", "--key", k, "--home", h, "--no-crawl"])).await.unwrap_err().contains("0 mainnet runs"));
    }
}
