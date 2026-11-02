//! The signed lists, in the node module's formats (`PeerList` and `ClearnetList` in its
//! rust-lib/src/peers.rs). Canonical bytes: a domain tag, then compact JSON in field order,
//! signature null.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::keys::{PublicKey, SecretKey};
use crate::onion;
use crate::results::Run;
use crate::util::{day, rfc3339};

pub const FORMAT: u32 = 1;
pub const DOMAIN: &[u8] = b"logos-bitcoin-peer-list/1\n";
/// The node module refuses longer lists.
pub const MAX_PEERS: usize = 1024;
pub const CLEARNET_DOMAIN: &[u8] = b"logos-bitcoin-clearnet-peers/1\n";
/// Clearnet peers kept per /16 (IPv4) or /32 (IPv6), so no one network holds the list.
pub const PER_NETGROUP: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerList {
    pub format: u32,
    pub network: String,
    /// Decimal u64; a fetched list replaces the current one only when newer.
    pub version: String,
    /// When the list was built and signed, RFC 3339 UTC.
    pub created: String,
    /// The UTC day of the last run it counts.
    pub date: Option<String>,
    pub note: String,
    pub refresh_url: Option<String>,
    pub peers: Vec<String>,
    pub key_id: Option<String>,
    /// Ed25519 over `signed_message()`, hex.
    pub signature: Option<String>,
}

impl PeerList {
    pub fn signed_message(&self) -> Vec<u8> {
        let unsigned = PeerList { signature: None, ..self.clone() };
        let mut m = DOMAIN.to_vec();
        m.extend(serde_json::to_vec(&unsigned).expect("a peer list serializes"));
        m
    }

    pub fn sign(&mut self, key: &SecretKey) {
        self.key_id = Some(key.key_id.clone());
        self.signature = None;
        self.signature = Some(hex::encode(key.sign(&self.signed_message())));
    }

    pub fn verify(&self, key: &PublicKey) -> Result<(), String> {
        if self.key_id.as_deref() != Some(key.key_id.as_str()) {
            return Err(format!("signed by {:?}, not {}", self.key_id, key.key_id));
        }
        let sig = hex::decode(self.signature.as_deref().ok_or("unsigned")?).map_err(|_| "signature is not hex")?;
        key.verify(&self.signed_message(), &sig)
    }
}

/// An IPv4 or IPv6 peer and the services it last announced, decimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearnetPeer {
    pub peer: String,
    pub services: String,
}

/// The clearnet list: like `PeerList`, with each peer's services (bit 11 means BIP324).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearnetList {
    pub format: u32,
    pub network: String,
    pub version: String,
    pub created: String,
    pub date: Option<String>,
    pub note: String,
    pub refresh_url: Option<String>,
    pub peers: Vec<ClearnetPeer>,
    pub key_id: Option<String>,
    pub signature: Option<String>,
}

impl ClearnetList {
    pub fn signed_message(&self) -> Vec<u8> {
        let unsigned = ClearnetList { signature: None, ..self.clone() };
        let mut m = CLEARNET_DOMAIN.to_vec();
        m.extend(serde_json::to_vec(&unsigned).expect("a peer list serializes"));
        m
    }

    pub fn sign(&mut self, key: &SecretKey) {
        self.key_id = Some(key.key_id.clone());
        self.signature = None;
        self.signature = Some(hex::encode(key.sign(&self.signed_message())));
    }

    pub fn verify(&self, key: &PublicKey) -> Result<(), String> {
        if self.key_id.as_deref() != Some(key.key_id.as_str()) {
            return Err(format!("signed by {:?}, not {}", self.key_id, key.key_id));
        }
        let sig = hex::decode(self.signature.as_deref().ok_or("unsigned")?).map_err(|_| "signature is not hex")?;
        key.verify(&self.signed_message(), &sig)
    }
}

/// Either list's file, verified; a one-line description.
pub fn verify_any(bytes: &[u8], key: &PublicKey) -> Result<String, String> {
    if let Ok(l) = serde_json::from_slice::<PeerList>(bytes) {
        l.verify(key)?;
        return Ok(format!("{} v{} {} onion peers", l.network, l.version, l.peers.len()));
    }
    let l = serde_json::from_slice::<ClearnetList>(bytes).map_err(|e| format!("neither list format: {e}"))?;
    l.verify(key)?;
    Ok(format!("{} v{} {} clearnet peers", l.network, l.version, l.peers.len()))
}

/// A globally routed unicast address: no private, loopback, link-local, CGNAT, documentation,
/// benchmarking, multicast or reserved range; IPv6 only from 2000::/3, without Teredo or 6to4.
pub fn public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(o[0] == 0
                || o[0] == 10
                || o[0] == 127
                || o[0] >= 224
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 172 && (16..32).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            s[0] & 0xe000 == 0x2000 && !(s[0] == 0x2001 && (s[1] == 0 || s[1] == 0xdb8 || (0x10..0x30).contains(&s[1]))) && s[0] != 0x2002
        }
    }
}

/// The /16 of an IPv4 address or the /32 of an IPv6 one.
pub fn netgroup(ip: &IpAddr) -> (u8, u32) {
    match ip {
        IpAddr::V4(a) => (4, u32::from(a.octets()[0]) << 8 | u32::from(a.octets()[1])),
        IpAddr::V6(a) => (6, u32::from(a.segments()[0]) << 16 | u32::from(a.segments()[1])),
    }
}

/// Peers that passed every check in at least `min_pass` of the last `last` runs (the plan: 6 of 7).
pub struct Rule {
    pub last: usize,
    pub min_pass: usize,
}

pub struct Built {
    /// Pass counts of every peer that passed at least once, best first.
    pub counts: Vec<(String, usize)>,
    pub runs: Vec<String>,
}

/// Median of a peer's handshake plus cfheaders time over the runs it passed.
fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v.get(v.len() / 2).copied().unwrap_or(u64::MAX)
}

/// The last `rule.last` runs of the network, oldest first, and every peer that passed in them
/// and `keep` accepts, ranked: most passes first, then the fastest, so a cap keeps the best.
fn ranked<'a>(runs: &'a [Run], network: &str, rule: &Rule, keep: impl Fn(&str) -> bool) -> Result<(Vec<&'a Run>, Vec<(String, usize)>), String> {
    let mut runs: Vec<&Run> = runs.iter().filter(|r| r.network == network).collect();
    runs.sort_by_key(|r| r.started_unix);
    let runs = runs.split_off(runs.len().saturating_sub(rule.last));
    if runs.len() < rule.min_pass {
        return Err(format!("{} {network} runs, and the rule needs {} passes", runs.len(), rule.min_pass));
    }
    let mut seen: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for r in &runs {
        for p in r.peers.iter().filter(|p| p.passed && keep(&p.addr)) {
            seen.entry(p.addr.clone()).or_default().push(p.handshake_ms.unwrap_or(0) + p.cfheaders_ms.unwrap_or(0));
        }
    }
    let mut ranked: Vec<(String, usize, u64)> = seen.into_iter().map(|(a, ms)| (a, ms.len(), median(ms))).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)).then(a.0.cmp(&b.0)));
    Ok((runs, ranked.into_iter().map(|(a, n, _)| (a, n)).collect()))
}

pub fn build(runs: &[Run], network: &str, rule: &Rule, version: u64, created: u64, note: &str) -> Result<(PeerList, Built), String> {
    let onion_v3 = |a: &str| onion::split_host_port(a).is_some_and(|(h, _)| onion::to_pubkey(h).is_some());
    let (runs, counts) = ranked(runs, network, rule, onion_v3)?;
    let mut peers: Vec<String> = counts.iter().filter(|(_, n)| *n >= rule.min_pass).map(|(a, _)| a.clone()).take(MAX_PEERS).collect();
    peers.sort();
    let list = PeerList {
        format: FORMAT,
        network: network.into(),
        version: version.to_string(),
        created: rfc3339(created),
        date: runs.last().map(|r| day(r.started_unix)),
        note: note.into(),
        refresh_url: None,
        peers,
        key_id: None,
        signature: None,
    };
    Ok((list, Built { counts, runs: runs.iter().map(|r| r.started.clone()).collect() }))
}

fn ip_of(addr: &str) -> Option<IpAddr> {
    onion::split_host_port(addr).and_then(|(h, _)| h.parse().ok())
}

/// The clearnet list: public IPv4 and IPv6 peers under `rule`, at most `PER_NETGROUP` per
/// netgroup, each with the services of the newest run it passed.
pub fn build_clearnet(runs: &[Run], network: &str, rule: &Rule, version: u64, created: u64, note: &str) -> Result<(ClearnetList, Built), String> {
    let (runs, counts) = ranked(runs, network, rule, |a| ip_of(a).is_some_and(|ip| public(&ip)))?;
    let mut services: HashMap<&str, &str> = HashMap::new();
    for r in &runs {
        for p in r.peers.iter().filter(|p| p.passed) {
            if let Some(s) = &p.services {
                services.insert(&p.addr, s);
            }
        }
    }
    let mut per_group: HashMap<(u8, u32), usize> = HashMap::new();
    let mut peers: Vec<ClearnetPeer> = vec![];
    for (addr, _) in counts.iter().filter(|(_, n)| *n >= rule.min_pass) {
        let (Some(ip), Some(svc)) = (ip_of(addr), services.get(addr.as_str())) else { continue };
        let Ok(svc) = u64::from_str_radix(svc.trim_start_matches("0x"), 16) else { continue };
        let g = per_group.entry(netgroup(&ip)).or_default();
        if *g >= PER_NETGROUP || peers.len() >= MAX_PEERS {
            continue;
        }
        *g += 1;
        peers.push(ClearnetPeer { peer: addr.clone(), services: svc.to_string() });
    }
    peers.sort_by(|a, b| a.peer.cmp(&b.peer));
    let list = ClearnetList {
        format: FORMAT,
        network: network.into(),
        version: version.to_string(),
        created: rfc3339(created),
        date: runs.last().map(|r| day(r.started_unix)),
        note: note.into(),
        refresh_url: None,
        peers,
        key_id: None,
        signature: None,
    };
    Ok((list, Built { counts, runs: runs.iter().map(|r| r.started.clone()).collect() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results::PeerResult;

    fn run(network: &str, t: u64, passed: &[&str]) -> Run {
        let peers = passed.iter().map(|a| PeerResult { addr: a.to_string(), passed: true, ..PeerResult::default() }).collect();
        Run { network: network.into(), started_unix: t, started: rfc3339(t), peers, ..Run::default() }
    }

    #[test]
    fn six_of_seven() {
        let a = format!("{}:8333", onion::from_pubkey(&[1; 32]));
        let b = format!("{}:8333", onion::from_pubkey(&[2; 32]));
        let mut runs: Vec<Run> = (0..7).map(|d| run("mainnet", 86_400 * (20_000 + d), &[&a])).collect();
        // b passes on 5 days only; a clearnet address never counts.
        for r in runs.iter_mut().take(5) {
            r.peers.push(PeerResult { addr: b.clone(), passed: true, ..PeerResult::default() });
            r.peers.push(PeerResult { addr: "1.2.3.4:8333".into(), passed: true, ..PeerResult::default() });
        }
        runs.push(run("signet", 0, &[&b]));
        let (list, built) = build(&runs, "mainnet", &Rule { last: 7, min_pass: 6 }, 3, 1_791_383_742, "n").unwrap();
        assert_eq!(list.peers, vec![a.clone()]);
        // With equal passes the faster peer ranks first.
        let fast = format!("{}:8333", onion::from_pubkey(&[9; 32]));
        let mut two = vec![run("mainnet", 1, &[&b]), run("mainnet", 2, &[&b])];
        for r in two.iter_mut() {
            r.peers[0].handshake_ms = Some(900);
            r.peers.push(PeerResult { addr: fast.clone(), passed: true, handshake_ms: Some(100), ..PeerResult::default() });
        }
        let (_, ranked) = build(&two, "mainnet", &Rule { last: 2, min_pass: 2 }, 1, 0, "").unwrap();
        assert_eq!(ranked.counts, vec![(fast, 2), (b.clone(), 2)]);
        assert_eq!(built.counts, vec![(a, 7), (b, 5)]);
        assert_eq!((list.version.as_str(), list.date.as_deref(), built.runs.len()), ("3", Some("2024-10-10"), 7));
        assert!(build(&runs[..3], "mainnet", &Rule { last: 7, min_pass: 6 }, 1, 0, "").is_err());
    }

    #[test]
    fn signature_covers_everything_but_itself() {
        let key = SecretKey::generate("test").unwrap();
        let mut l = build(&[run("signet", 5, &[])], "signet", &Rule { last: 1, min_pass: 1 }, 1, 9, "n").unwrap().0;
        l.peers.push(format!("{}:38333", onion::from_pubkey(&[3; 32])));
        l.sign(&key);
        let public = key.public();
        l.verify(&public).unwrap();
        let canonical = String::from_utf8(l.signed_message()).unwrap();
        assert!(canonical.starts_with("logos-bitcoin-peer-list/1\n{\"format\":1,\"network\":\"signet\",\"version\":\"1\",\"created\":"));
        assert!(canonical.ends_with(",\"signature\":null}"));
        let tampers: [fn(&mut PeerList); 4] = [
            |l: &mut PeerList| l.network = "mainnet".into(),
            |l: &mut PeerList| l.version = "2".into(),
            |l: &mut PeerList| l.peers.clear(),
            |l: &mut PeerList| l.note.push('!'),
        ];
        for tamper in tampers {
            let mut t = l.clone();
            tamper(&mut t);
            assert!(t.verify(&public).is_err());
        }
        let mut other = l.clone();
        other.key_id = Some("test-0000000000000000".into());
        assert!(other.verify(&public).unwrap_err().contains("signed by"));
    }

    #[test]
    fn public_addresses_only() {
        let yes = ["1.2.3.4", "8.8.8.8", "100.128.0.1", "172.32.0.1", "2a01:4f8::1", "2001:4860::8888"];
        let no = [
            "0.1.2.3", "10.0.0.1", "127.0.0.1", "100.64.0.1", "169.254.1.1", "172.16.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1",
            "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1", "2001:db8::1", "2001::1", "2002::1",
            "2001:10::1", "::ffff:1.2.3.4",
        ];
        for a in yes {
            assert!(public(&a.parse().unwrap()), "{a}");
        }
        for a in no {
            assert!(!public(&a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn clearnet_keeps_two_per_netgroup_with_services() {
        let p = |addr: &str, ms: u64, svc: &str| PeerResult { addr: addr.into(), passed: true, handshake_ms: Some(ms), services: Some(svc.into()), ..PeerResult::default() };
        let mut runs = vec![];
        for d in 0..2 {
            let mut r = run("signet", 86_400 * (20_000 + d), &[]);
            r.peers = vec![
                p("1.2.3.4:38333", 30, "0x449"),
                p("1.2.9.9:38333", 10, if d == 0 { "0x49" } else { "0xc49" }),
                p("1.2.5.5:38333", 20, "0x449"),
                p("[2a01:4f8::1]:38333", 5, "0x449"),
                p("192.168.1.1:38333", 1, "0x449"),
                p(&format!("{}:38333", onion::from_pubkey(&[4; 32])), 1, "0x449"),
            ];
            runs.push(r);
        }
        let (mut l, built) = build_clearnet(&runs, "signet", &Rule { last: 2, min_pass: 2 }, 7, 0, "n").unwrap();
        let got: Vec<(&str, &str)> = l.peers.iter().map(|p| (p.peer.as_str(), p.services.as_str())).collect();
        // 1.2.3.4 is the slowest of three in 1.2/16; services from the newest run (0xc49 = 3145).
        assert_eq!(got, [("1.2.5.5:38333", "1097"), ("1.2.9.9:38333", "3145"), ("[2a01:4f8::1]:38333", "1097")]);
        assert_eq!(built.counts.len(), 4, "the private and onion peers never count");
        let key = SecretKey::generate("test").unwrap();
        l.sign(&key);
        assert!(String::from_utf8(l.signed_message()).unwrap().starts_with("logos-bitcoin-clearnet-peers/1\n{\"format\":1,"));
        let body = serde_json::to_vec(&l).unwrap();
        assert_eq!(verify_any(&body, &key.public()).unwrap(), "signet v7 3 clearnet peers");
        let mut t = l.clone();
        t.peers[0].services = "1".into();
        assert!(verify_any(&serde_json::to_vec(&t).unwrap(), &key.public()).is_err(), "services are signed");
    }
}
