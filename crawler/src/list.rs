//! The lists, in the node module's formats (`PeerList` and `ClearnetList` in its
//! rust-lib/src/peers.rs). Unsigned: the module compiles them in, and Jenkins signs its packages.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::netcfg;
use crate::onion;
use crate::results::Run;
use crate::util::{day, rfc3339};

pub const FORMAT: u32 = 1;
/// The node module refuses longer lists.
pub const MAX_PEERS: usize = 1024;
/// Clearnet peers kept per /16 (IPv4) or /32 (IPv6), so no one network holds the list.
pub const PER_NETGROUP: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerList {
    pub format: u32,
    pub network: String,
    /// Decimal u64; a release replaces the shipped list only when newer.
    pub version: String,
    /// When the list was built, RFC 3339 UTC.
    pub created: String,
    /// The UTC day of the last run it counts.
    pub date: Option<String>,
    pub note: String,
    pub refresh_url: Option<String>,
    pub peers: Vec<String>,
}

impl PeerList {
    /// Well formed: the shared fields, and every peer an onion v3 `host:port`.
    pub fn check(&self) -> Result<(), String> {
        check_header(self.format, &self.network, &self.version, &self.created, self.date.as_deref(), self.peers.len())?;
        for p in &self.peers {
            if !onion::split_host_port(p).is_some_and(|(h, port)| onion::to_pubkey(h).is_some() && format!("{h}:{port}") == *p) {
                return Err(format!("{p} is not an onion v3 host:port"));
            }
        }
        Ok(())
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
}

impl ClearnetList {
    /// Well formed: the shared fields, and every peer a public IPv4 or IPv6 `host:port` with
    /// decimal services, at most `PER_NETGROUP` per netgroup.
    pub fn check(&self) -> Result<(), String> {
        check_header(self.format, &self.network, &self.version, &self.created, self.date.as_deref(), self.peers.len())?;
        let mut per_group: HashMap<(u8, u32), usize> = HashMap::new();
        for p in &self.peers {
            let addr = p.peer.parse::<SocketAddr>().ok().filter(|a| a.port() != 0 && a.to_string() == p.peer && public(&a.ip()));
            let Some(addr) = addr else { return Err(format!("{} is not a public IPv4 or IPv6 host:port", p.peer)) };
            if !decimal(&p.services) {
                return Err(format!("{}: services {:?} are not a decimal u64", p.peer, p.services));
            }
            let g = per_group.entry(netgroup(&addr.ip())).or_default();
            *g += 1;
            if *g > PER_NETGROUP {
                return Err(format!("more than {PER_NETGROUP} peers in the netgroup of {}", p.peer));
            }
        }
        Ok(())
    }
}

/// What both lists share: format 1, a known network, a decimal version, the dates' shapes.
fn check_header(format: u32, network: &str, version: &str, created: &str, date: Option<&str>, peers: usize) -> Result<(), String> {
    if format != FORMAT {
        return Err(format!("format {format} is not {FORMAT}"));
    }
    netcfg::by_name(network).ok_or(format!("unknown network {network:?}"))?;
    if !decimal(version) {
        return Err(format!("version {version:?} is not a decimal u64"));
    }
    if !time_ok(created.as_bytes()) {
        return Err(format!("created {created:?} is not YYYY-MM-DDTHH:MM:SSZ"));
    }
    if let Some(d) = date.filter(|d| !date_ok(d.as_bytes())) {
        return Err(format!("date {d:?} is not YYYY-MM-DD"));
    }
    if peers > MAX_PEERS {
        return Err(format!("{peers} peers, more than {MAX_PEERS}"));
    }
    Ok(())
}

/// A u64 written the way the node module reads it: plain decimal, no sign or leading zero.
fn decimal(s: &str) -> bool {
    s.parse::<u64>().is_ok_and(|n| n.to_string() == s)
}

fn date_ok(b: &[u8]) -> bool {
    b.len() == 10 && b.iter().enumerate().all(|(i, c)| if i == 4 || i == 7 { *c == b'-' } else { c.is_ascii_digit() })
}

fn time_ok(b: &[u8]) -> bool {
    b.len() == 20 && date_ok(&b[..10]) && b[10] == b'T' && b[13] == b':' && b[16] == b':' && b[19] == b'Z' && [11, 12, 14, 15, 17, 18].iter().all(|&i| b[i].is_ascii_digit())
}

/// Either list's file, checked; a one-line description.
pub fn verify_any(bytes: &[u8]) -> Result<String, String> {
    let onion_err = match serde_json::from_slice::<PeerList>(bytes) {
        Ok(l) => {
            l.check()?;
            return Ok(format!("{} v{} {} onion peers", l.network, l.version, l.peers.len()));
        }
        Err(e) => e,
    };
    let l = serde_json::from_slice::<ClearnetList>(bytes).map_err(|e| format!("neither list format: onion: {onion_err}; clearnet: {e}"))?;
    l.check()?;
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
    };
    Ok((list, Built { counts, runs: runs.iter().map(|r| r.started.clone()).collect() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results::PeerResult;

    /// A change to a good list, and what `verify_any` must say about it.
    type Bad<T> = (fn(&mut T), &'static str);

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
    fn the_format_and_what_verify_refuses() {
        let mut l = build(&[run("signet", 5, &[])], "signet", &Rule { last: 1, min_pass: 1 }, 1, 9, "n").unwrap().0;
        l.peers.push(format!("{}:38333", onion::from_pubkey(&[3; 32])));
        let body = serde_json::to_string(&l).unwrap();
        // The node module's field order, with nothing after the peers.
        assert!(body.starts_with("{\"format\":1,\"network\":\"signet\",\"version\":\"1\",\"created\":\"1970-01-01T00:00:09Z\",\"date\":\"1970-01-01\",\"note\":\"n\",\"refreshUrl\":null,\"peers\":[\""), "{body}");
        assert!(body.ends_with(".onion:38333\"]}"), "{body}");
        assert_eq!(verify_any(body.as_bytes()).unwrap(), "signet v1 1 onion peers");
        let bad: [Bad<PeerList>; 9] = [
            (|l: &mut PeerList| l.format = 2, "format 2 is not 1"),
            (|l: &mut PeerList| l.network = "regtest".into(), "unknown network"),
            (|l: &mut PeerList| l.version = "01".into(), "not a decimal u64"),
            (|l: &mut PeerList| l.created = "1970-01-01".into(), "created \"1970-01-01\" is not"),
            (|l: &mut PeerList| l.date = Some("yesterday".into()), "date \"yesterday\" is not"),
            (|l: &mut PeerList| l.peers.push("expyuzz4wqqyqhjn.onion:8333".into()), "expyuzz4wqqyqhjn.onion:8333 is not an onion v3"),
            (|l: &mut PeerList| l.peers.push(onion::from_pubkey(&[4; 32])), "is not an onion v3 host:port"),
            (|l: &mut PeerList| l.peers.push("1.2.3.4:38333".into()), "1.2.3.4:38333 is not an onion v3"),
            (|l: &mut PeerList| l.peers = vec![format!("{}:38333", onion::from_pubkey(&[5; 32])); MAX_PEERS + 1], "1025 peers, more than 1024"),
        ];
        for (tamper, why) in bad {
            let mut t = l.clone();
            tamper(&mut t);
            let e = verify_any(&serde_json::to_vec(&t).unwrap()).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
        // A list in the old signed shape is refused, not read with its signature ignored.
        let old = format!("{},\"keyId\":\"test-d680f3cac9837bf9\",\"signature\":null}}", &body[..body.len() - 1]);
        assert!(verify_any(old.as_bytes()).unwrap_err().contains("unknown field `keyId`"));
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
        let (l, built) = build_clearnet(&runs, "signet", &Rule { last: 2, min_pass: 2 }, 7, 0, "n").unwrap();
        let got: Vec<(&str, &str)> = l.peers.iter().map(|p| (p.peer.as_str(), p.services.as_str())).collect();
        // 1.2.3.4 is the slowest of three in 1.2/16; services from the newest run (0xc49 = 3145).
        assert_eq!(got, [("1.2.5.5:38333", "1097"), ("1.2.9.9:38333", "3145"), ("[2a01:4f8::1]:38333", "1097")]);
        assert_eq!(built.counts.len(), 4, "the private and onion peers never count");
        let body = serde_json::to_string(&l).unwrap();
        assert!(body.ends_with("\"peers\":[{\"peer\":\"1.2.5.5:38333\",\"services\":\"1097\"},{\"peer\":\"1.2.9.9:38333\",\"services\":\"3145\"},{\"peer\":\"[2a01:4f8::1]:38333\",\"services\":\"1097\"}]}"), "{body}");
        assert_eq!(verify_any(body.as_bytes()).unwrap(), "signet v7 3 clearnet peers");
        let bad: [Bad<ClearnetList>; 7] = [
            (|l: &mut ClearnetList| l.peers[0].services = "0x449".into(), "services \"0x449\" are not a decimal u64"),
            (|l: &mut ClearnetList| l.peers[0].peer = "192.168.1.1:38333".into(), "192.168.1.1:38333 is not a public"),
            (|l: &mut ClearnetList| l.peers[0].peer = "1.2.5.5".into(), "1.2.5.5 is not a public"),
            (|l: &mut ClearnetList| l.peers[2].peer = "2a01:4f8::1:38333".into(), "2a01:4f8::1:38333 is not a public"),
            (|l: &mut ClearnetList| l.peers[0].peer = format!("{}:38333", onion::from_pubkey(&[4; 32])), ".onion:38333 is not a public"),
            (|l: &mut ClearnetList| l.peers.push(ClearnetPeer { peer: "1.2.3.4:38333".into(), services: "1097".into() }), "more than 2 peers in the netgroup of 1.2.3.4:38333"),
            (|l: &mut ClearnetList| l.date = Some("2024-10-1".into()), "date \"2024-10-1\" is not"),
        ];
        for (tamper, why) in bad {
            let mut t = l.clone();
            tamper(&mut t);
            let e = verify_any(&serde_json::to_vec(&t).unwrap()).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
    }
}
