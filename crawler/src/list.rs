//! The signed list, in the node module's format (`PeerList` in its rust-lib/src/peers.rs).
//! Canonical bytes: a domain tag, then the list as compact JSON in field order, signature null.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::keys::{PublicKey, SecretKey};
use crate::onion;
use crate::results::Run;
use crate::util::{day, rfc3339};

pub const FORMAT: u32 = 1;
pub const DOMAIN: &[u8] = b"logos-bitcoin-peer-list/1\n";
/// The node module refuses longer lists.
pub const MAX_PEERS: usize = 1024;

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

/// Peers that passed every check in at least `min_pass` of the last `last` runs (the plan: 6 of 7).
pub struct Rule {
    pub last: usize,
    pub min_pass: usize,
}

pub struct Built {
    pub list: PeerList,
    /// Pass counts of every peer that passed at least once, most passes first.
    pub counts: Vec<(String, usize)>,
    pub runs: Vec<String>,
}

pub fn build(runs: &[Run], network: &str, rule: &Rule, version: u64, created: u64, note: &str) -> Result<Built, String> {
    let mut runs: Vec<&Run> = runs.iter().filter(|r| r.network == network).collect();
    runs.sort_by_key(|r| r.started_unix);
    let runs = &runs[runs.len().saturating_sub(rule.last)..];
    if runs.len() < rule.min_pass {
        return Err(format!("{} {network} runs, and the rule needs {} passes", runs.len(), rule.min_pass));
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for r in runs {
        for p in r.peers.iter().filter(|p| p.passed) {
            let onion_v3 = onion::split_host_port(&p.addr).is_some_and(|(h, _)| onion::to_pubkey(h).is_some());
            if onion_v3 {
                *counts.entry(p.addr.clone()).or_default() += 1;
            }
        }
    }
    let mut counts: Vec<(String, usize)> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
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
    Ok(Built { list, counts, runs: runs.iter().map(|r| r.started.clone()).collect() })
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
        let built = build(&runs, "mainnet", &Rule { last: 7, min_pass: 6 }, 3, 1_791_383_742, "n").unwrap();
        assert_eq!(built.list.peers, vec![a.clone()]);
        assert_eq!(built.counts, vec![(a, 7), (b, 5)]);
        assert_eq!((built.list.version.as_str(), built.list.date.as_deref(), built.runs.len()), ("3", Some("2024-10-10"), 7));
        assert!(build(&runs[..3], "mainnet", &Rule { last: 7, min_pass: 6 }, 1, 0, "").is_err());
    }

    #[test]
    fn signature_covers_everything_but_itself() {
        let key = SecretKey::generate("test").unwrap();
        let mut l = build(&[run("signet", 5, &[])], "signet", &Rule { last: 1, min_pass: 1 }, 1, 9, "n").unwrap().list;
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
}
