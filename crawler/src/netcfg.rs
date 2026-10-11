//! Per-network settings: P2P port, DNS seeds (asked for x49) and how many candidates a run checks.

use bitcoin::Network;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetCfg {
    pub name: &'static str,
    pub network: Network,
    pub port: u16,
    pub seeds: &'static [&'static str],
    /// Onion candidates checked per run, at most.
    pub budget: usize,
}

/// Core's current seeds plus the ones Kyoto still lists.
const MAINNET_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
    "seed.mainnet.achownodes.xyz",
];
const SIGNET_SEEDS: &[&str] = &["seed.signet.bitcoin.sprovoost.nl", "seed.signet.achownodes.xyz", "seed.dlsouza.lol"];
const TESTNET4_SEEDS: &[&str] = &["seed.testnet4.bitcoin.sprovoost.nl", "seed.testnet4.wiz.biz"];

pub const MAINNET: NetCfg = NetCfg { name: "mainnet", network: Network::Bitcoin, port: 8333, seeds: MAINNET_SEEDS, budget: 6000 };
pub const SIGNET: NetCfg = NetCfg { name: "signet", network: Network::Signet, port: 38333, seeds: SIGNET_SEEDS, budget: 2000 };
pub const TESTNET4: NetCfg = NetCfg { name: "testnet4", network: Network::Testnet4, port: 48333, seeds: TESTNET4_SEEDS, budget: 1000 };

pub fn by_name(s: &str) -> Option<NetCfg> {
    [MAINNET, SIGNET, TESTNET4].into_iter().find(|n| n.name == s)
}
