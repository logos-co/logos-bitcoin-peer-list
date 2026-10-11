//! The JSON a run writes: candidates per source, the reference, and every check with its latency.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const RUN_FORMAT: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Run {
    pub format: u32,
    pub tool: String,
    pub network: String,
    pub started: String,
    pub started_unix: u64,
    pub finished: String,
    pub config: RunConfig,
    pub sources: Sources,
    pub reference: Reference,
    pub summary: Summary,
    /// Onion v3 candidates, each checked once.
    pub peers: Vec<PeerResult>,
    /// Clearnet peers from the DNS seeds, dialled through Tor exits for their addrv2 gossip only.
    pub gossip_peers: Vec<PeerResult>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunConfig {
    pub socks: String,
    pub concurrency: usize,
    pub connect_timeout_s: u64,
    pub handshake_timeout_s: u64,
    pub cfheaders_timeout_s: u64,
    pub getaddr_window_s: u64,
    pub budget: usize,
    pub range: u32,
    pub depth: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sources {
    pub dns_seeds: Vec<SeedResult>,
    pub btcnodes: Option<BtcnodesResult>,
    pub own_node: Option<OwnNodeResult>,
    pub gossip: GossipSummary,
    /// Onion peers checked in earlier runs, checked again so each peer has a daily record.
    pub previous_runs: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeedResult {
    pub name: String,
    pub queries: u32,
    pub answers: u32,
    pub addresses: Vec<String>,
    pub errors: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BtcnodesResult {
    pub requested: bool,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub ratelimit_remaining: Option<String>,
    pub from_cache: bool,
    pub fetched_at: Option<String>,
    pub snapshot_timestamp: Option<u64>,
    pub total_nodes: usize,
    pub onion_v3: usize,
    pub onion_v3_bit6: usize,
    pub onion_v3_x49: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OwnNodeResult {
    pub onion_v3: usize,
    pub onion_v3_bit6: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GossipSummary {
    pub peers_asked: usize,
    pub peers_answered: usize,
    pub addresses: usize,
    pub onion_v3: usize,
    pub onion_v3_bit6: usize,
    pub new_candidates: usize,
    pub over_budget: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Reference {
    /// own-node, peer-agreement or none.
    pub kind: String,
    pub checked_against_own_node: bool,
    pub tip_height: Option<u32>,
    pub start_height: Option<u32>,
    pub stop_height: Option<u32>,
    pub stop_hash: Option<String>,
    pub prev_filter_header: Option<String>,
    pub stop_filter_header: Option<String>,
    pub agreeing: Option<usize>,
    pub responding: Option<usize>,
    pub headers_note: Option<String>,
    pub note: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerResult {
    pub addr: String,
    pub sources: Vec<String>,
    pub connect_ms: Option<u64>,
    pub handshake_ms: Option<u64>,
    pub version: Option<u32>,
    pub services: Option<String>,
    pub user_agent: Option<String>,
    pub start_height: Option<i32>,
    pub services_ok: bool,
    pub cfheaders_ms: Option<u64>,
    pub prev_filter_header: Option<String>,
    pub stop_filter_header: Option<String>,
    pub cfheaders_match: Option<bool>,
    pub gossip_addresses: Option<usize>,
    pub gossip_onion_bit6: Option<usize>,
    pub passed: bool,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Latency {
    pub n: usize,
    pub p10: Option<u64>,
    pub p50: Option<u64>,
    pub p90: Option<u64>,
    pub max: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub candidates: usize,
    pub candidates_by_source: BTreeMap<String, usize>,
    pub checked: usize,
    pub connected: usize,
    pub handshake_ok: usize,
    pub services_ok: usize,
    pub cfheaders_answered: usize,
    pub passed: usize,
    pub failures: BTreeMap<String, usize>,
    /// Over the peers that passed.
    pub latency_ms: BTreeMap<String, Latency>,
    pub duration_s: u64,
}
