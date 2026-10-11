//! The mainnet header chain from Kyoto's taproot checkpoint, checked for proof of work and
//! difficulty, so every peer gets the same recent stop block in the cfheaders check.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::params::Params;
use bitcoin::pow::{CompactTarget, Work};
use bitcoin::{BlockHash, Network};

use crate::p2p::Conn;
use crate::socks::{self, Target};
use crate::util::isolation;

/// Kyoto's `HashCheckpoint::taproot_activation()` at bip157 0.7.0 (copied from its source).
pub const BASE_HEIGHT: u32 = 709_631;
pub const BASE_HASH: &str = "000000000000000000013712fc242ee6dd28476d0e9c931c75f83e6974c6bccc";
const INTERVAL: u32 = 2016;
/// How far back a competing branch may fork.
const MAX_REORG: u32 = 2000;

#[derive(Clone)]
pub struct Chain {
    base_height: u32,
    base_hash: BlockHash,
    headers: Vec<Header>,
    hashes: Vec<BlockHash>,
}

fn work_of(hs: &[Header]) -> Work {
    hs.iter().fold(Work::from_le_bytes([0; 32]), |w, h| w + h.work())
}

impl Chain {
    pub fn new(base_height: u32, base_hash: BlockHash) -> Self {
        Chain { base_height, base_hash, headers: vec![], hashes: vec![] }
    }

    pub fn tip_height(&self) -> u32 {
        self.base_height + self.headers.len() as u32
    }

    pub fn tip_hash(&self) -> BlockHash {
        self.hashes.last().copied().unwrap_or(self.base_hash)
    }

    pub fn hash_at(&self, h: u32) -> Option<BlockHash> {
        if h == self.base_height {
            return Some(self.base_hash);
        }
        self.hashes.get(h.checked_sub(self.base_height + 1)? as usize).copied()
    }

    fn header_at(&self, h: u32) -> Option<&Header> {
        self.headers.get(h.checked_sub(self.base_height + 1)? as usize)
    }

    /// Newest first: ten single steps, then doubling, ending at the base.
    pub fn locator(&self) -> Vec<BlockHash> {
        let (mut out, mut h, mut step) = (vec![], self.tip_height(), 1u32);
        loop {
            out.extend(self.hash_at(h));
            if h == self.base_height {
                return out;
            }
            if out.len() >= 10 {
                step = step.saturating_mul(2);
            }
            h = h.saturating_sub(step).max(self.base_height);
        }
    }

    /// Appends `hdr` as block `self.tip_height() + 1` after its checks.
    fn push(&mut self, hdr: Header, params: &Params) -> Result<(), String> {
        let h = self.tip_height() + 1;
        if hdr.prev_blockhash != self.tip_hash() {
            return Err(format!("header {h} does not link to {}", self.tip_hash()));
        }
        let target = hdr.target();
        if target > params.max_attainable_target {
            return Err(format!("header {h}: target above the network's limit"));
        }
        if let Some(prev) = self.header_at(h - 1) {
            if h % INTERVAL != 0 {
                if hdr.bits != prev.bits {
                    return Err(format!("header {h}: difficulty changed outside a retarget"));
                }
            } else if let Some(first) = self.header_at(h - INTERVAL) {
                if hdr.bits != CompactTarget::from_header_difficulty_adjustment(*first, *prev, params) {
                    return Err(format!("header {h}: wrong retarget"));
                }
            } else {
                let p = prev.target();
                if target > p.max_transition_threshold(params) || target < p.min_transition_threshold() {
                    return Err(format!("header {h}: retarget beyond 4x"));
                }
            }
        }
        let hash = hdr.validate_pow(target).map_err(|e| format!("header {h}: {e}"))?;
        self.headers.push(hdr);
        self.hashes.push(hash);
        Ok(())
    }

    /// Takes a peer's `headers` answer: extends the tip, or switches to a branch with more work.
    pub fn accept(&mut self, new: &[Header], params: &Params) -> Result<usize, String> {
        let Some(first) = new.first() else { return Ok(0) };
        let tip = self.tip_height();
        let low = tip.saturating_sub(MAX_REORG).max(self.base_height);
        let fork = (low..=tip).rev().find(|&h| self.hash_at(h) == Some(first.prev_blockhash)).ok_or("headers do not connect to our chain")?;
        let mut c = if fork == tip {
            None
        } else {
            let ours = &self.headers[(fork - self.base_height) as usize..];
            if work_of(new) <= work_of(ours) {
                return Ok(0);
            }
            let mut c = self.clone();
            c.headers.truncate((fork - self.base_height) as usize);
            c.hashes.truncate((fork - self.base_height) as usize);
            Some(c)
        };
        let target = c.as_mut().unwrap_or(self);
        let mut n = 0;
        for h in new {
            target.push(*h, params)?;
            n += 1;
        }
        if let Some(c) = c {
            *self = c;
        }
        Ok(n)
    }

    pub fn load(path: &Path, base_height: u32, base_hash: BlockHash) -> Self {
        let fresh = Chain::new(base_height, base_hash);
        let Ok(b) = std::fs::read(path) else { return fresh };
        if b.len() < 36 || (b.len() - 36) % 80 != 0 || b[..4] != base_height.to_le_bytes() || b[4..36] != serialize(&base_hash)[..] {
            return fresh;
        }
        let mut c = fresh.clone();
        for chunk in b[36..].chunks(80) {
            let Ok(h) = deserialize::<Header>(chunk) else { return fresh };
            if h.prev_blockhash != c.tip_hash() {
                return fresh;
            }
            c.hashes.push(h.block_hash());
            c.headers.push(h);
        }
        c
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut b = Vec::with_capacity(36 + 80 * self.headers.len());
        b.extend_from_slice(&self.base_height.to_le_bytes());
        b.extend_from_slice(&serialize(&self.base_hash));
        for h in &self.headers {
            b.extend_from_slice(&serialize(h));
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, b)?;
        std::fs::rename(tmp, path)
    }
}

pub struct SyncOutcome {
    pub tried: usize,
    pub confirmed: usize,
    pub fetched: usize,
    pub max_peer_height: i32,
    pub errors: Vec<String>,
}

/// Follows one peer to its tip; Ok(true) when it has nothing past ours.
async fn follow(chain: &mut Chain, params: &Params, network: Network, proxy: SocketAddr, addr: &str, fetched: &mut usize, best: &mut i32) -> Result<bool, String> {
    let (host, port) = crate::onion::split_host_port(addr).ok_or("bad address")?;
    let tcp = tokio::time::timeout(Duration::from_secs(60), socks::connect(proxy, &Target::Name(host), port, &isolation()))
        .await
        .map_err(|_| "connect timeout".to_string())??;
    let mut c = Conn::new(tcp, network);
    let v = tokio::time::timeout(Duration::from_secs(20), c.handshake()).await.map_err(|_| "handshake timeout".to_string())??;
    *best = (*best).max(v.start_height);
    loop {
        let hs = tokio::time::timeout(Duration::from_secs(90), c.getheaders(chain.locator())).await.map_err(|_| "getheaders timeout".to_string())??;
        *fetched += chain.accept(&hs, params)?;
        if hs.len() < 2000 {
            return Ok(i64::from(v.start_height) <= i64::from(chain.tip_height()) + 1);
        }
    }
}

/// Syncs from up to 16 peers until 3 have nothing past our tip; saves progress after each.
pub async fn sync(chain: &mut Chain, path: &Path, network: Network, proxy: SocketAddr, peers: &[String]) -> SyncOutcome {
    let params = Params::new(network);
    let mut o = SyncOutcome { tried: 0, confirmed: 0, fetched: 0, max_peer_height: 0, errors: vec![] };
    for addr in peers.iter().take(16) {
        if o.confirmed >= 3 {
            break;
        }
        o.tried += 1;
        let r = tokio::time::timeout(Duration::from_secs(900), follow(chain, &params, network, proxy, addr, &mut o.fetched, &mut o.max_peer_height)).await;
        match r {
            Ok(Ok(true)) => o.confirmed += 1,
            Ok(Ok(false)) => o.errors.push(format!("{addr}: claims a higher tip than it served")),
            Ok(Err(e)) => o.errors.push(format!("{addr}: {e}")),
            Err(_) => o.errors.push(format!("{addr}: over 15 min")),
        }
        eprintln!("[headers] {addr}: tip {} after {} new, {} peers at their tip; {:?}", chain.tip_height(), o.fetched, o.confirmed, o.errors.last());
        if let Err(e) = chain.save(path) {
            o.errors.push(format!("saving headers: {e}"));
        }
    }
    o
}
