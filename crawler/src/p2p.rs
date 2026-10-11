//! Bitcoin P2P over a Tor stream (rust-bitcoin messages): framing, the version handshake with
//! sendaddrv2, getcfheaders, getaddr and getheaders. Callers bound each step with a timeout.

use std::net::SocketAddr;
use std::time::Duration;

use bitcoin::bip158::FilterHeader;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin::p2p::message_filter::GetCFHeaders;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::{BlockHash, Network};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const PROTOCOL: u32 = 70016;
pub const USER_AGENT: &str = concat!("/logos-peer-list:", env!("CARGO_PKG_VERSION"), "/");
/// NODE_NETWORK | NODE_WITNESS | NODE_COMPACT_FILTERS, bits 0, 3 and 6.
pub const X49: u64 = 0x49;
const MAX_PAYLOAD: usize = 4_000_000;
/// Messages we decode; everything else is skipped unread.
const WANTED: [&str; 8] = ["version", "verack", "ping", "cfheaders", "addr", "addrv2", "headers", "reject"];

pub struct Conn {
    s: TcpStream,
    magic: Magic,
}

impl Conn {
    pub fn new(s: TcpStream, network: Network) -> Self {
        Conn { s, magic: network.magic() }
    }

    async fn send(&mut self, m: NetworkMessage) -> Result<(), String> {
        let bytes = bitcoin::consensus::encode::serialize(&RawNetworkMessage::new(self.magic, m));
        self.s.write_all(&bytes).await.map_err(|e| format!("p2p send: {e}"))
    }

    /// The next message we care about; answers pings on the way.
    async fn recv(&mut self) -> Result<NetworkMessage, String> {
        loop {
            let mut head = [0u8; 24];
            self.s.read_exact(&mut head).await.map_err(|e| format!("p2p recv: {e}"))?;
            if head[..4] != self.magic.to_bytes() {
                return Err("p2p: wrong network magic".into());
            }
            let len = u32::from_le_bytes([head[16], head[17], head[18], head[19]]) as usize;
            if len > MAX_PAYLOAD {
                return Err(format!("p2p: {len}-byte message"));
            }
            let mut buf = vec![0u8; 24 + len];
            buf[..24].copy_from_slice(&head);
            self.s.read_exact(&mut buf[24..]).await.map_err(|e| format!("p2p recv: {e}"))?;
            let cmd = String::from_utf8_lossy(&head[4..16]).trim_end_matches('\0').to_string();
            if !WANTED.contains(&cmd.as_str()) {
                continue;
            }
            let raw: RawNetworkMessage = bitcoin::consensus::deserialize(&buf).map_err(|e| format!("p2p: bad {cmd}: {e}"))?;
            match raw.into_payload() {
                NetworkMessage::Ping(n) => self.send(NetworkMessage::Pong(n)).await?,
                NetworkMessage::Reject(r) => return Err(format!("p2p: reject {} {:?}", r.message, r.reason)),
                m => return Ok(m),
            }
        }
    }

    /// version, then sendaddrv2 before verack (BIP155); returns the peer's version message.
    pub async fn handshake(&mut self) -> Result<VersionMessage, String> {
        let none = Address::new(&SocketAddr::from(([0, 0, 0, 0], 0)), ServiceFlags::NONE);
        let now = crate::util::unix_now() as i64;
        let mut v = VersionMessage::new(ServiceFlags::NONE, now, none.clone(), none, rand::random(), USER_AGENT.into(), 0);
        v.version = PROTOCOL;
        v.relay = false;
        self.send(NetworkMessage::Version(v)).await?;
        let (mut theirs, mut verack) = (None, false);
        while theirs.is_none() || !verack {
            match self.recv().await? {
                NetworkMessage::Version(t) if theirs.is_none() => {
                    theirs = Some(t);
                    self.send(NetworkMessage::SendAddrV2).await?;
                    self.send(NetworkMessage::Verack).await?;
                }
                NetworkMessage::Verack => verack = true,
                _ => {}
            }
        }
        theirs.ok_or_else(|| "p2p: no version".into())
    }

    /// Filter headers at `start - 1` and at the stop block, folded from the peer's filter hashes.
    pub async fn cfheaders(&mut self, start: u32, stop: BlockHash, count: u32) -> Result<(FilterHeader, FilterHeader), String> {
        self.send(NetworkMessage::GetCFHeaders(GetCFHeaders { filter_type: 0, start_height: start, stop_hash: stop })).await?;
        loop {
            if let NetworkMessage::CFHeaders(c) = self.recv().await? {
                if c.stop_hash != stop || c.filter_type != 0 {
                    continue;
                }
                if c.filter_hashes.len() != count as usize {
                    return Err(format!("cfheaders: {} filter hashes, expected {count}", c.filter_hashes.len()));
                }
                let prev = c.previous_filter_header;
                let last = c.filter_hashes.iter().fold(prev, |h, fh| fh.filter_header(&h));
                return Ok((prev, last));
            }
        }
    }

    /// One getaddr; collects addr/addrv2 until the bulk answer (2+ entries) or `window` ends.
    pub async fn getaddr(&mut self, window: Duration) -> Result<Vec<AddrV2Message>, String> {
        self.send(NetworkMessage::GetAddr).await?;
        let deadline = tokio::time::Instant::now() + window;
        let mut out = Vec::new();
        while let Ok(m) = tokio::time::timeout_at(deadline, self.recv()).await {
            let batch: Vec<AddrV2Message> = match m? {
                NetworkMessage::AddrV2(v) => v,
                NetworkMessage::Addr(v) => v.into_iter().filter_map(|(time, a)| legacy(time, &a)).collect(),
                _ => continue,
            };
            let bulk = batch.len() >= 2;
            out.extend(batch);
            if bulk {
                break;
            }
        }
        Ok(out)
    }

    /// Up to 2000 headers after the first locator hash the peer knows.
    pub async fn getheaders(&mut self, locator: Vec<BlockHash>) -> Result<Vec<Header>, String> {
        let msg = GetHeadersMessage { version: PROTOCOL, locator_hashes: locator, stop_hash: BlockHash::all_zeros() };
        self.send(NetworkMessage::GetHeaders(msg)).await?;
        loop {
            if let NetworkMessage::Headers(h) = self.recv().await? {
                return Ok(h);
            }
        }
    }
}

/// A legacy addr entry as addrv2 (IPv4-mapped addresses become IPv4).
fn legacy(time: u32, a: &Address) -> Option<AddrV2Message> {
    let sa = a.socket_addr().ok()?;
    let addr = match sa.ip() {
        std::net::IpAddr::V4(v4) => AddrV2::Ipv4(v4),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(AddrV2::Ipv4).unwrap_or(AddrV2::Ipv6(v6)),
    };
    Some(AddrV2Message { time, services: a.services, addr, port: sa.port() })
}
