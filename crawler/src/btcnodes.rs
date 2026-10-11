//! The btcnodes.io snapshot (10 requests a day per IP): one HTTPS request per run at most,
//! through Tor. The last good snapshot is kept and stands in when a request fails.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::onion;
use crate::results::BtcnodesResult;
use crate::socks::{self, Target};
use crate::util::{isolation, rfc3339, unix_now};

pub const HOST: &str = "btcnodes.io";
pub const PATH: &str = "/api/v1/snapshots/latest/";
/// Our own cap, well under the site's 10 a day, in case runs are repeated.
const MAX_PER_DAY: usize = 3;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const BIT6: u64 = 1 << 6;

fn tls() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(c)
}

async fn fetch(proxy: SocketAddr) -> Result<crate::http::Response, String> {
    let tcp = socks::connect(proxy, &Target::Name(HOST), 443, &isolation()).await?;
    let name = ServerName::try_from(HOST.to_string()).map_err(|e| format!("tls: {e}"))?;
    let mut s = TlsConnector::from(tls()).connect(name, tcp).await.map_err(|e| format!("tls: {e}"))?;
    crate::http::request(&mut s, "GET", HOST, PATH, &[], &[], MAX_BYTES).await
}

/// Request times in the last 24 h, from the log beside the cache.
fn recent_requests(log: &Path, now: u64) -> Vec<u64> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().next()?.parse::<u64>().ok())
        .filter(|&t| t + 86_400 > now)
        .collect()
}

/// Onion v3 addresses with bit 6 in a snapshot body, and the counts the run reports.
pub fn parse(body: &[u8], r: &mut BtcnodesResult) -> Result<Vec<String>, String> {
    let v: Value = serde_json::from_slice(body).map_err(|e| format!("snapshot JSON: {e}"))?;
    let nodes = v.get("nodes").and_then(Value::as_object).ok_or("snapshot without nodes")?;
    r.snapshot_timestamp = v.get("timestamp").and_then(Value::as_u64);
    r.total_nodes = nodes.len();
    let mut out = Vec::new();
    for (addr, row) in nodes {
        let Some((host, _)) = onion::split_host_port(addr) else { continue };
        if onion::to_pubkey(host).is_none() {
            continue;
        }
        r.onion_v3 += 1;
        let services = row.get(3).and_then(Value::as_u64).unwrap_or(0);
        if services & BIT6 != 0 {
            r.onion_v3_bit6 += 1;
            out.push(addr.clone());
        }
        if services & crate::p2p::X49 == crate::p2p::X49 {
            r.onion_v3_x49 += 1;
        }
    }
    out.sort();
    Ok(out)
}

/// Today's snapshot, or the cached one; the result says which and why.
pub async fn get(state: &Path, proxy: SocketAddr, allow: bool, timeout: Duration) -> (BtcnodesResult, Vec<String>) {
    let (cache, meta, log) = (state.join("btcnodes-latest.json"), state.join("btcnodes-latest.fetched"), state.join("btcnodes-requests.log"));
    let now = unix_now();
    let mut r = BtcnodesResult::default();
    let recent = recent_requests(&log, now).len();
    if allow && recent < MAX_PER_DAY {
        r.requested = true;
        let line = format!("{now} {}\n", rfc3339(now));
        let _ = std::fs::OpenOptions::new().create(true).append(true).open(&log).and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
        match tokio::time::timeout(timeout, fetch(proxy)).await.unwrap_or_else(|_| Err("timeout".into())) {
            Ok(resp) => {
                r.status = Some(resp.status);
                r.ratelimit_remaining = resp.header("ratelimit-remaining").map(String::from);
                if resp.status == 200 {
                    let mut probe = BtcnodesResult::default();
                    match parse(&resp.body, &mut probe) {
                        Ok(_) => {
                            let _ = std::fs::write(&cache, &resp.body);
                            let _ = std::fs::write(&meta, format!("{now}\n"));
                        }
                        Err(e) => r.error = Some(e),
                    }
                } else {
                    r.error = Some(format!("HTTP {}", resp.status));
                }
            }
            Err(e) => r.error = Some(e),
        }
    } else if allow {
        r.error = Some(format!("not requested: {recent} requests in the last 24 h (our cap is {MAX_PER_DAY})"));
    }
    let fetched = std::fs::read_to_string(&meta).ok().and_then(|t| t.trim().parse::<u64>().ok());
    r.from_cache = !(r.requested && r.error.is_none());
    r.fetched_at = fetched.map(rfc3339);
    match std::fs::read(&cache) {
        Ok(body) => match parse(&body, &mut r) {
            Ok(list) => (r, list),
            Err(e) => {
                r.error.get_or_insert(e);
                (r, vec![])
            }
        },
        Err(_) => (r, vec![]),
    }
}
