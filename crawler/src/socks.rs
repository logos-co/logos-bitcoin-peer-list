//! SOCKS5 to Tor (RFC 1928 with RFC 1929 auth): CONNECT by name or address, and Tor's RESOLVE
//! extension. Fresh credentials per stream give it its own circuit (IsolateSOCKSAuth).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CMD_CONNECT: u8 = 0x01;
const CMD_RESOLVE: u8 = 0xF0;

pub enum Target<'a> {
    Name(&'a str),
    Ip(IpAddr),
}

/// SOCKS and Tor extended reply codes (Tor's ExtendedErrors flag), as short stable names.
fn reply_name(code: u8) -> &'static str {
    match code {
        0x01 => "general-failure",
        0x02 => "not-allowed",
        0x03 => "network-unreachable",
        0x04 => "host-unreachable",
        0x05 => "connection-refused",
        0x06 => "ttl-expired",
        0x07 => "command-not-supported",
        0x08 => "address-type-not-supported",
        0xF0 => "onion-descriptor-not-found",
        0xF1 => "onion-descriptor-invalid",
        0xF2 => "onion-intro-failed",
        0xF3 => "onion-rendezvous-failed",
        0xF4 => "onion-client-auth-missing",
        0xF5 => "onion-client-auth-wrong",
        0xF6 => "onion-address-invalid",
        0xF7 => "onion-intro-timeout",
        _ => "unknown-reply",
    }
}

async fn request(proxy: SocketAddr, cmd: u8, target: &Target<'_>, port: u16, isolation: &str) -> Result<(TcpStream, IpAddr), String> {
    crate::util::pace().await;
    let mut s = TcpStream::connect(proxy).await.map_err(|e| format!("socks: cannot reach the proxy: {e}"))?;
    s.set_nodelay(true).ok();
    let io = |e: std::io::Error| format!("socks: {e}");
    // Username/password only: Tor isolates streams by these credentials.
    s.write_all(&[5, 1, 2]).await.map_err(io)?;
    let mut b2 = [0u8; 2];
    s.read_exact(&mut b2).await.map_err(io)?;
    if b2 != [5, 2] {
        return Err(format!("socks: proxy refused username auth ({b2:?})"));
    }
    let user = isolation.as_bytes();
    let mut auth = vec![1, user.len() as u8];
    auth.extend_from_slice(user);
    auth.extend_from_slice(&[1, b'x']);
    s.write_all(&auth).await.map_err(io)?;
    s.read_exact(&mut b2).await.map_err(io)?;
    if b2 != [1, 0] {
        return Err("socks: auth failed".into());
    }
    let mut req = vec![5, cmd, 0];
    match target {
        Target::Name(n) => {
            req.push(3);
            req.push(n.len() as u8);
            req.extend_from_slice(n.as_bytes());
        }
        Target::Ip(IpAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.octets());
        }
        Target::Ip(IpAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.octets());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(io)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(io)?;
    if head[1] != 0 {
        return Err(format!("tor: {}", reply_name(head[1])));
    }
    let bound = match head[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await.map_err(io)?;
            IpAddr::V4(Ipv4Addr::from(a))
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await.map_err(io)?;
            IpAddr::V6(Ipv6Addr::from(a))
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(io)?;
            let mut n = vec![0u8; l[0] as usize];
            s.read_exact(&mut n).await.map_err(io)?;
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
        t => return Err(format!("socks: bad address type {t} in reply")),
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await.map_err(io)?;
    Ok((s, bound))
}

/// A stream to `target:port` through Tor, on the circuit `isolation` names.
pub async fn connect(proxy: SocketAddr, target: &Target<'_>, port: u16, isolation: &str) -> Result<TcpStream, String> {
    request(proxy, CMD_CONNECT, target, port, isolation).await.map(|(s, _)| s)
}

/// One address for `name`, resolved by a Tor exit (Tor answers a single record per query).
pub async fn resolve(proxy: SocketAddr, name: &str, isolation: &str) -> Result<IpAddr, String> {
    let (_s, ip) = request(proxy, CMD_RESOLVE, &Target::Name(name), 0, isolation).await?;
    if ip.is_unspecified() {
        return Err("tor: resolve returned no address".into());
    }
    Ok(ip)
}
