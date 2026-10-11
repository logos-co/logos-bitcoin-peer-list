//! Onion v3 addresses: the checksum, and conversion to and from BIP155 TorV3 keys.

use sha3::{Digest, Sha3_256};

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn b32_encode(data: &[u8]) -> String {
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
        buf &= (1 << bits) - 1;
    }
    Some(out)
}

/// `<56 chars>.onion` for a v3 service key.
pub fn from_pubkey(pk: &[u8; 32]) -> String {
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pk);
    h.update([3u8]);
    let cs = h.finalize();
    let mut raw = [0u8; 35];
    raw[..32].copy_from_slice(pk);
    raw[32] = cs[0];
    raw[33] = cs[1];
    raw[34] = 3;
    format!("{}.onion", b32_encode(&raw))
}

/// The service key of a v3 onion host, if its version and checksum check (lowercase only).
pub fn to_pubkey(host: &str) -> Option<[u8; 32]> {
    let label = host.strip_suffix(".onion")?;
    if label.len() != 56 {
        return None;
    }
    let raw = b32_decode(label)?;
    if raw.len() != 35 || raw[34] != 3 {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[..32]);
    (from_pubkey(&pk) == host).then_some(pk)
}

/// `host:port` split, for onion and IPv4 hosts (IPv6 in brackets).
pub fn split_host_port(s: &str) -> Option<(&str, u16)> {
    let (h, p) = s.rsplit_once(':')?;
    let port: u16 = p.parse().ok().filter(|&p| p != 0)?;
    Some((h.trim_start_matches('[').trim_end_matches(']'), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_checksum() {
        for seed in [0u8, 7, 255] {
            let pk = [seed; 32];
            let host = from_pubkey(&pk);
            assert_eq!(host.len(), 62);
            assert_eq!(to_pubkey(&host), Some(pk));
            // One flipped character breaks the checksum.
            let mut bad = host.clone().into_bytes();
            bad[10] = if bad[10] == b'a' { b'b' } else { b'a' };
            assert_eq!(to_pubkey(std::str::from_utf8(&bad).unwrap()), None);
        }
        // A real listening onion peer (btcnodes.io snapshot, 2026-10-07).
        let real = "5oycgv257gi666xvtc27ix3obygl2j6iy7qx2qgrulh6nst2bku7jmid.onion";
        assert_eq!(to_pubkey(real).map(|pk| from_pubkey(&pk)).as_deref(), Some(real));
        assert_eq!(to_pubkey("expyuzz4wqqyqhjn.onion"), None, "v2 is refused");
        assert_eq!(split_host_port("[2001:db8::1]:8333"), Some(("2001:db8::1", 8333)));
        assert_eq!(split_host_port("1.2.3.4:0"), None);
    }
}
