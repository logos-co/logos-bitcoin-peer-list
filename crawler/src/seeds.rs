//! Bitcoin Core's fixed seeds, onion v3 only, per network: the node module ships them as its
//! first-contact fallback. Read from a Core source tree's contrib/seeds/nodes_*.txt.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::onion;

pub const FORMAT: u32 = 1;
/// The networks the node module keeps, and Core's seed file for each.
pub const FILES: [(&str, &str); 3] = [("mainnet", "nodes_main.txt"), ("signet", "nodes_signet.txt"), ("testnet4", "nodes_testnet4.txt")];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Seeds {
    pub format: u32,
    pub network: String,
    /// Where they came from, such as `Bitcoin Core 31.1 contrib/seeds/nodes_main.txt`.
    pub source: String,
    pub peers: Vec<String>,
}

/// The onion v3 `host:port` lines of a seed file, checksums checked, sorted and unique.
pub fn parse(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().next())
        .filter_map(|t| onion::split_host_port(t).filter(|(h, _)| onion::to_pubkey(h).is_some()).map(|(h, p)| format!("{h}:{p}")))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `31.1` from the tree's CMakeLists.txt, when it says.
fn version(core_src: &Path) -> Option<String> {
    let text = std::fs::read_to_string(core_src.join("CMakeLists.txt")).ok()?;
    let field = |name: &str| text.lines().find_map(|l| l.trim().strip_prefix(&format!("set({name} ")).and_then(|r| r.trim_end_matches(')').trim().parse::<u32>().ok()));
    Some(format!("{}.{}", field("CLIENT_VERSION_MAJOR")?, field("CLIENT_VERSION_MINOR")?))
}

pub fn extract(core_src: &Path) -> Result<Vec<Seeds>, String> {
    let label = version(core_src).map(|v| format!("Bitcoin Core {v}")).unwrap_or_else(|| "Bitcoin Core".into());
    FILES
        .iter()
        .map(|(net, file)| {
            let path = core_src.join("contrib/seeds").join(file);
            let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let peers = parse(&text);
            if peers.is_empty() {
                return Err(format!("{}: no onion v3 seeds", path.display()));
            }
            Ok(Seeds { format: FORMAT, network: net.to_string(), source: format!("{label} contrib/seeds/{file}, onion v3 only"), peers })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_v3_lines_only() {
        let good = onion::from_pubkey(&[5; 32]);
        let bad = good.replacen('a', "b", 1);
        let text = format!(
            "# comment\n1.2.3.4:8333\n[2001:db8::1]:8333\n{good}:8333 # trailing\n{bad}:8333\nabcd.b32.i2p:0\n\n{good}:8333\n[fc00::1]:8333\n"
        );
        assert_eq!(parse(&text), vec![format!("{good}:8333")], "IP, I2P, CJDNS and a bad checksum dropped; duplicates once");
    }

    #[test]
    fn reads_a_core_tree() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("contrib/seeds")).unwrap();
        std::fs::write(dir.path().join("CMakeLists.txt"), "set(CLIENT_VERSION_MAJOR 31)\nset(CLIENT_VERSION_MINOR 1)\n").unwrap();
        for (i, (_, file)) in FILES.iter().enumerate() {
            let line = format!("{}:{}\n", onion::from_pubkey(&[i as u8 + 1; 32]), 8333 + i);
            std::fs::write(dir.path().join("contrib/seeds").join(file), line).unwrap();
        }
        let seeds = extract(dir.path()).unwrap();
        assert_eq!(seeds.iter().map(|s| s.network.as_str()).collect::<Vec<_>>(), ["mainnet", "signet", "testnet4"]);
        assert_eq!(seeds[0].source, "Bitcoin Core 31.1 contrib/seeds/nodes_main.txt, onion v3 only");
        assert!(seeds.iter().all(|s| s.peers.len() == 1));
        std::fs::write(dir.path().join("contrib/seeds/nodes_signet.txt"), "1.2.3.4:38333\n").unwrap();
        assert!(extract(dir.path()).unwrap_err().contains("no onion v3 seeds"));
    }
}
