//! Ed25519 list keys (ring). The secret is a PKCS#8 document, base64, in a file kept outside
//! the repo; the public half is a small JSON file the node module compiles in.

use std::path::Path;

use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `<label>-<first 8 bytes of SHA-256 of the public key, hex>`.
pub fn key_id(label: &str, public: &[u8]) -> String {
    format!("{label}-{}", hex::encode(&Sha256::digest(public)[..8]))
}

pub struct SecretKey {
    pair: Ed25519KeyPair,
    pkcs8: Vec<u8>,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicKey {
    pub key_id: String,
    /// 32 bytes, hex.
    pub ed25519: String,
    pub note: String,
}

impl SecretKey {
    pub fn generate(label: &str) -> Result<Self, String> {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| "key generation failed")?;
        Self::from_pkcs8(label, doc.as_ref())
    }

    fn from_pkcs8(label: &str, pkcs8: &[u8]) -> Result<Self, String> {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|e| format!("bad key: {e}"))?;
        let key_id = key_id(label, pair.public_key().as_ref());
        Ok(SecretKey { pair, pkcs8: pkcs8.to_vec(), key_id })
    }

    /// The file holds `<label> <base64 PKCS#8>`.
    pub fn load(path: &Path) -> Result<Self, String> {
        let t = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let (label, b64) = t.trim().split_once(' ').ok_or("secret key file: expected '<label> <base64>'")?;
        let der = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| format!("secret key file: {e}"))?;
        Self::from_pkcs8(label, &der)
    }

    pub fn save(&self, path: &Path, label: &str) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("{}: {e} (never overwritten)", path.display()))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&self.pkcs8);
        f.write_all(format!("{label} {b64}\n").as_bytes()).map_err(|e| e.to_string())
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.pair.sign(msg).as_ref().to_vec()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey {
            key_id: self.key_id.clone(),
            ed25519: hex::encode(self.pair.public_key().as_ref()),
            note: "TEST key for logos-bitcoin-peer-list lists; not a release key".into(),
        }
    }
}

impl PublicKey {
    pub fn load(path: &Path) -> Result<Self, String> {
        let t = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_slice(&t).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), String> {
        let pk = hex::decode(&self.ed25519).map_err(|_| "public key is not hex")?;
        UnparsedPublicKey::new(&ED25519, pk).verify(msg, sig).map_err(|_| "signature does not verify".into())
    }
}
