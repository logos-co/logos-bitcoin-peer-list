//! JSON-RPC to our own node on loopback, with its cookie: the signet reference.

use std::net::SocketAddr;
use std::path::Path;

use base64::Engine;
use serde_json::{json, Value};
use tokio::net::TcpStream;

pub struct Rpc {
    addr: SocketAddr,
    auth: String,
}

impl Rpc {
    pub fn from_cookie(port: u16, cookie: &Path) -> Result<Self, String> {
        let c = std::fs::read_to_string(cookie).map_err(|e| format!("rpc cookie {}: {e}", cookie.display()))?;
        let auth = base64::engine::general_purpose::STANDARD.encode(c.trim());
        Ok(Rpc { addr: SocketAddr::from(([127, 0, 0, 1], port)), auth })
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let mut s = TcpStream::connect(self.addr).await.map_err(|e| format!("rpc connect: {e}"))?;
        let body = json!({"jsonrpc": "1.0", "id": "peer-list", "method": method, "params": params}).to_string();
        let headers = [("Authorization", format!("Basic {}", self.auth)), ("Content-Type", "application/json".into())];
        let r = crate::http::request(&mut s, "POST", "127.0.0.1", "/", &headers, body.as_bytes(), 64 * 1024 * 1024).await?;
        let v: Value = serde_json::from_slice(&r.body).map_err(|e| format!("rpc {method}: HTTP {} {e}", r.status))?;
        if !v["error"].is_null() {
            return Err(format!("rpc {method}: {}", v["error"]));
        }
        Ok(v["result"].clone())
    }

    pub async fn block_hash(&self, height: u32) -> Result<String, String> {
        self.call("getblockhash", json!([height])).await?.as_str().map(String::from).ok_or_else(|| "rpc getblockhash: not a string".into())
    }

    /// The basic filter header at `height`, as Core prints it.
    pub async fn filter_header(&self, height: u32) -> Result<String, String> {
        let hash = self.block_hash(height).await?;
        let f = self.call("getblockfilter", json!([hash, "basic"])).await?;
        f["header"].as_str().map(String::from).ok_or_else(|| "rpc getblockfilter: no header".into())
    }
}
