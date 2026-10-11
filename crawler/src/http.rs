//! A minimal HTTP/1.1 client over any stream (Connection: close, identity encoding, chunked
//! bodies), for one HTTPS fetch through Tor and the local node's JSON-RPC.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub async fn request<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    method: &str,
    host: &str,
    path: &str,
    extra: &[(&str, String)],
    body: &[u8],
    max: usize,
) -> Result<Response, String> {
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: logos-peer-list/{}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        env!("CARGO_PKG_VERSION")
    );
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if method != "GET" {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    s.write_all(&out).await.map_err(|e| format!("http send: {e}"))?;
    s.flush().await.map_err(|e| format!("http send: {e}"))?;

    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > max {
                    return Err(format!("http: response over {max} bytes"));
                }
            }
            // A TLS peer that closes without close_notify: the framing below decides.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("http recv: {e}")),
        }
    }
    parse(&buf)
}

fn parse(buf: &[u8]) -> Result<Response, String> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or("http: no header end")?;
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| "http: header not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).ok_or_else(|| format!("http: bad status line {status_line:?}"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    let rest = &buf[end + 4..];
    let mut r = Response { status, headers, body: vec![] };
    if r.header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        r.body = dechunk(rest)?;
    } else if let Some(n) = r.header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if rest.len() < n {
            return Err(format!("http: body cut at {} of {n} bytes", rest.len()));
        }
        r.body = rest[..n].to_vec();
    } else {
        r.body = rest.to_vec();
    }
    Ok(r)
}

fn dechunk(mut b: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n").ok_or("http: chunk size line cut")?;
        let size_txt = std::str::from_utf8(&b[..eol]).map_err(|_| "http: bad chunk size")?;
        let size = usize::from_str_radix(size_txt.split(';').next().unwrap_or("").trim(), 16).map_err(|_| "http: bad chunk size")?;
        b = &b[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if b.len() < size + 2 {
            return Err("http: chunk cut".into());
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing() {
        let r = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nratelimit-remaining: 9\r\n\r\nhiXX").unwrap();
        assert_eq!((r.status, r.body.as_slice(), r.header("RateLimit-Remaining")), (200, &b"hi"[..], Some("9")));
        let r = parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n").unwrap();
        assert_eq!(r.body, b"abcde");
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc").is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab").is_err());
    }
}
