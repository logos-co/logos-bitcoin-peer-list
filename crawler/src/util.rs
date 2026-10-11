//! Small helpers: UTC time formatting, SOCKS isolation tokens, percentiles.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `2026-10-10T23:05:00Z`
pub fn rfc3339(unix: u64) -> String {
    let (y, m, d) = civil((unix / 86_400) as i64);
    let s = unix % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

/// `2026-10-10`
pub fn day(unix: u64) -> String {
    rfc3339(unix)[..10].to_string()
}

/// A file-name-safe stamp: `20261010T230500Z`.
pub fn stamp(unix: u64) -> String {
    rfc3339(unix).replace(['-', ':'], "")
}

/// Spaces out new Tor streams (each a new circuit) so a run never bursts circuit builds.
pub struct Pacer {
    next: tokio::sync::Mutex<tokio::time::Instant>,
    gap: std::time::Duration,
}

impl Pacer {
    pub fn new(per_second: f64) -> Self {
        let gap = std::time::Duration::from_secs_f64(1.0 / per_second.max(0.01));
        Pacer { next: tokio::sync::Mutex::new(tokio::time::Instant::now()), gap }
    }

    pub async fn wait(&self) {
        let at = {
            let mut next = self.next.lock().await;
            let at = (*next).max(tokio::time::Instant::now());
            *next = at + self.gap;
            at
        };
        tokio::time::sleep_until(at).await;
    }
}

static PACER: std::sync::OnceLock<Pacer> = std::sync::OnceLock::new();

/// Sets the stream rate once, at start; 2 per second unless set.
pub fn set_stream_rate(per_second: f64) {
    let _ = PACER.set(Pacer::new(per_second));
}

pub async fn pace() {
    PACER.get_or_init(|| Pacer::new(2.0)).wait().await;
}

/// Fresh SOCKS credentials, so Tor (IsolateSOCKSAuth) gives the stream its own circuit.
pub fn isolation() -> String {
    format!("bpl-{:016x}", rand::random::<u64>())
}

/// Nearest-rank percentiles of `v` (sorted here); empty when `v` is.
pub fn percentiles(v: &mut [u64], ps: &[u32]) -> Vec<(u32, u64)> {
    if v.is_empty() {
        return vec![];
    }
    v.sort_unstable();
    ps.iter()
        .map(|&p| {
            let rank = ((p as usize * v.len()).div_ceil(100)).clamp(1, v.len());
            (p, v[rank - 1])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_791_383_742), "2026-10-07T14:35:42Z");
        assert_eq!(day(1_791_383_742), "2026-10-07");
        assert_eq!(stamp(1_791_383_742), "20261007T143542Z");
    }

    #[tokio::test]
    async fn pacing() {
        let p = Pacer::new(20.0);
        let t = std::time::Instant::now();
        for _ in 0..5 {
            p.wait().await;
        }
        let e = t.elapsed().as_millis();
        assert!((190..400).contains(&e), "{e} ms for 5 at 20/s");
    }

    #[test]
    fn nearest_rank() {
        let mut v = vec![50, 10, 40, 20, 30];
        assert_eq!(percentiles(&mut v, &[10, 50, 90, 100]), vec![(10, 10), (50, 30), (90, 50), (100, 50)]);
        assert!(percentiles(&mut [], &[50]).is_empty());
        assert_ne!(isolation(), isolation());
    }
}
