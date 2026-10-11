//! DNS seeds asked for x49 through Tor's RESOLVE. Tor answers one address per query, so each
//! seed is asked a few times, each on a fresh circuit (another exit, another resolver).

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::results::SeedResult;
use crate::socks;
use crate::util::isolation;

pub async fn query_all(proxy: SocketAddr, seeds: &[&str], queries: u32, timeout: Duration) -> (Vec<SeedResult>, Vec<IpAddr>) {
    let mut tasks = tokio::task::JoinSet::new();
    // Four at a time, on top of the global stream pacing.
    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    for (i, seed) in seeds.iter().enumerate() {
        let name = format!("x49.{seed}");
        for _ in 0..queries {
            let (name, gate) = (name.clone(), gate.clone());
            tasks.spawn(async move {
                let _permit = gate.acquire_owned().await;
                let r = tokio::time::timeout(timeout, socks::resolve(proxy, &name, &isolation())).await;
                (i, r.unwrap_or_else(|_| Err("timeout".into())))
            });
        }
    }
    let mut results: Vec<SeedResult> = seeds
        .iter()
        .map(|s| SeedResult { name: format!("x49.{s}"), queries, ..SeedResult::default() })
        .collect();
    let mut found: Vec<BTreeSet<IpAddr>> = vec![BTreeSet::new(); seeds.len()];
    while let Some(Ok((i, r))) = tasks.join_next().await {
        match r {
            Ok(ip) => {
                results[i].answers += 1;
                found[i].insert(ip);
            }
            Err(e) => *results[i].errors.entry(e).or_default() += 1,
        }
    }
    let mut all = BTreeSet::new();
    for (r, f) in results.iter_mut().zip(found) {
        r.addresses = f.iter().map(IpAddr::to_string).collect();
        all.extend(f);
    }
    (results, all.into_iter().collect())
}
