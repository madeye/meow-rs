use crate::statistics::Statistics;
use crate::tunnel::TunnelInner;
use mihomo_common::{Metadata, ProxyConn};
use tokio::io;
use tracing::{debug, info, warn};

/// Per-direction relay buffer for `copy_bidirectional_with_sizes`. Two of these
/// live for the full connection lifetime, so on an iOS NE 50MB cap halving
/// the tokio default (8 KB → 4 KB) saves 8 KB/conn — ~40 MB at 5k conns.
const RELAY_BUF_SIZE: usize = 4 * 1024;

/// RAII wrapper around `Statistics::track_connection` /
/// `close_connection`. The previous implementation called
/// `close_connection` on the last line of `handle_tcp`, which is
/// unreachable when the future is dropped mid-`.await` — that happens
/// every time an embedder cancels the task (iOS tun2socks idle sweeper,
/// `JoinHandle::abort()`, tunnel shutdown, panic-unwind, etc.). Each
/// aborted flow leaked one entry in `Statistics.connections`, and the
/// `/connections` REST endpoint reads that map directly, so abort-heavy
/// embedders see the count climb without bound until process restart.
///
/// `Drop` runs on every exit path including unwind, so the entry is
/// removed regardless of how the surrounding future ends. Holding an
/// `&Statistics` is sufficient — the caller already owns an
/// `Arc<Statistics>` (via `TunnelInner.stats`) that outlives the guard.
struct ConnectionGuard<'a> {
    stats: &'a Statistics,
    id: String,
}

impl<'a> ConnectionGuard<'a> {
    fn track(
        stats: &'a Statistics,
        metadata: Metadata,
        rule: &str,
        rule_payload: &str,
        chains: Vec<String>,
    ) -> Self {
        let id = stats.track_connection(metadata, rule, rule_payload, chains);
        Self { stats, id }
    }
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.stats.close_connection(&self.id);
    }
}

pub async fn handle_tcp(
    tunnel: &TunnelInner,
    mut conn: Box<dyn ProxyConn>,
    mut metadata: Metadata,
) {
    // Pre-resolve metadata (host -> real IP if rules need it)
    tunnel.pre_resolve(&mut metadata).await;

    // Match rules to find the right proxy
    let Some((proxy, rule_name, rule_payload)) = tunnel.resolve_proxy(&metadata) else {
        warn!("no matching rule for {}", metadata.remote_address());
        return;
    };

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    // Track the connection — guard drops it on every exit path, including
    // the abort case where the manual close call below would never run.
    let _guard = ConnectionGuard::track(
        &tunnel.stats,
        metadata.pure(),
        &rule_name,
        &rule_payload,
        vec![proxy.name().to_string()],
    );

    // Dial the remote via proxy
    match proxy.dial_tcp(&metadata).await {
        Ok(mut remote) => {
            // Bidirectional copy
            match io::copy_bidirectional_with_sizes(
                &mut conn,
                &mut remote,
                RELAY_BUF_SIZE,
                RELAY_BUF_SIZE,
            )
            .await
            {
                Ok((up, down)) => {
                    tunnel.stats.add_upload(up as i64);
                    tunnel.stats.add_download(down as i64);
                    debug!(
                        "{} closed: up={} down={}",
                        metadata.remote_address(),
                        up,
                        down
                    );
                }
                Err(e) => {
                    debug!("{} relay error: {}", metadata.remote_address(), e);
                }
            }
        }
        Err(e) => {
            warn!("{} dial error: {}", metadata.remote_address(), e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mihomo_common::{ConnType, Network};

    fn metadata() -> Metadata {
        Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        }
    }

    #[test]
    fn guard_removes_entry_on_drop() {
        let stats = Statistics::new();
        {
            let _g = ConnectionGuard::track(&stats, metadata(), "DOMAIN", "example.com", vec![]);
            assert_eq!(stats.active_connection_count(), 1, "entry tracked");
        }
        assert_eq!(
            stats.active_connection_count(),
            0,
            "entry removed when guard goes out of scope"
        );
    }

    #[test]
    fn guard_removes_entry_on_unwind() {
        let stats = Statistics::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = ConnectionGuard::track(&stats, metadata(), "DOMAIN", "example.com", vec![]);
            assert_eq!(stats.active_connection_count(), 1);
            panic!("simulating mid-relay abort");
        }));
        assert!(result.is_err(), "panic must propagate");
        assert_eq!(
            stats.active_connection_count(),
            0,
            "entry removed even when the holding scope unwinds"
        );
    }

    #[test]
    fn multiple_guards_independent() {
        let stats = Statistics::new();
        let g1 = ConnectionGuard::track(&stats, metadata(), "DOMAIN", "a", vec![]);
        let g2 = ConnectionGuard::track(&stats, metadata(), "DOMAIN", "b", vec![]);
        assert_eq!(stats.active_connection_count(), 2);
        drop(g1);
        assert_eq!(stats.active_connection_count(), 1);
        drop(g2);
        assert_eq!(stats.active_connection_count(), 0);
    }
}
