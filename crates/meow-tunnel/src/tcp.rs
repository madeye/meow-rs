use crate::relay::{copy_bidirectional_buf, RELAY_BUF_SIZE};
use crate::statistics::Statistics;
use crate::tunnel::TunnelInner;
use meow_common::{Metadata, ProxyConn};
use smallvec::{smallvec, SmallVec};
use smol_str::SmolStr;
use std::sync::Arc;
use tracing::{debug, info, warn};

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
pub struct ConnectionGuard<'a> {
    stats: &'a Statistics,
    id: uuid::Uuid,
}

impl<'a> ConnectionGuard<'a> {
    pub fn track(
        stats: &'a Statistics,
        metadata: Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        chains: SmallVec<[Arc<str>; 1]>,
    ) -> Self {
        let id = stats.track_connection(metadata, rule, rule_payload, chains);
        Self { stats, id }
    }

    pub fn id(&self) -> uuid::Uuid {
        self.id
    }
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.stats.close_connection(self.id);
    }
}

pub async fn handle_tcp(
    tunnel: &TunnelInner,
    mut conn: Box<dyn ProxyConn>,
    mut metadata: Metadata,
) {
    // Fake-IP → host rewrite (no-op outside fake-IP mode aside from a
    // snooping-cache hostname fill-in).
    tunnel.pre_handle_metadata(&mut metadata);

    // Match rules with lazy enrichment: DNS pre-resolution and process
    // lookup run only if the scan reaches a rule that demands them.
    let Some((proxy, rule_name, rule_payload)) = tunnel.resolve_proxy_lazy(&mut metadata).await
    else {
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
    // `rule_name` / `rule_payload` are moved in (already `SmolStr`); the
    // chains vec carries one `Arc<str>` for the proxy name.
    let _guard = ConnectionGuard::track(
        &tunnel.stats,
        metadata.pure(),
        rule_name,
        rule_payload,
        smallvec![Arc::from(proxy.name())],
    );

    // Declare relay buffers on the future's stack frame — zero per-relay heap
    // allocation (ADR-0011 T6). Paid once at task-spawn, not at relay-call time.
    let mut buf_up = [0u8; RELAY_BUF_SIZE];
    let mut buf_dn = [0u8; RELAY_BUF_SIZE];

    // Dial the remote via proxy
    match proxy.dial_tcp(&metadata).await {
        Ok(mut remote) => {
            match copy_bidirectional_buf(&mut conn, &mut remote, &mut buf_up, &mut buf_dn).await {
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
    use meow_common::{ConnType, Network};

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
            let _g = ConnectionGuard::track(
                &stats,
                metadata(),
                SmolStr::new_static("DOMAIN"),
                SmolStr::new_static("example.com"),
                smallvec![],
            );
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
            let _g = ConnectionGuard::track(
                &stats,
                metadata(),
                SmolStr::new_static("DOMAIN"),
                SmolStr::new_static("example.com"),
                smallvec![],
            );
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
        let g1 = ConnectionGuard::track(
            &stats,
            metadata(),
            SmolStr::new_static("DOMAIN"),
            SmolStr::new_static("a"),
            smallvec![],
        );
        let g2 = ConnectionGuard::track(
            &stats,
            metadata(),
            SmolStr::new_static("DOMAIN"),
            SmolStr::new_static("b"),
            smallvec![],
        );
        assert_eq!(stats.active_connection_count(), 2);
        drop(g1);
        assert_eq!(stats.active_connection_count(), 1);
        drop(g2);
        assert_eq!(stats.active_connection_count(), 0);
    }
}
