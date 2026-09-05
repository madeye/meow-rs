use crate::relay::{copy_bidirectional_buf_tracked, RELAY_BUF_SIZE};
use crate::statistics::Statistics;
use crate::tunnel::TunnelInner;
use meow_common::{with_dial_timeout, Metadata, ProxyConn};
use smallvec::{smallvec, SmallVec};
use smol_str::SmolStr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
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
    counters: Arc<crate::statistics::ConnCounters>,
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
        // Entry was just inserted; the fallback Arc only exists to keep this
        // infallible if a concurrent close_all ever races connection setup.
        let counters = stats.connection_counters(id).unwrap_or_default();
        Self {
            stats,
            id,
            counters,
        }
    }

    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    /// Live byte counters shared with the statistics table. Clone the `Arc`
    /// into relay progress callbacks so the hot loop never touches the map.
    pub fn counters(&self) -> &Arc<crate::statistics::ConnCounters> {
        &self.counters
    }
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.stats.close_connection(self.id);
    }
}

pub async fn handle_tcp(tunnel: &TunnelInner, mut conn: Box<dyn ProxyConn>, metadata: Metadata) {
    route_inbound_tcp(tunnel, &mut conn, metadata, &[]).await;
}

/// Route a decrypted inbound TCP connection through the rule engine and relay
/// it to the matched proxy.
///
/// This is the shared tail of every blind-tunnel listener (SOCKS5 CONNECT,
/// HTTP CONNECT, the `handle_tcp` entry point, and — once added — the
/// shadowsocks inbound). It owns the four pieces that were previously
/// copy-pasted into each listener:
///
/// 1. fake-IP / snooping rewrite (`pre_handle_metadata`),
/// 2. lazy rule match + connection tracking,
/// 3. dial the matched proxy,
/// 4. bidirectional relay with byte counters.
///
/// `prefix` carries any bytes the listener already buffered ahead of the
/// relay (e.g. HTTP CONNECT pipelined application data); they are written to
/// the remote before the copy loop and counted as upload. Pass `&[]` when the
/// listener hands over a clean stream.
///
/// Relay scratch buffers are stack-allocated in this frame — zero
/// per-relay-setup heap allocation (ADR-0008 HP-1/HP-2/HP-3). The generic
/// parameter keeps the relay monomorphised per concrete stream type so the
/// hot copy loop stays dispatch-free.
///
/// Listeners whose relay is *not* a blind tunnel (e.g. the plain-HTTP proxy
/// path that rewrites the request line and wraps the client in a bounded
/// `SingleRequestClient`, or the TProxy path that uses eager rule
/// resolution) keep their own inline routing — this helper only targets the
/// `pre_handle_metadata` + `resolve_proxy_lazy` + blind-relay shape.
///
/// # Visibility
///
/// Exported as `pub` from `meow-tunnel` so that `meow-listener` can call it
/// directly from the SOCKS5/HTTP-CONNECT handlers. This is a workspace-internal
/// API contract: both crates are in the same workspace and share the
/// `TunnelInner` type, so the function is not intended for external consumers —
/// hence `#[doc(hidden)]`, which keeps it out of the public rustdoc surface
/// without restricting the workspace-internal call path (review low item).
///
/// The bound is the relay's actual needs (`AsyncRead + AsyncWrite + Unpin +
/// Send`) rather than `ProxyConn`: `ProxyConn` is defined in `meow-common`
/// and cannot be implemented for a foreign type like the `shadowsocks` crate's
/// `ProxyServerStream` from outside `meow-common` (orphan rule). `Sync` is not
/// required — the connection lives in a single spawned task. `handle_tcp`
/// still passes its `Box<dyn ProxyConn>`, which satisfies this bound via
/// tokio's `Box<?Sized + AsyncRead + Unpin>` impls.
#[doc(hidden)]
pub async fn route_inbound_tcp<C>(
    inner: &TunnelInner,
    conn: &mut C,
    mut metadata: Metadata,
    prefix: &[u8],
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // Fake-IP → host rewrite (no-op outside fake-IP mode aside from a
    // snooping-cache hostname fill-in).
    inner.pre_handle_metadata(&mut metadata);

    // Match rules with lazy enrichment: DNS pre-resolution and process
    // lookup run only if the scan reaches a rule that demands them.
    let Some((proxy, rule_name, rule_payload)) = inner.resolve_proxy_lazy(&mut metadata).await
    else {
        warn!(
            "{} no matching rule for {}",
            metadata.conn_type,
            metadata.remote_address()
        );
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
    let guard = ConnectionGuard::track(
        &inner.stats,
        metadata.pure(),
        rule_name,
        rule_payload,
        smallvec![Arc::from(proxy.name())],
    );

    // Declare relay buffers on the future's stack frame — zero per-relay heap
    // allocation (ADR-0011 T6). Paid once at task-spawn, not at relay-call time.
    let mut buf_up = [0u8; RELAY_BUF_SIZE];
    let mut buf_dn = [0u8; RELAY_BUF_SIZE];

    // Dial the remote via proxy, bounded like mihomo's `C.DefaultTCPTimeout`:
    // a server that accepts and then stalls mid-handshake would otherwise pin
    // this task, its inbound socket and its stats entry forever.
    match with_dial_timeout(proxy.name(), proxy.dial_tcp(&metadata)).await {
        Ok(mut remote) => {
            let up = Arc::clone(guard.counters());
            let dn = Arc::clone(guard.counters());
            // Re-emit any bytes the listener already read past the handshake
            // (e.g. pipelined TLS ClientHello after a CONNECT 200). Counted
            // as upload so the connection stats stay accurate. A failure
            // here kills the connection (the remote half is unusable), so it
            // must be visible at `warn` — the pre-refactor code propagated
            // it to the caller instead of swallowing it at `debug`
            // (review M9).
            if !prefix.is_empty() {
                if let Err(e) = remote.write_all(prefix).await {
                    warn!(
                        "{} {} prefix write error: {}",
                        metadata.conn_type,
                        metadata.remote_address(),
                        e
                    );
                    return;
                }
                inner
                    .stats
                    .record_upload(&up, prefix.len() as meow_common::atomic::Int);
            }
            match copy_bidirectional_buf_tracked(
                conn,
                &mut remote,
                &mut buf_up,
                &mut buf_dn,
                |n| {
                    inner
                        .stats
                        .record_upload(&up, n as meow_common::atomic::Int);
                },
                |n| {
                    inner
                        .stats
                        .record_download(&dn, n as meow_common::atomic::Int);
                },
            )
            .await
            {
                Ok((up, down)) => {
                    debug!(
                        "{} {} relay closed: up={} down={}",
                        metadata.conn_type,
                        metadata.remote_address(),
                        up,
                        down
                    );
                }
                Err(e) => {
                    debug!(
                        "{} {} relay error: {}",
                        metadata.conn_type,
                        metadata.remote_address(),
                        e
                    );
                }
            }
        }
        Err(e) => {
            warn!(
                "{} {} dial error: {}",
                metadata.conn_type,
                metadata.remote_address(),
                e
            );
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
