use crate::tunnel::TunnelInner;
use dashmap::DashMap;
use mihomo_common::{Metadata, ProxyPacketConn};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Idle timeout before a UDP NAT session is swept. Matches upstream mihomo-go.
pub const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(60);

/// How often the sweeper scans for expired sessions.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// NAT table entry for UDP sessions
pub struct UdpSession {
    pub conn: Box<dyn ProxyPacketConn>,
    pub proxy_name: String,
    /// Monotonic millis since process start. Bumped on every fast-path forward
    /// so idle sessions can be evicted by [`spawn_nat_sweeper`].
    last_activity_ms: AtomicU64,
}

impl UdpSession {
    pub fn new(conn: Box<dyn ProxyPacketConn>, proxy_name: String) -> Self {
        Self {
            conn,
            proxy_name,
            last_activity_ms: AtomicU64::new(monotonic_ms()),
        }
    }

    fn touch(&self) {
        self.last_activity_ms
            .store(monotonic_ms(), Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let now = monotonic_ms();
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        Duration::from_millis(now.saturating_sub(last))
    }
}

fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

// Direction A (ADR-0008 §6): key is a (src, dst) SocketAddr tuple — zero heap
// allocation on the per-packet fast path, replacing the previous String built
// by `format!("{}:{}", src, metadata.remote_address())`.
pub type NatTable = Arc<DashMap<(SocketAddr, SocketAddr), Arc<UdpSession>>>;

pub fn new_nat_table() -> NatTable {
    Arc::new(DashMap::new())
}

/// Spawn the background sweeper that evicts UDP NAT sessions idle for more
/// than `idle`. Scans every `interval`. The task exits when the caller drops
/// the returned `JoinHandle`'s aborter (or the last Arc to the table is
/// dropped and the weak upgrade fails).
pub fn spawn_nat_sweeper(
    nat_table: &NatTable,
    idle: Duration,
    interval: Duration,
) -> JoinHandle<()> {
    let weak = Arc::downgrade(nat_table);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately; skip it.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Some(table) = weak.upgrade() else {
                debug!("UDP NAT sweeper: table dropped, exiting");
                return;
            };
            let before = table.len();
            if before == 0 {
                continue;
            }
            table.retain(|_key, session| session.idle_for() < idle);
            let evicted = before.saturating_sub(table.len());
            if evicted > 0 {
                debug!(
                    "UDP NAT sweeper: evicted {evicted} idle sessions (remaining {})",
                    table.len()
                );
            }
        }
    })
}

/// Handle a UDP packet: look up or create a NAT session.
pub async fn handle_udp(
    tunnel: &TunnelInner,
    data: &[u8],
    src: SocketAddr,
    mut metadata: Metadata,
) {
    // Pre-resolve metadata (host -> real IP if rules need it).
    tunnel.pre_resolve(&mut metadata).await;

    // Build destination SocketAddr for the NAT key.
    // pre_resolve() populates dst_ip for any hostname; if it is still None
    // after that (resolution failure or unresolvable host), we cannot track
    // the session and must discard the packet.
    let Some(dst_ip) = metadata.dst_ip else {
        warn!(
            "UDP {}: dst_ip not resolved after pre_resolve — dropping",
            metadata.remote_address()
        );
        return;
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);
    let key = (src, dst_addr);

    // Fast path: existing session — forward and return.
    if let Some(session) = tunnel.nat_table.get(&key) {
        if let Err(e) = session.conn.write_packet(data, &dst_addr).await {
            debug!("UDP write error for {} -> {}: {}", src, dst_addr, e);
            tunnel.nat_table.remove(&key);
        } else {
            session.touch();
        }
        return;
    }

    // Slow path: new session — match rules and dial.
    let (proxy, rule_name, rule_payload) = match tunnel.resolve_proxy(&metadata) {
        Some(v) => v,
        None => {
            warn!("no matching rule for UDP {}", metadata.remote_address());
            return;
        }
    };

    info!(
        "UDP {} --> {} match {}({}) using {}",
        src,
        dst_addr,
        rule_name,
        rule_payload,
        proxy.name()
    );

    match proxy.dial_udp(&metadata).await {
        Ok(conn) => {
            if let Err(e) = conn.write_packet(data, &dst_addr).await {
                warn!("UDP initial write error for {} -> {}: {}", src, dst_addr, e);
                return;
            }
            let session = Arc::new(UdpSession::new(conn, proxy.name().to_string()));
            tunnel.nat_table.insert(key, session);
        }
        Err(e) => {
            warn!("UDP dial error for {} -> {}: {}", src, dst_addr, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mihomo_common::error::Result as MihomoResult;

    struct NoopPacketConn;

    #[async_trait]
    impl ProxyPacketConn for NoopPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MihomoResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> MihomoResult<usize> {
            Ok(buf.len())
        }
        fn local_addr(&self) -> MihomoResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MihomoResult<()> {
            Ok(())
        }
    }

    fn mk_session() -> Arc<UdpSession> {
        Arc::new(UdpSession::new(Box::new(NoopPacketConn), "test".into()))
    }

    fn mk_key(port: u16) -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::from(([8, 8, 8, 8], 53)),
        )
    }

    #[tokio::test(start_paused = false)]
    async fn sweeper_evicts_idle_sessions() {
        let table = new_nat_table();
        table.insert(mk_key(1), mk_session());
        table.insert(mk_key(2), mk_session());
        assert_eq!(table.len(), 2);

        let _handle =
            spawn_nat_sweeper(&table, Duration::from_millis(50), Duration::from_millis(20));

        // Wait past the idle threshold; sweeper runs every 20ms.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(table.len(), 0, "idle sessions should have been swept");
    }

    #[tokio::test(start_paused = false)]
    async fn touched_sessions_are_kept() {
        let table = new_nat_table();
        let session = mk_session();
        table.insert(mk_key(1), session.clone());

        let _handle =
            spawn_nat_sweeper(&table, Duration::from_millis(80), Duration::from_millis(20));

        // Touch repeatedly so the session stays young.
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            session.touch();
        }
        assert_eq!(table.len(), 1, "active session must not be evicted");
    }

    #[tokio::test(start_paused = false)]
    async fn sweeper_exits_when_table_dropped() {
        let table = new_nat_table();
        table.insert(mk_key(1), mk_session());
        let handle = spawn_nat_sweeper(&table, Duration::from_secs(60), Duration::from_millis(20));
        drop(table);
        // Allow the next tick to observe the dropped table.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            handle.is_finished(),
            "sweeper should exit once the table is dropped"
        );
    }
}
