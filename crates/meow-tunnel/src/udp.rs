use crate::tunnel::TunnelInner;
use dashmap::DashMap;
use meow_common::adapter::ProxyAdapter;
use meow_common::atomic::AtomicU;
use meow_common::{Metadata, ProxyPacketConn};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Idle timeout before a UDP NAT session is swept. Matches upstream mihomo-go.
pub const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(60);

/// How often the sweeper scans for expired sessions.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// NAT table entry for UDP sessions.
// M2 layout change (ADR-0011 T3):
//   proxy_name: String (24 B heap) → Arc<str> (16 B fat-ptr, −8 B)
//   One allocation per distinct proxy name across all NAT entries; identical
//   names share the same Arc instead of each holding an independent heap copy.
pub struct UdpSession {
    pub conn: Box<dyn ProxyPacketConn>,
    pub proxy_name: Arc<str>,
    /// Monotonic millis since process start. Bumped on every fast-path forward
    /// so idle sessions can be evicted by [`spawn_nat_sweeper`].
    last_activity_ms: AtomicU,
}

impl UdpSession {
    pub fn new(conn: Box<dyn ProxyPacketConn>, proxy_name: Arc<str>) -> Self {
        Self {
            conn,
            proxy_name,
            last_activity_ms: AtomicU::new(monotonic_ms() as meow_common::atomic::Uint),
        }
    }

    /// Mark the session active as of now. Called on every outbound fast-path
    /// forward so [`spawn_nat_sweeper`] keeps the entry alive. `pub` so an
    /// out-of-crate reply reader (e.g. the meow-ios FFI, which owns the
    /// inbound read loop) can refresh the same clock on server→app traffic —
    /// otherwise a receive-active / send-quiet session is wrongly swept.
    pub fn touch(&self) {
        self.last_activity_ms.store(
            monotonic_ms() as meow_common::atomic::Uint,
            Ordering::Relaxed,
        );
    }

    /// Time since the last [`touch`](Self::touch). `pub` so an out-of-crate
    /// reply reader can gate its own idle backstop on the same bidirectional
    /// clock the sweeper uses, instead of a one-directional wall-clock timer.
    pub fn idle_for(&self) -> Duration {
        let now = monotonic_ms() as meow_common::atomic::Uint;
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; u32→u64 widening on mips32"
        )]
        Duration::from_millis(u64::from(now.wrapping_sub(last)))
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
    // Fake-IP → host rewrite (no-op outside fake-IP mode aside from a
    // snooping-cache hostname fill-in).
    tunnel.pre_handle_metadata(&mut metadata);

    // Pre-resolve metadata (host -> real IP if rules need it). UDP keeps
    // the eager pre_resolve + resolve_proxy pair (no lazy enrichment): the
    // NAT session key below requires a resolved dst_ip regardless of what
    // the rules demand.
    tunnel.pre_resolve(&mut metadata).await;

    // Rule-demand gating is only an optimization. UDP still requires a real
    // address for its NAT key and outbound packet API, including after a
    // fake-IP was rewritten back to a hostname under domain-only rules.
    if metadata.dst_ip.is_none() && !metadata.host.is_empty() {
        metadata.dst_ip = tunnel.resolver.resolve_ip_real(&metadata.host).await;
    }

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
    //
    // Clone the `Arc<UdpSession>` out and DROP the DashMap guard before the
    // `.await` below. `nat_table.get()` returns a `Ref` that holds a *read*
    // lock on the key's shard for as long as it is alive. Two ways the old
    // `if let Some(session) = nat_table.get(&key)` form deadlocked:
    //   1. The guard was held across `write_packet().await`, so while this task
    //      parked on the upstream round-trip the shard read-lock stayed held,
    //      blocking every same-shard `insert`/`remove`/sweep.
    //   2. On a write error it called `nat_table.remove(&key)` — a *write* lock
    //      on the very shard whose read-lock the `session` guard still held.
    //      A read+write on the same shard from one thread self-deadlocks the
    //      shard's RwLock, parking the worker forever; on the 2-worker iOS
    //      runtime both workers then wedge → total packet stall + dead control
    //      API. Fires whenever an established session's upstream has died and
    //      the app sends another datagram (common for QUIC / long-lived UDP).
    // Holding only the cloned `Arc` keeps the session alive with no lock held.
    let existing = tunnel.nat_table.get(&key).map(|s| Arc::clone(s.value()));
    if let Some(session) = existing {
        if let Err(e) = session.conn.write_packet(data, &dst_addr).await {
            debug!("UDP write error for {} -> {}: {}", src, dst_addr, e);
            tunnel.nat_table.remove(&key);
        } else {
            session.touch();
        }
        return;
    }

    // Slow path: new session — match rules and dial.
    //
    // UDP DNS bypass: any UDP packet destined for port 53 short-circuits
    // rule matching and is dialled DIRECT. Routing client DNS through a
    // proxy would defeat the whole point of the in-process DNS resolver
    // (rule-set selection, fake-IP, snooping) and on Android would push
    // queries through the VPN tun rather than over the protected fd.
    let (proxy, rule_name, rule_payload) = if metadata.dst_port == 53 {
        (
            Arc::clone(&tunnel.direct) as Arc<dyn ProxyAdapter>,
            smol_str::SmolStr::new_static("DnsBypass"),
            smol_str::SmolStr::default(),
        )
    } else {
        let Some(matched) = tunnel.resolve_proxy(&metadata) else {
            warn!("no matching rule for UDP {}", metadata.remote_address());
            return;
        };
        matched
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
            let session = Arc::new(UdpSession::new(conn, Arc::from(proxy.name())));
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
    use meow_common::error::Result as MeowResult;

    struct NoopPacketConn;

    #[async_trait]
    impl ProxyPacketConn for NoopPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
            Ok(buf.len())
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            Ok(())
        }
    }

    fn mk_session() -> Arc<UdpSession> {
        Arc::new(UdpSession::new(Box::new(NoopPacketConn), Arc::from("test")))
    }

    /// A packet conn whose `write_packet` always fails — models an established
    /// UDP session whose upstream relay has died. Used to drive the fast-path
    /// write-error branch in `handle_udp`.
    struct FailingPacketConn;

    #[async_trait]
    impl ProxyPacketConn for FailingPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, _buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
            Err(meow_common::MeowError::Other("upstream dead".into()))
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            Ok(())
        }
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
        table.insert(mk_key(1), Arc::clone(&session));

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

    /// Regression: a fast-path write failure on an existing session must evict
    /// the entry and return promptly. The previous code held the
    /// `nat_table.get()` shard read-guard across `write_packet().await` and then
    /// called `nat_table.remove()` (same-shard write lock) while the read-guard
    /// was still alive — a self-deadlock that hangs forever. The `timeout` here
    /// fails the test instead of hanging CI if that pattern is reintroduced.
    #[tokio::test(start_paused = false)]
    async fn fast_path_write_failure_evicts_without_deadlock() {
        use crate::tunnel::Tunnel;
        use meow_common::{DnsMode, Metadata, Network};
        use meow_dns::Resolver;
        use meow_trie::DomainTrie;

        let resolver = Arc::new(Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
        ));
        let tunnel = Tunnel::new(resolver);

        // Literal-IP destination so pre_resolve is a no-op and the NAT key is
        // deterministic. Insert a session whose upstream write always fails.
        let src = SocketAddr::from(([127, 0, 0, 1], 5555));
        let dst = SocketAddr::from(([198, 51, 100, 7], 443));
        let key = (src, dst);
        tunnel.inner().nat_table.insert(
            key,
            Arc::new(UdpSession::new(
                Box::new(FailingPacketConn),
                Arc::from("test"),
            )),
        );

        let metadata = Metadata {
            network: Network::Udp,
            src_ip: Some(src.ip()),
            src_port: src.port(),
            dst_ip: Some(dst.ip()),
            dst_port: dst.port(),
            ..Default::default()
        };

        tokio::time::timeout(
            Duration::from_secs(2),
            handle_udp(tunnel.inner(), b"ping", src, metadata),
        )
        .await
        .expect("handle_udp must not deadlock on a fast-path write failure");

        assert!(
            tunnel.inner().nat_table.get(&key).is_none(),
            "a session with a dead upstream must be evicted"
        );
    }
}
