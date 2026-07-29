//! TUN inbound — transparent proxying via an L3 device (issue #326).
//!
//! This is the transparent-proxy path for platforms without a
//! tproxy/REDIRECT firewall — Windows first and foremost — and works the
//! same on Linux and macOS. A `tun-rs` device receives raw IP packets; the
//! `netstack-smoltcp` userspace TCP/IP stack (smoltcp-backed, the same
//! netstack clash-rs uses) terminates them and hands us ordinary
//! `AsyncRead + AsyncWrite` streams (TCP) and a packet-level UDP socket,
//! which are dispatched into the tunnel exactly like every other inbound.
//!
//! ## Loop freedom (v1: fake-IP-scoped capture)
//!
//! The classic TUN failure mode is the routing loop: a global default route
//! into the device makes meow's *own* outbound dials re-enter the tun. v1
//! avoids the whole problem class by capturing only the fake-IP range:
//!
//! 1. The OS resolver is pointed at an address inside the routed range, so
//!    DNS queries enter the tun and `dns-hijack` answers them with fake IPs.
//! 2. Client connections to those fake IPs route into the tun; the fake-IP
//!    rewrite recovers the hostname and rules match on domain.
//! 3. Outbound dials — proxy upstreams *and* DIRECT — go to real IPs, which
//!    are never inside the fake range, so they take the physical route and
//!    cannot loop. No SO_MARK, interface binding, or bypass routes needed.
//!
//! The trade-off: IP-literal traffic (no DNS lookup) is not captured.
//! Global capture ("route everything") needs loop protection on the
//! outbound path and is left to a follow-up; `auto-route` therefore only
//! installs the fake-IP-range route.
//!
//! On Windows the device is a wintun adapter: `wintun.dll` must be present
//! next to the binary (or on the DLL search path) and the process must run
//! elevated. On Linux/macOS creating the device requires root
//! (CAP_NET_ADMIN).

mod device;
mod dns;
#[cfg(target_os = "windows")]
mod local_dns;
mod route;
mod udp;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::StreamExt;
use ipnet::Ipv4Net;
use meow_common::{ConnType, Metadata, Network, ProxyConn};
use meow_tunnel::Tunnel;
use netstack_smoltcp::{StackBuilder, TcpStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{info, warn};

use route::RouteGuard;

/// Tracks all child `JoinHandle`s spawned by a TUN listener. On drop,
/// aborts every tracked task — this guarantees the TUN device and all its
/// resources are fully released even when the parent task is externally
/// aborted.
struct TaskGroup {
    aborts: Vec<tokio::task::AbortHandle>,
}

impl TaskGroup {
    fn new() -> Self {
        Self { aborts: Vec::new() }
    }

    /// Track a `JoinHandle<T>` by recording its `AbortHandle`. Type-erased
    /// via `AbortHandle` so heterogeneous task return types (e.g. `()`,
    /// `io::Result<()>`) coexist in the same collection.
    ///
    /// Reaps finished tasks first: an `AbortHandle` keeps its task's
    /// allocation alive, so without the `retain` the group would grow
    /// unboundedly with every accepted TCP flow.
    fn push<T>(&mut self, h: &tokio::task::JoinHandle<T>) {
        self.aborts.retain(|a| !a.is_finished());
        self.aborts.push(h.abort_handle());
    }

    /// Spawn a future and automatically track its handle.
    fn spawn(&mut self, f: impl std::future::Future<Output = ()> + Send + 'static) {
        let h = tokio::spawn(f);
        self.push(&h);
    }
}

impl Drop for TaskGroup {
    fn drop(&mut self) {
        for a in &self.aborts {
            a.abort();
        }
    }
}

/// Listener-facing subset of the `tun:` config section, mapped from
/// `meow_config::TunConfig` by the app layer (mirrors how the other
/// listeners take plain ctor args rather than depending on meow-config).
#[derive(Debug, Clone)]
pub struct TunListenerConfig {
    /// Device name. `None` lets the platform pick (`utunN` on macOS).
    pub device: Option<String>,
    /// Device MTU. The config layer enforces ≥ 1280 (RFC 8200 §5).
    pub mtu: u16,
    /// Address + prefix assigned to the device.
    pub inet4_address: Ipv4Net,
    /// Install the fake-IP-range route on startup (removed on shutdown).
    pub auto_route: bool,
    /// Answer UDP :53 flows with the in-process DNS resolver.
    pub dns_hijack: bool,
    /// Idle timeout for UDP flows (flow-table eviction).
    pub udp_timeout: Duration,
}

/// Outcome of TUN listener startup, sent through the readiness channel.
/// Allows callers to distinguish immediate setup failure from a timeout
/// without waiting for the full `TUN_STARTUP_TIMEOUT`.
pub enum TunReady {
    /// Device + stack + child tasks are fully initialized.
    Ready,
    /// Setup failed before reaching the accept loop.  The String carries
    /// the underlying error message so callers can surface it directly.
    Failed(String),
}

/// RAII helper that guarantees the readiness oneshot is always fired.
///
/// If `ready()` is called, the sender sends `TunReady::Ready` and is
/// consumed (no drop-side-effect).  If the notifier is dropped without
/// a prior `ready()` call — e.g. because `run()` hit a `?` and the
/// local variable goes out of scope — the sender fires
/// `TunReady::Failed(...)` so the caller gets an immediate,
/// descriptive error instead of a bare `RecvError`.
struct ReadyNotifier {
    tx: Option<tokio::sync::oneshot::Sender<TunReady>>,
}

impl ReadyNotifier {
    fn new(tx: tokio::sync::oneshot::Sender<TunReady>) -> Self {
        Self { tx: Some(tx) }
    }

    /// Consume the notifier and send `TunReady::Ready`.
    fn ready(mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(TunReady::Ready);
        } else {
            tracing::warn!("ReadyNotifier::ready called but tx was already None");
        }
    }
}

impl Drop for ReadyNotifier {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(TunReady::Failed(
                "listener setup failed before reaching readiness".into(),
            ));
        }
    }
}

pub struct TunListener {
    tunnel: Tunnel,
    cfg: TunListenerConfig,
    name: String,
    /// Optional readiness signal: sent once after the device, stack, and
    /// child tasks are fully initialized (before the accept loop).
    /// If the listener fails before reaching that point the notifier's
    /// `Drop` impl sends `TunReady::Failed`, giving callers an immediate
    /// error without waiting for a timeout.
    ready: Option<tokio::sync::oneshot::Sender<TunReady>>,
}

impl TunListener {
    pub fn new(tunnel: Tunnel, cfg: TunListenerConfig, name: String) -> Self {
        Self {
            tunnel,
            cfg,
            name,
            ready: None,
        }
    }

    /// Attach a readiness signal. The sender will fire `TunReady::Ready`
    /// after device creation + stack init + child-task setup succeeds,
    /// and before the accept loop starts.  If `run()` fails before
    /// reaching that point the notifier's `Drop` impl sends
    /// `TunReady::Failed(msg)`, giving callers an immediate error without
    /// waiting for a timeout.
    pub fn with_readiness_signal(mut self, tx: tokio::sync::oneshot::Sender<TunReady>) -> Self {
        self.ready = Some(tx);
        self
    }

    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let t0 = Instant::now();
        info!("TUN listener '{}' starting...", self.name);

        // Extract the readiness sender into a notifier that will
        // automatically fire `TunReady::Failed(...)` on drop, so a `?`
        // early-return immediately notifies the caller with the fact
        // that setup did not complete — no 30 s timeout needed.
        let notifier = self.ready.take().map(ReadyNotifier::new);

        let cfg = &self.cfg;

        // Try up to 5 device names in case the previous instance left a
        // stale adapter that hasn't been cleaned up yet (common on Windows
        // after an unclean shutdown).
        //
        // Each attempt runs on a blocking thread with a per-attempt timeout
        // so a stuck `build_async()` (wintun init can hang) doesn't block the
        // tokio worker forever.  Multiple attempts × per-attempt timeout must
        // fit inside the caller's overall TUN_STARTUP_TIMEOUT (30 s).
        const MAX_TUN_RETRIES: u32 = 5;
        const TUN_CREATE_TIMEOUT_SECS: u64 = 8;
        let base_name = cfg.device.clone().unwrap_or_else(|| "meow-tun".into());
        let mut device: Option<Arc<tun_rs::AsyncDevice>> = None;
        let mut dev_name = String::new();

        for attempt in 0..MAX_TUN_RETRIES {
            let name = if attempt == 0 {
                base_name.clone()
            } else {
                format!("{}-{}", base_name, attempt)
            };

            // Copy the values we need inside `spawn_blocking` so we don't
            // borrow `cfg` across the closure boundary.
            let mtu = cfg.mtu;
            let addr = cfg.inet4_address.addr();
            let prefix = cfg.inet4_address.prefix_len();
            let name_for_closure = name.clone();

            info!(
                "creating TUN device '{}' (attempt {}/{}, timeout {}s)...",
                name,
                attempt + 1,
                MAX_TUN_RETRIES,
                TUN_CREATE_TIMEOUT_SECS
            );

            let result = tokio::time::timeout(
                Duration::from_secs(TUN_CREATE_TIMEOUT_SECS),
                tokio::task::spawn_blocking(move || {
                    tun_rs::DeviceBuilder::new()
                        .mtu(mtu)
                        .ipv4(addr, prefix, None)
                        .name(&name_for_closure)
                        .build_async()
                }),
            )
            .await;

            match result {
                // spawn_blocking ran, build_async returned Ok
                Ok(Ok(Ok(d))) => {
                    dev_name = d.name().unwrap_or_else(|_| name.clone());
                    device = Some(Arc::new(d));
                    break;
                }
                // spawn_blocking ran, build_async returned Err
                Ok(Ok(Err(e))) => {
                    warn!("failed to create TUN device '{}': {e}", name);
                }
                // spawn_blocking panicked or join error
                Ok(Err(join_err)) => {
                    warn!(
                        "spawn_blocking for TUN device '{}' panicked: {join_err}",
                        name
                    );
                }
                // per-attempt timeout elapsed
                Err(_elapsed) => {
                    warn!(
                        "creating TUN device '{}' timed out after {}s",
                        name, TUN_CREATE_TIMEOUT_SECS
                    );
                }
            }

            if attempt + 1 >= MAX_TUN_RETRIES {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "failed to create TUN device after {MAX_TUN_RETRIES} attempts \
                         ({MAX_TUN_RETRIES}×{TUN_CREATE_TIMEOUT_SECS}s timeout)"
                    ),
                )));
            }
        }
        // SAFETY: the loop either breaks with `device = Some(...)` and
        // `dev_name` set, or returns `Err` above.
        let device = device.unwrap();

        let tun_create_ms = t0.elapsed().as_secs_f64() * 1000.0;
        info!("TUN device '{dev_name}' created in {tun_create_ms:.0}ms");

        // auto-route v1: capture exactly the fake-IP range (see module docs).
        //
        // RouteManager::add() calls into OS routing APIs that may block
        // (PowerShell on Windows), so it runs on a blocking thread with a
        // timeout so the outer startup guard can fire.
        const ROUTE_SETUP_TIMEOUT_SECS: u64 = 5;
        let _routes = if cfg.auto_route {
            match self.tunnel.resolver().fake_ip_v4_net() {
                Some(fake_net) => {
                    let if_index = device.if_index()?;
                    let t_route = Instant::now();

                    let result = tokio::time::timeout(
                        Duration::from_secs(ROUTE_SETUP_TIMEOUT_SECS),
                        tokio::task::spawn_blocking(move || {
                            RouteGuard::setup(if_index, &[fake_net])
                        }),
                    )
                    .await;

                    let guard = match result {
                        Ok(Ok(Ok(g))) => {
                            let route_ms = t_route.elapsed().as_secs_f64() * 1000.0;
                            info!("auto-route installed in {route_ms:.0}ms");
                            Some(g)
                        }
                        Ok(Ok(Err(e))) => {
                            return Err(Box::new(io::Error::new(
                                io::ErrorKind::Other,
                                format!("failed to install auto-route: {e}"),
                            )));
                        }
                        Ok(Err(join_err)) => {
                            return Err(Box::new(io::Error::new(
                                io::ErrorKind::Other,
                                format!("auto-route spawn_blocking panicked: {join_err}"),
                            )));
                        }
                        Err(_elapsed) => {
                            return Err(Box::new(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!(
                                    "auto-route setup timed out after {}s",
                                    ROUTE_SETUP_TIMEOUT_SECS
                                ),
                            )));
                        }
                    };
                    guard
                }
                None => {
                    warn!(
                        "tun '{}': auto-route currently only routes the fake-IP range, but \
                         DNS is not in fake-ip mode — no routes installed. Add routes to \
                         '{dev_name}' manually (and make sure outbound traffic cannot loop \
                         back into the device).",
                        self.name
                    );
                    None
                }
            }
        } else {
            None
        };

        // When dns-hijack is on and we're in fake-IP mode, point the OS
        // resolver at the loopback DNS server.  The backup + set calls into
        // PowerShell (Get-DnsClientServerAddress / Set-DnsClientServerAddress)
        // which can take tens of seconds on Windows, so run them on a
        // blocking thread with a timeout.
        const DNS_GUARD_TIMEOUT_SECS: u64 = 20;
        let _dns_guard = if cfg.dns_hijack && cfg.auto_route {
            let t_dns = Instant::now();
            let guard = match self.tunnel.resolver().fake_ip_v4_gateway() {
                Some(gateway) => {
                    let result = tokio::time::timeout(
                        Duration::from_secs(DNS_GUARD_TIMEOUT_SECS),
                        tokio::task::spawn_blocking(move || dns::DnsGuard::setup(gateway)),
                    )
                    .await;

                    match result {
                        Ok(Ok(g)) => {
                            let dns_ms = t_dns.elapsed().as_secs_f64() * 1000.0;
                            let dns_active = g.is_some();
                            info!("dns-guard setup took {dns_ms:.0}ms (active: {dns_active})");
                            g
                        }
                        Ok(Err(_join_err)) => {
                            warn!(
                                "dns-guard spawn_blocking panicked, continuing without DNS hijack"
                            );
                            None
                        }
                        Err(_elapsed) => {
                            warn!(
                                "dns-guard setup timed out after {}s, continuing without DNS hijack",
                                DNS_GUARD_TIMEOUT_SECS
                            );
                            None
                        }
                    }
                }
                None => None,
            };
            guard
        } else {
            None
        };

        // ICMP rides on the TCP interface (echo replies are answered by
        // smoltcp itself), hence tcp+icmp+udp; with tcp and udp enabled the
        // runner/listener/socket options are always populated.
        let t_stack = Instant::now();
        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .mtu(usize::from(cfg.mtu))
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true)
            .build()?;
        let runner = runner.expect("netstack runner (TCP enabled)");
        let mut tcp_listener = tcp_listener.expect("netstack TCP listener (TCP enabled)");
        let udp_socket = udp_socket.expect("netstack UDP socket (UDP enabled)");

        let stack_ms = t_stack.elapsed().as_secs_f64() * 1000.0;
        info!("netstack built in {stack_ms:.0}ms");

        let mut tasks = TaskGroup::new();

        // Windows: start local DNS server on 127.0.0.1:53 and [::1]:53.
        // DnsGuard has already set system DNS to these loopback addresses;
        // the server answers queries using the same DnsServer::handle_query
        // pipeline as the TUN dns-hijack path, returning fake IPs.
        #[cfg(target_os = "windows")]
        if _dns_guard.is_some() {
            let resolver = Arc::clone(self.tunnel.resolver());
            tasks.spawn(async move {
                local_dns::run(resolver).await;
            });
        }

        tasks.spawn(async move {
            let _ = runner.await;
        });
        let (mut pump_in, mut pump_out) = device::spawn_pumps(device, stack);
        tasks.push(&pump_in);
        tasks.push(&pump_out);
        tasks.spawn(udp::run_udp(
            self.tunnel.clone(),
            udp_socket,
            cfg.dns_hijack,
            cfg.udp_timeout,
            self.name.clone(),
        ));

        let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
        info!(
            "TUN listener '{}' started on device '{dev_name}' ({}, mtu {}, auto-route: {}, \
             dns-hijack: {}, total startup {total_ms:.0}ms)",
            self.name, cfg.inet4_address, cfg.mtu, cfg.auto_route, cfg.dns_hijack
        );

        // Signal readiness: device, stack, and child tasks are all up.
        // Any `?` above would have dropped the notifier, sending
        // `TunReady::Failed` instead.
        match notifier {
            Some(notifier) => {
                info!("TUN listener '{}' signalling readiness...", self.name);
                notifier.ready();
                info!("TUN listener '{}' readiness signal sent", self.name);
            }
            None => {
                info!(
                    "TUN listener '{}' has no readiness signal configured",
                    self.name
                );
            }
        }

        loop {
            tokio::select! {
                accepted = tcp_listener.next() => match accepted {
                    Some((stream, src, dst)) => {
                        let tunnel = self.tunnel.clone();
                        let name = self.name.clone();
                        tasks.spawn(async move {
                            handle_tcp_flow(tunnel, stream, src, dst, &name).await;
                        });
                    }
                    None => return Err("netstack TCP listener closed".into()),
                },
                joined = &mut pump_in => {
                    return Err(pump_error("device→stack", joined).into());
                }
                joined = &mut pump_out => {
                    return Err(pump_error("stack→device", joined).into());
                }
            }
        }
    }
}

fn pump_error(direction: &str, joined: Result<io::Result<()>, tokio::task::JoinError>) -> String {
    match joined {
        Ok(Ok(())) => format!("tun {direction} pump exited"),
        Ok(Err(e)) => format!("tun {direction} pump failed: {e}"),
        Err(e) => format!("tun {direction} pump panicked: {e}"),
    }
}

async fn handle_tcp_flow(
    tunnel: Tunnel,
    tcp: TcpStream,
    src: SocketAddr, // client behind the tun
    dst: SocketAddr, // original destination
    in_name: &str,
) {
    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Tun,
        src_ip: Some(src.ip()),
        src_port: src.port(),
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        in_name: in_name.into(),
        ..Default::default()
    };

    // handle_tcp does the rest: fake-IP rewrite, lazy rule match, stats
    // guard, dial, zero-alloc relay.
    meow_tunnel::tcp::handle_tcp(tunnel.inner(), Box::new(TunTcpConn(tcp)), metadata).await;
}

/// Newtype so the netstack TCP stream satisfies `ProxyConn` (a foreign
/// type cannot implement the foreign `meow_common::ProxyConn` here).
struct TunTcpConn(TcpStream);

impl AsyncRead for TunTcpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunTcpConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl ProxyConn for TunTcpConn {}
