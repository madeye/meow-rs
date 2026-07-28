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
mod route;
mod udp;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

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

pub struct TunListener {
    tunnel: Tunnel,
    cfg: TunListenerConfig,
    name: String,
    /// Optional readiness signal: sent once after the device, stack, and
    /// child tasks are fully initialized (before the accept loop).
    /// Dropped on setup failure so callers can distinguish "not started"
    /// from "briefly delayed".
    ready: Option<tokio::sync::oneshot::Sender<()>>,
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

    /// Attach a readiness signal. The sender will fire after device
    /// creation + stack init + child-task setup succeeds, and before the
    /// accept loop starts. If `run()` fails before reaching that point,
    /// the sender is dropped — the receiver sees a `RecvError`.
    pub fn with_readiness_signal(mut self, tx: tokio::sync::oneshot::Sender<()>) -> Self {
        self.ready = Some(tx);
        self
    }

    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cfg = &self.cfg;

        let mut builder = tun_rs::DeviceBuilder::new().mtu(cfg.mtu).ipv4(
            cfg.inet4_address.addr(),
            cfg.inet4_address.prefix_len(),
            None,
        );
        if let Some(name) = &cfg.device {
            builder = builder.name(name);
        }
        let device = builder.build_async().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "failed to create TUN device: {e} (requires root/CAP_NET_ADMIN on \
                     Linux/macOS; elevation + wintun.dll on Windows)"
                ),
            )
        })?;
        let device = Arc::new(device);
        let dev_name = device.name().unwrap_or_else(|_| "<unknown>".into());

        // auto-route v1: capture exactly the fake-IP range (see module docs).
        let _routes = if cfg.auto_route {
            match self.tunnel.resolver().fake_ip_v4_net() {
                Some(fake_net) => {
                    let if_index = device.if_index()?;
                    Some(RouteGuard::setup(if_index, &[fake_net])?)
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
        // resolver at the fake-IP gateway (e.g. 198.18.0.1).  DNS queries
        // will route into the TUN device, be answered with fake IPs, and
        // client traffic to those fake IPs will be captured by the route
        // guard above.  The guard restores the original resolver config
        // when the listener exits.
        let _dns_guard = if cfg.dns_hijack && cfg.auto_route {
            self.tunnel
                .resolver()
                .fake_ip_v4_gateway()
                .and_then(dns::DnsGuard::setup)
        } else {
            None
        };

        // ICMP rides on the TCP interface (echo replies are answered by
        // smoltcp itself), hence tcp+icmp+udp; with tcp and udp enabled the
        // runner/listener/socket options are always populated.
        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .mtu(usize::from(cfg.mtu))
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true)
            .build()?;
        let runner = runner.expect("netstack runner (TCP enabled)");
        let mut tcp_listener = tcp_listener.expect("netstack TCP listener (TCP enabled)");
        let udp_socket = udp_socket.expect("netstack UDP socket (UDP enabled)");

        let mut tasks = TaskGroup::new();

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

        info!(
            "TUN listener '{}' started on device '{dev_name}' ({}, mtu {}, auto-route: {}, \
             dns-hijack: {})",
            self.name, cfg.inet4_address, cfg.mtu, cfg.auto_route, cfg.dns_hijack
        );

        // Signal readiness: device, stack, and child tasks are all up.
        // If we return Err before this point the sender is dropped,
        // which allows callers (put_configs / startup) to surface the
        // failure instead of silently storing a dead JoinHandle.
        if let Some(ready) = self.ready.take() {
            let _ = ready.send(());
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
