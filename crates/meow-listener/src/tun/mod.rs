//! TUN inbound — transparent proxying via an L3 device (issue #326).
//!
//! This is the transparent-proxy path for platforms without a
//! tproxy/REDIRECT firewall — Windows first and foremost — and works the
//! same on Linux and macOS. A `tun-rs` device receives raw IP packets; the
//! `ipstack` userspace TCP/IP stack terminates them and hands us ordinary
//! `AsyncRead + AsyncWrite` streams (TCP) and per-flow datagram streams
//! (UDP), which are dispatched into the tunnel exactly like every other
//! inbound.
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
mod route;
mod udp;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ipnet::Ipv4Net;
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream};
use meow_common::{ConnType, Metadata, Network, ProxyConn};
use meow_tunnel::Tunnel;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info, warn};

use device::DeviceAdapter;
use route::RouteGuard;

/// Listener-facing subset of the `tun:` config section, mapped from
/// `meow_config::TunConfig` by the app layer (mirrors how the other
/// listeners take plain ctor args rather than depending on meow-config).
#[derive(Debug, Clone)]
pub struct TunListenerConfig {
    /// Device name. `None` lets the platform pick (`utunN` on macOS).
    pub device: Option<String>,
    /// Device MTU. `ipstack` requires ≥ 1280.
    pub mtu: u16,
    /// Address + prefix assigned to the device.
    pub inet4_address: Ipv4Net,
    /// Install the fake-IP-range route on startup (removed on shutdown).
    pub auto_route: bool,
    /// Answer UDP :53 flows with the in-process DNS resolver.
    pub dns_hijack: bool,
    /// Idle timeout for UDP flows (ipstack NAT eviction).
    pub udp_timeout: Duration,
}

pub struct TunListener {
    tunnel: Tunnel,
    cfg: TunListenerConfig,
    name: String,
}

impl TunListener {
    pub fn new(tunnel: Tunnel, cfg: TunListenerConfig, name: String) -> Self {
        Self { tunnel, cfg, name }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

        let mut stack_cfg = IpStackConfig::default();
        stack_cfg
            .mtu(cfg.mtu)
            .map_err(|e| format!("tun mtu {}: {e}", cfg.mtu))?
            .udp_timeout(cfg.udp_timeout);
        let mut stack = IpStack::new(stack_cfg, DeviceAdapter(device));

        info!(
            "TUN listener '{}' started on device '{dev_name}' ({}, mtu {}, auto-route: {}, \
             dns-hijack: {})",
            self.name, cfg.inet4_address, cfg.mtu, cfg.auto_route, cfg.dns_hijack
        );

        loop {
            match stack.accept().await? {
                IpStackStream::Tcp(tcp) => {
                    let tunnel = self.tunnel.clone();
                    let name = self.name.clone();
                    tokio::spawn(async move {
                        handle_tcp_flow(tunnel, tcp, &name).await;
                    });
                }
                IpStackStream::Udp(udp_stream) => {
                    let tunnel = self.tunnel.clone();
                    let name = self.name.clone();
                    let dns_hijack = cfg.dns_hijack;
                    tokio::spawn(async move {
                        udp::handle_udp_flow(tunnel, udp_stream, dns_hijack, &name).await;
                    });
                }
                IpStackStream::UnknownTransport(pkt) => {
                    debug!(
                        "tun '{}': dropping unsupported transport {:?} to {}",
                        self.name,
                        pkt.ip_protocol(),
                        pkt.dst_addr()
                    );
                }
                IpStackStream::UnknownNetwork(pkt) => {
                    debug!(
                        "tun '{}': dropping unknown network packet ({} bytes)",
                        self.name,
                        pkt.len()
                    );
                }
            }
        }
    }
}

async fn handle_tcp_flow(tunnel: Tunnel, tcp: IpStackTcpStream, in_name: &str) {
    let src = tcp.local_addr(); // client behind the tun
    let dst = tcp.peer_addr(); // original destination

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

/// Newtype so the ipstack TCP stream satisfies `ProxyConn`
/// (`AsyncRead + AsyncWrite + Unpin + Send + Sync`).
struct TunTcpConn(IpStackTcpStream);

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
