//! Per-flow UDP handling for the TUN inbound.
//!
//! `ipstack` surfaces each (src, dst) UDP tuple as one `IpStackUdpStream`
//! and owns the NAT/idle bookkeeping (the stream closes after
//! `udp-timeout` of silence), so unlike the SOCKS5 associate path there is
//! no per-listener NAT table here — one task per flow, torn down when the
//! stream ends.
//!
//! Routing mirrors `meow_tunnel::udp::handle_udp`: fake-IP rewrite →
//! pre-resolve → port-53 handling → rule match → `dial_udp`. Port 53 is
//! special two ways: with `dns-hijack` enabled the query is answered
//! in-process by `DnsServer::handle_query` (required for fake-IP mode —
//! point the OS resolver at any address inside the routed range); without
//! it the flow bypasses rule matching to DIRECT, mirroring the tunnel-level
//! DNS bypass.

use std::net::SocketAddr;
use std::sync::Arc;

use ipstack::IpStackUdpStream;
use meow_common::{ConnType, Metadata, Network, ProxyAdapter, ProxyPacketConn};
use meow_dns::server::DnsServer;
use meow_tunnel::Tunnel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

/// One datagram payload cap. UDP over IPv4 tops out below 64 KiB.
const DATAGRAM_BUF: usize = 65535;

pub(super) async fn handle_udp_flow(
    tunnel: Tunnel,
    stream: IpStackUdpStream,
    dns_hijack: bool,
    in_name: &str,
) {
    let src = stream.local_addr();
    let dst = stream.peer_addr();

    if dns_hijack && dst.port() == 53 {
        if let Err(e) = serve_dns(&tunnel, stream).await {
            debug!("tun dns-hijack {src} -> {dst}: {e}");
        }
        return;
    }

    if let Err(e) = relay_flow(&tunnel, stream, src, dst, in_name).await {
        debug!("tun UDP {src} -> {dst}: {e}");
    }
}

/// Answer DNS queries on this flow with the in-process resolver. Each read
/// yields one datagram (one query); the response is written straight back.
async fn serve_dns(tunnel: &Tunnel, mut stream: IpStackUdpStream) -> Result<(), String> {
    let resolver = Arc::clone(tunnel.resolver());
    let mut buf = vec![0u8; DATAGRAM_BUF];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => return Ok(()), // idle-timeout close
            Ok(n) => n,
            Err(e) => return Err(format!("read: {e}")),
        };
        match DnsServer::handle_query(&buf[..n], &resolver).await {
            Ok(response) => {
                if let Err(e) = stream.write_all(&response).await {
                    return Err(format!("write: {e}"));
                }
            }
            Err(e) => debug!("tun dns-hijack: unanswerable query: {e}"),
        }
    }
}

/// Route the flow and pump datagrams both ways until either side closes.
async fn relay_flow(
    tunnel: &Tunnel,
    stream: IpStackUdpStream,
    src: SocketAddr,
    dst: SocketAddr,
    in_name: &str,
) -> Result<(), String> {
    let mut metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Tun,
        src_ip: Some(src.ip()),
        src_port: src.port(),
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        in_name: in_name.into(),
        ..Default::default()
    };

    let inner = tunnel.inner();
    inner.pre_handle_metadata(&mut metadata);
    // UDP keeps the eager pre_resolve (no lazy enrichment): the outbound
    // packet API below needs a resolved dst_ip regardless of what the rules
    // demand — including after a fake-IP was rewritten back to a hostname.
    inner.pre_resolve(&mut metadata).await;
    if metadata.dst_ip.is_none() && !metadata.host.is_empty() {
        metadata.dst_ip = inner.resolver.resolve_ip_real(&metadata.host).await;
    }
    let Some(dst_ip) = metadata.dst_ip else {
        return Err(format!(
            "dst_ip not resolved for {}",
            metadata.remote_address()
        ));
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);

    // Port-53 DIRECT bypass (dns-hijack off), mirroring
    // `meow_tunnel::udp::handle_udp`: never loop client DNS through a proxy.
    let proxy: Arc<dyn ProxyAdapter> = if metadata.dst_port == 53 {
        Arc::clone(&inner.direct) as Arc<dyn ProxyAdapter>
    } else {
        match inner.resolve_proxy(&metadata) {
            Some((p, rule_name, rule_payload)) => {
                info!(
                    "UDP {} --> {} match {}({}) using {}",
                    src,
                    metadata.remote_address(),
                    rule_name,
                    rule_payload,
                    p.name()
                );
                p
            }
            None => {
                return Err(format!(
                    "no matching rule for {}",
                    metadata.remote_address()
                ))
            }
        }
    };

    let conn: Arc<dyn ProxyPacketConn> = Arc::from(
        proxy
            .dial_udp(&metadata)
            .await
            .map_err(|e| format!("dial_udp via {}: {e}", proxy.name()))?,
    );

    // Downstream pump (server → client) runs as its own task so the
    // upstream loop below can block on the stream read. Reply source
    // addresses are not rewritten: the tun flow is locked to one (src, dst)
    // tuple, so every reply is delivered as coming from `dst`.
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let downstream = {
        let conn = Arc::clone(&conn);
        tokio::spawn(async move {
            let mut buf = vec![0u8; DATAGRAM_BUF];
            while let Ok((n, _from)) = conn.read_packet(&mut buf).await {
                if write_half.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        })
    };

    let mut buf = vec![0u8; DATAGRAM_BUF];
    let result = loop {
        match read_half.read(&mut buf).await {
            Ok(0) => break Ok(()), // idle-timeout close by ipstack
            Ok(n) => {
                if let Err(e) = conn.write_packet(&buf[..n], &dst_addr).await {
                    break Err(format!("upstream write {dst_addr}: {e}"));
                }
            }
            Err(e) => break Err(format!("read: {e}")),
        }
    };

    downstream.abort();
    let _ = conn.close();
    result
}
