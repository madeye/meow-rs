use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_dns::Resolver;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

pub struct DirectAdapter {
    routing_mark: Option<u32>,
    /// Optional internal DNS resolver. When set, `dial_tcp` resolves
    /// hostnames via this resolver instead of the OS resolver — this is
    /// important when meow-rs *is* the system DNS, because routing a direct
    /// DNS query back through the OS would loop the query back into meow-rs.
    resolver: Option<Arc<Resolver>>,
    /// Wall-clock bound on `TcpStream::connect`. iOS / macOS scoped-routing
    /// and reachability-cache transients can leave a `connect()` hanging
    /// indefinitely against a destination whose route is in flux (Wi-Fi
    /// assoc churn, IPv6 RA churn, post-wake route reassessment). Without
    /// this bound the dial holds whatever upstream scheduling resource the
    /// caller allocated to it until the OS gives up (~75 s on iOS BSD-style
    /// SYN retransmit grid). `None` preserves the legacy unbounded
    /// behaviour for downstream consumers that haven't opted in.
    connect_timeout: Option<Duration>,
    health: ProxyHealth,
}

impl DirectAdapter {
    pub fn new() -> Self {
        Self {
            routing_mark: None,
            resolver: None,
            connect_timeout: None,
            health: ProxyHealth::new(),
        }
    }

    pub fn with_routing_mark(mut self, routing_mark: u32) -> Self {
        self.routing_mark = Some(routing_mark);
        self
    }

    pub fn with_resolver(mut self, resolver: Arc<Resolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Bound `TcpStream::connect` on `dial_tcp`. Returns `MeowError::Io`
    /// with `ErrorKind::TimedOut` if the connect exceeds `timeout`. See
    /// the `connect_timeout` field doc for the motivating failure mode
    /// (iOS routing-cache transients) and meow-ios'
    /// `docs/INVESTIGATION-2026-05-18-tcp-direct-rule-disconnect.md` for
    /// the device-side trace.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Determine the concrete `SocketAddr` to dial for `metadata`, avoiding
    /// the OS resolver whenever possible.
    async fn resolve_target(&self, metadata: &Metadata) -> Result<SocketAddr> {
        // 1. Destination already resolved (e.g. by rule-matching pre_resolve,
        //    or when the client supplied an IP literal).
        if let Some(ip) = metadata.dst_ip {
            return Ok(SocketAddr::new(ip, metadata.dst_port));
        }

        // 2. `host` is an IP literal — no DNS needed.
        if let Ok(ip) = metadata.host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, metadata.dst_port));
        }

        // 3. Resolve via meow-rs's internal resolver if available. Falls back
        //    to the OS resolver only when no resolver was injected (tests,
        //    standalone usage).
        if !metadata.host.is_empty() {
            if let Some(resolver) = &self.resolver {
                return match resolver.resolve_ip(&metadata.host).await {
                    Some(ip) => Ok(SocketAddr::new(ip, metadata.dst_port)),
                    None => Err(MeowError::Dns(format!(
                        "direct: failed to resolve {}",
                        metadata.host
                    ))),
                };
            }

            // Legacy fallback: let tokio use getaddrinfo. Only reachable when
            // no resolver was injected — production code paths always inject.
            let addr = format!("{}:{}", metadata.host, metadata.dst_port);
            return tokio::net::lookup_host(&addr)
                .await
                .map_err(MeowError::Io)?
                .next()
                .ok_or_else(|| MeowError::Dns(format!("direct: no address for {addr}")));
        }

        Err(MeowError::Proxy(
            "direct: metadata has no destination".into(),
        ))
    }
}

impl Default for DirectAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// Wrapper for TcpStream that implements ProxyConn
struct DirectConn(TcpStream);

impl tokio::io::AsyncRead for DirectConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for DirectConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Unpin for DirectConn {}
impl ProxyConn for DirectConn {}

// UDP wrapper
struct DirectPacketConn(UdpSocket);

#[async_trait]
impl ProxyPacketConn for DirectPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await.map_err(MeowError::Io)
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        self.0.send_to(buf, addr).await.map_err(MeowError::Io)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr().map_err(MeowError::Io)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Create a TCP socket with an optional routing mark (SO_MARK on Linux)
/// set BEFORE connecting, so the SYN packet is already marked.
async fn connect_with_mark(
    dest: SocketAddr,
    routing_mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    #[cfg(target_os = "linux")]
    if let Some(mark) = routing_mark {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if dest.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_mark(mark)?;
        socket.set_nonblocking(true)?;

        match socket.connect(&dest.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }

        let std_stream: std::net::TcpStream = socket.into();
        return TcpStream::from_std(std_stream);
    }

    #[cfg(not(target_os = "linux"))]
    let _ = routing_mark;

    TcpStream::connect(dest).await
}

#[async_trait]
impl ProxyAdapter for DirectAdapter {
    fn name(&self) -> &str {
        "DIRECT"
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let dest = self.resolve_target(metadata).await?;
        let connect = connect_with_mark(dest, self.routing_mark);
        let stream = match self.connect_timeout {
            Some(t) => match tokio::time::timeout(t, connect).await {
                Ok(res) => res.map_err(MeowError::Io)?,
                Err(_) => {
                    return Err(MeowError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("direct: connect to {dest} timed out after {t:?}"),
                    )));
                }
            },
            None => connect.await.map_err(MeowError::Io)?,
        };
        Ok(Box::new(DirectConn(stream)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(MeowError::Io)?;
        Ok(Box::new(DirectPacketConn(socket)))
    }

    /// Pass the stream through unchanged.
    ///
    /// A direct hop in a relay chain is a no-op — useful for
    /// `relay: [direct, ss-node]` topologies where the first hop is a
    /// plain TCP connection without any proxy framing.
    ///
    /// upstream: adapter/outbound/direct.go — no DialContextWithDialer defined;
    /// relay skips direct hops by convention.  Class A ADR-0002: we make it
    /// explicit so the compiler enforces the override.
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Ok(stream)
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{ConnType, Network};
    use std::net::Ipv4Addr;

    /// Dial against `192.0.2.1` (RFC 5737 TEST-NET-1, reserved as a
    /// documentation black-hole — packets to this address never get a
    /// response on a properly-routed network). Without the timeout the
    /// connect would hang for the OS SYN-retransmit grid (~75 s on
    /// macOS/iOS). With `with_connect_timeout` set, the dial must surface
    /// a `TimedOut` error inside the configured budget.
    ///
    /// Wrapped in `tokio::time::timeout` with a generous outer cap so a
    /// regression — i.e. the timeout *not* firing — fails the test in a
    /// bounded wall-clock window rather than wedging CI.
    #[tokio::test]
    #[ignore = "flaky: depends on TEST-NET-1 (192.0.2.0/24) being a blackhole; fails on hosts where the local network/VPN responds with ICMP unreachable"]
    async fn dial_tcp_honours_connect_timeout_against_blackhole() {
        let adapter = DirectAdapter::new().with_connect_timeout(Duration::from_millis(500));

        let metadata = Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            dst_port: 1,
            ..Default::default()
        };

        let started = std::time::Instant::now();
        let res = tokio::time::timeout(Duration::from_secs(5), adapter.dial_tcp(&metadata)).await;
        let elapsed = started.elapsed();

        let inner = res.expect("outer guard: timeout never fired within 5 s");
        let Err(err) = inner else {
            panic!("dial against TEST-NET-1 must fail, got success");
        };
        match err {
            MeowError::Io(io_err) => {
                assert_eq!(
                    io_err.kind(),
                    std::io::ErrorKind::TimedOut,
                    "expected TimedOut, got {io_err:?}"
                );
            }
            other => panic!("expected MeowError::Io(TimedOut), got {other:?}"),
        }
        // 500 ms budget + scheduling slack — generous upper bound so CI
        // jitter doesn't flake, tight enough to catch a regression where
        // the timeout is silently ignored.
        assert!(
            elapsed < Duration::from_secs(2),
            "dial took {elapsed:?}, expected <2s",
        );
    }

    /// When no `connect_timeout` is configured, `dial_tcp` keeps its
    /// historical unbounded behaviour. We can't easily wait out the OS
    /// SYN grid in CI, so this test asserts the legacy path is still
    /// running unbounded by checking that a short outer guard does *not*
    /// see the dial complete on its own.
    #[tokio::test]
    #[ignore = "flaky: depends on TEST-NET-1 (192.0.2.0/24) being a blackhole; fails on hosts where the local network/VPN responds within the 750 ms outer guard"]
    async fn dial_tcp_without_timeout_remains_unbounded() {
        let adapter = DirectAdapter::new();

        let metadata = Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            dst_port: 1,
            ..Default::default()
        };

        let res =
            tokio::time::timeout(Duration::from_millis(750), adapter.dial_tcp(&metadata)).await;
        assert!(
            res.is_err(),
            "expected outer guard to fire; the unbounded dial finished too quickly",
        );
    }
}
