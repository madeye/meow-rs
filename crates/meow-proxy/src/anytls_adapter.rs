//! AnyTLS outbound (issue #75).
//!
//! Thin wrapper over the `anytls-rs` crate's `Client`. The protocol itself
//! — TLS handshake, password auth, session multiplexing, padding scheme —
//! lives upstream; this file only translates between meow-rs's `ProxyAdapter`
//! trait and `anytls_rs`'s `Client::create_proxy_stream` / `Session` API,
//! plus the sing-box udp-over-tcp v2 framing that carries UDP (see the `uot`
//! section below).
//!
//! `tests/anytls_integration.rs` covers TCP and UDP end to end against an
//! in-process `anytls_rs::server::Server`; no external anytls server needed.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anytls_rs::client::Client as AnytlsClient;
use anytls_rs::client::UDP_OVER_TCP_MAGIC_ADDR;
use anytls_rs::padding::PaddingFactory;
use anytls_rs::protocol::{Command, Frame};
use anytls_rs::session::{Session, Stream as AnytlsStream, StreamReader};
use anytls_rs::{AsyncStream, TlsConnect, TlsConnectFuture};
use async_trait::async_trait;
use bytes::Bytes;
use meow_transport::tls::{TlsConfig, TlsLayer};
use meow_transport::Transport as _;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};

/// AnyTLS outbound adapter.
pub struct AnytlsAdapter {
    name: String,
    addr: String,
    health: ProxyHealth,
    client: AnytlsClient,
    udp: bool,
}

impl AnytlsAdapter {
    /// Build a new adapter.
    ///
    /// `server`/`port` is the AnyTLS server's TLS endpoint. `password` is the
    /// shared secret. `sni` is the SNI sent during the TLS handshake; pass
    /// `None` to default to `server`. When `skip_cert_verify` is set, the TLS
    /// stack accepts any certificate — useful for self-signed dev servers and
    /// matches the `skip-cert-verify` semantics of the trojan/vless adapters.
    /// `udp` mirrors mihomo's `udp:` option (`AnyTLSOption.UDP`, default
    /// `false`): when unset, [`ProxyAdapter::support_udp`] reports `false` and
    /// the tunnel routes UDP elsewhere.
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: Option<&str>,
        skip_cert_verify: bool,
        udp: bool,
    ) -> std::result::Result<Self, String> {
        // Bridge meow_common's outbound-socket hooks (resolver-aware TCP
        // dialer + Android `SocketProtector`) into anytls-rs's separate
        // registries exactly once — see `install_anytls_bridges`.
        install_anytls_bridges();

        let server_addr = format!("{server}:{port}");

        let effective_sni = sni.filter(|s| !s.trim().is_empty()).unwrap_or(server);
        let server_name =
            normalize_server_name(effective_sni).map_err(|e| format!("anytls[{name}]: {e}"))?;

        // Same BoringSSL TlsLayer every other TLS outbound uses; the
        // SSL_CTX is shared across proxies with the same shaping key.
        let tls_layer = TlsLayer::new(&TlsConfig {
            skip_cert_verify,
            ..TlsConfig::new(server_name)
        })
        .map_err(|e| format!("anytls[{name}]: tls config: {e}"))?;
        let tls: Arc<dyn TlsConnect> = Arc::new(MeowTlsConnect { layer: tls_layer });

        let padding = PaddingFactory::default();

        let client = AnytlsClient::new(password, server_addr.clone(), tls, padding);

        Ok(Self {
            name: name.to_string(),
            addr: server_addr,
            health: ProxyHealth::new(),
            client,
            udp,
        })
    }
}

#[async_trait]
impl ProxyAdapter for AnytlsAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Anytls
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let host = metadata.rule_host().to_string();
        let port = metadata.dst_port;
        let (stream, session) = self
            .client
            .create_proxy_stream((host, port))
            .await
            .map_err(|e| MeowError::Proxy(format!("anytls dial: {e}")))?;
        Ok(Box::new(AnytlsConn::new(stream, session)))
    }

    /// Open a udp-over-tcp v2 relay stream (issue #75 follow-up).
    ///
    /// Mirrors mihomo `adapter/outbound/anytls.go: ListenPacketContext`: a
    /// plain proxy stream to the magic destination, then sing-box's `uot`
    /// framing on top of it. The uot request is written lazily together with
    /// the first datagram, exactly as upstream's `uot.NewLazyConn` does.
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.udp {
            return Err(MeowError::NotSupported(
                "anytls: UDP is disabled for this proxy (set `udp: true`)".to_string(),
            ));
        }
        let (stream, session) = self
            .client
            .create_proxy_stream((UDP_OVER_TCP_MAGIC_ADDR.to_string(), 0))
            .await
            .map_err(|e| MeowError::Proxy(format!("anytls udp dial: {e}")))?;
        Ok(Box::new(AnytlsPacketConn::new(
            stream,
            session,
            encode_uot_request(metadata),
        )))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

/// Bridge `(Arc<Stream>, Arc<Session>)` into a `ProxyConn`-shaped value.
///
/// The upstream `Stream` impls `AsyncRead`/`AsyncWrite` on `Pin<&mut Self>`,
/// but `create_proxy_stream` only hands us an `Arc<Stream>` — we can never
/// obtain `&mut Stream`. So we re-implement the trait against the public
/// `Stream::reader()` and `Session::write_data_frame()` API surface that the
/// crate's own SOCKS5 client uses (`src/client/socks5.rs`).
// The pending futures are `Send` but not `Sync`; `ProxyConn` requires `Sync`,
// so we wrap them in `parking_lot::Mutex` (which is `Sync` whenever its
// payload is `Send`). The mutex is uncontended in practice because all
// access happens through `Pin<&mut Self>` from the AsyncRead/AsyncWrite
// trait, but the type-level `Sync` bound on `ProxyConn` is what forces the
// wrapping.
type PendingRead = Pin<Box<dyn std::future::Future<Output = io::Result<Vec<u8>>> + Send>>;
type PendingWrite = Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>;

struct AnytlsConn {
    stream: Arc<AnytlsStream>,
    session: Arc<Session>,
    stream_id: u32,
    pending_read: Mutex<Option<PendingRead>>,
    pending_write: Mutex<Option<PendingWrite>>,
    fin_sent: AtomicBool,
}

impl AnytlsConn {
    fn new(stream: Arc<AnytlsStream>, session: Arc<Session>) -> Self {
        let stream_id = stream.id();
        Self {
            stream,
            session,
            stream_id,
            pending_read: Mutex::new(None),
            pending_write: Mutex::new(None),
            fin_sent: AtomicBool::new(false),
        }
    }

    /// Best-effort FIN for just this stream, idempotent across `poll_shutdown`
    /// and `Drop`. Emits a `Fin` control frame so the server releases the
    /// proxied target connection and evicts the per-stream map entry (issue
    /// #201 item 4). The session is pooled and multiplexes other streams, so
    /// this must never close the session itself.
    ///
    /// The registry `anytls-rs` exposes only an async session writer (the
    /// git fork's synchronous `Stream::close()` is not published), so the frame
    /// is sent fire-and-forget on the current runtime. If no runtime is active
    /// (e.g. dropped outside tokio), the FIN is skipped — the connection is
    /// being torn down regardless.
    fn fin_stream(&self) {
        if self.fin_sent.swap(true, Ordering::Relaxed) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let session = Arc::clone(&self.session);
        let stream_id = self.stream_id;
        handle.spawn(async move {
            let _ = session
                .write_control_frame(Frame::control(Command::Fin, stream_id))
                .await;
        });
    }
}

impl AsyncRead for AnytlsConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let remaining = buf.remaining();
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut guard = self.pending_read.lock();
        if guard.is_none() {
            let reader = Arc::clone(self.stream.reader());
            let fut = async move {
                let mut g = reader.lock().await;
                let mut tmp = vec![0u8; remaining];
                let n = g
                    .read(&mut tmp)
                    .await
                    .map_err(|e| io::Error::other(format!("anytls read: {e}")))?;
                tmp.truncate(n);
                Ok(tmp)
            };
            *guard = Some(Box::pin(fut));
        }
        let fut = guard.as_mut().expect("just set");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(data)) => {
                *guard = None;
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                *guard = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnytlsConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = buf.len();
        let mut guard = self.pending_write.lock();
        if guard.is_none() {
            let session = Arc::clone(&self.session);
            let stream_id = self.stream_id;
            let data = Bytes::copy_from_slice(buf);
            let fut = async move {
                session
                    .write_data_frame(stream_id, data)
                    .await
                    .map_err(|e| io::Error::other(format!("anytls write: {e}")))
            };
            *guard = Some(Box::pin(fut));
        }
        let fut = guard.as_mut().expect("just set");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                *guard = None;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(e)) => {
                *guard = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The upstream session writer is unbuffered (each write_data_frame
        // pushes onto a tokio mpsc that's drained on the wire side), so
        // there's nothing to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Tear down just this stream (not the whole session, which is pooled
        // and multiplexes other streams): `Stream::close` emits a FIN frame so
        // the server releases the proxied target connection and evicts the
        // stream from the session maps. Without this the server-side proxied
        // socket and the session's per-stream map entry leaked on every dial
        // (issue #201 item 4). Idempotent.
        self.fin_stream();
        Poll::Ready(Ok(()))
    }
}

impl Drop for AnytlsConn {
    fn drop(&mut self) {
        // Belt-and-suspenders: the relay path that drops the boxed `ProxyConn`
        // without first calling `poll_shutdown` (e.g. on a copy error) must
        // still FIN the stream so the proxied connection and map entry are
        // released. `fin_stream` is idempotent with `poll_shutdown`.
        self.fin_stream();
    }
}

impl ProxyConn for AnytlsConn {}

// ─── udp-over-tcp v2 (sing-box `uot`) ────────────────────────────────────────
//
// AnyTLS carries UDP the same way sing-box and mihomo do: a normal proxy
// stream opened to the magic destination `sp.v2.udp-over-tcp.arpa:0`, then
// sing-box's `uot` framing inside it.
//
//   request (once, before the first datagram):
//       | isConnect | ATYP | Address | Port  |
//       | u8        | u8   | var     | u16be |   ← SOCKS5 family bytes
//
//   datagram (repeated, non-connect mode):
//       | ATYP | Address | Port  | Length | Payload |
//       | u8   | var     | u16be | u16be  | var     |   ← uot family bytes
//
// Beware the asymmetry: upstream serializes the *request* address with
// `M.SocksaddrSerializer` (SOCKS5 bytes 0x01/0x03/0x04) but every *per-packet*
// address with `uot.AddrParser` (its own 0x00/0x01/0x02). Reusing one table
// for both is silently wrong on the wire.
//
// Like mihomo we run in non-connect mode (`uot.Request{Destination: …}` leaves
// `IsConnect` false), so each datagram carries its own address and replies
// carry the real source address — which is what `ProxyPacketConn` needs to
// hand back to the SOCKS5/TUN listeners.
//
// upstream: sing `common/uot/{protocol,conn,server}.go`,
// mihomo `adapter/outbound/anytls.go: ListenPacketContext`

/// SOCKS5 address-family bytes — the **request** header only.
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

/// `uot.AddrParser` address-family bytes — every **per-packet** header.
const UOT_ATYP_IPV4: u8 = 0x00;
const UOT_ATYP_IPV6: u8 = 0x01;
const UOT_ATYP_DOMAIN: u8 = 0x02;

/// One anytls data frame carries a `u16` length, so a datagram plus its uot
/// header must fit in 64 KiB. The largest possible IPv6 header is
/// ATYP(1) + addr(16) + port(2) + length(2) = 21 bytes, which still leaves
/// room for a maximum-size (65507-byte) UDP payload.
const MAX_UOT_FRAME: usize = u16::MAX as usize;

/// Encode the one-shot uot request: `isConnect = 0` followed by the session's
/// nominal destination in SOCKS5 form. In non-connect mode the server ignores
/// this address (it routes per packet), but upstream still sends it and its
/// serializer rejects an empty address, so mirror mihomo and send the
/// resolved destination — falling back to the hostname when the metadata has
/// no IP yet.
fn encode_uot_request(metadata: &Metadata) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    buf.push(0); // isConnect = false
    match metadata.dst_ip {
        Some(IpAddr::V4(v4)) => {
            buf.push(SOCKS5_ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => {
                buf.push(SOCKS5_ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            None => {
                buf.push(SOCKS5_ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        },
        None => {
            // No resolved IP: send the hostname, truncated to the 255-byte
            // ceiling the length prefix allows. An empty host degrades to
            // 0.0.0.0 rather than an unencodable address.
            let host = metadata.host.as_bytes();
            if host.is_empty() || host.len() > 255 {
                buf.push(SOCKS5_ATYP_IPV4);
                buf.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
            } else {
                buf.push(SOCKS5_ATYP_DOMAIN);
                buf.push(host.len() as u8);
                buf.extend_from_slice(host);
            }
        }
    }
    buf.extend_from_slice(&metadata.dst_port.to_be_bytes());
    buf
}

/// Append a per-packet uot address header (`uot.AddrParser` bytes).
fn encode_uot_addr(buf: &mut Vec<u8>, addr: &SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(UOT_ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        // Upstream unmaps before serializing, so a `::ffff:a.b.c.d` peer goes
        // out as plain IPv4 rather than as an IPv6 address the server would
        // then have to unmap itself.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => {
                buf.push(UOT_ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            None => {
                buf.push(UOT_ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        },
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

/// Read a per-packet uot address header.
///
/// Domain-form replies are best-effort, matching `trojan.rs`: an IP literal is
/// parsed, anything else degrades to `0.0.0.0:<port>`. Servers echo the IP
/// form here — the FQDN branch exists because the serializer allows it.
async fn read_uot_addr(reader: &mut StreamReader) -> Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await.map_err(MeowError::Io)?;
    let ip = match atyp[0] {
        UOT_ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader
                .read_exact(&mut octets)
                .await
                .map_err(MeowError::Io)?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        UOT_ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            reader
                .read_exact(&mut octets)
                .await
                .map_err(MeowError::Io)?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        UOT_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await.map_err(MeowError::Io)?;
            let mut domain = vec![0u8; len[0] as usize];
            reader
                .read_exact(&mut domain)
                .await
                .map_err(MeowError::Io)?;
            std::str::from_utf8(&domain)
                .ok()
                .and_then(|d| d.parse::<IpAddr>().ok())
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        other => {
            return Err(MeowError::Proxy(format!(
                "anytls udp: unknown uot address type {other:#x}"
            )))
        }
    };
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await.map_err(MeowError::Io)?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

/// UDP-over-AnyTLS packet connection.
///
/// Each datagram becomes exactly one anytls data frame, so the framing the
/// server reassembles never interleaves with another task's packet. Reads
/// borrow the stream's own reader mutex; writes are serialized by the
/// `pending_request` mutex, which doubles as the lazy-request slot.
struct AnytlsPacketConn {
    stream: Arc<AnytlsStream>,
    session: Arc<Session>,
    stream_id: u32,
    /// uot request, sent coalesced with the first datagram (upstream
    /// `uot.NewLazyConn`); `None` once it has gone out.
    pending_request: tokio::sync::Mutex<Option<Vec<u8>>>,
    fin_sent: AtomicBool,
}

impl AnytlsPacketConn {
    fn new(stream: Arc<AnytlsStream>, session: Arc<Session>, request: Vec<u8>) -> Self {
        let stream_id = stream.id();
        Self {
            stream,
            session,
            stream_id,
            pending_request: tokio::sync::Mutex::new(Some(request)),
            fin_sent: AtomicBool::new(false),
        }
    }

    /// Idempotent per-stream FIN, identical in intent to [`AnytlsConn::fin_stream`]:
    /// release the server's UDP socket and the session's stream-map entry
    /// without tearing down the pooled session.
    fn fin_stream(&self) {
        if self.fin_sent.swap(true, Ordering::Relaxed) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let session = Arc::clone(&self.session);
        let stream_id = self.stream_id;
        handle.spawn(async move {
            let _ = session
                .write_control_frame(Frame::control(Command::Fin, stream_id))
                .await;
        });
    }
}

#[async_trait]
impl ProxyPacketConn for AnytlsPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut reader = self.stream.reader().lock().await;

        let addr = read_uot_addr(&mut reader).await?;

        let mut len_bytes = [0u8; 2];
        reader
            .read_exact(&mut len_bytes)
            .await
            .map_err(MeowError::Io)?;
        let length = u16::from_be_bytes(len_bytes) as usize;

        // Copy what fits and drain the rest, so an undersized caller buffer
        // truncates one datagram instead of desynchronizing the stream.
        let to_copy = length.min(buf.len());
        if to_copy > 0 {
            reader
                .read_exact(&mut buf[..to_copy])
                .await
                .map_err(MeowError::Io)?;
        }
        if length > to_copy {
            let mut sink = vec![0u8; length - to_copy];
            reader.read_exact(&mut sink).await.map_err(MeowError::Io)?;
        }
        Ok((to_copy, addr))
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        let mut pending = self.pending_request.lock().await;

        let request_len = pending.as_ref().map_or(0, Vec::len);
        let mut frame = Vec::with_capacity(request_len + 21 + buf.len());
        if let Some(request) = pending.as_ref() {
            frame.extend_from_slice(request);
        }
        encode_uot_addr(&mut frame, addr);
        let Ok(length) = u16::try_from(buf.len()) else {
            return Err(MeowError::Proxy(format!(
                "anytls udp: packet too large ({} > {})",
                buf.len(),
                u16::MAX
            )));
        };
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(buf);

        // The anytls frame header is a `u16` too, and the codec truncates
        // silently rather than erroring — reject instead of corrupting.
        if frame.len() > MAX_UOT_FRAME {
            return Err(MeowError::Proxy(format!(
                "anytls udp: framed packet too large ({} > {MAX_UOT_FRAME})",
                frame.len()
            )));
        }

        self.session
            .write_data_frame(self.stream_id, Bytes::from(frame))
            .await
            .map_err(|e| MeowError::Proxy(format!("anytls udp write: {e}")))?;
        *pending = None;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        // Diagnostics only: the datagrams ride a multiplexed TLS stream, there
        // is no local UDP socket to report.
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        self.fin_stream();
        Ok(())
    }
}

impl Drop for AnytlsPacketConn {
    fn drop(&mut self) {
        // NAT eviction drops the boxed conn without calling `close()`, so FIN
        // here too; `fin_stream` is idempotent across both paths.
        self.fin_stream();
    }
}

/// Normalise the SNI / verification name: trim whitespace and IPv6 brackets;
/// an IP literal is verified against the certificate's `iPAddress` SAN and
/// (per RFC 6066 §3) not sent as SNI — `TlsLayer` handles both.
fn normalize_server_name(value: &str) -> std::result::Result<String, String> {
    let normalized = value.trim().trim_start_matches('[').trim_end_matches(']');
    if normalized.is_empty() {
        return Err("SNI cannot be empty".to_string());
    }
    Ok(normalized.to_string())
}

/// Bridges `meow_transport::tls::TlsLayer` into anytls-rs's [`TlsConnect`]
/// hook so the vendored client links no TLS library of its own.
struct MeowTlsConnect {
    layer: TlsLayer,
}

impl TlsConnect for MeowTlsConnect {
    fn connect(&self, tcp: TcpStream) -> TlsConnectFuture<'_> {
        Box::pin(async move {
            let stream =
                self.layer.connect(Box::new(tcp)).await.map_err(|e| {
                    anytls_rs::AnyTlsError::Tls(format!("TLS handshake failed: {e}"))
                })?;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }
}

// ─── meow_common ⇄ anytls_rs protector bridge ────────────────────────────────
//
// `anytls_rs` can't depend on `meow_common` (or vice-versa), so each ships
// its own outbound-socket hook registries. These bridges — installed exactly
// once via the `Once` guard inside `AnytlsAdapter::new` — re-publish
// meow_common's hooks into the `anytls-rs` registries:
//
// - `TcpDialer` (all targets): routes the client-side session dial through
//   `meow_common::connect_tcp_host`, i.e. the installed `HostResolver` +
//   `SocketProtector` stack. Without it `anytls-rs` resolves the server
//   hostname with `tokio::net::lookup_host` (the system resolver), which
//   inside a meow VPN is the in-process fake-IP DNS — the protected socket
//   then dials an unroutable fake IP and times out (the loop-routing
//   failure mode described in `meow_common::socket_protect`).
//
// - `SocketProtector` (Android): covers the remaining direct socket sites
//   in `anytls-rs` (the per-stream UDP relay's `bind_udp`), which don't go
//   through the dialer.
fn install_anytls_bridges() {
    use std::sync::Once;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        struct DialBridge;
        impl anytls_rs::TcpDialer for DialBridge {
            fn dial<'a>(
                &'a self,
                host: &'a str,
                port: u16,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = std::io::Result<tokio::net::TcpStream>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(meow_common::connect_tcp_host(host, port))
            }
        }
        anytls_rs::set_tcp_dialer(Arc::new(DialBridge));

        #[cfg(target_os = "android")]
        {
            struct Bridge;
            impl anytls_rs::SocketProtector for Bridge {
                fn protect(&self, fd: std::os::fd::RawFd) -> std::io::Result<()> {
                    match meow_common::socket_protector() {
                        Some(p) => p.protect(fd),
                        // No protector installed on the meow_common side —
                        // match the off-Android no-protector behaviour.
                        None => Ok(()),
                    }
                }
            }
            anytls_rs::set_socket_protector(Arc::new(Bridge));
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::Network;

    fn reader_over(bytes: &[u8]) -> StreamReader {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tx.send(Bytes::copy_from_slice(bytes)).unwrap();
        StreamReader::new(0, rx)
    }

    fn metadata_for(host: &str, ip: Option<IpAddr>, port: u16) -> Metadata {
        Metadata {
            network: Network::Udp,
            host: smol_str::SmolStr::from(host),
            dst_ip: ip,
            dst_port: port,
            ..Default::default()
        }
    }

    /// The request header uses SOCKS5 family bytes, *not* the uot ones.
    #[test]
    fn request_encodes_socks5_family_bytes() {
        let v4 = encode_uot_request(&metadata_for("", Some("8.8.8.8".parse().unwrap()), 53));
        assert_eq!(v4, vec![0, SOCKS5_ATYP_IPV4, 8, 8, 8, 8, 0, 53]);

        let v6 = encode_uot_request(&metadata_for(
            "",
            Some("2001:4860:4860::8888".parse().unwrap()),
            53,
        ));
        assert_eq!(v6[0], 0, "isConnect must be false (Bind format)");
        assert_eq!(v6[1], SOCKS5_ATYP_IPV6);
        assert_eq!(v6.len(), 1 + 1 + 16 + 2);

        let domain = encode_uot_request(&metadata_for("example.com", None, 443));
        assert_eq!(domain[0], 0);
        assert_eq!(domain[1], SOCKS5_ATYP_DOMAIN);
        assert_eq!(domain[2], 11);
        assert_eq!(&domain[3..14], b"example.com");
        assert_eq!(u16::from_be_bytes([domain[14], domain[15]]), 443);
    }

    /// A resolved IPv4-mapped destination goes out as plain IPv4, matching
    /// upstream's `Socksaddr` normalization.
    #[test]
    fn request_unmaps_v4_mapped_destination() {
        let mapped = encode_uot_request(&metadata_for(
            "",
            Some("::ffff:1.2.3.4".parse().unwrap()),
            8080,
        ));
        assert_eq!(mapped, vec![0, SOCKS5_ATYP_IPV4, 1, 2, 3, 4, 0x1f, 0x90]);
    }

    /// Metadata with neither an IP nor a host must still produce an address
    /// the upstream serializer accepts.
    #[test]
    fn request_falls_back_to_unspecified_without_address() {
        let empty = encode_uot_request(&metadata_for("", None, 1234));
        assert_eq!(empty, vec![0, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0x04, 0xd2]);
    }

    /// Per-packet headers use the uot family bytes — 0x00/0x01, not SOCKS5's
    /// 0x01/0x04. Getting this wrong is silent on the wire.
    #[test]
    fn packet_header_encodes_uot_family_bytes() {
        let mut buf = Vec::new();
        encode_uot_addr(&mut buf, &"1.2.3.4:80".parse().unwrap());
        assert_eq!(buf, vec![UOT_ATYP_IPV4, 1, 2, 3, 4, 0, 80]);

        let mut buf = Vec::new();
        encode_uot_addr(&mut buf, &"[::1]:80".parse().unwrap());
        assert_eq!(buf[0], UOT_ATYP_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2);

        // v4-mapped peers are unmapped, as upstream does before serializing.
        let mut buf = Vec::new();
        encode_uot_addr(&mut buf, &"[::ffff:1.2.3.4]:80".parse().unwrap());
        assert_eq!(buf, vec![UOT_ATYP_IPV4, 1, 2, 3, 4, 0, 80]);
    }

    #[tokio::test]
    async fn read_uot_addr_round_trips_encode() {
        for addr in ["1.2.3.4:53", "[2001:db8::1]:443"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let mut buf = Vec::new();
            encode_uot_addr(&mut buf, &addr);
            let mut reader = reader_over(&buf);
            assert_eq!(read_uot_addr(&mut reader).await.unwrap(), addr);
        }
    }

    /// Domain-form replies degrade to `0.0.0.0:<port>` unless the "domain" is
    /// an IP literal — same best-effort rule as `trojan.rs`.
    #[tokio::test]
    async fn read_uot_addr_handles_domain_form() {
        let mut wire = vec![UOT_ATYP_DOMAIN, 11];
        wire.extend_from_slice(b"example.com");
        wire.extend_from_slice(&443u16.to_be_bytes());
        let mut reader = reader_over(&wire);
        assert_eq!(
            read_uot_addr(&mut reader).await.unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443)
        );

        let mut wire = vec![UOT_ATYP_DOMAIN, 7];
        wire.extend_from_slice(b"1.2.3.4");
        wire.extend_from_slice(&53u16.to_be_bytes());
        let mut reader = reader_over(&wire);
        assert_eq!(
            read_uot_addr(&mut reader).await.unwrap(),
            "1.2.3.4:53".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn read_uot_addr_rejects_unknown_family() {
        let mut reader = reader_over(&[0x09, 0, 0, 0, 0, 0, 0]);
        let Err(err) = read_uot_addr(&mut reader).await else {
            panic!("unknown address family must error");
        };
        assert!(
            err.to_string().contains("unknown uot address type"),
            "{err}"
        );
    }
}
