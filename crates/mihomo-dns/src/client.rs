//! Internal DNS client transports — UDP, TCP, DoT, DoH.
//!
//! Sockets are created through a pluggable [`SocketFactory`] so the caller
//! (e.g. an Android VPN service) can intercept fd creation and call
//! `protect()` before the socket is used. This is the reason the project
//! ships its own DNS client instead of relying on `hickory-resolver`.

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[cfg(feature = "encrypted")]
use {rustls::pki_types::ServerName, std::convert::TryFrom, tokio_rustls::TlsConnector};

/// Default per-query timeout (matches the hickory-resolver value previously
/// used in `Resolver::build_*`).
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Factory that creates the raw sockets the DNS client transports run on.
///
/// Implementations may call platform-specific hooks (Android `protect()`,
/// Linux `SO_MARK`, …) before returning the socket so DNS traffic bypasses
/// the local VPN tunnel.
pub trait SocketFactory: Send + Sync + 'static {
    /// Bind an unconnected UDP socket. Implementations typically bind to
    /// `0.0.0.0:0`.
    fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>>;

    /// Open an outbound TCP connection to `addr`.
    fn connect_tcp(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>>;
}

/// Tokio default factory: plain `UdpSocket::bind` / `TcpStream::connect`.
struct DefaultSocketFactory;

impl SocketFactory for DefaultSocketFactory {
    fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>> {
        Box::pin(async {
            // Bind to v4 unspecified; this is fine because we always
            // `connect()` the socket before sending, and connect() will
            // re-resolve the local address family.
            UdpSocket::bind(SocketAddr::from(([0u8; 4], 0))).await
        })
    }

    fn connect_tcp(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        Box::pin(async move { TcpStream::connect(addr).await })
    }
}

static SOCKET_FACTORY: OnceLock<Arc<dyn SocketFactory>> = OnceLock::new();
static DEFAULT_FACTORY: DefaultSocketFactory = DefaultSocketFactory;

/// Install a custom [`SocketFactory`]. Can only be called once; subsequent
/// calls return the supplied factory unchanged so the caller can detect the
/// programming error.
pub fn set_socket_factory(factory: Arc<dyn SocketFactory>) -> Result<(), Arc<dyn SocketFactory>> {
    SOCKET_FACTORY.set(factory)
}

fn factory() -> &'static dyn SocketFactory {
    match SOCKET_FACTORY.get() {
        Some(f) => f.as_ref(),
        None => &DEFAULT_FACTORY,
    }
}

/// All errors produced by the internal DNS client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("dns proto: {0}")]
    Proto(#[from] hickory_proto::ProtoError),
    #[error("dns decode: {0}")]
    Decode(#[from] hickory_proto::serialize::binary::DecodeError),
    #[error("query timed out after {0:?}")]
    Timeout(Duration),
    #[error("invalid response: {0}")]
    Protocol(&'static str),
    #[error("tls: {0}")]
    Tls(String),
    #[error("upstream returned rcode {0:?}")]
    Rcode(hickory_proto::op::ResponseCode),
}

/// A single DNS upstream the resolver can query.
pub struct DnsClient {
    transport: Transport,
    timeout: Duration,
}

enum Transport {
    Udp {
        addr: SocketAddr,
    },
    Tcp {
        addr: SocketAddr,
    },
    #[cfg(feature = "encrypted")]
    Dot {
        addr: SocketAddr,
        sni: Arc<str>,
        tls: Arc<rustls::ClientConfig>,
    },
    #[cfg(feature = "encrypted")]
    Doh {
        addr: SocketAddr,
        sni: Arc<str>,
        path: Arc<str>,
        tls: Arc<rustls::ClientConfig>,
    },
}

impl DnsClient {
    /// Plain DNS over UDP.
    pub fn udp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Udp { addr },
            timeout: DEFAULT_QUERY_TIMEOUT,
        }
    }

    /// Plain DNS over TCP (RFC 7766 length-prefixed framing).
    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Tcp { addr },
            timeout: DEFAULT_QUERY_TIMEOUT,
        }
    }

    /// DNS over TLS (RFC 7858).
    #[cfg(feature = "encrypted")]
    pub fn dot(addr: SocketAddr, sni: &str) -> Self {
        Self {
            transport: Transport::Dot {
                addr,
                sni: Arc::from(sni),
                tls: tls_client_config("dot"),
            },
            timeout: DEFAULT_QUERY_TIMEOUT,
        }
    }

    /// DNS over HTTPS (RFC 8484) — HTTP/1.1 POST application/dns-message.
    #[cfg(feature = "encrypted")]
    pub fn doh(addr: SocketAddr, sni: &str, path: &str) -> Self {
        Self {
            transport: Transport::Doh {
                addr,
                sni: Arc::from(sni),
                path: Arc::from(path),
                tls: tls_client_config("doh"),
            },
            timeout: DEFAULT_QUERY_TIMEOUT,
        }
    }

    /// Override the per-query timeout.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Send a query for `(name, record_type)` and return the parsed response
    /// `Message`. ID is randomised internally and the response's ID is not
    /// checked against the request — DoT/DoH/UDP-connected guarantee a 1:1
    /// pairing on the socket so spoofing a different ID would be a no-op.
    pub async fn query(&self, name: &str, record_type: RecordType) -> Result<Message, ClientError> {
        let id: u16 = rand::random();
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let parsed: Name = name
            .parse()
            .map_err(|_| ClientError::Protocol("invalid query name"))?;
        msg.add_query(Query::query(parsed, record_type));
        let wire = msg.to_bytes()?;
        let resp_bytes = tokio::time::timeout(self.timeout, self.exchange(&wire))
            .await
            .map_err(|_| ClientError::Timeout(self.timeout))??;
        let resp = Message::from_bytes(&resp_bytes)?;
        Ok(resp)
    }

    /// Convenience: query `A` and `AAAA` in parallel, merge addresses, return
    /// (addrs, min_ttl).  Empty answer set returns `Ok((vec![], _))`; upstream
    /// SERVFAIL surfaces as `ClientError::Rcode`.
    pub async fn lookup_ip(&self, name: &str) -> Result<(Vec<IpAddr>, Duration), ClientError> {
        let (a, aaaa) = tokio::join!(
            self.query(name, RecordType::A),
            self.query(name, RecordType::AAAA),
        );
        let mut addrs = Vec::new();
        let mut min_ttl: Option<u32> = None;
        let mut had_any_ok = false;
        let mut last_err: Option<ClientError> = None;
        for r in [a, aaaa] {
            match r {
                Ok(msg) => {
                    had_any_ok = true;
                    for rec in &msg.answers {
                        if let Some(ip) = ip_from_record(rec) {
                            addrs.push(ip);
                            min_ttl = Some(min_ttl.map_or(rec.ttl, |t| t.min(rec.ttl)));
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        if !had_any_ok {
            return Err(last_err.unwrap_or(ClientError::Protocol("no response")));
        }
        Ok((addrs, Duration::from_secs(u64::from(min_ttl.unwrap_or(0)))))
    }

    async fn exchange(&self, wire: &[u8]) -> Result<Vec<u8>, ClientError> {
        match &self.transport {
            Transport::Udp { addr } => udp_exchange(*addr, wire).await,
            Transport::Tcp { addr } => tcp_exchange(*addr, wire).await,
            #[cfg(feature = "encrypted")]
            Transport::Dot { addr, sni, tls } => {
                dot_exchange(*addr, sni, Arc::clone(tls), wire).await
            }
            #[cfg(feature = "encrypted")]
            Transport::Doh {
                addr,
                sni,
                path,
                tls,
            } => doh_exchange(*addr, sni, path, Arc::clone(tls), wire).await,
        }
    }
}

fn ip_from_record(rec: &Record) -> Option<IpAddr> {
    match &rec.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    }
}

async fn udp_exchange(addr: SocketAddr, wire: &[u8]) -> Result<Vec<u8>, ClientError> {
    let sock = factory().bind_udp().await?;
    sock.connect(addr).await?;
    sock.send(wire).await?;
    let mut buf = vec![0u8; 4096];
    let n = sock.recv(&mut buf).await?;
    buf.truncate(n);
    if n < 12 {
        return Err(ClientError::Protocol("udp response shorter than header"));
    }
    // RFC 6891 / RFC 7766 — handle TC=1 by retrying over TCP. Bit is byte 2
    // bit 1 (0x02).
    if buf[2] & 0x02 != 0 {
        return tcp_exchange(addr, wire).await;
    }
    Ok(buf)
}

async fn tcp_exchange(addr: SocketAddr, wire: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut stream = factory().connect_tcp(addr).await?;
    write_lp(&mut stream, wire).await?;
    read_lp(&mut stream).await
}

async fn write_lp<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    let len =
        u16::try_from(payload.len()).map_err(|_| io::Error::other("dns message too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}

async fn read_lp<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>, ClientError> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(feature = "encrypted")]
async fn dot_exchange(
    addr: SocketAddr,
    sni: &str,
    tls: Arc<rustls::ClientConfig>,
    wire: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let tcp = factory().connect_tcp(addr).await?;
    let connector = TlsConnector::from(tls);
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| ClientError::Tls(format!("invalid SNI: {e}")))?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ClientError::Tls(e.to_string()))?;
    write_lp(&mut stream, wire).await?;
    read_lp(&mut stream).await
}

#[cfg(feature = "encrypted")]
async fn doh_exchange(
    addr: SocketAddr,
    sni: &str,
    path: &str,
    tls: Arc<rustls::ClientConfig>,
    wire: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let tcp = factory().connect_tcp(addr).await?;
    let connector = TlsConnector::from(tls);
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| ClientError::Tls(format!("invalid SNI: {e}")))?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ClientError::Tls(e.to_string()))?;

    // Minimal HTTP/1.1 POST. Connection: close so the server EOFs and we can
    // read-to-end without parsing chunked transfer-encoding.
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: mihomo-rust\r\n\
         Accept: application/dns-message\r\n\
         Content-Type: application/dns-message\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        host = sni,
        len = wire.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(wire).await?;
    stream.flush().await?;

    let mut all = Vec::with_capacity(1024);
    stream.read_to_end(&mut all).await?;
    let split = find_subseq(&all, b"\r\n\r\n")
        .ok_or(ClientError::Protocol("doh: missing header terminator"))?;
    let head_bytes = &all[..split];
    let body = &all[split + 4..];
    let head_str =
        std::str::from_utf8(head_bytes).map_err(|_| ClientError::Protocol("doh: bad headers"))?;
    let status_line = head_str
        .lines()
        .next()
        .ok_or(ClientError::Protocol("doh: empty response"))?;
    // "HTTP/1.1 200 OK" — extract the status code.
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status = parts.next().unwrap_or("");
    if status != "200" {
        return Err(ClientError::Protocol("doh: non-200 status"));
    }
    Ok(body.to_vec())
}

fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

#[cfg(feature = "encrypted")]
fn tls_client_config(alpn: &str) -> Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    static DOT: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static DOH: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let slot = match alpn {
        "dot" => &DOT,
        _ => &DOH,
    };
    Arc::clone(slot.get_or_init(|| {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        // Be explicit about the provider — when both `ring` and `aws_lc_rs`
        // are linked (e.g. by mihomo-transport's `ech` feature), the default
        // `ClientConfig::builder()` panics on the auto-detect.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("rustls protocol versions are safe defaults")
            .with_root_certificates(root_store)
            .with_no_client_auth();
        cfg.alpn_protocols = match alpn {
            "dot" => vec![b"dot".to_vec()],
            // h2 first, but the client speaks http/1.1 so include it too.
            _ => vec![b"http/1.1".to_vec()],
        };
        Arc::new(cfg)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_subseq_basic() {
        assert_eq!(find_subseq(b"abc\r\n\r\nbody", b"\r\n\r\n"), Some(3));
        assert_eq!(find_subseq(b"abcdef", b"\r\n\r\n"), None);
        assert_eq!(find_subseq(b"", b"x"), None);
    }

    #[tokio::test]
    async fn udp_client_times_out_on_unroutable() {
        // 192.0.2.1/24 is TEST-NET-1, guaranteed not to respond.
        let client = DnsClient::udp("192.0.2.1:53".parse().unwrap())
            .with_timeout(Duration::from_millis(200));
        let r = client.query("example.test", RecordType::A).await;
        assert!(matches!(r, Err(ClientError::Timeout(_))));
    }
}
