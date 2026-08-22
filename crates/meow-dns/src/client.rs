//! Internal DNS client transports — UDP, TCP, DoT, DoH.
//!
//! Sockets are created through a pluggable [`SocketFactory`] so the caller
//! (e.g. an Android VPN service) can intercept fd creation and call
//! `protect()` before the socket is used. This is the reason the project
//! ships its own DNS client instead of relying on `hickory-resolver`.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

#[cfg(feature = "encrypted")]
use {rustls::pki_types::ServerName, std::convert::TryFrom, tokio_rustls::TlsConnector};

/// Default per-query timeout (matches the hickory-resolver value previously
/// used in `Resolver::build_*`).
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum number of pooled *and* concurrently active `tcp://` streams per
/// `DnsClient`.
///
/// The `Semaphore` in [`TcpPool`] uses this value for two purposes: it bounds
/// the idle pool size (a stream is only pushed while a permit is held) and,
/// as a side effect, limits concurrent exchanges to the same number. The
/// pool-size bound is the intended effect; the concurrency cap is an
/// acceptable consequence for this low-frequency path — plain `tcp://` DNS
/// carries truncated responses and zone transfers, not the bulk of
/// resolution traffic. If a future workload needs higher concurrency without
/// a larger pool, split this into separate `POOL_SIZE` / `MAX_CONCURRENCY`
/// constants.
const TCP_POOL_CAPACITY: usize = 4;
/// How long a pooled `tcp://` stream may sit idle before it is closed rather
/// than reused.
///
/// A pooled stream can be dropped by an upstream or a NAT without an RST or a
/// FIN ever reaching us: the write still succeeds and the peer simply never
/// answers, so the reuse attempt burns its whole read deadline before falling
/// back to a fresh connect. Reaping on an idle clock keeps that worst case out
/// of the common path — a burst of queries still shares connections, while a
/// stream idle past this window is closed and the next query pays only a
/// normal connect. RFC 7766 §6.2.3 recommends clients close idle connections
/// well inside typical server timeouts; 30 s stays under the shortest of
/// those while still covering the bursts pooling exists to serve.
const TCP_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Tokio default factory: routes through [`meow_common::bind_udp`] /
/// [`meow_common::connect_tcp`] so the Android `VpnService.protect(fd)`
/// hook (when installed) covers DNS upstream sockets too.
struct DefaultSocketFactory;

impl SocketFactory for DefaultSocketFactory {
    fn bind_udp(&self) -> BoxFuture<'_, io::Result<UdpSocket>> {
        Box::pin(async {
            // Bind to v4 unspecified; this is fine because we always
            // `connect()` the socket before sending, and connect() will
            // re-resolve the local address family.
            meow_common::bind_udp(SocketAddr::from(([0u8; 4], 0))).await
        })
    }

    fn connect_tcp(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        Box::pin(async move { meow_common::connect_tcp(addr).await })
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

/// Optional proxy adapter for routing DNS queries through. When set, the
/// TCP exchange is performed via `proxy.dial_tcp` instead of
/// `factory().connect_tcp` — see ADR-0012 (issue #67 phase 2).
pub type DnsProxy = Arc<dyn meow_common::Proxy>;

/// A single DNS upstream the resolver can query.
pub struct DnsClient {
    transport: Transport,
    timeout: Duration,
    proxy: Option<DnsProxy>,
    label: Option<Arc<str>>,
    /// Idle direct `tcp://` connections. Streams are checked out for the whole
    /// exchange and returned only after the DNS response is fully validated.
    tcp_pool: TcpPool,
}

struct TcpPool {
    /// Idle streams paired with the instant they were returned to the pool.
    /// Pushed and popped at the end, so the freshest stream is reused first
    /// and the staler ones age out instead of being handed to a query.
    idle: AsyncMutex<Vec<(TcpStream, Instant)>>,
    permits: Semaphore,
    idle_timeout: Duration,
}

impl TcpPool {
    fn new() -> Self {
        Self {
            idle: AsyncMutex::new(Vec::with_capacity(TCP_POOL_CAPACITY)),
            permits: Semaphore::new(TCP_POOL_CAPACITY),
            idle_timeout: TCP_POOL_IDLE_TIMEOUT,
        }
    }
}

/// Close every stream idle past `idle_timeout` and hand back the freshest
/// survivor, or `None` when the pool has nothing reusable.
///
/// Split out from the exchange so the reaping rule is testable without a
/// socket or a clock: dropping the expired entries closes those connections.
fn take_fresh<T>(idle: &mut Vec<(T, Instant)>, now: Instant, idle_timeout: Duration) -> Option<T> {
    idle.retain(|(_, returned_at)| now.duration_since(*returned_at) < idle_timeout);
    idle.pop().map(|(stream, _)| stream)
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
    RCode {
        code: ResponseCode,
    },
}

impl DnsClient {
    /// Plain DNS over UDP.
    pub fn udp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Udp { addr },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
            tcp_pool: TcpPool::new(),
        }
    }

    /// Plain DNS over TCP (RFC 7766 length-prefixed framing).
    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Tcp { addr },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
            tcp_pool: TcpPool::new(),
        }
    }

    /// Synthetic DNS response with a fixed response code and no answers.
    pub fn rcode(code: ResponseCode) -> Self {
        Self {
            transport: Transport::RCode { code },
            timeout: DEFAULT_QUERY_TIMEOUT,
            proxy: None,
            label: None,
            tcp_pool: TcpPool::new(),
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
            proxy: None,
            label: None,
            tcp_pool: TcpPool::new(),
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
            proxy: None,
            label: None,
            tcp_pool: TcpPool::new(),
        }
    }

    /// Override the per-query timeout.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Route this client's exchanges through `proxy` (issue #67 phase 2).
    ///
    /// When set:
    /// - TCP / DoT / DoH exchanges use `proxy.dial_tcp` instead of opening
    ///   a direct TCP connection.
    /// - UDP exchanges fall through to TCP-over-proxy, since most proxy
    ///   adapters can't relay arbitrary UDP. The fallback matches the
    ///   semantics in ADR-0012.
    pub fn with_proxy(mut self, proxy: DnsProxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Override the API/UI label used to report this upstream in DNS results.
    pub fn with_upstream_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(Arc::from(label.into()));
        self
    }

    /// Whether this client's exchanges are routed through a proxy adapter
    /// (`with_proxy`). Exposed so config-layer tests can assert that
    /// `#PROXY`-tagged nameserver entries actually got their adapter wired.
    pub fn is_proxied(&self) -> bool {
        self.proxy.is_some()
    }

    /// Human-readable upstream identifier for API/UI surfaces.
    pub fn upstream_label(&self) -> String {
        let mut label = if let Some(label) = &self.label {
            label.to_string()
        } else {
            match &self.transport {
                Transport::Udp { addr } | Transport::Tcp { addr } => socket_label(*addr, 53),
                Transport::RCode { code } => format!("rcode:{code:?}"),
                #[cfg(feature = "encrypted")]
                Transport::Dot { addr, sni, .. } => {
                    if sni.is_empty() {
                        format!("tls://{}", socket_label(*addr, 853))
                    } else if addr.port() == 853 {
                        format!("tls://{sni}")
                    } else {
                        format!("tls://{sni}:{}", addr.port())
                    }
                }
                #[cfg(feature = "encrypted")]
                Transport::Doh {
                    addr, sni, path, ..
                } => {
                    if sni.is_empty() {
                        format!("https://{}", socket_label(*addr, 443))
                    } else if path.as_ref() == "/dns-query" {
                        if addr.port() == 443 {
                            format!("https://{sni}")
                        } else {
                            format!("https://{sni}:{}", addr.port())
                        }
                    } else if addr.port() == 443 {
                        format!("https://{sni}{path}")
                    } else {
                        format!("https://{sni}:{}{path}", addr.port())
                    }
                }
            }
        };
        if self.proxy.is_some() {
            label.push_str("#PROXY");
        }
        label
    }

    /// Send a query for `(name, record_type)` and return the parsed response
    /// `Message`. The response transaction ID, message type, opcode, and
    /// question must match the request before any response flags or records
    /// are used.
    pub async fn query(&self, name: &str, record_type: RecordType) -> Result<Message, ClientError> {
        let id: u16 = rand::random();
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let parsed: Name = name
            .parse()
            .map_err(|_| ClientError::Protocol("invalid query name"))?;
        let query = Query::query(parsed, record_type);
        if let Transport::RCode { code } = &self.transport {
            let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = true;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = *code;
            resp.add_query(query);
            return Ok(resp);
        }
        msg.add_query(query.clone());
        let wire = msg.to_bytes()?;
        let expected = ExpectedResponse { id, query };
        tokio::time::timeout(self.timeout, self.exchange(&wire, &expected))
            .await
            .map_err(|_| ClientError::Timeout(self.timeout))?
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
                    let (response_addrs, response_ttl) = relevant_ip_answers(&msg);
                    addrs.extend(response_addrs);
                    if let Some(ttl) = response_ttl {
                        min_ttl = Some(min_ttl.map_or(ttl, |current| current.min(ttl)));
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

    /// Send a direct `tcp://` query through a bounded keep-alive pool.
    /// Checked-out streams stay local to this future, so cancellation drops a
    /// partially consumed stream instead of returning it to the pool.
    ///
    /// Concurrency is bounded by a `Semaphore` (`TCP_POOL_CAPACITY`); the async
    /// mutex only guards the idle-slot pop/push, so up to four exchanges run
    /// concurrently on separate streams while a fifth caller waits for a
    /// permit.
    ///
    /// The pooled (reused) attempt runs under a *short* read deadline — half
    /// the per-query timeout. A reused stream that has been idle-half-closed
    /// by an upstream or NAT (write succeeds, peer never answers) would
    /// otherwise block in `read_lp` until the outer deadline is nearly
    /// exhausted, leaving the fresh-connect retry almost no budget. RST/EOF
    /// still fail fast; only the silent half-close case is bounded here, so a
    /// query that would succeed in ~30 ms on a fresh connection no longer
    /// spuriously times out. That deadline is the second line of defence:
    /// [`TCP_POOL_IDLE_TIMEOUT`] closes a stream before it has been idle long
    /// enough to be silently dropped, so the common path after a quiet period
    /// is a plain connect rather than a reuse attempt that has to time out
    /// first. Pooling is intentionally scoped to plain
    /// `tcp://`; DoT/DoH keep a full TLS handshake per query and are out of
    /// scope.
    /// Test hook: shorten the pooled-stream idle window so reaping can be
    /// exercised without sleeping for the production timeout.
    #[cfg(test)]
    fn with_tcp_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.tcp_pool.idle_timeout = idle_timeout;
        self
    }

    async fn tcp_exchange_pooled(
        &self,
        addr: SocketAddr,
        wire: &[u8],
        expected: &ExpectedResponse,
    ) -> Result<Message, ClientError> {
        let _permit = self
            .tcp_pool
            .permits
            .acquire()
            .await
            .map_err(|_| ClientError::Protocol("TCP pool closed"))?;
        let pooled = {
            let mut idle = self.tcp_pool.idle.lock().await;
            take_fresh(&mut idle, Instant::now(), self.tcp_pool.idle_timeout)
        };
        // Half the budget for the reused-stream attempt, half in reserve for a
        // fresh connect + full exchange if the pooled stream turns out stale.
        let pooled_budget = self.timeout / 2;

        if let Some(mut stream) = pooled {
            let attempt = tcp_message_exchange(&mut stream, wire, expected);
            if let Ok(Ok(response)) = tokio::time::timeout(pooled_budget, attempt).await {
                self.tcp_pool
                    .idle
                    .lock()
                    .await
                    .push((stream, Instant::now()));
                return Ok(response);
            }
            // Timeout or error: drop the (possibly desynced/half-closed)
            // stream and reconnect. Do not return a timed-out reused stream
            // to the pool.
        }

        let mut stream = factory().connect_tcp(addr).await?;
        let response = tcp_message_exchange(&mut stream, wire, expected).await?;
        self.tcp_pool
            .idle
            .lock()
            .await
            .push((stream, Instant::now()));
        Ok(response)
    }

    async fn exchange(
        &self,
        wire: &[u8],
        expected: &ExpectedResponse,
    ) -> Result<Message, ClientError> {
        if let Some(proxy) = self.proxy.as_ref() {
            let addr = match &self.transport {
                Transport::Udp { addr } | Transport::Tcp { addr } => *addr,
                Transport::RCode { .. } => {
                    return Err(ClientError::Protocol(
                        "rcode transport should not perform network exchange",
                    ));
                }
                #[cfg(feature = "encrypted")]
                Transport::Dot { .. } | Transport::Doh { .. } => {
                    // DoT/DoH-over-proxy needs TLS layered on a Box<dyn
                    // ProxyConn>; the upstream tokio_rustls TlsConnector
                    // is generic over the IO stream but the call sites
                    // here aren't wired yet. ADR-0012 marks it
                    // follow-up. Refuse so misconfiguration is loud.
                    return Err(ClientError::Tls(
                        "DoT/DoH routing through a proxy is not implemented yet \
                        (issue #67 phase 2 follow-up); use plain udp:// or tcp:// for \
                        a #PROXY-tagged nameserver"
                            .to_string(),
                    ));
                }
            };
            let response = proxy_tcp_exchange(proxy, addr, wire).await?;
            return decode_validated_response(&response, expected);
        }
        match &self.transport {
            Transport::Udp { addr } => udp_exchange(*addr, wire, expected).await,
            Transport::Tcp { addr } => self.tcp_exchange_pooled(*addr, wire, expected).await,
            Transport::RCode { .. } => Err(ClientError::Protocol(
                "rcode transport should not perform network exchange",
            )),
            #[cfg(feature = "encrypted")]
            Transport::Dot { addr, sni, tls } => {
                let response = dot_exchange(*addr, sni, Arc::clone(tls), wire).await?;
                decode_validated_response(&response, expected)
            }
            #[cfg(feature = "encrypted")]
            Transport::Doh {
                addr,
                sni,
                path,
                tls,
            } => {
                let response = doh_exchange(*addr, sni, path, Arc::clone(tls), wire).await?;
                decode_validated_response(&response, expected)
            }
        }
    }
}

struct ExpectedResponse {
    id: u16,
    query: Query,
}

fn decode_validated_response(
    wire: &[u8],
    expected: &ExpectedResponse,
) -> Result<Message, ClientError> {
    let response = Message::from_bytes(wire)?;
    validate_response(&response, expected)?;
    Ok(response)
}

async fn tcp_message_exchange(
    stream: &mut TcpStream,
    wire: &[u8],
    expected: &ExpectedResponse,
) -> Result<Message, ClientError> {
    write_lp(stream, wire).await?;
    let response = read_lp(stream).await?;
    decode_validated_response(&response, expected)
}

fn validate_response(response: &Message, expected: &ExpectedResponse) -> Result<(), ClientError> {
    if response.metadata.id != expected.id {
        return Err(ClientError::Protocol("response ID mismatch"));
    }
    if response.metadata.message_type != MessageType::Response {
        return Err(ClientError::Protocol("received DNS query as response"));
    }
    if response.metadata.op_code != OpCode::Query {
        return Err(ClientError::Protocol("response opcode mismatch"));
    }
    let [question] = response.queries.as_slice() else {
        return Err(ClientError::Protocol("response question count mismatch"));
    };
    if !question.name.eq_ignore_root(&expected.query.name) {
        return Err(ClientError::Protocol("response question name mismatch"));
    }
    if question.query_type != expected.query.query_type {
        return Err(ClientError::Protocol("response question type mismatch"));
    }
    if question.query_class != expected.query.query_class {
        return Err(ClientError::Protocol("response question class mismatch"));
    }
    Ok(())
}

fn socket_label(addr: SocketAddr, default_port: u16) -> String {
    if addr.port() == default_port {
        addr.ip().to_string()
    } else {
        addr.to_string()
    }
}

async fn proxy_tcp_exchange(
    proxy: &DnsProxy,
    addr: SocketAddr,
    wire: &[u8],
) -> Result<Vec<u8>, ClientError> {
    use meow_common::{ConnType, Metadata, Network};
    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        host: smol_str::SmolStr::from(addr.ip().to_string()),
        dst_ip: Some(addr.ip()),
        dst_port: addr.port(),
        ..Default::default()
    };
    let mut stream = proxy
        .dial_tcp(&metadata)
        .await
        .map_err(|e| io::Error::other(format!("dns-via-proxy dial: {e}")))?;
    write_lp(&mut stream, wire).await?;
    read_lp(&mut stream).await
}

fn ip_from_record(rec: &Record) -> Option<IpAddr> {
    match &rec.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    }
}

fn canonical_name(name: &Name) -> Name {
    let mut canonical = name.to_lowercase();
    canonical.set_fqdn(true);
    canonical
}

struct CnameLink {
    target: Name,
    ttl: u32,
    ambiguous: bool,
}

fn relevant_ip_answers(message: &Message) -> (Vec<IpAddr>, Option<u32>) {
    let Some(question) = message.queries.first() else {
        return (Vec::new(), None);
    };
    if !matches!(question.query_type, RecordType::A | RecordType::AAAA) {
        return (Vec::new(), None);
    }

    // Index CNAME links once, then walk the single chain from QNAME. Besides
    // making answer order irrelevant, this keeps hostile reverse-ordered
    // chains linear instead of repeatedly rescanning every answer.
    let mut cname_links = HashMap::new();
    for record in &message.answers {
        if record.dns_class != question.query_class {
            continue;
        }
        let RData::CNAME(target) = &record.data else {
            continue;
        };
        let owner = canonical_name(&record.name);
        let target = canonical_name(&target.0);
        match cname_links.entry(owner) {
            Entry::Vacant(entry) => {
                entry.insert(CnameLink {
                    target,
                    ttl: record.ttl,
                    ambiguous: false,
                });
            }
            Entry::Occupied(mut entry) => {
                let link = entry.get_mut();
                if link.target == target {
                    link.ttl = link.ttl.min(record.ttl);
                } else {
                    // Multiple canonical names for one owner violate the
                    // CNAME rules. Do not pick an attacker-controlled branch.
                    link.ambiguous = true;
                }
            }
        }
    }

    let mut reachable = HashSet::new();
    let mut current = canonical_name(&question.name);
    let mut cname_ttl: Option<u32> = None;
    loop {
        if !reachable.insert(current.clone()) {
            // A CNAME loop has no usable terminal address.
            return (Vec::new(), None);
        }
        let Some(link) = cname_links.get(&current) else {
            break;
        };
        if link.ambiguous {
            return (Vec::new(), None);
        }
        cname_ttl = Some(cname_ttl.map_or(link.ttl, |ttl| ttl.min(link.ttl)));
        current = link.target.clone();
    }

    let mut addrs = Vec::new();
    let mut min_ttl = cname_ttl;
    for record in &message.answers {
        if record.dns_class != question.query_class
            || !reachable.contains(&canonical_name(&record.name))
        {
            continue;
        }
        let matches_query = matches!(
            (&record.data, question.query_type),
            (RData::A(_), RecordType::A) | (RData::AAAA(_), RecordType::AAAA)
        );
        if matches_query {
            addrs.extend(ip_from_record(record));
            min_ttl = Some(min_ttl.map_or(record.ttl, |ttl| ttl.min(record.ttl)));
        }
    }
    (addrs, min_ttl)
}

async fn udp_exchange(
    addr: SocketAddr,
    wire: &[u8],
    expected: &ExpectedResponse,
) -> Result<Message, ClientError> {
    let sock = factory().bind_udp().await?;
    sock.connect(addr).await?;
    sock.send(wire).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        let Ok(response) = decode_validated_response(&buf[..n], expected) else {
            // A connected UDP socket only filters the peer tuple. Ignore
            // malformed or unrelated datagrams and keep waiting under the
            // query's original overall timeout.
            continue;
        };
        if response.metadata.truncation {
            let response = tcp_exchange(addr, wire).await?;
            return decode_validated_response(&response, expected);
        }
        return Ok(response);
    }
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
         User-Agent: meow-rs\r\n\
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

#[cfg(feature = "encrypted")]
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
        // are linked (e.g. by meow-transport's `ech` feature), the default
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
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::DNSClass;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn expected(name: &str, record_type: RecordType, id: u16) -> ExpectedResponse {
        ExpectedResponse {
            id,
            query: Query::query(name.parse().unwrap(), record_type),
        }
    }

    fn response_for(request: &Message, id: u16) -> Message {
        let mut response = Message::new(id, MessageType::Response, OpCode::Query);
        response.add_queries(request.queries.iter().cloned());
        response
    }

    fn a_record(name: &str, ttl: u32, octets: [u8; 4]) -> Record {
        Record::from_rdata(
            name.parse().unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::from(octets))),
        )
    }

    fn cname_record(name: &str, ttl: u32, target: &str) -> Record {
        Record::from_rdata(
            name.parse().unwrap(),
            ttl,
            RData::CNAME(CNAME(target.parse().unwrap())),
        )
    }

    #[cfg(feature = "encrypted")]
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

    #[tokio::test]
    async fn rcode_client_returns_noerror_empty_without_network() {
        let client = DnsClient::rcode(ResponseCode::NoError);
        let resp = client.query("example.test", RecordType::A).await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
        assert_eq!(resp.queries.len(), 1);
    }

    #[test]
    fn response_validation_rejects_mismatched_metadata_and_question() {
        let expected = expected("victim.example", RecordType::A, 0x1234);
        let mut response = Message::new(0x1234, MessageType::Response, OpCode::Query);
        response.add_query(expected.query.clone());
        assert!(validate_response(&response, &expected).is_ok());

        response.metadata.id = 0x4321;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response ID mismatch"))
        ));
        response.metadata.id = expected.id;

        response.metadata.message_type = MessageType::Query;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("received DNS query as response"))
        ));
        response.metadata.message_type = MessageType::Response;

        response.metadata.op_code = OpCode::Status;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response opcode mismatch"))
        ));
        response.metadata.op_code = OpCode::Query;

        response.queries[0].name = "other.example".parse().unwrap();
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response question name mismatch"))
        ));
        response.queries[0].name = expected.query.name.clone();

        response.queries[0].query_type = RecordType::AAAA;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response question type mismatch"))
        ));
        response.queries[0].query_type = expected.query.query_type;

        response.queries[0].query_class = DNSClass::CH;
        assert!(matches!(
            validate_response(&response, &expected),
            Err(ClientError::Protocol("response question class mismatch"))
        ));
    }

    #[test]
    fn address_answers_are_limited_to_the_valid_cname_chain() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        // Deliberately put the terminal address and second CNAME before the
        // first link to prove answer ordering is irrelevant.
        message.add_answer(a_record("target.example", 300, [192, 0, 2, 10]));
        message.add_answer(cname_record("alias.example", 120, "target.example"));
        message.add_answer(a_record("unrelated.example", 1, [6, 6, 6, 6]));
        message.add_answer(cname_record("victim.example", 60, "alias.example"));

        let (addrs, ttl) = relevant_ip_answers(&message);
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        assert_eq!(ttl, Some(60));
    }

    #[test]
    fn unrelated_address_answer_is_not_returned() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        message.add_answer(a_record("unrelated.example", 30, [6, 6, 6, 6]));

        assert_eq!(relevant_ip_answers(&message), (Vec::new(), None));
    }

    #[test]
    fn cname_loop_is_rejected() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        message.add_answer(cname_record("victim.example", 60, "alias.example"));
        message.add_answer(cname_record("alias.example", 30, "victim.example"));
        message.add_answer(a_record("alias.example", 300, [192, 0, 2, 10]));

        assert_eq!(relevant_ip_answers(&message), (Vec::new(), None));
    }

    #[test]
    fn conflicting_cname_targets_are_rejected() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            "victim.example".parse().unwrap(),
            RecordType::A,
        ));
        message.add_answer(cname_record("victim.example", 60, "first.example"));
        message.add_answer(cname_record("victim.example", 30, "second.example"));
        message.add_answer(a_record("first.example", 300, [192, 0, 2, 10]));
        message.add_answer(a_record("second.example", 300, [192, 0, 2, 11]));

        assert_eq!(relevant_ip_answers(&message), (Vec::new(), None));
    }

    #[tokio::test]
    async fn udp_ignores_wrong_id_before_valid_response() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();

            let wrong = response_for(&request, request.metadata.id.wrapping_add(1));
            server
                .send_to(&wrong.to_bytes().unwrap(), peer)
                .await
                .unwrap();
            let valid = response_for(&request, request.metadata.id);
            server
                .send_to(&valid.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });

        let response = DnsClient::udp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("victim.example", RecordType::A)
            .await
            .unwrap();
        assert_eq!(response.queries[0].query_type, RecordType::A);
    }

    #[tokio::test]
    async fn wrong_id_truncated_udp_response_does_not_trigger_tcp_fallback() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();

            let mut wrong = response_for(&request, request.metadata.id.wrapping_add(1));
            wrong.metadata.truncation = true;
            server
                .send_to(&wrong.to_bytes().unwrap(), peer)
                .await
                .unwrap();
            let valid = response_for(&request, request.metadata.id);
            server
                .send_to(&valid.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });

        DnsClient::udp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("victim.example", RecordType::A)
            .await
            .expect("the valid UDP response must win without a TCP connection");
    }

    #[tokio::test]
    async fn tcp_rejects_mismatched_framed_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_lp(&mut stream).await.unwrap();
            let request = Message::from_bytes(&request).unwrap();
            let wrong = response_for(&request, request.metadata.id.wrapping_add(1));
            write_lp(&mut stream, &wrong.to_bytes().unwrap())
                .await
                .unwrap();
        });

        let result = DnsClient::tcp(addr)
            .with_timeout(Duration::from_secs(1))
            .query("victim.example", RecordType::A)
            .await;
        assert!(matches!(
            result,
            Err(ClientError::Protocol("response ID mismatch"))
        ));
    }

    #[cfg(feature = "encrypted")]
    #[test]
    fn encrypted_upstream_labels_include_scheme() {
        let dot = DnsClient::dot("8.8.8.8:853".parse().unwrap(), "dns.google");
        assert_eq!(dot.upstream_label(), "tls://dns.google");

        let doh = DnsClient::doh(
            "1.1.1.1:443".parse().unwrap(),
            "cloudflare-dns.com",
            "/dns-query",
        );
        assert_eq!(doh.upstream_label(), "https://cloudflare-dns.com");
    }

    #[test]
    fn explicit_upstream_label_overrides_default_label() {
        let client = DnsClient::udp("8.8.8.8:53".parse().unwrap())
            .with_upstream_label("tls://dns.google:853");
        assert_eq!(client.upstream_label(), "tls://dns.google:853");
    }

    #[tokio::test]
    async fn tcp_short_frames_never_panic_or_return_to_pool() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let server_connections = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let index = server_connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    while read_lp(&mut stream).await.is_ok() {
                        // First connection answers with a zero-length frame,
                        // the second with a one-byte frame — both are
                        // malformed and must surface as `ClientError` instead
                        // of panicking or being returned to the pool.
                        let frame: &[u8] = if index == 0 { &[0, 0] } else { &[0, 1, 0] };
                        if stream.write_all(frame).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let client = DnsClient::tcp(addr).with_timeout(Duration::from_secs(1));
        for _ in 0..2 {
            assert!(client.query("victim.example", RecordType::A).await.is_err());
        }
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancelled_tcp_exchange_discards_partial_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let connection = server_accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    if connection == 0 {
                        let request = read_lp(&mut stream).await.unwrap();
                        let request = Message::from_bytes(&request).unwrap();
                        let response = response_for(&request, request.metadata.id);
                        write_lp(&mut stream, &response.to_bytes().unwrap())
                            .await
                            .unwrap();
                        read_lp(&mut stream).await.unwrap();
                        stream.write_all(&[0, 64, 0]).await.unwrap();
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        return;
                    }
                    let request = read_lp(&mut stream).await.unwrap();
                    let request = Message::from_bytes(&request).unwrap();
                    let response = response_for(&request, request.metadata.id);
                    write_lp(&mut stream, &response.to_bytes().unwrap())
                        .await
                        .unwrap();
                });
            }
        });

        let client = DnsClient::tcp(addr).with_timeout(Duration::from_millis(200));
        client
            .query("warm.example", RecordType::A)
            .await
            .expect("the first query primes the pool");
        // The reused stream stalls on a partial length-prefixed frame (the
        // server announces 64 bytes but sends 1, then sleeps). With a short
        // read deadline on the pooled attempt, the client
        // abandons the stale stream well before the 200 ms query budget is
        // spent and retries on a fresh connection — so this query succeeds
        // instead of burning the full timeout. Cancellation safety (the
        // partial stream is discarded, never returned to the pool) is what
        // makes the retry safe.
        client
            .query("partial.example", RecordType::A)
            .await
            .expect("stale pooled stream retried within budget");
        client
            .query("after-cancel.example", RecordType::A)
            .await
            .expect("the discarded partial stream must not be reused");
        assert!(accepted.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn tcp_pool_bounds_concurrency_and_reuses_connections() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));

        let server_accepted = Arc::clone(&accepted);
        let server_active = Arc::clone(&active);
        let server_released = Arc::clone(&released);
        let server_gate = Arc::clone(&gate);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                server_accepted.fetch_add(1, Ordering::SeqCst);
                let active = Arc::clone(&server_active);
                let released = Arc::clone(&server_released);
                let gate = Arc::clone(&server_gate);
                tokio::spawn(async move {
                    while let Ok(request) = read_lp(&mut stream).await {
                        let request = Message::from_bytes(&request).unwrap();
                        active.fetch_add(1, Ordering::SeqCst);
                        if !released.load(Ordering::SeqCst) {
                            gate.acquire().await.unwrap().forget();
                        }
                        active.fetch_sub(1, Ordering::SeqCst);
                        let response = response_for(&request, request.metadata.id);
                        if write_lp(&mut stream, &response.to_bytes().unwrap())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });

        let client = Arc::new(DnsClient::tcp(addr).with_timeout(Duration::from_secs(2)));
        let queries: Vec<_> = (0..6)
            .map(|index| {
                let client = Arc::clone(&client);
                tokio::spawn(async move {
                    client
                        .query(&format!("pool-{index}.example"), RecordType::A)
                        .await
                })
            })
            .collect();

        tokio::time::timeout(Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) < TCP_POOL_CAPACITY {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("four TCP exchanges should run concurrently");
        assert_eq!(accepted.load(Ordering::SeqCst), TCP_POOL_CAPACITY);

        released.store(true, Ordering::SeqCst);
        gate.add_permits(TCP_POOL_CAPACITY);
        for query in queries {
            query.await.unwrap().unwrap();
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            TCP_POOL_CAPACITY,
            "queued queries should reuse the four established connections"
        );
    }
    #[test]
    fn take_fresh_reaps_expired_and_returns_the_freshest() {
        let timeout = Duration::from_secs(30);
        let now = Instant::now();
        // Oldest first, freshest last — the order `push` produces.
        let mut idle = vec![
            (1u32, now - Duration::from_secs(90)),
            (2u32, now - Duration::from_secs(45)),
            (3u32, now - Duration::from_secs(5)),
        ];
        assert_eq!(
            take_fresh(&mut idle, now, timeout),
            Some(3),
            "the most recently returned stream must be reused first"
        );
        assert!(
            idle.is_empty(),
            "both streams idle past the timeout must have been closed, not left pooled"
        );
    }

    #[test]
    fn take_fresh_returns_none_when_every_stream_is_stale() {
        let timeout = Duration::from_secs(30);
        let now = Instant::now();
        let mut idle = vec![
            (1u32, now - Duration::from_secs(31)),
            (2u32, now - Duration::from_secs(60)),
        ];
        assert_eq!(
            take_fresh(&mut idle, now, timeout),
            None,
            "an all-stale pool must force a fresh connect"
        );
        assert!(idle.is_empty());
    }

    #[test]
    fn take_fresh_keeps_streams_inside_the_window() {
        let timeout = Duration::from_secs(30);
        let now = Instant::now();
        let mut idle = vec![
            (1u32, now - Duration::from_secs(29)),
            (2u32, now - Duration::from_secs(1)),
        ];
        assert_eq!(take_fresh(&mut idle, now, timeout), Some(2));
        assert_eq!(
            idle.len(),
            1,
            "a stream still inside the idle window must stay pooled"
        );
    }

    /// A stream idle past the timeout must be closed instead of reused: the
    /// second query dials a fresh connection rather than spending its read
    /// deadline discovering that a silently-dropped stream will never answer.
    #[tokio::test]
    async fn tcp_pool_discards_streams_idle_past_the_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));

        let server_accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                server_accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    while let Ok(request) = read_lp(&mut stream).await {
                        let request = Message::from_bytes(&request).unwrap();
                        let response = response_for(&request, request.metadata.id);
                        if write_lp(&mut stream, &response.to_bytes().unwrap())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });

        let idle_timeout = Duration::from_millis(20);
        let client = DnsClient::tcp(addr)
            .with_timeout(Duration::from_secs(2))
            .with_tcp_idle_timeout(idle_timeout);

        client.query("first.example", RecordType::A).await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        // Still inside the window: the pooled stream is reused.
        client.query("second.example", RecordType::A).await.unwrap();
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "a stream inside the idle window must be reused"
        );

        // Past the window: the pooled stream is closed and a new one dialled.
        tokio::time::sleep(idle_timeout * 5).await;
        client.query("third.example", RecordType::A).await.unwrap();
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "a stream idle past the timeout must be closed, not reused"
        );
    }
}
