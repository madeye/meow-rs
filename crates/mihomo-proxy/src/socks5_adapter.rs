//! SOCKS5 outbound proxy adapter (M1.B-4).
//!
//! Implements `ProxyAdapter` for `type: socks5` config entries.  Supports:
//! - Auth method negotiation: no-auth (0x00) and username/password (0x02).
//! - `CMD CONNECT` (0x01) — TCP tunnel.
//! - `atyp` 0x03 (domain) preferred when `metadata.host` is set;
//!   0x01 (IPv4) or 0x04 (IPv6) otherwise.
//! - Optional TLS-wrapping of the TCP connection to the proxy server.
//! - `udp: true` is accepted at parse time and silently ignored (warn-once);
//!   `support_udp()` always returns `false` in M1.
//!
//! # Divergences from upstream (ADR-0002)
//!
//! | # | Case | Class |
//! |---|------|:-----:|
//! | 1 | SOCKS5 UDP ASSOCIATE deferred | B |
//!
//! upstream: `adapter/outbound/socks5.go`

use std::net::IpAddr;

use async_trait::async_trait;
use mihomo_common::{
    AdapterType, Metadata, MihomoError, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn,
    Result,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use crate::stream_conn::StreamConn;

// ─── SOCKS5 constants ─────────────────────────────────────────────────────────

const VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const RESERVED: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCESS: u8 = 0x00;
const REPLY_SUCCESS: u8 = 0x00;

// ─── Adapter ─────────────────────────────────────────────────────────────────

/// SOCKS5 outbound proxy adapter.
///
/// upstream: `adapter/outbound/socks5.go` — `Socks5`
pub struct Socks5Adapter {
    name: String,
    server: String,
    port: u16,
    /// `"server:port"` — returned by `addr()` for relay metadata building.
    addr_str: String,
    /// `Some((username, password))` — both present or neither (ADR-0002 Class A).
    auth: Option<(String, String)>,
    tls: bool,
    skip_cert_verify: bool,
    health: ProxyHealth,
}

impl Socks5Adapter {
    /// Create a `Socks5Adapter`.
    ///
    /// `udp` is ignored in M1 (SOCKS5 UDP ASSOCIATE deferred, ADR-0002 Class B).
    /// Warn-once at parse time if `udp: true` is configured.
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        auth: Option<(String, String)>,
        tls: bool,
        skip_cert_verify: bool,
    ) -> Self {
        Self {
            name: name.to_string(),
            addr_str: format!("{}:{}", server, port),
            server: server.to_string(),
            port,
            auth,
            tls,
            skip_cert_verify,
            health: ProxyHealth::new(),
        }
    }

    /// Dial TCP to the proxy server, optionally wrapping in TLS.
    async fn dial_stream(&self) -> Result<Box<dyn mihomo_transport::Stream>> {
        let tcp = TcpStream::connect(format!("{}:{}", self.server, self.port))
            .await
            .map_err(MihomoError::Io)?;

        if self.tls {
            use mihomo_transport::tls::{TlsConfig, TlsLayer};
            use mihomo_transport::Transport;

            let tls_cfg = TlsConfig {
                skip_cert_verify: self.skip_cert_verify,
                ..TlsConfig::new(&self.server)
            };
            let tls_layer =
                TlsLayer::new(&tls_cfg).map_err(|e| MihomoError::Proxy(e.to_string()))?;
            tls_layer
                .connect(Box::new(tcp))
                .await
                .map_err(|e| MihomoError::Proxy(e.to_string()))
        } else {
            Ok(Box::new(tcp))
        }
    }

    /// Run the full SOCKS5 handshake (auth negotiation + CONNECT) over `stream`.
    ///
    /// `target_host` — destination hostname (used as `atyp 0x03` when non-empty).
    /// `target_ip`   — destination IP (used as `atyp 0x01`/`0x04` when host is empty).
    /// `target_port` — destination port.
    async fn run_handshake<S>(
        &self,
        stream: &mut S,
        target_host: &str,
        target_ip: Option<IpAddr>,
        target_port: u16,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // ── Pre-flight length guards ───────────────────────────────────────────
        //
        // SOCKS5 ATYP 0x03 encodes the hostname length as a single byte (0–255).
        // RFC 1929 §2 encodes the username and password lengths as single bytes.
        // Casting `len() as u8` when len > 255 silently truncates and produces a
        // malformed frame; we reject early instead.
        //
        // ADR-0002 Class A divergence: upstream socks5.go does not guard these.
        if !target_host.is_empty() && target_host.len() > 255 {
            return Err(MihomoError::Proxy(format!(
                "socks5: hostname too long ({} bytes, max 255 per protocol)",
                target_host.len()
            )));
        }
        if let Some((user, pass)) = &self.auth {
            if user.len() > 255 {
                return Err(MihomoError::Proxy(format!(
                    "socks5: username too long ({} bytes, max 255 per RFC 1929)",
                    user.len()
                )));
            }
            if pass.len() > 255 {
                return Err(MihomoError::Proxy(format!(
                    "socks5: password too long ({} bytes, max 255 per RFC 1929)",
                    pass.len()
                )));
            }
        }

        // ── Step 1: Method negotiation ────────────────────────────────────────
        let methods: &[u8] = if self.auth.is_some() {
            &[METHOD_NO_AUTH, METHOD_USER_PASS]
        } else {
            &[METHOD_NO_AUTH]
        };

        let mut greeting = Vec::with_capacity(2 + methods.len());
        greeting.push(VERSION);
        greeting.push(methods.len() as u8);
        greeting.extend_from_slice(methods);
        stream.write_all(&greeting).await.map_err(MihomoError::Io)?;

        let mut server_choice = [0u8; 2];
        stream
            .read_exact(&mut server_choice)
            .await
            .map_err(MihomoError::Io)?;

        if server_choice[0] != VERSION {
            return Err(MihomoError::Proxy(format!(
                "socks5: unexpected version byte {:#04x} in method selection",
                server_choice[0]
            )));
        }

        let chosen = server_choice[1];
        if chosen == METHOD_NO_ACCEPTABLE {
            return Err(MihomoError::NoAcceptableMethod);
        }

        // ── Step 2: Username/password sub-negotiation (if server chose 0x02) ──
        //
        // upstream: socks5.go::handshake — if server picks no-auth even when
        // credentials were offered, proceed WITHOUT sub-negotiation.
        // NOT Err(NoAcceptableMethod). NOT panic.
        if chosen == METHOD_USER_PASS {
            let (user, pass) = self
                .auth
                .as_ref()
                .expect("auth set when METHOD_USER_PASS offered");

            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(AUTH_VERSION);
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth_req).await.map_err(MihomoError::Io)?;

            let mut auth_resp = [0u8; 2];
            stream
                .read_exact(&mut auth_resp)
                .await
                .map_err(MihomoError::Io)?;

            if auth_resp[1] != AUTH_SUCCESS {
                return Err(MihomoError::ProxyAuthFailed);
            }
        }

        // ── Step 3: CONNECT request ───────────────────────────────────────────
        //
        // Prefer domain name (atyp 0x03) when metadata.host is set;
        // fall back to IPv4/IPv6 literal otherwise.
        // upstream: socks5.go — uses hostname when available, NOT IP-only dial.
        let mut req = vec![VERSION, CMD_CONNECT, RESERVED];

        if !target_host.is_empty() {
            // atyp 0x03: domain name
            let host_bytes = target_host.as_bytes();
            req.push(ATYP_DOMAIN);
            req.push(host_bytes.len() as u8);
            req.extend_from_slice(host_bytes);
        } else {
            match target_ip {
                Some(IpAddr::V4(v4)) => {
                    req.push(ATYP_IPV4);
                    req.extend_from_slice(&v4.octets());
                }
                Some(IpAddr::V6(v6)) => {
                    req.push(ATYP_IPV6);
                    req.extend_from_slice(&v6.octets());
                }
                None => {
                    return Err(MihomoError::Proxy(
                        "socks5: no destination address in metadata".into(),
                    ));
                }
            }
        }

        req.push((target_port >> 8) as u8);
        req.push((target_port & 0xFF) as u8);
        stream.write_all(&req).await.map_err(MihomoError::Io)?;

        // ── Step 4: CONNECT response ──────────────────────────────────────────
        // [0x05, rep, 0x00, atyp, bnd_addr..., bnd_port_hi, bnd_port_lo]
        let mut resp_hdr = [0u8; 4];
        stream
            .read_exact(&mut resp_hdr)
            .await
            .map_err(MihomoError::Io)?;

        if resp_hdr[1] != REPLY_SUCCESS {
            return Err(MihomoError::Socks5ConnectFailed(resp_hdr[1]));
        }

        // Drain the bound address (we don't use it for TCP relay).
        drain_socks5_addr(stream, resp_hdr[3]).await?;

        Ok(())
    }
}

/// Read and discard the bound address + port from a SOCKS5 response.
///
/// `atyp` is the address-type byte already read from the response header.
async fn drain_socks5_addr<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    atyp: u8,
) -> Result<()> {
    let addr_len: usize = match atyp {
        ATYP_IPV4 => 4,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(MihomoError::Io)?;
            len[0] as usize
        }
        ATYP_IPV6 => 16,
        other => {
            return Err(MihomoError::Proxy(format!(
                "socks5: unknown atyp {other:#04x} in response"
            )));
        }
    };
    // addr bytes + 2-byte port
    let mut discard = vec![0u8; addr_len + 2];
    stream
        .read_exact(&mut discard)
        .await
        .map_err(MihomoError::Io)?;
    Ok(())
}

// ─── ProxyAdapter ─────────────────────────────────────────────────────────────

#[async_trait]
impl ProxyAdapter for Socks5Adapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Socks5
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        // SOCKS5 UDP ASSOCIATE deferred to M1.x. ADR-0002 Class B.
        false
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "socks5: CONNECT {}:{} via {}:{}",
            metadata.host, metadata.dst_port, self.server, self.port
        );

        let mut stream = self.dial_stream().await?;
        self.run_handshake(
            &mut stream,
            &metadata.host,
            metadata.dst_ip,
            metadata.dst_port,
        )
        .await?;
        Ok(Box::new(StreamConn(stream)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        // SOCKS5 UDP ASSOCIATE not implemented in M1. ADR-0002 Class B.
        Err(MihomoError::NotSupported(
            "socks5: UDP ASSOCIATE not supported in M1 (deferred)".into(),
        ))
    }

    /// Run the SOCKS5 handshake over an already-established stream.
    ///
    /// TLS-wrapping is intentionally skipped — the passed stream is already
    /// inside the relay chain's encryption.
    ///
    /// upstream: `adapter/outbound/socks5.go` — `DialContextWithDialer`
    async fn connect_over(
        &self,
        mut stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "socks5: CONNECT (relay) {}:{} over existing stream",
            metadata.host, metadata.dst_port
        );
        self.run_handshake(
            &mut stream,
            &metadata.host,
            metadata.dst_ip,
            metadata.dst_port,
        )
        .await?;
        Ok(stream)
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use mihomo_common::MihomoError;

    // ─── Mock SOCKS5 server ───────────────────────────────────────────────────

    enum AuthMode {
        NoAuth,
        UserPass {
            user: &'static str,
            pass: &'static str,
        },
        ForceNoAuth, // advertise only 0x00 even when client offers 0x02
        NoAcceptable,
    }

    enum ConnectResult {
        Success,
        Fail(u8),
    }

    struct MockServer {
        auth_mode: AuthMode,
        connect_result: ConnectResult,
    }

    impl MockServer {
        fn new_no_auth() -> Self {
            Self {
                auth_mode: AuthMode::NoAuth,
                connect_result: ConnectResult::Success,
            }
        }
        fn new_user_pass(user: &'static str, pass: &'static str) -> Self {
            Self {
                auth_mode: AuthMode::UserPass { user, pass },
                connect_result: ConnectResult::Success,
            }
        }
        fn new_no_acceptable() -> Self {
            Self {
                auth_mode: AuthMode::NoAcceptable,
                connect_result: ConnectResult::Success,
            }
        }
        fn new_force_no_auth() -> Self {
            Self {
                auth_mode: AuthMode::ForceNoAuth,
                connect_result: ConnectResult::Success,
            }
        }
        fn with_connect_fail(mut self, rep: u8) -> Self {
            self.connect_result = ConnectResult::Fail(rep);
            self
        }

        async fn spawn(self) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let handle = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut captured_req = Vec::new();

                // Method negotiation
                let mut hdr = [0u8; 2];
                s.read_exact(&mut hdr).await.unwrap();
                let n_methods = hdr[1] as usize;
                let mut methods = vec![0u8; n_methods];
                s.read_exact(&mut methods).await.unwrap();
                captured_req.extend_from_slice(&hdr);
                captured_req.extend_from_slice(&methods);

                let chosen = match &self.auth_mode {
                    AuthMode::NoAuth => METHOD_NO_AUTH,
                    AuthMode::UserPass { .. } => METHOD_USER_PASS,
                    AuthMode::ForceNoAuth => METHOD_NO_AUTH,
                    AuthMode::NoAcceptable => METHOD_NO_ACCEPTABLE,
                };
                s.write_all(&[VERSION, chosen]).await.unwrap();

                if chosen == METHOD_NO_ACCEPTABLE {
                    return captured_req;
                }

                // Sub-negotiation (if chosen = 0x02)
                if chosen == METHOD_USER_PASS {
                    let mut auth_hdr = [0u8; 2];
                    s.read_exact(&mut auth_hdr).await.unwrap();
                    let ulen = auth_hdr[1] as usize;
                    let mut user_bytes = vec![0u8; ulen];
                    s.read_exact(&mut user_bytes).await.unwrap();
                    let mut plen_buf = [0u8; 1];
                    s.read_exact(&mut plen_buf).await.unwrap();
                    let plen = plen_buf[0] as usize;
                    let mut pass_bytes = vec![0u8; plen];
                    s.read_exact(&mut pass_bytes).await.unwrap();

                    let ok = match &self.auth_mode {
                        AuthMode::UserPass { user, pass } => {
                            user_bytes == user.as_bytes() && pass_bytes == pass.as_bytes()
                        }
                        _ => false,
                    };
                    let status = if ok { AUTH_SUCCESS } else { 0x01u8 };
                    s.write_all(&[AUTH_VERSION, status]).await.unwrap();
                    if !ok {
                        return captured_req;
                    }
                }

                // CONNECT request
                let mut req_hdr = [0u8; 4];
                s.read_exact(&mut req_hdr).await.unwrap();
                captured_req.extend_from_slice(&req_hdr);
                let atyp = req_hdr[3];
                let addr_len = match atyp {
                    ATYP_IPV4 => 4,
                    ATYP_DOMAIN => {
                        let mut l = [0u8; 1];
                        s.read_exact(&mut l).await.unwrap();
                        captured_req.push(l[0]);
                        l[0] as usize
                    }
                    ATYP_IPV6 => 16,
                    _ => 0,
                };
                let mut addr_port = vec![0u8; addr_len + 2];
                s.read_exact(&mut addr_port).await.unwrap();
                captured_req.extend_from_slice(&addr_port);

                // Reply
                let rep = match &self.connect_result {
                    ConnectResult::Success => REPLY_SUCCESS,
                    ConnectResult::Fail(r) => *r,
                };
                // Bound addr: IPv4 0.0.0.0:0
                s.write_all(&[VERSION, rep, RESERVED, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();

                if rep == REPLY_SUCCESS {
                    // Echo payload
                    let mut buf = [0u8; 256];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = s.write_all(&buf[..n]).await;
                            }
                        }
                    }
                }

                captured_req
            });

            (addr, handle)
        }
    }

    fn make_adapter(server: &str, port: u16, auth: Option<(String, String)>) -> Socks5Adapter {
        Socks5Adapter::new(server, server, port, auth, false, false)
    }

    fn meta_with_host(host: &str, port: u16) -> Metadata {
        Metadata {
            host: host.to_string(),
            dst_port: port,
            ..Default::default()
        }
    }

    fn meta_with_ipv4(ip: Ipv4Addr, port: u16) -> Metadata {
        Metadata {
            host: String::new(),
            dst_ip: Some(IpAddr::V4(ip)),
            dst_port: port,
            ..Default::default()
        }
    }

    // ─── socks5_no_auth_connects ──────────────────────────────────────────────
    // upstream: adapter/outbound/socks5.go::DialContext

    #[tokio::test]
    async fn socks5_no_auth_connects() {
        let (addr, _) = MockServer::new_no_auth().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);
        let meta = meta_with_host("example.com", 443);
        adapter
            .dial_tcp(&meta)
            .await
            .expect("socks5 no-auth connect");
    }

    // ─── socks5_user_pass_auth_succeeds ───────────────────────────────────────

    #[tokio::test]
    async fn socks5_user_pass_auth_succeeds() {
        let (addr, _) = MockServer::new_user_pass("bob", "hunter2").spawn().await;
        let adapter = make_adapter(
            "127.0.0.1",
            addr.port(),
            Some(("bob".into(), "hunter2".into())),
        );
        let meta = meta_with_host("example.com", 443);
        adapter
            .dial_tcp(&meta)
            .await
            .expect("socks5 user-pass auth");
    }

    // ─── socks5_no_acceptable_method_returns_error ────────────────────────────
    // NOT retry. NOT fallback to no-auth.

    #[tokio::test]
    async fn socks5_no_acceptable_method_returns_error() {
        let (addr, _) = MockServer::new_no_acceptable().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);
        let meta = meta_with_host("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MihomoError::NoAcceptableMethod),
            "0xFF must map to NoAcceptableMethod; got {err:?}"
        );
    }

    // ─── socks5_server_chooses_no_auth_despite_creds_configured ──────────────
    // Server may prefer no-auth even when client offers user/pass.
    // NOT Err(NoAcceptableMethod). NOT sending auth sub-negotiation.
    // upstream: socks5.go::handshake

    #[tokio::test]
    async fn socks5_server_chooses_no_auth_despite_creds_configured() {
        let (addr, _) = MockServer::new_force_no_auth().spawn().await;
        let adapter = make_adapter(
            "127.0.0.1",
            addr.port(),
            Some(("bob".into(), "hunter2".into())),
        );
        let meta = meta_with_host("example.com", 443);
        // Must succeed — server chose no-auth, skip sub-negotiation.
        adapter
            .dial_tcp(&meta)
            .await
            .expect("server chose no-auth despite creds configured");
    }

    // ─── socks5_auth_failure_returns_proxy_auth_failed ────────────────────────

    #[tokio::test]
    async fn socks5_auth_failure_returns_proxy_auth_failed() {
        // Server expects different credentials → auth status != 0x00.
        let (addr, _) = MockServer::new_user_pass("correct", "correct")
            .spawn()
            .await;
        let adapter = make_adapter(
            "127.0.0.1",
            addr.port(),
            Some(("wrong".into(), "wrong".into())),
        );
        let meta = meta_with_host("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MihomoError::ProxyAuthFailed),
            "auth failure must map to ProxyAuthFailed; got {err:?}"
        );
    }

    // ─── socks5_connect_failure_returns_socks5_connect_failed ────────────────
    // rep=0x02 = CONN_NOT_ALLOWED

    #[tokio::test]
    async fn socks5_connect_failure_returns_socks5_connect_failed() {
        let (addr, _) = MockServer::new_no_auth()
            .with_connect_fail(0x02)
            .spawn()
            .await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);
        let meta = meta_with_host("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MihomoError::Socks5ConnectFailed(0x02)),
            "rep=0x02 must map to Socks5ConnectFailed(0x02); got {err:?}"
        );
    }

    // ─── socks5_domain_name_preferred_over_ip ────────────────────────────────
    // metadata has both host and dst_ip; assert wire frame uses atyp 0x03 (domain).
    // NOT atyp 0x01 (IPv4) when domain is available.

    #[tokio::test]
    async fn socks5_domain_name_preferred_over_ip() {
        let (addr, handle) = MockServer::new_no_auth().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);

        // Metadata has BOTH host and dst_ip.
        let meta = Metadata {
            host: "example.com".to_string(),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            dst_port: 80,
            ..Default::default()
        };
        adapter.dial_tcp(&meta).await.expect("dial_tcp");

        let captured = handle.await.unwrap();
        // captured_req layout:
        //   [0] = 0x05 (VERSION from greeting)  [1] = n_methods  [2..] = methods
        //   then CONNECT: [0]=VER [1]=CMD [2]=RSV [3]=ATYP ...
        // The CONNECT header starts at offset 2 + n_methods.
        let n_methods = captured[1] as usize;
        let connect_start = 2 + n_methods;
        let atyp = captured[connect_start + 3];
        assert_eq!(
            atyp, ATYP_DOMAIN,
            "atyp must be 0x03 (domain) when metadata.host is set; got {atyp:#04x}"
        );
    }

    // ─── socks5_ipv4_used_when_no_hostname ────────────────────────────────────
    // metadata has dst_ip only; assert atyp 0x01 frame.

    #[tokio::test]
    async fn socks5_ipv4_used_when_no_hostname() {
        let (addr, handle) = MockServer::new_no_auth().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);
        let meta = meta_with_ipv4(Ipv4Addr::new(10, 0, 0, 1), 8080);
        adapter.dial_tcp(&meta).await.expect("dial_tcp");

        let captured = handle.await.unwrap();
        let n_methods = captured[1] as usize;
        let connect_start = 2 + n_methods;
        let atyp = captured[connect_start + 3];
        assert_eq!(
            atyp, ATYP_IPV4,
            "atyp must be 0x01 (IPv4) when only dst_ip is set; got {atyp:#04x}"
        );
    }

    // ─── socks5_hostname_too_long_returns_error ───────────────────────────────
    // Pre-VLESS hardening (M1.B-4): hostname > 255 bytes → Proxy error.
    // NOT silently truncated. NOT protocol frame sent.
    // ADR-0002 Class A divergence from upstream socks5.go.

    #[tokio::test]
    async fn socks5_hostname_too_long_returns_error() {
        let (addr, _) = MockServer::new_no_auth().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);
        let long_host = "a".repeat(256); // 256 bytes > 255 limit
        let meta = meta_with_host(&long_host, 80);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MihomoError::Proxy(ref msg) if msg.contains("hostname too long")),
            "hostname > 255 bytes must return Proxy error; got {err:?}"
        );
    }

    // ─── socks5_auth_username_too_long_returns_error ──────────────────────────
    // RFC 1929 §2: username length field is 1 byte (max 255).
    // NOT silently truncated.

    #[tokio::test]
    async fn socks5_auth_username_too_long_returns_error() {
        let (addr, _) = MockServer::new_user_pass("ignored", "ignored")
            .spawn()
            .await;
        let long_user = "u".repeat(256);
        let adapter = make_adapter("127.0.0.1", addr.port(), Some((long_user, "pass".into())));
        let meta = meta_with_host("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MihomoError::Proxy(ref msg) if msg.contains("username too long")),
            "username > 255 bytes must return Proxy error; got {err:?}"
        );
    }

    // ─── socks5_auth_password_too_long_returns_error ──────────────────────────
    // RFC 1929 §2: password length field is 1 byte (max 255).
    // NOT silently truncated.

    #[tokio::test]
    async fn socks5_auth_password_too_long_returns_error() {
        let (addr, _) = MockServer::new_user_pass("ignored", "ignored")
            .spawn()
            .await;
        let long_pass = "p".repeat(256);
        let adapter = make_adapter("127.0.0.1", addr.port(), Some(("user".into(), long_pass)));
        let meta = meta_with_host("example.com", 443);
        let err = adapter.dial_tcp(&meta).await.err().expect("expected Err");
        assert!(
            matches!(err, MihomoError::Proxy(ref msg) if msg.contains("password too long")),
            "password > 255 bytes must return Proxy error; got {err:?}"
        );
    }

    // ─── socks5_udp_returns_not_supported ─────────────────────────────────────
    // ADR-0002 Class B: UDP deferred.

    #[tokio::test]
    async fn socks5_udp_returns_not_supported() {
        let adapter = make_adapter("127.0.0.1", 1080, None);
        assert!(!adapter.support_udp(), "support_udp must be false in M1");
        let meta = meta_with_host("example.com", 53);
        let err = adapter
            .dial_udp(&meta)
            .await
            .err()
            .expect("dial_udp should return Err");
        assert!(
            matches!(err, MihomoError::NotSupported(_)),
            "dial_udp must return NotSupported; got {err:?}"
        );
    }

    // ─── socks5_connect_over_relay ────────────────────────────────────────────
    // Pass mock ProxyConn stream; assert handshake runs over it.
    // NOT fresh TCP connect.

    #[tokio::test]
    async fn socks5_connect_over_relay() {
        let (addr, _) = MockServer::new_no_auth().spawn().await;
        let adapter = make_adapter("127.0.0.1", addr.port(), None);

        // Establish the "outer" connection.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let outer: Box<dyn ProxyConn> = Box::new(tcp);

        let meta = meta_with_host("example.com", 443);
        let mut conn = adapter
            .connect_over(outer, &meta)
            .await
            .expect("connect_over");

        // Tunnel is live — echo works.
        conn.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
    }
}
