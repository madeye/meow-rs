use super::config::Config;
use super::socket::Hy2UdpSocket;
use super::tcp::{self, DuplexStream};
use super::tls;
use super::udp::{self, UdpRouter, UdpSession};
use super::{Error, Result};
use bytes::Buf;
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::Runtime;
use quinn::{Connection, Endpoint};
use std::future::pending;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicU16;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ReconnectableClient {
    cfg: Arc<Config>,
    conn: Mutex<Option<Arc<ClientConnection>>>,
}

impl ReconnectableClient {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Arc::new(cfg),
            conn: Mutex::new(None),
        }
    }

    pub async fn tcp_connect(&self, target: &str) -> Result<DuplexStream> {
        let client = self.connection().await?;
        let (mut send, mut recv) = timeout(CONNECT_TIMEOUT, client.connection.open_bi())
            .await
            .map_err(|_| Error::Quic(format!("open stream timeout after {CONNECT_TIMEOUT:?}")))?
            .map_err(|e| Error::Quic(e.to_string()))?;

        timeout(
            CONNECT_TIMEOUT,
            tcp::write_initial_request(&mut send, target),
        )
        .await
        .map_err(|_| Error::Quic(format!("TCP request timeout after {CONNECT_TIMEOUT:?}")))??;

        let response_read = if self.cfg.fast_open {
            false
        } else {
            timeout(CONNECT_TIMEOUT, tcp::read_initial_response(&mut recv))
                .await
                .map_err(|_| {
                    Error::Quic(format!("TCP response timeout after {CONNECT_TIMEOUT:?}"))
                })??;
            true
        };

        Ok(DuplexStream::new(send, recv, response_read))
    }

    pub async fn udp(&self) -> Result<UdpSession> {
        let client = self.connection().await?;
        UdpSession::new(client)
    }

    async fn connection(&self) -> Result<Arc<ClientConnection>> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            if conn.is_active() {
                return Ok(Arc::clone(conn));
            }
        }

        let conn = Arc::new(connect_new(Arc::clone(&self.cfg)).await?);
        *guard = Some(Arc::clone(&conn));
        Ok(conn)
    }
}

pub(crate) struct ClientConnection {
    pub(crate) connection: Connection,
    _endpoint: Endpoint,
    h3_driver: tokio::task::JoinHandle<()>,
    udp_driver: Option<tokio::task::JoinHandle<()>>,
    pub(crate) udp_enabled: bool,
    pub(crate) udp_router: Arc<UdpRouter>,
    pub(crate) next_session_id: std::sync::atomic::AtomicU32,
    pub(crate) next_packet_id: AtomicU16,
}

impl ClientConnection {
    fn is_active(&self) -> bool {
        self.connection.close_reason().is_none()
    }
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        self.h3_driver.abort();
        if let Some(driver) = &self.udp_driver {
            driver.abort();
        }
    }
}

async fn connect_new(cfg: Arc<Config>) -> Result<ClientConnection> {
    let server = ServerTarget::parse(&cfg.server_addr)?;
    let addrs = meow_common::resolve_host_all(&server.host, server.port)
        .await
        .map_err(|e| Error::Resolve(format!("{}:{}: {e}", server.host, server.port)))?;
    let server_name = if cfg.server_name.trim().is_empty() {
        server.host.clone()
    } else {
        cfg.server_name.trim().to_string()
    };

    let mut last_error = None;
    for addr in addrs {
        match connect_addr(Arc::clone(&cfg), addr, &server_name).await {
            Ok(conn) => return Ok(conn),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or_else(|| Error::Resolve("no address resolved".into())))
}

async fn connect_addr(
    cfg: Arc<Config>,
    server_addr: SocketAddr,
    server_name: &str,
) -> Result<ClientConnection> {
    let needs_custom_socket = !cfg.obfs_password.is_empty() || !cfg.hop_ports.trim().is_empty();
    let mut endpoint = if needs_custom_socket {
        let socket = Hy2UdpSocket::bind(
            server_addr,
            &cfg.hop_ports,
            cfg.hop_interval_min_secs,
            cfg.hop_interval_max_secs,
            &cfg.obfs_password,
        )
        .await?;
        let mut endpoint_cfg = quinn::EndpointConfig::default();
        endpoint_cfg.grease_quic_bit(false);
        Endpoint::new_with_abstract_socket(
            endpoint_cfg,
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?
    } else {
        let bind_addr = if server_addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let std_sock = std::net::UdpSocket::bind(bind_addr).map_err(Error::Io)?;
        let runtime = Arc::new(quinn::TokioRuntime);
        let socket = runtime.wrap_udp_socket(std_sock)?;
        let mut endpoint_cfg = quinn::EndpointConfig::default();
        endpoint_cfg.grease_quic_bit(false);
        Endpoint::new_with_abstract_socket(endpoint_cfg, None, socket, runtime)?
    };
    let client_cfg = tls::build_client_config(&cfg)?;
    endpoint.set_default_client_config(client_cfg);
    let connecting = endpoint
        .connect(server_addr, server_name)
        .map_err(|e| Error::Quic(format!("connect start: {e}")))?;
    let connection = timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| Error::Quic(format!("connect timeout after {CONNECT_TIMEOUT:?}")))?
        .map_err(|e| Error::Quic(format!("connect: {e}")))?;

    let (h3_conn, mut send_request) = timeout(
        CONNECT_TIMEOUT,
        h3::client::new(h3_quinn::Connection::new(connection.clone())),
    )
    .await
    .map_err(|_| Error::Http3(format!("client setup timeout after {CONNECT_TIMEOUT:?}")))?
    .map_err(|e| Error::Http3(e.to_string()))?;

    let udp_enabled = match timeout(CONNECT_TIMEOUT, authenticate(&cfg, &mut send_request)).await {
        Ok(Ok(udp_enabled)) => udp_enabled,
        Ok(Err(e)) => {
            connection.close(0u32.into(), b"auth failed");
            return Err(e);
        }
        Err(_) => {
            connection.close(0u32.into(), b"auth timeout");
            return Err(Error::Http3(format!(
                "authentication timeout after {CONNECT_TIMEOUT:?}"
            )));
        }
    };

    // Authentication owns `h3_conn` locally, so cancellation before this point
    // drops every connection handle instead of detaching a task that keeps the
    // unauthenticated QUIC session alive.
    let h3_driver = tokio::spawn(async move {
        // Keep the HTTP/3 session alive for the lifetime of the QUIC connection.
        // Driving `poll_close` here would tear down the connection and break
        // proxied TCP/UDP streams opened via `open_bi`.
        let _ = h3_conn;
        pending::<()>().await;
    });

    let udp_router = Arc::new(UdpRouter::new());
    let udp_driver =
        udp_enabled.then(|| udp::spawn_receiver(connection.clone(), Arc::clone(&udp_router)));

    Ok(ClientConnection {
        connection,
        _endpoint: endpoint,
        h3_driver,
        udp_driver,
        udp_enabled,
        udp_router,
        next_session_id: std::sync::atomic::AtomicU32::new(0),
        next_packet_id: AtomicU16::new(0),
    })
}

async fn authenticate(
    cfg: &Config,
    send_request: &mut SendRequest<OpenStreams, bytes::Bytes>,
) -> Result<bool> {
    let padding = super::proto::auth_request_padding();
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header(http::header::HOST, "hysteria")
        .header("Hysteria-Auth", cfg.auth.as_str())
        .header("Hysteria-CC-RX", cfg.rx_bps.to_string())
        .header("Hysteria-Padding", padding)
        .body(())
        .map_err(|e| Error::Http3(format!("auth request build: {e}")))?;

    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| Error::Http3(format!("auth send: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| Error::Http3(format!("auth finish: {e}")))?;

    let response = stream
        .recv_response()
        .await
        .map_err(|e| Error::Http3(format!("auth response: {e}")))?;
    if response.status().as_u16() != 233 {
        return Err(Error::Auth(format!(
            "authentication failed, status code: {}",
            response.status()
        )));
    }

    let udp_enabled = response
        .headers()
        .get("Hysteria-UDP")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("true") || value == "1" || value.eq_ignore_ascii_case("yes")
        });

    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| Error::Http3(format!("auth body: {e}")))?
    {
        chunk.advance(chunk.remaining());
    }

    Ok(udp_enabled)
}

struct ServerTarget {
    host: String,
    port: u16,
}

impl ServerTarget {
    fn parse(addr: &str) -> Result<Self> {
        if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            return Ok(Self {
                host: socket_addr.ip().to_string(),
                port: socket_addr.port(),
            });
        }

        let (host, port) = addr
            .rsplit_once(':')
            .ok_or_else(|| Error::config(format!("server address has no port: {addr}")))?;
        if host.is_empty() || host.contains(':') {
            return Err(Error::config(format!(
                "invalid server address, bracket IPv6 literals: {addr}"
            )));
        }
        let port = port
            .parse::<u16>()
            .map_err(|e| Error::config(format!("invalid server port in '{addr}': {e}")))?;
        if port == 0 {
            return Err(Error::config("server port must be non-zero"));
        }

        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::sync::oneshot;

    fn h3_server_config() -> quinn::ServerConfig {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = CertificateDer::from(certified_key.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified_key.key_pair.serialize_der(),
        ));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        quinn::ServerConfig::with_crypto(Arc::new(crypto))
    }

    #[test]
    fn parses_domain_server_target() {
        let target = ServerTarget::parse("example.com:443").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn parses_bracketed_ipv6_server_target() {
        let target = ServerTarget::parse("[::1]:443").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 443);
    }

    #[tokio::test]
    async fn cancelling_authentication_closes_the_quic_connection() {
        let endpoint =
            Endpoint::server(h3_server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let (auth_seen_tx, auth_seen_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let incoming = endpoint.accept().await.expect("client must connect");
            let connection = incoming.await.expect("QUIC handshake must succeed");
            let mut h3 = h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(
                connection.clone(),
            ))
            .await
            .expect("HTTP/3 handshake must succeed");
            let resolver = h3
                .accept()
                .await
                .expect("auth request must be accepted")
                .expect("auth request stream must exist");
            let (request, request_stream) = resolver
                .resolve_request()
                .await
                .expect("auth request must be valid");
            assert_eq!(request.uri().path(), "/auth");
            auth_seen_tx.send(()).unwrap();

            let reason = connection.closed().await;
            drop((h3, request_stream));
            reason
        });

        let cfg = Arc::new(Config {
            server_addr: server_addr.to_string(),
            server_name: "localhost".into(),
            auth: "test-password".into(),
            insecure: true,
            rx_bps: 1_000_000,
            ..Default::default()
        });
        let dial = tokio::spawn(connect_addr(cfg, server_addr, "localhost"));
        timeout(Duration::from_secs(2), auth_seen_rx)
            .await
            .expect("authentication request timed out")
            .expect("server stopped before receiving authentication");

        dial.abort();
        let Err(join_error) = dial.await else {
            panic!("dial task completed before it could be cancelled")
        };
        assert!(join_error.is_cancelled());
        timeout(Duration::from_secs(2), server)
            .await
            .expect("cancelled authentication leaked the QUIC connection")
            .expect("server task failed");
    }
}
