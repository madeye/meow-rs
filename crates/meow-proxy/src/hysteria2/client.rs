//! `ReconnectableClient`: the public entry point. Owns the current connection
//! handle (a spawned quiche driver) and lazily (re)connects on demand, then
//! opens proxied TCP streams and UDP sessions through it.

use super::config::Config;
use super::driver::{self, Cmd, ConnHandle};
use super::proto;
use super::tcp::DuplexStream;
use super::udp::UdpSession;
use super::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{timeout, Duration};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ReconnectableClient {
    cfg: Arc<Config>,
    conn: Mutex<Option<Arc<ConnHandle>>>,
}

impl ReconnectableClient {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Arc::new(cfg),
            conn: Mutex::new(None),
        }
    }

    pub async fn tcp_connect(&self, target: &str) -> Result<DuplexStream> {
        let handle = self.handle().await?;
        // Always send the TCP-request frame at open and parse the response off
        // the stream in the driver. Writes are never gated on the response, so
        // this covers both fast-open and non-fast-open semantics.
        let first_frame = proto::encode_tcp_request(target, &[])?;
        let (reply_tx, reply_rx) = oneshot::channel();
        handle
            .cmd_tx
            .send(Cmd::OpenTcp {
                first_frame,
                expect_response: true,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::Closed)?;
        reply_rx.await.map_err(|_| Error::Closed)?
    }

    pub async fn udp(&self) -> Result<UdpSession> {
        let handle = self.handle().await?;
        if !handle.udp_enabled {
            return Err(Error::protocol("UDP disabled by hysteria2 server"));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        handle
            .cmd_tx
            .send(Cmd::RegisterUdp { reply: reply_tx })
            .await
            .map_err(|_| Error::Closed)?;
        let (session_id, rx) = reply_rx.await.map_err(|_| Error::Closed)?;
        Ok(UdpSession::new(session_id, handle.cmd_tx.clone(), rx))
    }

    async fn handle(&self) -> Result<Arc<ConnHandle>> {
        let mut guard = self.conn.lock().await;
        if let Some(handle) = guard.as_ref() {
            if handle.is_active() {
                return Ok(Arc::clone(handle));
            }
        }
        let handle = Arc::new(connect_new(Arc::clone(&self.cfg)).await?);
        *guard = Some(Arc::clone(&handle));
        Ok(handle)
    }
}

async fn connect_new(cfg: Arc<Config>) -> Result<ConnHandle> {
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
        match timeout(CONNECT_TIMEOUT, connect_addr(&cfg, addr, &server_name)).await {
            Ok(Ok(handle)) => return Ok(handle),
            Ok(Err(e)) => last_error = Some(e),
            Err(_) => {
                last_error = Some(Error::Quic(format!(
                    "connect timeout after {CONNECT_TIMEOUT:?}"
                )));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| Error::Resolve("no address resolved".into())))
}

async fn connect_addr(
    cfg: &Config,
    server_addr: SocketAddr,
    server_name: &str,
) -> Result<ConnHandle> {
    let bind_addr = if server_addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind_addr).await.map_err(Error::Io)?;
    let local = socket.local_addr().map_err(Error::Io)?;

    let mut config = super::tls::build_quiche_config(cfg)?;
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    for b in &mut scid {
        *b = rand::random();
    }
    let scid = quiche::ConnectionId::from_ref(&scid);
    let conn = quiche::connect(Some(server_name), &scid, local, server_addr, &mut config)
        .map_err(|e| Error::Quic(format!("connect start: {e}")))?;

    driver::spawn(cfg, socket, local, server_addr, conn).await
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
}
