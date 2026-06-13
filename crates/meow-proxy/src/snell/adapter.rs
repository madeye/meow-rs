//! Snell outbound adapter — implements `ProxyAdapter` for `type: snell`.
//!
//! Wires together the v3/v4 AEAD codecs, the optional simple-obfs (http/tls)
//! layer, the snell request/response framing, and the optional v4/v5 reuse
//! pool (`CommandConnectV2`).

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_transport::Stream as TransportStream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::simple_obfs::{HttpObfs, TlsObfs};

use super::pool::{drain_for_reuse, Pool, PoolStream};
use super::protocol::{write_header, write_udp_header, Snell};
use super::udp::SnellPacketConn;

/// What Snell version label the adapter uses. v5 servers are
/// backward-compatible with the v4 TCP client wire, matching mihomo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnellVersion {
    V3,
    V4,
    V5,
}

impl SnellVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            SnellVersion::V3 => "v3",
            SnellVersion::V4 => "v4",
            SnellVersion::V5 => "v5",
        }
    }

    fn supports_reuse(self) -> bool {
        matches!(self, SnellVersion::V4 | SnellVersion::V5)
    }
}

/// Optional simple-obfs wrapping the underlying TCP. Mirrors the SS adapter's
/// `BuiltinObfs` enum, but kept private to the snell module so the two
/// adapters stay independent at the type level.
#[derive(Debug, Clone)]
pub enum SnellObfs {
    None,
    Http { host: String },
    Tls { server: String },
}

pub struct SnellAdapter {
    name: String,
    server: String,
    port: u16,
    addr_str: String,
    psk: Arc<[u8]>,
    obfs: SnellObfs,
    support_udp: bool,
    pool: Option<Arc<Pool>>,
    version: SnellVersion,
    health: ProxyHealth,
}

impl SnellAdapter {
    #[allow(
        clippy::too_many_arguments,
        reason = "snell config surface is wide; struct-of-args adds no clarity here"
    )]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        psk: &str,
        obfs: SnellObfs,
        version: SnellVersion,
        udp: bool,
        reuse: bool,
    ) -> Result<Self> {
        if psk.is_empty() {
            return Err(MeowError::Config(format!(
                "snell[{name}]: psk must not be empty"
            )));
        }
        if port == 0 {
            return Err(MeowError::Config(format!(
                "snell[{name}]: port must be non-zero"
            )));
        }
        if server.is_empty() {
            return Err(MeowError::Config(format!(
                "snell[{name}]: server must not be empty"
            )));
        }
        let psk_bytes: Arc<[u8]> = Arc::from(psk.as_bytes());
        let effective_reuse = reuse && version.supports_reuse();
        debug!(
            "snell '{}' configured: version={} reuse={} udp={} obfs={}",
            name,
            version.as_str(),
            effective_reuse,
            udp,
            match &obfs {
                SnellObfs::None => "off",
                SnellObfs::Http { .. } => "http",
                SnellObfs::Tls { .. } => "tls",
            }
        );
        Ok(Self {
            name: name.to_string(),
            server: server.to_string(),
            port,
            addr_str: format!("{server}:{port}"),
            psk: psk_bytes,
            obfs,
            support_udp: udp,
            pool: if effective_reuse {
                Some(Arc::new(Pool::new()))
            } else {
                None
            },
            version,
            health: ProxyHealth::new(),
        })
    }

    /// Open a fresh underlying byte stream (TCP, optionally wrapped in obfs)
    /// and Snell-wrap it. No CONNECT header is sent yet.
    async fn dial_fresh(&self) -> Result<PoolStream> {
        let tcp = meow_common::connect_tcp_host(&self.server, self.port)
            .await
            .map_err(MeowError::Io)?;
        let _ = tcp.set_nodelay(true);
        let inner: Box<dyn TransportStream> = match &self.obfs {
            SnellObfs::None => Box::new(tcp),
            SnellObfs::Http { host } => Box::new(HttpObfs::new(tcp, host.clone(), self.port)),
            SnellObfs::Tls { server } => Box::new(TlsObfs::new(tcp, server.clone())),
        };
        Ok(match self.version {
            SnellVersion::V3 => Snell::new_v3(inner, Arc::clone(&self.psk)),
            SnellVersion::V4 | SnellVersion::V5 => Snell::new(inner, Arc::clone(&self.psk)),
        })
    }

    /// Number of idle connections currently parked in the reuse pool.
    /// Returns 0 when reuse is disabled. Exposed so integration tests can
    /// synchronize with the background drain-and-return task that runs after
    /// a pooled connection is dropped, instead of sleeping.
    pub fn idle_pool_size(&self) -> usize {
        self.pool.as_ref().map_or(0, |pool| pool.idle_count())
    }

    fn extract_dest(metadata: &Metadata) -> Result<(String, u16)> {
        let port = metadata.dst_port;
        if !metadata.host.is_empty() {
            return Ok((metadata.host.to_string(), port));
        }
        if let Some(ip) = metadata.dst_ip {
            return Ok((ip.to_string(), port));
        }
        Err(MeowError::Proxy(
            "snell: metadata has neither host nor dst_ip".into(),
        ))
    }
}

#[async_trait]
impl ProxyAdapter for SnellAdapter {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Snell
    }
    fn addr(&self) -> &str {
        &self.addr_str
    }
    fn support_udp(&self) -> bool {
        self.support_udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let (host, port) = Self::extract_dest(metadata)?;
        debug!(
            "snell connecting to {}:{} via {} (reuse={})",
            host,
            port,
            self.addr_str,
            self.pool.is_some()
        );

        // Pool-first path — opensnell client.go DialTCP semantics.
        if let Some(pool) = &self.pool {
            // Two tries: a pooled conn may have been silently closed by the
            // server between sessions, in which case the header write fails
            // and we try the next/dial fresh.
            for attempt in 0..2u32 {
                let Some((mut snell, prev_uses)) = pool.take_idle() else {
                    break;
                };
                snell.reset_reply_state();
                if let Err(e) = write_header(&mut snell, &host, port, true).await {
                    debug!("snell pool conn write failed (attempt {attempt}): {e}");
                    continue;
                }
                return Ok(Box::new(PooledConn::new(
                    snell,
                    Some(Arc::clone(pool)),
                    prev_uses + 1,
                )));
            }
        }

        let mut snell = self.dial_fresh().await?;
        let reuse = self.pool.is_some();
        write_header(&mut snell, &host, port, reuse)
            .await
            .map_err(MeowError::Io)?;
        Ok(Box::new(PooledConn::new(
            snell,
            self.pool.as_ref().map(Arc::clone),
            1,
        )))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.support_udp {
            return Err(MeowError::NotSupported(
                "snell UDP is disabled for this proxy (set `udp: true`)".into(),
            ));
        }
        let mut snell = self.dial_fresh().await?;
        write_udp_header(&mut snell).await.map_err(MeowError::Io)?;
        if self.version.supports_reuse() {
            snell.read_reply().await.map_err(MeowError::Io)?;
        }
        Ok(Box::new(SnellPacketConn::new(snell)))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ─── PooledConn ──────────────────────────────────────────────────────────────

/// `ProxyConn` that returns its underlying snell stream to a pool on drop
/// (when the pool is configured). Behaves as a transparent passthrough
/// otherwise — the v4 zero-chunk → EOF mapping happens inside `Snell` itself.
struct PooledConn {
    inner: Option<PoolStream>,
    pool: Option<Arc<Pool>>,
    uses: u32,
}

impl PooledConn {
    fn new(snell: PoolStream, pool: Option<Arc<Pool>>, uses: u32) -> Self {
        Self {
            inner: Some(snell),
            pool,
            uses,
        }
    }
}

impl AsyncRead for PooledConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let inner = self
            .inner
            .as_mut()
            .expect("PooledConn::poll_read after take");
        Pin::new(inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PooledConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let inner = self
            .inner
            .as_mut()
            .expect("PooledConn::poll_write after take");
        Pin::new(inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let inner = self
            .inner
            .as_mut()
            .expect("PooledConn::poll_flush after take");
        Pin::new(inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let inner = self
            .inner
            .as_mut()
            .expect("PooledConn::poll_shutdown after take");
        // Send the half-close zero chunk via the v4 codec (empty write =>
        // zero-chunk frame). After the frame drains we report Ready, and
        // the pool-return logic runs in `Drop`.
        match Pin::new(inner).poll_write(cx, &[]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
        }
    }
}

impl Unpin for PooledConn {}
impl ProxyConn for PooledConn {}

impl Drop for PooledConn {
    fn drop(&mut self) {
        let (Some(snell), Some(pool)) = (self.inner.take(), self.pool.take()) else {
            return;
        };
        let uses = self.uses;
        // Spawn a background task to drain the server's tail bytes + the
        // zero-chunk half-close, then push the conn back. Failures simply
        // drop the conn — its underlying TCP is closed by `Snell`'s drop.
        //
        // Requires an active tokio runtime; the meow-rs binary always runs
        // inside #[tokio::main], so this is safe in production. In unit
        // tests that drop a PooledConn outside any runtime, `tokio::spawn`
        // panics — those tests should use a #[tokio::test] runtime.
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        tokio::spawn(async move {
            let mut snell = snell;
            if drain_for_reuse(&mut snell).await {
                snell.reset_reply_state();
                pool.put(snell, uses);
            }
        });
    }
}
