use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use std::net::SocketAddr;

pub struct RejectAdapter {
    drop: bool,
    health: ProxyHealth,
}

impl RejectAdapter {
    pub fn new(drop: bool) -> Self {
        Self {
            drop,
            health: ProxyHealth::new(),
        }
    }
}

struct RejectConn;

impl tokio::io::AsyncRead for RejectConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(())) // EOF
    }
}

impl tokio::io::AsyncWrite for RejectConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len())) // Discard
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Unpin for RejectConn {}
impl ProxyConn for RejectConn {}

struct RejectPacketConn;

#[async_trait]
impl ProxyPacketConn for RejectPacketConn {
    async fn read_packet(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Err(MeowError::Proxy("rejected".into()))
    }

    async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> Result<usize> {
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Err(MeowError::Proxy("rejected".into()))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for RejectAdapter {
    fn name(&self) -> &str {
        if self.drop {
            "REJECT-DROP"
        } else {
            "REJECT"
        }
    }

    fn adapter_type(&self) -> AdapterType {
        if self.drop {
            AdapterType::RejectDrop
        } else {
            AdapterType::Reject
        }
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        if self.drop {
            // Sleep for a long time to simulate DROP behavior
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
        Ok(Box::new(RejectConn))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Ok(Box::new(RejectPacketConn))
    }

    /// Refuse the relay chain at a Reject hop.
    ///
    /// upstream: adapter/outbound/reject.go — no DialContextWithDialer.
    /// Inserting REJECT into a relay chain is a misconfiguration; we surface
    /// a clear error rather than silently dropping bytes.
    async fn connect_over(
        &self,
        _stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Err(MeowError::Proxy("rejected".into()))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn naming_reflects_drop_mode() {
        assert_eq!(RejectAdapter::new(false).name(), "REJECT");
        assert_eq!(RejectAdapter::new(true).name(), "REJECT-DROP");
        assert_eq!(
            RejectAdapter::new(false).adapter_type(),
            AdapterType::Reject
        );
        assert_eq!(
            RejectAdapter::new(true).adapter_type(),
            AdapterType::RejectDrop
        );
    }

    #[test]
    fn empty_addr_and_supports_udp() {
        let a = RejectAdapter::new(false);
        assert_eq!(a.addr(), "");
        assert!(
            a.support_udp(),
            "reject claims UDP so rules don't bypass it"
        );
    }

    #[tokio::test]
    async fn dial_tcp_reject_returns_eof_stream_immediately() {
        let a = RejectAdapter::new(false);
        let mut conn = a
            .dial_tcp(&Metadata::default())
            .await
            .expect("REJECT must produce a connection (not error)");
        // Read returns 0 (EOF) without blocking.
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "REJECT stream is EOF on read");
    }

    #[tokio::test]
    async fn dial_tcp_reject_silently_discards_writes() {
        let a = RejectAdapter::new(false);
        let mut conn = a.dial_tcp(&Metadata::default()).await.unwrap();
        // Writes report success but go nowhere.
        let n = conn.write(b"discarded").await.unwrap();
        assert_eq!(n, b"discarded".len());
        conn.flush().await.unwrap();
        conn.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn dial_tcp_reject_drop_hangs_then_yields_eof() {
        // RejectDrop simulates a black-hole by sleeping ~60 s before yielding
        // the same EOF stream. Under paused tokio time we can advance past
        // that without wall-clock waiting.
        let a = std::sync::Arc::new(RejectAdapter::new(true));
        let a2 = std::sync::Arc::clone(&a);
        let task = tokio::spawn(async move { a2.dial_tcp(&Metadata::default()).await });
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "dial must not return before sleep");
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let mut conn = task.await.unwrap().expect("eventual EOF stream");
        let mut buf = [0u8; 4];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn dial_udp_returns_writeonly_packet_conn() {
        let a = RejectAdapter::new(false);
        let conn = a.dial_udp(&Metadata::default()).await.expect("packet conn");
        let dst: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let n = conn.write_packet(b"x", &dst).await.unwrap();
        assert_eq!(n, 1);
        let mut buf = [0u8; 16];
        let err = conn.read_packet(&mut buf).await.err();
        assert!(err.is_some(), "REJECT UDP read must error, not block");
        assert!(conn.local_addr().is_err());
        assert!(conn.close().is_ok());
    }

    #[tokio::test]
    async fn connect_over_refuses_relay_insertion() {
        let a = RejectAdapter::new(false);
        let upstream = a.dial_tcp(&Metadata::default()).await.unwrap();
        let err = a
            .connect_over(upstream, &Metadata::default())
            .await
            .err()
            .expect("relay through REJECT must be a hard error");
        match err {
            MeowError::Proxy(msg) => assert!(
                msg.to_lowercase().contains("reject"),
                "error message should name 'reject': {msg}"
            ),
            other => panic!("expected MeowError::Proxy, got {other:?}"),
        }
    }
}
