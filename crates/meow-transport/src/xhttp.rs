use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Result, Stream, Transport, TransportError};

#[derive(Debug, Clone)]
pub struct XhttpConfig {
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub mode: XhttpMode,
    pub max_each_post_bytes: usize,
}

impl Default for XhttpConfig {
    fn default() -> Self {
        Self {
            path: "/".into(),
            host: "localhost".into(),
            headers: Vec::new(),
            mode: XhttpMode::StreamOne,
            max_each_post_bytes: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

pub struct XhttpLayer {
    config: XhttpConfig,
}

impl XhttpLayer {
    pub fn new(config: XhttpConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for XhttpLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        match self.config.mode {
            XhttpMode::StreamOne => self.connect_stream_one(inner).await,
            XhttpMode::StreamUp => self.connect_stream_up(inner).await,
            XhttpMode::PacketUp => Err(TransportError::Config(
                "xhttp: packet-up mode is not yet implemented".into(),
            )),
        }
    }
}

impl XhttpLayer {
    async fn connect_stream_one(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let host = &self.config.host;
        let path = &self.config.path;

        let mut req_builder = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://{host}{path}"))
            .header("Content-Type", "application/grpc");

        for (k, v) in &self.config.headers {
            req_builder = req_builder.header(k.as_str(), v.as_str());
        }

        let request = req_builder
            .body(())
            .map_err(|e| TransportError::Config(format!("xhttp: invalid request config: {e}")))?;

        let (mut h2, conn) = h2::client::handshake(inner)
            .await
            .map_err(|e| TransportError::H2(e.to_string()))?;

        tokio::spawn(async move {
            let _ = conn.await;
        });

        let (response_future, send_stream) = h2
            .send_request(request, false)
            .map_err(|e| TransportError::H2(e.to_string()))?;

        let response = response_future
            .await
            .map_err(|e| TransportError::H2(e.to_string()))?;

        let status = response.status();
        if status != http::StatusCode::OK {
            return Err(TransportError::Config(format!(
                "xhttp: server returned {status}"
            )));
        }

        let recv_stream = response.into_body();

        Ok(Box::new(XhttpStream::new(send_stream, recv_stream)))
    }

    async fn connect_stream_up(&self, _inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        Err(TransportError::Config(
            "xhttp: stream-up mode is not yet implemented".into(),
        ))
    }
}

struct XhttpStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    read_buf: Bytes,
    pending_write: Option<Bytes>,
}

impl XhttpStream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: Bytes::new(),
            pending_write: None,
        }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if !this.read_buf.is_empty() {
                let n = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..n]);
                let _ = this.read_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }

            match this.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    let _ = this.recv.flow_control().release_capacity(bytes.len());
                    this.read_buf = bytes;
                }
            }
        }
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.pending_write.is_none() {
            let data = Bytes::copy_from_slice(buf);
            this.send.reserve_capacity(data.len());
            this.pending_write = Some(data);
        }

        match this.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "xhttp: send stream closed",
                )))
            }
            Poll::Ready(Some(Err(e))) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Ready(Some(Ok(_capacity))) => {
                let data = this.pending_write.take().expect("set above");
                this.send.send_data(data, false).map_err(io::Error::other)?;
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.send
            .send_data(Bytes::new(), true)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

impl Unpin for XhttpStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn make_config() -> XhttpConfig {
        XhttpConfig {
            path: "/".into(),
            host: "localhost".into(),
            headers: vec![],
            mode: XhttpMode::StreamOne,
            max_each_post_bytes: 1_000_000,
        }
    }

    #[test]
    fn xhttp_config_defaults() {
        let cfg = XhttpConfig::default();
        assert_eq!(cfg.path, "/");
        assert_eq!(cfg.host, "localhost");
        assert_eq!(cfg.mode, XhttpMode::StreamOne);
        assert_eq!(cfg.max_each_post_bytes, 1_000_000);
    }

    #[test]
    fn xhttp_config_custom() {
        let cfg = XhttpConfig {
            path: "/xhttp".into(),
            host: "example.com".into(),
            headers: vec![("X-Custom".into(), "value".into())],
            mode: XhttpMode::StreamOne,
            max_each_post_bytes: 500_000,
        };
        assert_eq!(cfg.path, "/xhttp");
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.headers.len(), 1);
    }

    #[test]
    fn xhttp_layer_new() {
        let cfg = make_config();
        let layer = XhttpLayer::new(cfg);
        assert_eq!(layer.config.path, "/");
    }
}