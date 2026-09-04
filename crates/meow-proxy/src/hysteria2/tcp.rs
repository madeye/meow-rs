//! `DuplexStream`: an `AsyncRead`/`AsyncWrite` view of one proxied TCP stream,
//! bridged to the quiche driver over channels. Reads pull decoded payload from a
//! per-stream channel the driver fills (the hysteria2 TCP response is parsed and
//! stripped by the driver); writes are forwarded to the driver as `Cmd::Write`,
//! with backpressure from the bounded command channel.

use super::driver::{Cmd, ReadItem};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio_util::sync::PollSender;

pub struct DuplexStream {
    id: u64,
    read_rx: mpsc::Receiver<ReadItem>,
    read_notify: Arc<Notify>,
    writer: PollSender<Cmd>,
    cmd_tx: mpsc::Sender<Cmd>,
    leftover: Vec<u8>,
    leftover_pos: usize,
    read_done: bool,
    shutdown_sent: bool,
}

impl DuplexStream {
    pub(crate) fn new(
        id: u64,
        read_rx: mpsc::Receiver<ReadItem>,
        read_notify: Arc<Notify>,
        cmd_tx: mpsc::Sender<Cmd>,
    ) -> Self {
        Self {
            id,
            read_rx,
            read_notify,
            writer: PollSender::new(cmd_tx.clone()),
            cmd_tx,
            leftover: Vec::new(),
            leftover_pos: 0,
            read_done: false,
            shutdown_sent: false,
        }
    }

    fn drain_leftover(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.leftover_pos >= self.leftover.len() {
            return false;
        }
        let avail = &self.leftover[self.leftover_pos..];
        let n = avail.len().min(buf.remaining());
        buf.put_slice(&avail[..n]);
        self.leftover_pos += n;
        true
    }
}

impl AsyncRead for DuplexStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.drain_leftover(buf) {
            return Poll::Ready(Ok(()));
        }
        if this.read_done {
            return Poll::Ready(Ok(()));
        }
        match this.read_rx.poll_recv(cx) {
            Poll::Ready(Some(ReadItem::Data(v))) => {
                this.leftover = v;
                this.leftover_pos = 0;
                // Free the driver to read more into this stream's channel.
                this.read_notify.notify_one();
                this.drain_leftover(buf);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(ReadItem::Eof)) | Poll::Ready(None) => {
                this.read_done = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(ReadItem::Err(kind))) => {
                this.read_done = true;
                Poll::Ready(Err(io::Error::new(kind, "hysteria2 stream error")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for DuplexStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.writer.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                match this.writer.send_item(Cmd::Write {
                    id: this.id,
                    data: buf.to_vec(),
                }) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(_) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "hysteria2 connection closed",
                    ))),
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "hysteria2 connection closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        match this.writer.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let _ = this.writer.send_item(Cmd::Shutdown { id: this.id });
                this.shutdown_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                this.shutdown_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for DuplexStream {
    fn drop(&mut self) {
        if !self.shutdown_sent {
            // Half-close the write side so the driver fins the stream and
            // reclaims its state; best-effort.
            let _ = self.cmd_tx.try_send(Cmd::Shutdown { id: self.id });
        }
    }
}

impl Unpin for DuplexStream {}
