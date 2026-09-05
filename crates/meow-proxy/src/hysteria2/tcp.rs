//! `DuplexStream`: an `AsyncRead`/`AsyncWrite` view of one proxied TCP stream,
//! bridged to the quiche driver over channels. Reads pull decoded payload from a
//! per-stream channel the driver fills (the hysteria2 TCP response is parsed and
//! stripped by the driver); writes are forwarded to the driver as `Cmd::Write`,
//! with a byte budget released only when QUIC accepts the queued data.

use super::driver::{Cmd, ReadItem};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, Notify, Semaphore};
use tokio_util::sync::{PollSemaphore, PollSender};

pub(crate) const WRITE_BUFFER_BYTES: u32 = 64 * 1024;
const WRITE_CHUNK_BYTES: usize = 16 * 1024;

pub struct DuplexStream {
    id: u64,
    read_rx: mpsc::Receiver<ReadItem>,
    read_notify: Arc<Notify>,
    writer: PollSender<Cmd>,
    write_capacity: PollSemaphore,
    connected: Option<oneshot::Receiver<super::Result<()>>>,
    leftover: Vec<u8>,
    leftover_pos: usize,
    read_done: bool,
    shutdown_sent: bool,
    shutdown: Arc<AtomicBool>,
}

impl DuplexStream {
    pub(crate) fn new(
        id: u64,
        read_rx: mpsc::Receiver<ReadItem>,
        read_notify: Arc<Notify>,
        cmd_tx: mpsc::Sender<Cmd>,
        capacity: Arc<Semaphore>,
        connected: oneshot::Receiver<super::Result<()>>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            id,
            read_rx,
            read_notify,
            writer: PollSender::new(cmd_tx),
            write_capacity: PollSemaphore::new(capacity),
            connected: Some(connected),
            leftover: Vec::new(),
            leftover_pos: 0,
            read_done: false,
            shutdown_sent: false,
            shutdown,
        }
    }

    pub(crate) async fn wait_connected(&mut self) -> super::Result<()> {
        if let Some(connected) = self.connected.take() {
            connected.await.map_err(|_| super::Error::Closed)??;
        }
        Ok(())
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
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
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
            Poll::Ready(Some(ReadItem::Eof)) => {
                this.read_done = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                this.read_done = true;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "hysteria2 driver closed",
                )))
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
        if this.shutdown_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(WRITE_CHUNK_BYTES);
        let permit = match this.write_capacity.poll_acquire_many(cx, n as u32) {
            Poll::Ready(Some(permit)) => permit,
            Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => return Poll::Pending,
        };
        match this.writer.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                match this.writer.send_item(Cmd::Write {
                    id: this.id,
                    data: buf[..n].to_vec(),
                    permit,
                }) {
                    Ok(()) => Poll::Ready(Ok(n)),
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

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // All permits being available means every prior write has entered
        // QUIC's bounded send buffer. Acquiring them also registers our waker.
        match self
            .get_mut()
            .write_capacity
            .poll_acquire_many(cx, WRITE_BUFFER_BYTES)
        {
            Poll::Ready(Some(_permit)) => Poll::Ready(Ok(())),
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self;
        if this.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(this.as_mut().poll_flush(cx))?;
        let this = this.get_mut();
        this.shutdown.store(true, Ordering::Release);
        this.shutdown_sent = true;
        this.read_notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for DuplexStream {
    fn drop(&mut self) {
        // Cancellation must work even if the command channel is full.
        self.read_rx.close();
        self.read_notify.notify_one();
    }
}

impl Unpin for DuplexStream {}
