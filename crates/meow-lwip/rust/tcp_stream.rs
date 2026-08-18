use std::{cmp::min, io, net::SocketAddr, pin::Pin};

use bytes::BytesMut;
use futures::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::PollSender;

use super::core::{Cmd, StreamCmd, StreamId, WRITE_CHUNK};

/// Pure-channel TCP stream handle. Never touches lwIP state: reads drain a
/// channel filled by `tcp_recv_cb` on the core task, writes travel a bounded
/// ordered channel the core drains into `tcp_write`, and dropping the handle
/// closes that channel — which *is* the close signal, so teardown can't be
/// lost. Fully `Send`; safe to poll from any runtime.
pub struct TcpStream {
    id: StreamId,
    src_addr: SocketAddr,
    dest_addr: SocketAddr,
    read_rx: UnboundedReceiver<Vec<u8>>,
    /// Data pulled off `read_rx` that didn't fit the caller's buffer.
    leftover: BytesMut,
    /// EOF marker observed; subsequent reads return 0 bytes.
    eof: bool,
    write_tx: PollSender<StreamCmd>,
    cmd_tx: UnboundedSender<Cmd>,
}

impl TcpStream {
    pub(crate) fn new(
        id: StreamId,
        src_addr: SocketAddr,
        dest_addr: SocketAddr,
        read_rx: UnboundedReceiver<Vec<u8>>,
        write_tx: Sender<StreamCmd>,
        cmd_tx: UnboundedSender<Cmd>,
    ) -> Self {
        TcpStream {
            id,
            src_addr,
            dest_addr,
            read_rx,
            leftover: BytesMut::new(),
            eof: false,
            write_tx: PollSender::new(write_tx),
            cmd_tx,
        }
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dest_addr
    }
}

fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if !me.leftover.is_empty() {
            // The window credit (Recved) for these bytes was sent when the
            // chunk was pulled off the channel, matching the old behavior.
            let to_read = min(buf.remaining(), me.leftover.len());
            let piece = me.leftover.split_to(to_read);
            buf.put_slice(&piece[..to_read]);
            return Poll::Ready(Ok(()));
        }
        if me.eof {
            return Poll::Ready(Ok(()));
        }
        let mut has_read_data = false;
        loop {
            match me.read_rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    if data.is_empty() {
                        // EOF marker from tcp_recv_cb.
                        me.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    // Open the receive window for what we consumed. Ignoring
                    // a send error is fine: the core being gone means the
                    // pcb is gone too.
                    let _ = me.cmd_tx.send(Cmd::Recved(me.id, data.len()));
                    let to_read = min(buf.remaining(), data.len());
                    buf.put_slice(&data[..to_read]);
                    has_read_data = true;
                    if to_read < data.len() {
                        me.leftover.extend_from_slice(&data[to_read..]);
                        return Poll::Ready(Ok(()));
                    }
                }
                // Channel closed without EOF: tcp_err_cb dropped the sender.
                Poll::Ready(None) => return Poll::Ready(Err(broken_pipe())),
                Poll::Pending => {
                    return if has_read_data {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match me.write_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            // Receiver dropped: pcb errored or the core tore down.
            Poll::Ready(Err(_)) => return Poll::Ready(Err(broken_pipe())),
            Poll::Pending => return Poll::Pending,
        }
        let n = min(buf.len(), WRITE_CHUNK);
        if me
            .write_tx
            .send_item(StreamCmd::Write(buf[..n].to_vec()))
            .is_err()
        {
            return Poll::Ready(Err(broken_pipe()));
        }
        let _ = me.cmd_tx.send(Cmd::Kick(me.id));
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        // Data durability is guaranteed by ordering: queued writes are handed
        // to lwIP before any Shutdown/close is processed on the same channel,
        // and lwIP flushes its send buffer before FIN. tcp_output runs after
        // every core drain, so there is nothing to actively flush here.
        if self.write_tx.is_closed() {
            return Poll::Ready(Err(broken_pipe()));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let me = &mut *self;
        match me.write_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => return Poll::Ready(Err(broken_pipe())),
            Poll::Pending => return Poll::Pending,
        }
        if me.write_tx.send_item(StreamCmd::Shutdown).is_err() {
            return Poll::Ready(Err(broken_pipe()));
        }
        let _ = me.cmd_tx.send(Cmd::Kick(me.id));
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // Dropping write_tx closes the per-stream channel; the Kick makes the
        // core notice promptly (it doesn't select on per-stream channels).
        // The core drains queued writes first, then closes the pcb — abort if
        // no half-close was seen, graceful close otherwise.
        self.write_tx.close();
        let _ = self.cmd_tx.send(Cmd::Kick(self.id));
    }
}
