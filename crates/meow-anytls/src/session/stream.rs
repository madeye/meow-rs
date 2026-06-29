//! Stream implementation for AnyTLS protocol
//!
//! Stream provides a duplex communication channel that implements AsyncRead and AsyncWrite

use crate::session::StreamReader;
use crate::util::{AnyTlsError, Result};
use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

/// Stream represents a single data stream within a Session
/// It implements AsyncRead and AsyncWrite to be used as a connection
pub struct Stream {
    id: u32,

    // ===== 读取部分：使用独立的 StreamReader =====
    // Arc<Mutex<>> 是为了在 poll_read 中获取 &mut
    reader: Arc<tokio::sync::Mutex<StreamReader>>,

    // ===== 写入部分：直接使用 channel，无需锁 =====
    writer_tx: mpsc::UnboundedSender<(u32, Bytes)>,

    // ===== SYNACK 通知 (用于超时检测) =====
    synack_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<Result<()>>>>>,

    // ===== 状态管理 =====
    is_closed: Arc<AtomicBool>,
    close_error: Arc<tokio::sync::Mutex<Option<AnyTlsError>>>,

    // Guards the one-shot stream-close sentinel so a FIN is emitted at most
    // once regardless of how many times `close()`/`poll_shutdown` fire.
    fin_sent: Arc<AtomicBool>,
}

impl Stream {
    /// Create a new stream
    ///
    /// # Arguments
    /// * `id` - Stream ID
    /// * `reader` - StreamReader 用于读取数据
    /// * `writer_tx` - 发送数据到 Session 的 channel
    ///
    /// # Returns
    /// (Stream, Receiver) - The receiver can be used to wait for SYNACK
    pub fn new(
        id: u32,
        reader: StreamReader,
        writer_tx: mpsc::UnboundedSender<(u32, Bytes)>,
    ) -> (Self, oneshot::Receiver<Result<()>>) {
        let (synack_tx, synack_rx) = oneshot::channel();

        let stream = Self {
            id,
            reader: Arc::new(tokio::sync::Mutex::new(reader)),
            writer_tx,
            synack_tx: Arc::new(tokio::sync::Mutex::new(Some(synack_tx))),
            is_closed: Arc::new(AtomicBool::new(false)),
            close_error: Arc::new(tokio::sync::Mutex::new(None)),
            fin_sent: Arc::new(AtomicBool::new(false)),
        };

        (stream, synack_rx)
    }

    /// Notify that SYNACK has been received
    ///
    /// # Arguments
    /// * `result` - Ok(()) for success, Err for error
    pub async fn notify_synack(&self, result: Result<()>) {
        let mut tx_guard = self.synack_tx.lock().await;
        match tx_guard.take() {
            Some(tx) => {
                let result_clone = match &result {
                    Ok(()) => Ok(()),
                    Err(e) => Err(AnyTlsError::Protocol(e.to_string())),
                };
                let _ = tx.send(result_clone);
                tracing::debug!(
                    "[Stream] SYNACK notified for stream {}: {:?}",
                    self.id,
                    result.is_ok()
                );
            }
            _ => {
                tracing::warn!("[Stream] SYNACK already notified for stream {}", self.id);
            }
        }
    }

    /// Get stream ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Close the stream with error (can be called with `Arc<Stream>`)
    pub async fn close_with_error(&self, err: AnyTlsError) {
        if self
            .is_closed
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            tracing::warn!(
                stream_id = self.id,
                cause = %err,
                "[Stream] Closing stream with error"
            );
            *self.close_error.lock().await = Some(err);
        }
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }

    /// Gracefully close this client stream.
    ///
    /// Signals the owning session (via the writer channel's empty-`Bytes`
    /// sentinel — see `Session::process_stream_data`) to emit a `Fin` frame
    /// for this stream id and evict it from the session's stream maps. Without
    /// this, client streams were never removed from `Session::streams` /
    /// `Session::stream_receive_tx` and never FIN-acked to the peer, so both
    /// maps grew unbounded for the life of the (long-lived, pooled) session.
    ///
    /// Lock-free and idempotent, so it is safe to call from `poll_shutdown`
    /// or a `Drop` impl on a wrapper type.
    pub fn close(&self) {
        self.is_closed.store(true, Ordering::Relaxed);
        if self
            .fin_sent
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            // Best-effort: if the session writer task is already gone the
            // stream is being torn down anyway, so a send error is harmless.
            let _ = self.writer_tx.send((self.id, Bytes::new()));
        }
    }

    /// Get a reference to the reader (for direct access in handlers)
    pub fn reader(&self) -> &Arc<tokio::sync::Mutex<StreamReader>> {
        &self.reader
    }

    /// Send data through the writer channel (无锁方式)
    ///
    /// 这个方法可以被多个任务并发调用，无需任何锁
    pub fn send_data(
        &self,
        data: Bytes,
    ) -> std::result::Result<(), mpsc::error::SendError<(u32, Bytes)>> {
        self.writer_tx.send((self.id, data))
    }
}

// Stream is not meant to be cloned - use Arc<Stream> instead
// This implementation is only for compatibility with HashMap storage

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let stream_id = self.id;
        let remaining = buf.remaining();

        // 使用 tokio::task::block_in_place 同步读取
        // 这避免了复杂的 Future polling 和借用问题
        let reader = Arc::clone(&self.reader);

        // 创建读取 future
        let mut read_fut = Box::pin(async move {
            let mut reader_guard = reader.lock().await;
            let mut temp_buf = vec![0u8; remaining];
            let n = reader_guard.read(&mut temp_buf).await?;
            Ok::<(usize, Vec<u8>), std::io::Error>((n, temp_buf))
        });

        // Poll the future
        match read_fut.as_mut().poll(cx) {
            Poll::Ready(Ok((n, temp_buf))) => {
                if n > 0 {
                    buf.put_slice(&temp_buf[..n]);
                    tracing::trace!(
                        "[Stream] poll_read: Read {} bytes (stream_id={})",
                        n,
                        stream_id
                    );
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                tracing::error!(
                    "[Stream] poll_read: Error reading (stream_id={}): {}",
                    stream_id,
                    e
                );
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let stream_id = self.id;
        let buf_len = buf.len();
        tracing::trace!(
            "[Stream] poll_write: stream_id={}, buf_len={}",
            stream_id,
            buf_len
        );

        if self.is_closed.load(Ordering::Relaxed) {
            tracing::warn!("[Stream] poll_write: Stream {} is closed", stream_id);
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        // Send data to session via channel
        let data = Bytes::copy_from_slice(buf);
        tracing::trace!(
            "[Stream] poll_write: Sending {} bytes to channel for stream {}",
            buf_len,
            stream_id
        );
        match self.writer_tx.send((self.id, data)) {
            Ok(_) => {
                tracing::debug!(
                    "[Stream] poll_write: Successfully sent {} bytes to channel for stream {}",
                    buf_len,
                    stream_id
                );
                Poll::Ready(Ok(buf.len()))
            }
            Err(e) => {
                tracing::error!(
                    "[Stream] poll_write: Failed to send {} bytes to channel for stream {}: {:?}",
                    buf_len,
                    stream_id,
                    e
                );
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "session channel closed",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Emit a FIN and evict this stream from the session maps.
        self.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::StreamReader;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_stream_write() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (_reader_tx, reader_rx) = mpsc::unbounded_channel();

        let reader = StreamReader::new(1, reader_rx);
        let (mut stream, _synack_rx) = Stream::new(1, reader, tx);

        // 写入数据
        stream.write_all(b"hello").await.unwrap();

        // 验证数据发送到 channel
        let (stream_id, data) = rx.recv().await.unwrap();
        assert_eq!(stream_id, 1);
        assert_eq!(data.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn test_stream_read() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (reader_tx, reader_rx) = mpsc::unbounded_channel();

        let reader = StreamReader::new(1, reader_rx);
        let (mut stream, _synack_rx) = Stream::new(1, reader, tx);

        // 发送数据到 reader
        reader_tx.send(Bytes::from("world")).unwrap();

        // 读取数据
        let mut buf = vec![0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();

        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"world");
    }

    #[tokio::test]
    async fn test_stream_read_write() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (reader_tx, reader_rx) = mpsc::unbounded_channel();

        let reader = StreamReader::new(1, reader_rx);
        let (mut stream, _synack_rx) = Stream::new(1, reader, tx);

        // 同时读写
        reader_tx.send(Bytes::from("input")).unwrap();
        stream.write_all(b"output").await.unwrap();

        // 验证读取
        let mut buf = vec![0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"input");

        // 验证写入
        let (stream_id, data) = rx.recv().await.unwrap();
        assert_eq!(stream_id, 1);
        assert_eq!(data.as_ref(), b"output");
    }
}
