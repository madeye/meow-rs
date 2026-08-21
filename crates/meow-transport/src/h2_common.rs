//! Shared raw HTTP/2 stream plumbing for the h2 transport and sing-h2mux.

use bytes::Bytes;
use http::StatusCode;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Accepted response status for a lazily resolved HTTP/2 body.
#[derive(Clone, Copy)]
pub enum StatusPolicy {
    Success,
    Exact(StatusCode),
}

enum RecvInner {
    Pending(h2::client::ResponseFuture),
    Ready(h2::RecvStream),
    Failed,
}

/// Receive half of a client-initiated h2 request, resolved lazily on first
/// read so servers that wait for request DATA cannot deadlock setup.
pub struct RecvState {
    inner: RecvInner,
    timeout: Option<Pin<Box<tokio::time::Sleep>>>,
    status: StatusPolicy,
    label: &'static str,
}

impl RecvState {
    pub fn new(response: h2::client::ResponseFuture) -> Self {
        Self {
            inner: RecvInner::Pending(response),
            timeout: None,
            status: StatusPolicy::Success,
            label: "h2",
        }
    }

    pub fn with_timeout(
        response: h2::client::ResponseFuture,
        timeout: Duration,
        status: StatusPolicy,
        label: &'static str,
    ) -> Self {
        Self {
            inner: RecvInner::Pending(response),
            timeout: Some(Box::pin(tokio::time::sleep(timeout))),
            status,
            label,
        }
    }

    fn accepts(&self, status: StatusCode) -> bool {
        match self.status {
            StatusPolicy::Success => status.is_success(),
            StatusPolicy::Exact(expected) => status == expected,
        }
    }

    /// Drive the response future far enough that [`Self::stream`] returns the
    /// body. Once this resolves `Ready(Ok(()))`, the body is retained.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            RecvInner::Ready(_) => return Poll::Ready(Ok(())),
            RecvInner::Failed => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("{}: response stream already failed", self.label),
                )))
            }
            RecvInner::Pending(future) => match Pin::new(future).poll(cx) {
                Poll::Pending => {}
                Poll::Ready(Ok(response)) => {
                    let status = response.status();
                    if !self.accepts(status) {
                        self.inner = RecvInner::Failed;
                        return Poll::Ready(Err(io::Error::other(format!(
                            "{}: unexpected response status {status}",
                            self.label
                        ))));
                    }
                    self.inner = RecvInner::Ready(response.into_body());
                    self.timeout = None;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    self.inner = RecvInner::Failed;
                    return Poll::Ready(Err(io::Error::other(error)));
                }
            },
        }

        if let Some(timeout) = &mut self.timeout {
            if timeout.as_mut().poll(cx).is_ready() {
                self.inner = RecvInner::Failed;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{}: response timeout", self.label),
                )));
            }
        }
        Poll::Pending
    }

    pub fn stream(&mut self) -> Option<&mut h2::RecvStream> {
        match &mut self.inner {
            RecvInner::Ready(stream) => Some(stream),
            _ => None,
        }
    }
}

/// Per-poll cap on the bytes copied into `pending_write`.  Without a cap,
/// a large write under backpressure re-copies the whole shrinking
/// remainder on every `write_all` resubmission (a 1 MiB write through a
/// 64 KiB window costs ~16 allocations / ~8 MiB of memcpy); capping the
/// stash bounds every copy to one window's worth.  64 KiB is chosen to
/// exceed h2's default 65535-byte initial window, so writes that fit the
/// default window keep their single-poll behaviour.
const WRITE_STASH_CAP: usize = 64 * 1024;

/// Raw bidirectional bytes over one HTTP/2 request/response pair.
pub struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: RecvState,
    read_buf: Bytes,
    /// Payload stashed while a `poll_write` waits for h2 send-window
    /// capacity — at most [`WRITE_STASH_CAP`] bytes, i.e. possibly only a
    /// prefix of the caller's buffer.  Only retained across a
    /// `Poll::Pending` return — every `Ready` return (including a partial
    /// one) clears it, because after `Ready(Ok(n))` the caller may legally
    /// submit a different buffer (issue #423).  Only granted capacity is
    /// ever handed to the connection, so a peer that stops reading applies
    /// real backpressure instead of growing h2's internal buffer.
    pending_write: Option<Bytes>,
    remote_no_error_is_eof: bool,
    eos_sent: bool,
}

impl H2Stream {
    pub fn new(send: h2::SendStream<Bytes>, recv: RecvState) -> Self {
        Self {
            send,
            recv,
            read_buf: Bytes::new(),
            pending_write: None,
            remote_no_error_is_eof: false,
            eos_sent: false,
        }
    }

    pub fn with_remote_no_error_eof(mut self) -> Self {
        self.remote_no_error_is_eof = true;
        self
    }

    fn best_effort_eos(&mut self) {
        if !self.eos_sent {
            self.eos_sent = true;
            let _ = self.send.send_data(Bytes::new(), true);
        }
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        self.best_effort_eos();
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A zero-capacity buffer yields Ready(Ok(())) per the tokio
        // AsyncRead docs (a Pending here would leave `read(&mut [])`
        // parked forever).
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !this.read_buf.is_empty() {
                let count = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..count]);
                let _ = this.read_buf.split_to(count);
                return Poll::Ready(Ok(()));
            }
            match this.recv.poll_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            let recv = this.recv.stream().expect("poll_ready resolved Ok");
            match recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(error))) => {
                    if this.remote_no_error_is_eof
                        && error.is_reset()
                        && error.is_remote()
                        && error.reason() == Some(h2::Reason::NO_ERROR)
                    {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    let _ = recv.flow_control().release_capacity(bytes.len());
                    this.read_buf = bytes;
                }
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        // Stash the payload exactly once per parked write.  If
        // pending_write is set, the previous poll returned Pending and
        // capacity has been reserved — do not copy or reserve again.
        // A Pending poll must be retried with the same buffer; reject a
        // changed buffer rather than silently sending stale bytes under
        // its reported length.  The stash may be a capped prefix of the
        // caller's buffer, so compare it against the new buffer's prefix
        // of the stash's length.  This guard applies to the Pending path
        // only: pending_write never survives a Ready return, so after a
        // partial `Ready(Ok(n))` the caller is free to submit anything
        // (issue #423).
        if let Some(data) = &this.pending_write {
            if buf.len() < data.len() || &buf[..data.len()] != data.as_ref() {
                // Hand the stale stash's reservation back to the
                // connection along with the stash itself: this error
                // taints the stream, so nothing will ever send those
                // bytes, and leaving the reservation requested would pin
                // window capacity on the connection for good.
                this.send.reserve_capacity(0);
                this.pending_write = None;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "h2: write buffer changed after Pending; \
                     AsyncWrite requires retrying with the same buffer",
                )));
            }
        } else {
            // Stash (and therefore accept) at most WRITE_STASH_CAP bytes
            // per poll so `write_all`-style resubmissions of a large
            // buffer copy bounded chunks instead of the whole remainder.
            let stash_len = buf.len().min(WRITE_STASH_CAP);
            let data = Bytes::copy_from_slice(&buf[..stash_len]);
            this.send.reserve_capacity(data.len());
            this.pending_write = Some(data);
        }
        match this.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2: send stream closed",
                )))
            }
            Poll::Ready(Some(Err(error))) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::other(error)))
            }
            Poll::Ready(Some(Ok(capacity))) => {
                let data = this.pending_write.take().expect("set above");
                // poll_capacity may grant less than the reserved amount
                // (the peer's flow-control window); send only the
                // granted prefix and report a short write.
                let allowed = capacity.min(data.len());
                if allowed == 0 {
                    // Unreachable: poll_capacity yields Some(Ok(n)) with
                    // n > 0, and pending_write is never stashed empty.
                    // Re-stash and re-register the waker defensively so a
                    // future code change cannot park this task forever.
                    debug_assert!(allowed > 0, "h2: zero capacity grant with pending data");
                    this.pending_write = Some(data);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let chunk = data.slice(..allowed);
                if let Err(error) = this.send.send_data(chunk, false) {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                if allowed < data.len() {
                    // Short write: the unsent remainder is dropped (the
                    // caller re-submits it — or a different buffer — on
                    // the next write), so hand its reservation back to
                    // the connection instead of pinning window capacity
                    // for bytes that may never arrive.  reserve_capacity
                    // sets a target on top of already-buffered data, so 0
                    // keeps what send_data just queued.
                    this.send.reserve_capacity(0);
                }
                Poll::Ready(Ok(allowed))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().best_effort_eos();
        Poll::Ready(Ok(()))
    }
}

impl Unpin for H2Stream {}

/// Stalled-h2-server harness shared with the `h2_test` integration suite
/// (single source in `tests/support/h2_stalled.rs`, see its module docs).
#[cfg(test)]
#[path = "../tests/support/h2_stalled.rs"]
mod h2_stalled;

#[cfg(test)]
mod tests {
    use super::h2_stalled::{stalled_h2_parts, STALLED_PAYLOAD_LEN};
    use super::*;
    use std::future::poll_fn;
    use tokio::io::AsyncWriteExt as _;

    async fn stalled_h2_stream() -> (H2Stream, tokio::task::JoinHandle<()>) {
        let (send_stream, response, server) = stalled_h2_parts().await;
        (H2Stream::new(send_stream, RecvState::new(response)), server)
    }

    /// Poll `poll_write` exactly once, surfacing `Pending` as `None` instead
    /// of parking the test.
    async fn poll_write_once(stream: &mut H2Stream, buf: &[u8]) -> Option<io::Result<usize>> {
        poll_fn(|cx| {
            Poll::Ready(match Pin::new(&mut *stream).poll_write(cx, buf) {
                Poll::Pending => None,
                Poll::Ready(result) => Some(result),
            })
        })
        .await
    }

    /// Issue #423: `pending_write` must not survive a partial
    /// `Ready(Ok(n))`.  After a short write the caller may legally submit a
    /// *different* buffer; the changed-buffer guard applies only to retries
    /// after `Pending`.
    #[tokio::test]
    async fn partial_write_then_different_buffer_is_accepted() {
        let (mut stream, _server) = stalled_h2_stream().await;
        let payload = vec![b'a'; STALLED_PAYLOAD_LEN];

        // Drive the first logical write to its first Ready(Ok(n)).  The send
        // window (at most 64 KiB) cannot cover the payload, so the write is
        // necessarily partial.  Deadline-bounded so a regression that never
        // yields Ready fails with a diagnostic instead of hanging CI.
        let sent = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match poll_write_once(&mut stream, &payload).await {
                    // Capacity not assigned yet — let the connection task run.
                    None => tokio::task::yield_now().await,
                    Some(Ok(n)) => break n,
                    Some(Err(error)) => panic!("unexpected write error: {error}"),
                }
            }
        })
        .await
        .expect("first write must reach Ready(Ok(n)) once capacity is assigned");
        assert!(sent < payload.len(), "expected a partial write");

        // Submit a buffer with different contents.  Before the fix this
        // tripped the identity guard and failed with InvalidInput; it must
        // be treated as a fresh logical write.
        let decoy = vec![b'b'; 64 * 1024];
        loop {
            match poll_write_once(&mut stream, &decoy).await {
                // Parked on flow control — expected once the window is gone.
                None => break,
                Some(Ok(n)) => {
                    assert!(n > 0, "poll_write must not return Ok(0) for data");
                }
                Some(Err(error)) => {
                    panic!("a different buffer after a partial write must be accepted: {error}")
                }
            }
        }
    }

    /// The stash is capped at [`WRITE_STASH_CAP`], so a parked large write
    /// retried with the same *full* remainder (longer than the stash) must
    /// keep parking: the changed-buffer guard compares the stash against
    /// the retry buffer's prefix of the stash's length, not the whole
    /// buffer.  Before the cap the two were always the same length, so an
    /// exact comparison sufficed; with the cap an exact comparison would
    /// falsely reject every `write_all` resubmission of a > 64 KiB buffer.
    #[tokio::test]
    async fn capped_stash_accepts_same_full_buffer_retry() {
        let (mut stream, _server) = stalled_h2_stream().await;
        let payload = vec![b'a'; STALLED_PAYLOAD_LEN];

        // Exhaust the send window (at most 65535 bytes accepted), leaving a
        // remainder strictly longer than WRITE_STASH_CAP parked in
        // pending_write as a capped prefix.  A poll is treated as parked
        // only after several consecutive Pendings with yields in between,
        // so a capacity grant split across connection-task runs cannot
        // race the assertions below.
        let sent = tokio::time::timeout(Duration::from_secs(5), async {
            let mut sent = 0usize;
            let mut idle_polls = 0usize;
            loop {
                match poll_write_once(&mut stream, &payload[sent..]).await {
                    None => {
                        idle_polls += 1;
                        if sent > 0 && idle_polls >= 3 {
                            break sent;
                        }
                        tokio::task::yield_now().await;
                    }
                    Some(Ok(n)) => {
                        sent += n;
                        idle_polls = 0;
                    }
                    Some(Err(error)) => panic!("unexpected write error: {error}"),
                }
            }
        })
        .await
        .expect("the stalled window must park the write, not spin forever");
        let remainder = &payload[sent..];
        assert!(
            remainder.len() > WRITE_STASH_CAP,
            "setup: the parked remainder must exceed the stash cap"
        );

        // Contract-abiding retry with the same (uncapped) remainder: must
        // stay Pending, never trip the changed-buffer guard.
        for _ in 0..3 {
            let polled = poll_write_once(&mut stream, remainder).await;
            assert!(
                polled.is_none(),
                "same-buffer retry of a capped stash must stay Pending, got {polled:?}"
            );
        }
    }

    /// A large write against a peer with plenty of window is accepted in
    /// at most [`WRITE_STASH_CAP`]-byte chunks per poll, so `write_all`
    /// resubmissions copy bounded chunks instead of re-copying the whole
    /// shrinking remainder each time.
    #[tokio::test]
    async fn large_write_accepts_at_most_stash_cap_per_poll() {
        const PAYLOAD_LEN: usize = 1024 * 1024;

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        // Server with windows large enough to cover the whole payload, so
        // only the stash cap can bound a single accept.  It drains the
        // request body while keeping the connection driven.
        let server = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(2 * 1024 * 1024)
                .initial_connection_window_size(2 * 1024 * 1024)
                .handshake::<_, Bytes>(server_io)
                .await
                .expect("server handshake");
            let (request, respond) = connection
                .accept()
                .await
                .expect("one request")
                .expect("accept ok");
            let mut body = request.into_body();
            let drain = async {
                let mut total = 0usize;
                while let Some(data) = body.data().await {
                    let bytes = data.expect("body data");
                    total += bytes.len();
                    let _ = body.flow_control().release_capacity(bytes.len());
                }
                total
            };
            let drive = async {
                while connection.accept().await.is_some() {}
                std::future::pending::<()>().await;
            };
            let total = tokio::select! {
                total = drain => total,
                () = drive => unreachable!("drive never resolves"),
            };
            assert_eq!(total, PAYLOAD_LEN, "server must receive every byte");
            drop(respond); // kept alive until here so the stream is not reset
        });

        let (send_request, connection) = h2::client::handshake(client_io)
            .await
            .expect("client handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost")
            .body(())
            .expect("static request");
        let mut send_request = send_request.ready().await.expect("send_request ready");
        let (response, send_stream) = send_request
            .send_request(request, false)
            .expect("send_request");
        let mut stream = H2Stream::new(send_stream, RecvState::new(response));

        let payload = vec![b'z'; PAYLOAD_LEN];
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut sent = 0usize;
            while sent < payload.len() {
                match poll_write_once(&mut stream, &payload[sent..]).await {
                    None => tokio::task::yield_now().await,
                    Some(Ok(n)) => {
                        assert!(
                            n <= WRITE_STASH_CAP,
                            "a single poll accepted {n} bytes, more than the stash cap"
                        );
                        sent += n;
                    }
                    Some(Err(error)) => panic!("unexpected write error: {error}"),
                }
            }
        })
        .await
        .expect("the whole payload must be accepted against an open window");

        // Half-close so the server's body drain sees end-of-stream.
        poll_fn(|cx| Pin::new(&mut stream).poll_shutdown(cx))
            .await
            .expect("shutdown");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server must finish draining")
            .expect("server task");
    }

    /// Dropping an `H2Stream` half-closes the request body with a clean
    /// `end_of_stream` DATA frame instead of resetting the stream, so bytes
    /// already accepted by the peer are not torn down retroactively.  This
    /// pins the behaviour for both the plain `network: h2` transport and
    /// h2mux, which share this type (issue #423, follow-up to #417).
    #[tokio::test]
    async fn drop_sends_end_of_stream_not_reset() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .handshake::<_, Bytes>(server_io)
                .await
                .expect("server handshake");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("one request")
                .expect("accept ok");
            let mut body = request.into_body();
            respond
                .send_response(http::Response::new(()), true)
                .expect("send response");

            // Read the request body to completion while a second future
            // keeps the connection driven (RecvStream does not drive IO).
            let read_body = async {
                let mut received = Vec::new();
                loop {
                    match body.data().await {
                        Some(Ok(bytes)) => {
                            let _ = body.flow_control().release_capacity(bytes.len());
                            received.extend_from_slice(&bytes);
                        }
                        Some(Err(error)) => return Err(error),
                        None => return Ok(received),
                    }
                }
            };
            let drive = async {
                while connection.accept().await.is_some() {}
                std::future::pending::<()>().await;
            };
            tokio::select! {
                body_result = read_body => {
                    let received = body_result.expect("drop must end the stream cleanly, not reset it");
                    assert_eq!(received, b"hello", "bytes written before drop must survive");
                }
                () = drive => unreachable!("drive never resolves"),
            }
        });

        let (send_request, connection) = h2::client::handshake(client_io)
            .await
            .expect("client handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost")
            .body(())
            .expect("static request");
        let mut send_request = send_request.ready().await.expect("send_request ready");
        let (response, send_stream) = send_request
            .send_request(request, false)
            .expect("send_request");
        let mut stream = H2Stream::new(send_stream, RecvState::new(response));

        stream.write_all(b"hello").await.expect("write");
        drop(stream);

        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server must observe end-of-stream")
            .expect("server task");
    }
}
