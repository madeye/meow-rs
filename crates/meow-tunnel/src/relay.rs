// M2 relay-buffer-pool (ADR-0011 T6):
//   `tokio::io::copy_bidirectional_with_sizes` allocates a `Box<[u8]>` per
//   direction per connection (via `CopyBuffer::new`). At 4 KiB per direction
//   that is 8 KiB heap per TCP connection setup — confirmed in the dhat
//   baseline as sites #2 and #3 (66 MB each over 8 105 connections).
//
//   This module provides `copy_bidirectional_buf` which accepts caller-supplied
//   `&mut [u8]` scratch buffers. Callers declare `[0u8; BUF]` arrays inside the
//   enclosing async fn; those arrays become part of the future's state machine
//   and are paid for at task-spawn time (one allocation per task, shared with
//   everything else in the future), not at relay-call time.
//
//   Public API: `copy_bidirectional_buf` and `RELAY_BUF_SIZE`.
//   No new public types exposed — no M2 API break.
//
// Direction fairness (#345):
//   The two directions are driven by ONE future, so they can never run on two
//   cores at once — but they must not starve each other either. Each direction
//   advances at most one buffer fill+drain cycle per turn, and turns strictly
//   alternate a→b, b→a inside the poll loop. A busy direction therefore delays
//   the other by at most one `RELAY_BUF_SIZE` cycle, instead of monopolizing
//   the task until its reader runs dry (the pre-#345 behavior, where a→b was
//   always polled first and drained to `Pending` before b→a ever ran).
//   `RELAY_CYCLES_PER_POLL` additionally bounds total work per poll so the
//   relay yields to sibling tasks even on streams that don't participate in
//   tokio's coop budget.

use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Buffer size used for each relay direction.
/// 4 KiB halves the tokio default (8 KiB) to save 8 KiB/conn at the
/// cost of more syscalls; acceptable for proxy workloads where connections
/// are long-lived and latency matters less than memory at 5k+ conns.
pub const RELAY_BUF_SIZE: usize = 4 * 1024;

/// Idle window granted to the surviving relay direction after the *other*
/// direction has reached EOF.
///
/// Without a bound, a peer that closes one half of the connection and then
/// holds its read side open forever pins this future — and with it both
/// underlying sockets. That surfaces as leaked CLOSE-WAIT sockets on the
/// inbound (client) side (the client sent FIN but meow never `close()`s its
/// socket) and FIN-WAIT-2 on the outbound side. The reference mihomo kernel
/// avoids this by tearing the whole relay down once *either* direction
/// completes; this linger is the equivalent, but lenient.
///
/// The window is an **idle timeout, not an absolute deadline**: it is re-armed
/// every time the surviving direction transfers more bytes, so a legitimate
/// half-closed connection that keeps streaming (e.g. a client that shuts down
/// its write side after a request, then downloads a large response) is never
/// truncated mid-transfer. Only a connection that goes genuinely silent for the
/// full window — no progress in either direction — is reaped. A normal
/// simultaneous close drains in microseconds, far inside the window.
pub const RELAY_HALF_CLOSE_LINGER: Duration = Duration::from_secs(30);

/// Upper bound on buffer fill+drain cycles executed per `poll_fn` invocation
/// across both directions before the relay voluntarily yields back to the
/// scheduler (self-waking first, so it is promptly re-polled).
///
/// Real sockets already hit tokio's per-task coop budget (128 ops) around the
/// same magnitude, but coop is an implementation detail of tokio's leaf
/// resources — custom `ProxyConn` stacks (or the in-memory streams used in
/// tests) may never return `Pending` on their own. This cap makes the yield
/// deterministic: at 4 KiB per cycle it bounds one poll at 256 KiB relayed.
const RELAY_CYCLES_PER_POLL: u32 = 64;

// ---------------------------------------------------------------------------
// Internal copy-one-direction state (no heap allocation)
// ---------------------------------------------------------------------------

/// Outcome of one [`HalfCopy::poll_cycle`] turn.
enum Cycle {
    /// EOF reached, buffer fully flushed, writer shutdown complete.
    Done,
    /// The cycle moved data and the direction may have more work available —
    /// give the peer direction a turn, then call again.
    Progress,
    /// Blocked on the reader or the writer; a waker is registered.
    Pending,
}

struct HalfCopy<'buf> {
    buf: &'buf mut [u8],
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    need_flush: bool,
}

impl<'buf> HalfCopy<'buf> {
    fn new(buf: &'buf mut [u8]) -> Self {
        Self {
            buf,
            read_done: false,
            pos: 0,
            cap: 0,
            amt: 0,
            need_flush: false,
        }
    }

    /// Advance this direction by at most ONE buffer fill+drain cycle.
    ///
    /// The pre-#345 `poll_copy` looped read→write until `Pending`, so a busy
    /// direction monopolized the poll while the peer direction waited. Capping
    /// each turn at a single cycle lets the caller interleave the two
    /// directions fairly; the caller loops as long as either side reports
    /// [`Cycle::Progress`].
    fn poll_cycle<R, W, F>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        on_progress: &mut F,
    ) -> io::Result<Cycle>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
        F: FnMut(u64),
    {
        // Refill the buffer when empty — at most one read per cycle.
        if self.pos == self.cap && !self.read_done {
            let mut rb = ReadBuf::new(self.buf);
            match reader.as_mut().poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled().len();
                    if filled == 0 {
                        self.read_done = true;
                    } else {
                        self.pos = 0;
                        self.cap = filled;
                    }
                }
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => {
                    // Nothing buffered and the reader is idle: push written
                    // bytes to the peer before parking this direction.
                    if self.need_flush {
                        match writer.as_mut().poll_flush(cx) {
                            Poll::Ready(Ok(())) => self.need_flush = false,
                            Poll::Ready(Err(e)) => return Err(e),
                            Poll::Pending => return Ok(Cycle::Pending),
                        }
                    }
                    return Ok(Cycle::Pending);
                }
            }
        }

        // Drain buffered data to the writer.
        while self.pos < self.cap {
            let data = &self.buf[self.pos..self.cap];
            match writer.as_mut().poll_write(cx, data) {
                Poll::Ready(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero bytes to writer",
                    ));
                }
                Poll::Ready(Ok(n)) => {
                    self.pos += n;
                    self.amt += n as u64;
                    on_progress(n as u64);
                    self.need_flush = true;
                }
                Poll::Ready(Err(e)) => return Err(e),
                // Blocked on the writer — retrying this direction cannot help
                // until its waker fires, even though bytes may have moved.
                Poll::Pending => return Ok(Cycle::Pending),
            }
        }

        if self.read_done {
            return match writer.as_mut().poll_shutdown(cx) {
                Poll::Ready(Ok(())) => Ok(Cycle::Done),
                Poll::Ready(Err(e)) => Err(e),
                Poll::Pending => Ok(Cycle::Pending),
            };
        }

        // Buffer drained and the reader has not hit EOF: more work may be
        // immediately available next turn.
        Ok(Cycle::Progress)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Bidirectional relay using caller-supplied scratch buffers.
///
/// `buf_a_to_b` and `buf_b_to_a` are borrowed for the duration of the copy;
/// they must be at least 1 byte (typically `RELAY_BUF_SIZE`).
/// Callers declare these as `[0u8; RELAY_BUF_SIZE]` arrays in the enclosing
/// async fn so they live in the future's state machine — zero per-relay heap
/// allocation (ADR-0011 T6 / ADR-0008 HP-1 goal).
///
/// Returns `(bytes_a_to_b, bytes_b_to_a)`.
pub async fn copy_bidirectional_buf<A, B>(
    a: &mut A,
    b: &mut B,
    buf_a_to_b: &mut [u8],
    buf_b_to_a: &mut [u8],
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    copy_bidirectional_buf_tracked(a, b, buf_a_to_b, buf_b_to_a, |_| {}, |_| {}).await
}

/// Tracked variant of [`copy_bidirectional_buf`]. The callbacks run after
/// bytes are successfully written in each direction, allowing live traffic
/// and connection statistics without waiting for relay completion.
pub async fn copy_bidirectional_buf_tracked<A, B, FA, FB>(
    a: &mut A,
    b: &mut B,
    buf_a_to_b: &mut [u8],
    buf_b_to_a: &mut [u8],
    mut on_a_to_b: FA,
    mut on_b_to_a: FB,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    FA: FnMut(u64),
    FB: FnMut(u64),
{
    let mut a_to_b = HalfCopy::new(buf_a_to_b);
    let mut b_to_a = HalfCopy::new(buf_b_to_a);
    let mut a_done = false;
    let mut b_done = false;

    // Linger timer reaping a half-closed-then-stuck connection. Created up front
    // so it can be pinned on the stack (no per-relay heap allocation), but not
    // polled — and therefore not registered with the timer driver — until one
    // direction has finished and the other is still running. See
    // `RELAY_HALF_CLOSE_LINGER`.
    let linger = tokio::time::sleep(RELAY_HALF_CLOSE_LINGER);
    tokio::pin!(linger);
    let mut linger_armed = false;
    // Bytes transferred by the surviving direction when the linger was last
    // (re)armed. Used to re-arm the idle window on every byte of progress so an
    // active half-closed transfer is never truncated. See `RELAY_HALF_CLOSE_LINGER`.
    let mut linger_progress: u64 = 0;

    poll_fn(move |cx| {
        // Fair interleave (#345): alternate single fill+drain cycles between
        // the directions instead of draining one to `Pending` before touching
        // the other. Loop while either direction reports `Progress`, up to
        // `RELAY_CYCLES_PER_POLL` progress cycles per poll.
        //
        // Once a direction returns `Pending` it is parked for the REST of this
        // poll: it can only become ready again by waking the task (which
        // re-enters this closure), so re-polling it every iteration would just
        // burn a readiness check + waker re-registration per 4 KiB cycle of
        // the busy direction. A readiness event that fires while we are still
        // looping marks the task notified and triggers an immediate re-poll,
        // so no wakeup is lost by parking.
        let mut cycles: u32 = 0;
        let mut a_parked = false;
        let mut b_parked = false;
        loop {
            let mut progressed = false;

            if !a_done && !a_parked {
                let a_pin = Pin::new(&mut *a);
                let b_pin = Pin::new(&mut *b);
                match a_to_b.poll_cycle(cx, a_pin, b_pin, &mut on_a_to_b) {
                    Ok(Cycle::Done) => a_done = true,
                    Ok(Cycle::Progress) => {
                        progressed = true;
                        cycles += 1;
                    }
                    Ok(Cycle::Pending) => a_parked = true,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            if !b_done && !b_parked {
                let a_pin = Pin::new(&mut *a);
                let b_pin = Pin::new(&mut *b);
                match b_to_a.poll_cycle(cx, b_pin, a_pin, &mut on_b_to_a) {
                    Ok(Cycle::Done) => b_done = true,
                    Ok(Cycle::Progress) => {
                        progressed = true;
                        cycles += 1;
                    }
                    Ok(Cycle::Pending) => b_parked = true,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            if a_done && b_done {
                return Poll::Ready(Ok((a_to_b.amt, b_to_a.amt)));
            }

            if !progressed {
                break;
            }

            if cycles >= RELAY_CYCLES_PER_POLL {
                // Yield to sibling tasks; self-wake so the scheduler re-polls
                // this relay promptly.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        // Exactly one direction has finished while the other is still open.
        // Arm the idle window on that transition and re-arm it on every byte the
        // surviving direction makes progress, then let it race that direction:
        // whichever resolves first ends the relay. Because the window resets on
        // progress, an actively-streaming half-closed connection is never
        // truncated — only one that goes silent for the full window is reaped.
        // The surviving direction is re-polled above on every wake, so if it
        // drains before the timer fires we still return the full byte counts.
        if a_done || b_done {
            let surviving_amt = if a_done { b_to_a.amt } else { a_to_b.amt };
            if !linger_armed || surviving_amt != linger_progress {
                linger_armed = true;
                linger_progress = surviving_amt;
                linger
                    .as_mut()
                    .reset(tokio::time::Instant::now() + RELAY_HALF_CLOSE_LINGER);
            }
            if linger.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok((a_to_b.amt, b_to_a.amt)));
            }
        }

        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_small() {
        let (mut a, mut b) = duplex(64);
        let (mut a2, mut b2) = duplex(64);

        // Write some data into the pipe ends that will be relayed.
        use tokio::io::AsyncWriteExt;
        a.write_all(b"hello").await.unwrap();
        a.shutdown().await.unwrap();
        b2.write_all(b"world").await.unwrap();
        b2.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];
        let (up, down) = copy_bidirectional_buf(&mut b, &mut a2, &mut buf1, &mut buf2)
            .await
            .unwrap();

        assert_eq!(up, 5, "a→b direction");
        assert_eq!(down, 5, "b→a direction");
    }

    // Regression: a peer that half-closes (sends EOF on its write side) and
    // then holds its read side open forever must not pin the relay. Before the
    // half-close linger, `copy_bidirectional_buf` waited for *both* directions
    // to EOF, so this hung indefinitely — surfacing in production as leaked
    // CLOSE-WAIT (inbound) / FIN-WAIT-2 (outbound) sockets.
    #[tokio::test(start_paused = true)]
    async fn half_closed_peer_does_not_pin_relay() {
        use tokio::io::AsyncWriteExt;

        // `a` is the relay's view of the "client": the client sends a byte then
        // closes its write side, so a→b sees EOF. `b` is the relay's view of the
        // "upstream", whose far end (`_upstream_held_open`) never sends and never
        // closes, so b→a would otherwise block forever. The underscore-prefixed
        // binding is kept (not dropped) for the whole test so `b` never sees EOF.
        let (mut client, mut a) = duplex(64);
        let (mut b, _upstream_held_open) = duplex(64);

        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];

        // With paused time the linger only elapses via the runtime's auto-advance
        // once the future is genuinely stalled, so completion proves the timer —
        // not real wall-clock — drove teardown.
        let (up, down) = tokio::time::timeout(
            RELAY_HALF_CLOSE_LINGER * 4,
            copy_bidirectional_buf(&mut a, &mut b, &mut buf1, &mut buf2),
        )
        .await
        .expect("relay must tear down within the linger window, not hang")
        .expect("relay returns Ok after the linger reaps the stuck direction");

        assert_eq!(up, 1, "the client's byte was relayed before teardown");
        assert_eq!(down, 0, "upstream never sent anything");
    }

    // Regression: a legitimate half-closed connection that keeps actively
    // streaming on the surviving direction must NOT be truncated by the linger.
    // The client shuts down its write side, then the upstream streams for far
    // longer than one linger window, with each gap shorter than the window. An
    // absolute-deadline linger would cut this off at `RELAY_HALF_CLOSE_LINGER`;
    // the idle-timeout linger re-arms on every chunk and lets it all through.
    #[tokio::test(start_paused = true)]
    async fn active_half_closed_transfer_is_not_truncated() {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut a) = duplex(64);
        let (mut b, mut upstream) = duplex(64);

        // Client sends one byte then half-closes — a→b sees EOF, arming the linger.
        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();

        // Upstream streams 6 chunks spaced at half the linger window (total span
        // 3× the window), then closes. No single gap reaches the window, so the
        // idle timer keeps getting re-armed and never reaps the live transfer.
        let feeder = tokio::spawn(async move {
            for _ in 0..6 {
                tokio::time::sleep(RELAY_HALF_CLOSE_LINGER / 2).await;
                upstream.write_all(b"yy").await.unwrap();
            }
            upstream.shutdown().await.unwrap();
        });

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];

        // Drain `a` (the relay writes upstream bytes here) so the duplex buffer
        // never backpressures and the relay can run to upstream's clean EOF.
        let drain = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut sink = Vec::new();
            client.read_to_end(&mut sink).await.unwrap();
            sink.len()
        });

        let (up, down) = copy_bidirectional_buf(&mut a, &mut b, &mut buf1, &mut buf2)
            .await
            .expect("relay completes via upstream EOF, not a truncating linger");

        feeder.await.unwrap();
        let drained = drain.await.unwrap();

        assert_eq!(up, 1, "the client's byte was relayed");
        assert_eq!(
            down, 12,
            "every upstream byte must be relayed — the active transfer is not truncated"
        );
        assert_eq!(drained, 12, "client received the full upstream stream");
    }

    // Regression for #345: under symmetric load, neither direction may
    // monopolize the relay. The old `poll_copy` drained the entire a→b
    // direction to `Pending` before b→a was polled at all, so every a→b
    // progress event fired before the first b→a event. The interleaved relay
    // alternates one buffer cycle per direction, so both directions must show
    // progress from the very start of the transfer.
    #[tokio::test]
    async fn directions_interleave_under_symmetric_load() {
        use tokio::io::AsyncWriteExt;

        // 8 relay-buffers of data queued in EACH direction before the relay
        // starts, with enough duplex capacity that no write ever backpressures
        // — progress order is then determined purely by relay poll order.
        let total = RELAY_BUF_SIZE * 8;
        let (mut client, mut a) = duplex(total * 2);
        let (mut b, mut upstream) = duplex(total * 2);

        client.write_all(&vec![1u8; total]).await.unwrap();
        client.shutdown().await.unwrap();
        upstream.write_all(&vec![2u8; total]).await.unwrap();
        upstream.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];

        // Record the order of write-progress events per direction.
        let events = std::cell::RefCell::new(Vec::new());
        let (up, down) = copy_bidirectional_buf_tracked(
            &mut a,
            &mut b,
            &mut buf1,
            &mut buf2,
            |n| events.borrow_mut().push(('a', n)),
            |n| events.borrow_mut().push(('b', n)),
        )
        .await
        .unwrap();

        assert_eq!(up as usize, total, "a→b relayed everything");
        assert_eq!(down as usize, total, "b→a relayed everything");

        let events = events.into_inner();
        let first_b = events
            .iter()
            .position(|e| e.0 == 'b')
            .expect("b→a made progress");
        let last_a = events
            .iter()
            .rposition(|e| e.0 == 'a')
            .expect("a→b made progress");
        assert!(
            first_b < last_a,
            "b→a must progress before a→b fully drains (first b event at \
             index {first_b}, last a event at index {last_a})"
        );
        assert!(
            first_b <= 2,
            "with fair interleaving b→a's first progress arrives within the \
             first few cycles, not at index {first_b}"
        );
    }

    #[tokio::test]
    async fn empty_streams() {
        let (mut a, mut b) = duplex(64);
        let (mut a2, mut b2) = duplex(64);

        use tokio::io::AsyncWriteExt;
        a.shutdown().await.unwrap();
        b2.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];
        let (up, down) = copy_bidirectional_buf(&mut b, &mut a2, &mut buf1, &mut buf2)
            .await
            .unwrap();
        assert_eq!(up, 0);
        assert_eq!(down, 0);
    }
}
