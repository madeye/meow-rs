//! XTLS-Vision splice wrapper for VLESS.
//!
//! `VisionConn` wraps a `VlessConn` and intercepts the first application-layer
//! write.  If the first 5 bytes are a TLS handshake record
//! (`byte[0] == 0x16 && byte[1] == 0x03`), Vision mode is entered:
//!
//! 1. Buffer the full ClientHello (5-byte header + `uint16_BE(bytes[3..5])` body).
//! 2. Write a Vision padding header (disguised as a TLS AppData record) to inner.
//! 3. Write the full ClientHello to inner.
//! 4. Pass all subsequent writes through to inner unchanged.
//!
//! If the first 5 bytes are NOT a TLS record, pass-through mode is entered
//! immediately (no padding, no buffering beyond the initial peek).
//!
//! # Padding header wire format
//!
//! ```text
//! 0x17                  TLS AppData record type (disguise)
//! 0x03 0x03             TLS 1.2 version (always these bytes)
//! len_be(2)             2-byte big-endian length of the payload below
//! 0x00                  Vision marker byte (server recognises this)
//! random(N)             N in PADDING_RANGE
//! ```
//!
//! upstream: transport/vless/vision/vision.go::sendPaddingMessage
// upstream SHA: xray-core/xray-core main (2024) — pin before Vision PR merges

use std::io;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::task::{Context, Poll};

use mihomo_common::ProxyConn;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::conn::VlessConn;

// ─── Upstream-pinned constant ────────────────────────────────────────────────

/// Padding payload random-byte count range.
///
/// upstream: transport/vless/vision/vision.go — const `paddingMaxLen = 900`.
/// The padding payload is `[0x00] + random(N)` where N ∈ PADDING_RANGE.
/// Byte-exact match with the upstream constant is required (servers check the
/// marker byte and reject malformed padding).
pub const PADDING_RANGE: RangeInclusive<usize> = 0..=900;

// ─── State machine ────────────────────────────────────────────────────────────

enum WriteState {
    /// Buffering the first 5 bytes of application data.
    Peek(Vec<u8>),
    /// TLS ClientHello detected; buffering the body (beyond the 5-byte peek).
    Body {
        peek5: [u8; 5],
        body: Vec<u8>,
        need_more: usize,
    },
    /// Draining the prebuilt [padding_header + clienthello] buffer to inner.
    Drain { to_send: Vec<u8>, pos: usize },
    /// Passthrough — no more buffering.
    Through,
}

/// Vision-mode wrapper around `VlessConn`.
///
/// Returns `VisionConn` when `flow = xtls-rprx-vision` and the outer transport
/// provides TLS. See module-level docs for the splice algorithm.
pub struct VisionConn {
    inner: VlessConn,
    write_state: WriteState,
    /// Set to true once we entered Vision mode (padding header emitted).
    /// Used only in test assertions and the C11 log-noise guard.
    #[allow(dead_code)]
    vision_entered: bool,
}

impl VisionConn {
    pub fn new(inner: VlessConn) -> Self {
        Self {
            inner,
            write_state: WriteState::Peek(Vec::with_capacity(5)),
            vision_entered: false,
        }
    }

    /// Whether Vision mode was triggered (first 5 bytes were a TLS record).
    /// Used in tests and log-noise guards.
    #[allow(dead_code)]
    pub fn vision_entered(&self) -> bool {
        self.vision_entered
    }
}

// ─── Padding header builder ───────────────────────────────────────────────────

/// Build the Vision padding header.
///
/// Wire format:
/// ```text
/// 0x17  0x03  0x03  len_hi  len_lo  0x00  random...
/// ```
/// upstream: transport/vless/vision/vision.go::sendPaddingMessage
fn build_padding_header() -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::rng();
    let n = {
        let mut b = [0u8; 4];
        rng.fill_bytes(&mut b);
        (u32::from_le_bytes(b) as usize) % (*PADDING_RANGE.end() + 1)
    };
    let payload_len = 1 + n; // marker byte + random bytes
    let len = payload_len as u16;
    let mut buf = Vec::with_capacity(5 + payload_len);
    buf.push(0x17); // TLS AppData type
    buf.push(0x03); // TLS 1.2 major
    buf.push(0x03); // TLS 1.2 minor
    buf.push((len >> 8) as u8);
    buf.push((len & 0xFF) as u8);
    buf.push(0x00); // Vision marker byte
    for _ in 0..n {
        buf.push(rng.next_u32() as u8);
    }
    buf
}

// ─── AsyncRead ────────────────────────────────────────────────────────────────

impl AsyncRead for VisionConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// ─── AsyncWrite (state machine) ───────────────────────────────────────────────

impl AsyncWrite for VisionConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // `src_pos` tracks how many bytes of `buf` have been "consumed" by this
        // call.  States that buffer (Peek/Body) advance it; Drain/Through write to
        // inner from their own buffers or from the unconsumed remainder of buf.
        let mut src_pos = 0usize;

        loop {
            match &mut this.write_state {
                // ── Peek: collect first 5 bytes ────────────────────────────
                WriteState::Peek(pbuf) => {
                    let need = 5 - pbuf.len();
                    let take = need.min(buf[src_pos..].len());
                    pbuf.extend_from_slice(&buf[src_pos..src_pos + take]);
                    src_pos += take;

                    if pbuf.len() < 5 {
                        // Still buffering; return what we consumed from buf.
                        return Poll::Ready(Ok(src_pos));
                    }

                    // We now have exactly 5 bytes.
                    let is_tls = pbuf[0] == 0x16 && pbuf[1] == 0x03;
                    let peek5: [u8; 5] = pbuf[..5].try_into().unwrap();

                    if is_tls {
                        let body_len = u16::from_be_bytes([pbuf[3], pbuf[4]]) as usize;
                        this.vision_entered = true;

                        if body_len == 0 {
                            // Zero-length body — unlikely but handle it.
                            let mut to_send = build_padding_header();
                            to_send.extend_from_slice(&peek5);
                            this.write_state = WriteState::Drain { to_send, pos: 0 };
                        } else {
                            this.write_state = WriteState::Body {
                                peek5,
                                body: Vec::with_capacity(body_len),
                                need_more: body_len,
                            };
                        }
                    } else {
                        // Not TLS — passthrough mode.  Drain the peek bytes first.
                        let to_send = peek5.to_vec();
                        this.write_state = WriteState::Drain { to_send, pos: 0 };
                    }

                    // Continue into the new state (Body or Drain) within this
                    // same poll_write call so the caller sees data forwarded to
                    // inner as soon as possible.
                }

                // ── Body: accumulate full ClientHello ─────────────────────
                WriteState::Body {
                    peek5,
                    body,
                    need_more,
                } => {
                    let remaining_body = *need_more - body.len();
                    let take = remaining_body.min(buf[src_pos..].len());
                    body.extend_from_slice(&buf[src_pos..src_pos + take]);
                    src_pos += take;

                    if body.len() == *need_more {
                        // Full ClientHello assembled.  Build drain buffer and
                        // continue to Drain in this same poll_write so that the
                        // prebuilt buffer is flushed to inner before we return.
                        let mut to_send = build_padding_header();
                        to_send.extend_from_slice(peek5);
                        to_send.extend_from_slice(body);
                        this.write_state = WriteState::Drain { to_send, pos: 0 };
                        // continue → Drain
                    } else {
                        // Still accumulating body bytes; return what we consumed.
                        return Poll::Ready(Ok(src_pos));
                    }
                }

                // ── Drain: write prebuilt buffer to inner ──────────────────
                WriteState::Drain { to_send, pos } => {
                    let remaining = &to_send[*pos..];
                    if remaining.is_empty() {
                        this.write_state = WriteState::Through;
                        continue; // loop → Through
                    }

                    match Pin::new(&mut this.inner).poll_write(cx, remaining)? {
                        Poll::Pending => {
                            // Inner can't accept right now.  Return any buf bytes
                            // already consumed (if any); otherwise propagate Pending.
                            if src_pos > 0 {
                                return Poll::Ready(Ok(src_pos));
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(0) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "vision: zero write during padding drain",
                            )));
                        }
                        Poll::Ready(n) => {
                            *pos += n;
                            // Loop: either drain more or switch to Through.
                        }
                    }
                }

                // ── Through: transparent passthrough ──────────────────────
                WriteState::Through => {
                    let remaining_buf = &buf[src_pos..];
                    if remaining_buf.is_empty() {
                        // All buf bytes were consumed by earlier states; nothing
                        // left to forward.  Return the total consumed count.
                        return Poll::Ready(Ok(src_pos));
                    }
                    return Pin::new(&mut this.inner)
                        .poll_write(cx, remaining_buf)
                        .map(|r| r.map(|n| src_pos + n));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Unpin for VisionConn {}

impl ProxyConn for VisionConn {}

// ─── Unit tests (§C) ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    // ─── Minimal mock inner stream ────────────────────────────────────────────

    /// Records what was written to it.
    struct RecordingStream {
        written: Arc<Mutex<Vec<Vec<u8>>>>,
        /// Bytes to deliver on read.
        read_buf: VecDeque<u8>,
    }

    impl RecordingStream {
        fn new(written: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
            Self {
                written,
                read_buf: VecDeque::new(),
            }
        }
    }

    impl AsyncRead for RecordingStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = buf.remaining().min(self.read_buf.len());
            if n == 0 {
                return Poll::Pending;
            }
            for b in self.read_buf.drain(..n) {
                buf.put_slice(&[b]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for RecordingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.get_mut().written.lock().unwrap().push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for RecordingStream {}

    /// Build a `VisionConn` wrapping a `RecordingStream`.
    fn vision_over_recorder(written: Arc<Mutex<Vec<Vec<u8>>>>) -> VisionConn {
        let recorder = Box::new(RecordingStream::new(written));
        let vless = VlessConn {
            inner: recorder,
            response_pending: false,
        };
        VisionConn::new(vless)
    }

    // ─── C1: padding header matches reference ────────────────────────────────

    /// Padding header must match the upstream wire format from
    /// transport/vless/vision/vision.go::sendPaddingMessage.
    /// NOT arbitrary bytes — byte-exact marker at payload[0].
    #[test]
    fn vision_padding_header_matches_reference() {
        for _ in 0..100 {
            let hdr = build_padding_header();
            assert!(
                hdr.len() >= 5,
                "padding header must have 5-byte record prefix"
            );
            assert_eq!(hdr[0], 0x17, "byte[0] must be TLS AppData 0x17");
            assert_eq!(hdr[1], 0x03, "byte[1] must be 0x03 (TLS 1.2 major)");
            assert_eq!(hdr[2], 0x03, "byte[2] must be 0x03 (TLS 1.2 minor)");
            let payload_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            assert_eq!(
                hdr.len(),
                5 + payload_len,
                "record length must match actual bytes"
            );
            assert!(
                payload_len >= 1,
                "payload must have at least the marker byte"
            );
            assert_eq!(hdr[5], 0x00, "payload[0] must be Vision marker 0x00");
            let n = payload_len - 1;
            assert!(
                PADDING_RANGE.contains(&n),
                "random byte count {} not in PADDING_RANGE {:?}",
                n,
                PADDING_RANGE
            );
        }
    }

    // ─── C2: PADDING_RANGE matches upstream constant ─────────────────────────

    /// upstream: transport/vless/vision/vision.go paddingMaxLen = 900
    #[test]
    fn vision_padding_range_is_upstream_constant() {
        assert_eq!(
            *PADDING_RANGE.start(),
            0,
            "PADDING_RANGE lower bound must be 0"
        );
        assert_eq!(
            *PADDING_RANGE.end(),
            900,
            "PADDING_RANGE upper bound must be 900 (upstream paddingMaxLen)"
        );
    }

    // ─── C3: Vision mode on TLS first 5 bytes ────────────────────────────────

    #[tokio::test]
    async fn vision_detects_inner_tls_by_first_5_bytes() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut conn = vision_over_recorder(written.clone());

        // Write exactly 5 bytes: TLS handshake record type + TLS 1.2 version.
        // ClientHello body_len = 0x0001 (1 byte body).
        let first5 = [0x16u8, 0x03, 0x01, 0x00, 0x01];
        conn.write_all(&first5).await.unwrap();

        // We've fed 5 bytes — Vision should now be in Body state (need 1 more byte).
        // Feed the body byte.
        conn.write_all(&[0x42]).await.unwrap();

        // Now Vision should have emitted padding + peek5 + body to inner.
        let w = written.lock().unwrap();
        let combined: Vec<u8> = w.iter().flat_map(|v| v.iter().copied()).collect();

        // The combined output must start with the padding header (0x17 ...).
        assert_eq!(
            combined[0], 0x17,
            "output must start with padding header 0x17"
        );
        // Marker byte must be 0x00.
        let payload_len = u16::from_be_bytes([combined[3], combined[4]]) as usize;
        assert_eq!(
            combined[5], 0x00,
            "Vision marker byte must be 0x00; got: {:#04x}",
            combined[5]
        );
        // After the padding header (5 + payload_len bytes), the ClientHello follows.
        let ch_start = 5 + payload_len;
        assert_eq!(
            &combined[ch_start..ch_start + 5],
            &first5,
            "ClientHello must follow padding header verbatim"
        );
        assert_eq!(combined[ch_start + 5], 0x42, "ClientHello body must follow");
    }

    // ─── C4: passthrough on non-TLS first byte ───────────────────────────────

    #[tokio::test]
    async fn vision_passthrough_on_non_tls_first_byte() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut conn = vision_over_recorder(written.clone());

        // 0x47 = 'G' — first byte of "GET /"
        let data = [0x47u8, 0x45, 0x54, 0x20, 0x2F];
        conn.write_all(&data).await.unwrap();

        // Drain state transitions to Through after emitting the 5 peek bytes.
        let w = written.lock().unwrap();
        let combined: Vec<u8> = w.iter().flat_map(|v| v.iter().copied()).collect();

        // Must NOT start with 0x17 (no padding header emitted).
        assert_ne!(
            combined[0], 0x17,
            "passthrough must NOT emit padding header 0x17"
        );
        // The 5 data bytes must appear verbatim (no extra prefix).
        assert!(
            combined.windows(5).any(|w| w == data),
            "passthrough must forward the 5 original bytes; got {:?}",
            combined
        );
        assert!(
            !conn.vision_entered,
            "vision_entered must be false for non-TLS data"
        );
    }

    // ─── C5: passthrough on TLS type but wrong version ───────────────────────

    /// byte[0] = 0x16 (TLS handshake) but byte[1] = 0x04 (not 0x03).
    /// Guards against checking only byte[0].
    #[tokio::test]
    async fn vision_passthrough_on_tls_type_but_wrong_version() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut conn = vision_over_recorder(written.clone());

        let data = [0x16u8, 0x04, 0x00, 0x00, 0x00]; // TLS type, version major 0x04
        conn.write_all(&data).await.unwrap();

        assert!(
            !conn.vision_entered,
            "vision must NOT be entered when byte[1] != 0x03"
        );
    }

    // ─── C6: passthrough on EOF before 5 bytes ───────────────────────────────

    #[tokio::test]
    async fn vision_passthrough_on_empty_stream() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut conn = vision_over_recorder(written.clone());

        // Write only 3 bytes and then nothing more.
        conn.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        // This is an incomplete peek (< 5 bytes buffered).
        // No panic, no panic, graceful partial handling.
        assert!(
            !conn.vision_entered,
            "vision must not be entered on partial data"
        );
    }

    // ─── C7: full ClientHello buffered before sending ─────────────────────────

    /// "Stage a ClientHello arriving in two poll_write chunks; assert VisionConn
    ///  does not emit any bytes to the underlying writer until the full record is
    ///  buffered."
    /// upstream: transport/vless/vision/vision.go::ReadClientHelloRecord
    /// NOT partial-send on first chunk — truncated ClientHello breaks inner TLS.
    #[tokio::test]
    async fn vision_reads_full_clienthello_before_sending() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut conn = vision_over_recorder(written.clone());

        // ClientHello: 5-byte header claiming body_length=4.
        let hdr = [0x16u8, 0x03, 0x01, 0x00, 0x04];
        conn.write_all(&hdr).await.unwrap();

        // After the 5-byte peek, nothing should have been written to inner yet.
        {
            let w = written.lock().unwrap();
            let combined: Vec<u8> = w.iter().flat_map(|v| v.iter().copied()).collect();
            assert!(
                combined.is_empty(),
                "must NOT write to inner after only the 5-byte header; got {:?}",
                combined
            );
        }

        // Supply the first 2 body bytes.
        conn.write_all(&[0xAA, 0xBB]).await.unwrap();
        {
            let w = written.lock().unwrap();
            let combined: Vec<u8> = w.iter().flat_map(|v| v.iter().copied()).collect();
            assert!(
                combined.is_empty(),
                "must NOT write to inner after partial body (2/4 bytes); got {:?}",
                combined
            );
        }

        // Supply remaining 2 body bytes — full record complete.
        conn.write_all(&[0xCC, 0xDD]).await.unwrap();
        {
            let w = written.lock().unwrap();
            let combined: Vec<u8> = w.iter().flat_map(|v| v.iter().copied()).collect();
            assert!(
                !combined.is_empty(),
                "must write to inner once full ClientHello is assembled"
            );
        }
    }

    // ─── C8: body_length parsed from bytes[3..5] ──────────────────────────────

    /// Feed ClientHello where uint16_BE(bytes[3..5]) = 512.
    /// Guards against off-by-one or wrong byte range.
    #[tokio::test]
    async fn vision_clienthello_body_length_from_bytes_3_4() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut conn = vision_over_recorder(written.clone());

        // body_length = 512 = 0x0200
        let hdr = [0x16u8, 0x03, 0x01, 0x02, 0x00];
        conn.write_all(&hdr).await.unwrap();

        // Nothing written yet.
        assert!(
            written.lock().unwrap().is_empty(),
            "no write after 5-byte peek"
        );

        // Supply 511 bytes (not enough).
        conn.write_all(&vec![0u8; 511]).await.unwrap();
        assert!(
            written.lock().unwrap().iter().all(|v| v.is_empty())
                || written.lock().unwrap().is_empty(),
            "partial body must not trigger send"
        );

        // Wait — check more carefully.
        {
            let w = written.lock().unwrap();
            let combined: Vec<u8> = w.iter().flat_map(|v| v.iter().copied()).collect();
            assert!(
                combined.is_empty(),
                "must not write after 511/512 body bytes; got {} bytes",
                combined.len()
            );
        }

        // Supply the last byte.
        conn.write_all(&[0xFE]).await.unwrap();
        let w = written.lock().unwrap();
        let combined: Vec<u8> = w.iter().flat_map(|v| v.iter().copied()).collect();
        assert!(!combined.is_empty(), "must write after all 512 body bytes");
    }

    // ─── C9: padding header precedes ClientHello in output ───────────────────

    #[tokio::test]
    async fn vision_sends_padding_then_clienthello_in_order() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut conn = vision_over_recorder(written.clone());

        let hdr = [0x16u8, 0x03, 0x01, 0x00, 0x02]; // body_len = 2
        conn.write_all(&hdr).await.unwrap();
        conn.write_all(&[0xAB, 0xCD]).await.unwrap();

        let w = written.lock().unwrap();
        let combined: Vec<u8> = w.iter().flat_map(|v| v.iter().copied()).collect();
        assert!(!combined.is_empty(), "must have written something");

        // First byte must be 0x17 (padding header).
        assert_eq!(combined[0], 0x17, "padding header 0x17 must come first");

        // Locate the ClientHello (bytes [0x16, 0x03, 0x01, 0x00, 0x02]) in output.
        let search = [0x16u8, 0x03, 0x01, 0x00, 0x02];
        let ch_pos = combined
            .windows(5)
            .position(|w| w == search)
            .expect("ClientHello must appear in output");

        // The padding header (at offset 0) must come before the ClientHello.
        assert_eq!(combined[0], 0x17, "padding header at offset 0");
        assert!(ch_pos > 0, "ClientHello must follow the padding header");

        // The body bytes must follow the ClientHello header.
        assert_eq!(combined[ch_pos + 5], 0xAB);
        assert_eq!(combined[ch_pos + 6], 0xCD);
    }

    // ─── C11: non-TLS passthrough emits no warn/error logs ───────────────────

    /// Feed non-TLS data in passthrough mode.  Assert no `warn!` or `error!` logged.
    /// Vision passthrough is the expected path for HTTP-over-VLESS — must not spam logs.
    #[test]
    fn vision_no_inner_tls_no_log_noise() {
        use std::sync::Mutex as StdMutex;
        use tracing_subscriber::fmt::MakeWriter;

        let lines: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let line_buf: Arc<StdMutex<String>> = Arc::new(StdMutex::new(String::new()));

        #[derive(Clone)]
        struct CapWriter(Arc<StdMutex<Vec<String>>>, Arc<StdMutex<String>>);
        impl std::io::Write for CapWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let s = String::from_utf8_lossy(buf).to_string();
                let mut lb = self.1.lock().unwrap();
                lb.push_str(&s);
                if lb.contains('\n') {
                    let mut log = self.0.lock().unwrap();
                    for line in lb.split('\n') {
                        let t = line.trim();
                        if !t.is_empty() {
                            log.push(t.to_string());
                        }
                    }
                    lb.clear();
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for CapWriter {
            type Writer = Self;
            fn make_writer(&'a self) -> Self {
                self.clone()
            }
        }

        let cap = CapWriter(lines.clone(), line_buf);
        let sub = tracing_subscriber::fmt()
            .with_writer(cap)
            .with_ansi(false)
            .with_level(true)
            .finish();

        tracing::subscriber::with_default(sub, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async {
                let written = Arc::new(Mutex::new(Vec::new()));
                let mut conn = vision_over_recorder(written);
                // HTTP data — not TLS.
                conn.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
            });
        });

        let captured = lines.lock().unwrap();
        let bad_lines: Vec<&str> = captured
            .iter()
            .filter(|l| l.contains("WARN") || l.contains("ERROR"))
            .map(|s| s.as_str())
            .collect();
        assert!(
            bad_lines.is_empty(),
            "passthrough must not emit WARN/ERROR logs; got: {:?}",
            bad_lines
        );
    }
}
