//! Log-capture utilities for `warn!`/`info!` assertion tests.
// Each test binary (tls_test, ws_test, …) includes this module but only
// uses a subset of the functions.
#![allow(dead_code)]
//!
//! # Strategy: home-rolled `MakeWriter` + `with_default` scoped subscriber
//!
//! We do NOT use the `tracing-test` crate because it installs a process-global
//! subscriber that cross-contaminates **parallel test binaries** (each file in
//! `tests/` is compiled into a separate binary, and `cargo test` can run them
//! concurrently).  A process-global subscriber can only be set once; if two
//! test binaries race to set it, one panics.
//!
//! Instead we use [`tracing::subscriber::with_default`] which installs a
//! subscriber only for the duration of the given closure (thread-local scoping).
//! This works correctly for both sync and async code as long as the async code
//! does not spawn tasks onto other threads mid-capture (all our log-capture
//! tests are sync construction calls, so this is fine).
//!
//! # Usage
//!
//! ```rust,ignore
//! use support::log_capture::capture_logs;
//!
//! let logs = capture_logs(|| {
//!     // Code that may emit tracing events
//!     TlsLayer::new(&config).unwrap();
//! });
//!
//! let warn_count = logs.iter().filter(|l| l.contains("WARN") && l.contains("chrome")).count();
//! assert_eq!(warn_count, 1);
//! ```

use std::io;
use std::sync::{Arc, Mutex};
use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;

// ─── Captured-log buffer ─────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct LogBuffer(pub Arc<Mutex<Vec<String>>>);

impl LogBuffer {
    pub fn lines(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Count lines that contain every needle in `needles`.
    pub fn count_containing(&self, needles: &[&str]) -> usize {
        self.lines()
            .iter()
            .filter(|line| needles.iter().all(|n| line.contains(n)))
            .count()
    }

    pub fn contains_all(&self, needles: &[&str]) -> bool {
        self.count_containing(needles) > 0
    }
}

// ─── MakeWriter impl ─────────────────────────────────────────────────────────

struct BufferWriter(Arc<Mutex<Vec<String>>>, Arc<Mutex<String>>);

impl io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let s = String::from_utf8_lossy(buf);
        // Accumulate into a line buffer; flush to the log on newline.
        let mut line_buf = self
            .1
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        line_buf.push_str(&s);
        if line_buf.contains('\n') {
            let mut log = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for line in line_buf.split('\n') {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    log.push(trimmed.to_string());
                }
            }
            line_buf.clear();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct BufMakeWriter(Arc<Mutex<Vec<String>>>, Arc<Mutex<String>>);

impl<'a> MakeWriter<'a> for BufMakeWriter {
    type Writer = BufferWriter;
    fn make_writer(&'a self) -> Self::Writer {
        BufferWriter(Arc::clone(&self.0), Arc::clone(&self.1))
    }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Build a scoped tracing subscriber that captures all log lines into a
/// [`LogBuffer`].  Subscriber is active only for the lifetime of the
/// returned subscriber value; use with [`tracing::subscriber::with_default`].
pub fn make_capture_subscriber() -> (impl Subscriber + Send + Sync, LogBuffer) {
    let buf = LogBuffer::default();
    let line_buf = Arc::new(Mutex::new(String::new()));
    let make_writer = BufMakeWriter(Arc::clone(&buf.0), line_buf);

    let sub = tracing_subscriber::fmt()
        .with_writer(make_writer)
        .with_ansi(false)
        .with_level(true)
        .finish();

    (sub, buf)
}

/// Run `f` with a capturing subscriber installed; return all captured log lines.
///
/// Suitable for **synchronous** code that emits `tracing` events.
/// Do not use for async code that spawns tasks on other threads — those tasks
/// would inherit the default (non-capturing) subscriber.
pub fn capture_logs<F: FnOnce()>(f: F) -> LogBuffer {
    let (sub, buf) = make_capture_subscriber();
    tracing::subscriber::with_default(sub, f);
    buf
}
