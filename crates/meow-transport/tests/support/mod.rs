//! Shared test helpers for `meow-transport` integration tests.
//!
//! Contains server-side code (TcpListener, TlsAcceptor, etc.) that is
//! explicitly forbidden inside `src/` by acceptance criterion #8.
//! Tests/support is whitelisted from the F2 grep-check.

pub mod log_capture;
pub mod loopback;
