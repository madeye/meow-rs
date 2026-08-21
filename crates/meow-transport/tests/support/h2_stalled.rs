//! Stalled-h2-server harness shared between the `h2_common` unit tests and
//! the `h2_test` integration suite (D6/D7).
//!
//! Single source of truth: the unit tests inside `src/h2_common.rs` include
//! this file via `#[path]`, the integration tests via `support::h2_stalled` —
//! keep it free of crate-relative paths (`crate::…` / `meow_transport::…`)
//! so both contexts compile it unchanged.  That is also why
//! [`stalled_h2_parts`] returns the raw h2 halves instead of an `H2Stream`:
//! each suite wraps them in the stream type under its own path.
// Included by two suites that use different subsets; dead-code warnings on
// the unused half are expected and suppressed here (same policy as
// loopback.rs).
#![allow(dead_code)]

use bytes::Bytes;

/// Payload larger than h2's default 65535-byte send window, so a write
/// against a stalled peer can never complete in one poll however the peer's
/// SETTINGS race the first `poll_write`.
pub const STALLED_PAYLOAD_LEN: usize = 128 * 1024;

/// Open one client stream against a server that accepts the request and
/// then stops driving its connection: the request body is never read, so
/// the send window is never replenished and writes stall once the initial
/// window is spent.
///
/// Returns the client send half and response future — callers wrap them in
/// `H2Stream` — plus the server task handle.
pub async fn stalled_h2_parts() -> (
    h2::SendStream<Bytes>,
    h2::client::ResponseFuture,
    tokio::task::JoinHandle<()>,
) {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);

    let server = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .handshake::<_, Bytes>(server_io)
            .await
            .expect("server handshake");
        let _accepted = connection.accept().await;
        // Never polled again: no WINDOW_UPDATE is ever sent back.
        std::future::pending::<()>().await;
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

    (send_stream, response, server)
}
