//! Network-related utilities (TCP tuning)

use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

/// Enable low-latency options on a TCP stream (best-effort).
pub fn configure_tcp_stream(stream: &TcpStream, context: &str) {
    if let Err(err) = stream.set_nodelay(true) {
        debug!(
            "[Net] Failed to enable TCP_NODELAY for {}: {}",
            context, err
        );
    }

    #[cfg(any(unix, windows))]
    {
        use socket2::{SockRef, TcpKeepalive};

        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(120))
            .with_interval(Duration::from_secs(30));

        if let Err(err) = SockRef::from(stream).set_tcp_keepalive(&keepalive) {
            debug!(
                "[Net] Failed to configure TCP keepalive for {}: {}",
                context, err
            );
        }
    }
}
