//! Local DNS server for TUN mode (seeker-style).
//!
//! Binds UDP sockets to `127.0.0.1:53` and `[::1]:53`, answering DNS
//! queries via `DnsServer::serve` — the same hardened serve loop (bounded
//! worker pool with backpressure) and `handle_query` pipeline used by the
//! main DNS server and the TUN dns-hijack path.  System DNS is set to
//! `127.0.0.1` / `::1` by `DnsGuard`, so all DNS queries from the OS DNS
//! Client arrive at these sockets directly — no TUN netstack traversal
//! needed.
//!
//! This is the seeker approach: instead of relying on DNS queries
//! traversing the TUN userspace IP stack (which only handles IPv4 and
//! requires complex routing), we run a real UDP socket that the OS can
//! reach via loopback.  Both IPv4 and IPv6 queries are handled, returning
//! fake IPs that route through the TUN device.
//!
//! Binding is split from serving: `bind()` must be called (and must
//! succeed) *before* `DnsGuard` repoints the OS resolver at loopback.
//! If port 53 is already taken (ICS, Docker, another resolver), startup
//! fails loudly instead of leaving the whole machine with its DNS aimed
//! at an address nothing listens on.

use std::io;
use std::sync::Arc;

use meow_dns::server::DnsServer;
use meow_dns::Resolver;
use tokio::net::UdpSocket;
use tracing::info;

/// The pre-bound loopback DNS sockets. Produced by [`bind`], consumed by
/// [`run`].
pub struct Sockets {
    v4: UdpSocket,
    v6: UdpSocket,
}

/// Bind the loopback DNS sockets on `127.0.0.1:53` and `[::1]:53`.
///
/// Errors if either bind fails — the caller must treat that as a fatal
/// startup error and must NOT repoint the system DNS at loopback.
pub async fn bind() -> io::Result<Sockets> {
    let v4 = UdpSocket::bind("127.0.0.1:53")
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("bind 127.0.0.1:53: {e}")))?;
    let v6 = UdpSocket::bind("[::1]:53")
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("bind [::1]:53: {e}")))?;
    Ok(Sockets { v4, v6 })
}

/// Serve DNS on the pre-bound sockets until both are closed.
pub async fn run(sockets: Sockets, resolver: Arc<Resolver>) {
    let Sockets { v4, v6 } = sockets;
    info!("tun local-dns: serving on 127.0.0.1:53 and [::1]:53");
    let v4 = DnsServer::serve(Arc::new(v4), Arc::clone(&resolver));
    let v6 = DnsServer::serve(Arc::new(v6), resolver);
    tokio::join!(v4, v6);
}
