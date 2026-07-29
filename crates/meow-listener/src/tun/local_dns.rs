//! Local DNS server for TUN mode (seeker-style).
//!
//! Binds UDP sockets to `127.0.0.1:53` and `[::1]:53`, answering DNS
//! queries using the same `DnsServer::handle_query` pipeline as the TUN
//! dns-hijack path.  System DNS is set to `127.0.0.1` / `::1` by
//! `DnsGuard`, so all DNS queries from the OS DNS Client arrive at these
//! sockets directly — no TUN netstack traversal needed.
//!
//! This is the seeker approach: instead of relying on DNS queries
//! traversing the TUN userspace IP stack (which only handles IPv4 and
//! requires complex routing), we run a real UDP socket that the OS can
//! reach via loopback.  Both IPv4 and IPv6 queries are handled, returning
//! fake IPs that route through the TUN device.

use std::net::SocketAddr;
use std::sync::Arc;

use meow_dns::server::DnsServer;
use meow_dns::Resolver;
use tokio::net::UdpSocket;
use tracing::{info, warn};

const RECV_BUF_SIZE: usize = 4096;

/// Run local DNS servers on `127.0.0.1:53` and `[::1]:53`.
///
/// Each socket runs concurrently; queries are handled in independent
/// tasks.  The function runs until both sockets are closed.
pub async fn run(resolver: Arc<Resolver>) {
    let v4 = serve_socket(
        "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
        Arc::clone(&resolver),
    );
    let v6 = serve_socket("[::1]:53".parse::<SocketAddr>().unwrap(), resolver);
    let _ = tokio::join!(v4, v6);
}

async fn serve_socket(addr: SocketAddr, resolver: Arc<Resolver>) {
    let socket = match UdpSocket::bind(addr).await {
        Ok(s) => {
            info!("tun local-dns: listening on {addr}");
            s
        }
        Err(e) => {
            warn!("tun local-dns: bind {addr} failed: {e}");
            return;
        }
    };

    let socket = Arc::new(socket);
    let mut buf = vec![0u8; RECV_BUF_SIZE];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                if len == 0 {
                    continue;
                }
                let query = buf[..len].to_vec();
                let sock = Arc::clone(&socket);
                let res = Arc::clone(&resolver);
                tokio::spawn(async move {
                    match DnsServer::handle_query(&query, &res).await {
                        Ok(response) => {
                            if let Err(e) = sock.send_to(&response, peer).await {
                                warn!("tun local-dns: send_to {peer} failed: {e}");
                            }
                        }
                        Err(e) => {
                            warn!("tun local-dns: query from {peer} failed: {e}");
                        }
                    }
                });
            }
            Err(e) => {
                warn!("tun local-dns: recv on {addr} failed: {e}");
            }
        }
    }
}
