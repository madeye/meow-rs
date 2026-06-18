//! Bridge between [`crate::Resolver`] and the global
//! [`meow_common::HostResolver`] hook consulted by
//! [`meow_common::connect_tcp_host`] / [`meow_common::resolve_host`].
//!
//! Compiled on every platform (the `meow_common::HostResolver` trait is now
//! cross-platform): Android installs it alongside the `SocketProtector`, iOS
//! installs it on its own from the NE FFI engine start.
//!
//! See `meow-common/src/socket_protect.rs` for *why* this hook exists:
//! `getaddrinfo` queries from libc bypass the per-fd protection and loop DNS
//! back through meow-rs's own tunnel; even where they don't loop, they run on
//! the blocking pool one thread per lookup. Routing the lookup through
//! `Resolver::resolve_ips` instead resolves async, coalesces + caches, and
//! keeps the query off the tunnel.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use meow_common::HostResolver;

use crate::Resolver;

/// Adapter that implements `meow_common::HostResolver` by delegating to
/// `Resolver::resolve_ips` — i.e. the same path `DirectAdapter` uses, so
/// hosts file entries and fake-IP rules behave consistently between the
/// direct outbound and the socket-protect dial path.
pub struct ResolverHostHook {
    resolver: Arc<Resolver>,
}

impl ResolverHostHook {
    pub fn new(resolver: Arc<Resolver>) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl HostResolver for ResolverHostHook {
    async fn resolve(&self, host: &str) -> io::Result<IpAddr> {
        self.resolver.resolve_ip(host).await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("meow-dns resolver: no address for {host}"),
            )
        })
    }

    async fn resolve_all(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.resolver.resolve_ips(host).await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("meow-dns resolver: no address for {host}"),
            )
        })
    }
}
