//! Bridge between [`crate::Resolver`] and the global
//! [`meow_common::HostResolver`] hook consulted by
//! [`meow_common::connect_tcp_host`] / [`meow_common::resolve_host`].
//!
//! Gated identically to the trait it implements (Android in production,
//! plus `test/unix` so CI can exercise the wiring) — outside of those
//! cfgs the hook isn't compiled, so no impl is needed.
//!
//! See `meow-common/src/socket_protect.rs` for *why* this hook exists:
//! `getaddrinfo` queries from libc bypass `VpnService.protect(fd)` and
//! therefore route back through meow-rs's own tunnel, looping. Routing
//! the lookup through `Resolver::resolve_ip` instead breaks that loop
//! because the resolver's upstream sockets are themselves protected.

#![cfg(target_os = "android")]

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use meow_common::HostResolver;

use crate::Resolver;

/// Adapter that implements `meow_common::HostResolver` by delegating to
/// `Resolver::resolve_ip` — i.e. the same path `DirectAdapter` uses, so
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
}
