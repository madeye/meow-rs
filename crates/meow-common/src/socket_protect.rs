//! Outbound-socket protector hook for Android `VpnService.protect(fd)`.
//!
//! When meow-rs runs *inside* an Android VPN app, every outbound socket it
//! opens must bypass the VPN itself — otherwise packets to proxy upstreams
//! loop back into the tunnel and deadlock. Android exposes a per-fd hook
//! for this: `android.net.VpnService.protect(int fd)`. This module is the
//! single place the JNI bridge installs that hook; the proxy adapters that
//! open outbound sockets dial through [`connect_tcp`] / [`bind_udp`], which
//! call the installed protector before `connect()` / `bind()` so the very
//! first SYN / UDP packet already bypasses the tunnel.
//!
//! The protector trait and global setter are compiled only on Android. On
//! every other target [`connect_tcp`] / [`bind_udp`] degrade to the same
//! plain tokio code path the adapters used historically — so call sites
//! need no `cfg` guards.

use std::io;

use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket};

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::Arc;

    use parking_lot::RwLock;

    /// Hook invoked on every outbound socket fd just before `connect()` /
    /// `bind()`. Typically a thin JNI shim around
    /// `android.net.VpnService.protect(int)`.
    ///
    /// Implementations must not block — the call runs on the async runtime
    /// worker that is dialing the socket.
    pub trait SocketProtector: Send + Sync {
        /// Protect `fd`. Returning `Err` aborts the connect/bind and the
        /// error propagates back to the caller.
        fn protect(&self, fd: RawFd) -> io::Result<()>;
    }

    static PROTECTOR: RwLock<Option<Arc<dyn SocketProtector>>> = RwLock::new(None);

    /// Install the global socket protector. Call once during VPN startup,
    /// before any proxy adapter dials.
    ///
    /// Re-installing is allowed (e.g. VPN tear-down / re-create); the new
    /// protector takes effect on the next outbound socket.
    pub fn set_socket_protector(protector: Arc<dyn SocketProtector>) {
        *PROTECTOR.write() = Some(protector);
    }

    /// Remove the currently installed protector, if any.
    pub fn clear_socket_protector() {
        *PROTECTOR.write() = None;
    }

    /// Snapshot of the currently-installed protector. Exposed so callers
    /// that build sockets through `socket2` directly (e.g. for `SO_MARK`)
    /// can still apply protect on the fd they own.
    pub fn socket_protector() -> Option<Arc<dyn SocketProtector>> {
        PROTECTOR.read().clone()
    }

    pub(super) async fn connect_tcp_protected(
        dest: SocketAddr,
        protector: &dyn SocketProtector,
    ) -> io::Result<TcpStream> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if dest.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        protector.protect(socket.as_raw_fd())?;
        socket.set_nonblocking(true)?;

        match socket.connect(&dest.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)?;
        stream.writable().await?;
        if let Some(err) = stream.take_error()? {
            return Err(err);
        }
        Ok(stream)
    }

    pub(super) fn bind_udp_protected(
        local: SocketAddr,
        protector: &dyn SocketProtector,
    ) -> io::Result<UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if local.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        protector.protect(socket.as_raw_fd())?;
        socket.set_nonblocking(true)?;
        socket.bind(&local.into())?;

        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket)
    }
}

#[cfg(target_os = "android")]
pub use android::{
    clear_socket_protector, set_socket_protector, socket_protector, SocketProtector,
};

/// Dial an outbound TCP stream. On Android, applies the installed
/// `SocketProtector` (if any) to the socket fd before `connect()` so the
/// connection bypasses the VPN. On every other target this is equivalent to
/// [`TcpStream::connect`].
///
/// Accepts the same address forms as [`TcpStream::connect`] (a `SocketAddr`,
/// `(host, port)`, `"host:port"`, etc.). When the Android protector path is
/// taken, addresses are resolved first via `tokio::net::lookup_host` and each
/// resolved `SocketAddr` is tried in turn.
pub async fn connect_tcp<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
    #[cfg(target_os = "android")]
    {
        if let Some(p) = android::socket_protector() {
            let mut last_err: Option<io::Error> = None;
            let mut any = false;
            for resolved in tokio::net::lookup_host(addr).await? {
                any = true;
                match android::connect_tcp_protected(resolved, p.as_ref()).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last_err = Some(e),
                }
            }
            return Err(last_err.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    if any {
                        "connect_tcp: all candidates failed"
                    } else {
                        "connect_tcp: no addresses resolved"
                    },
                )
            }));
        }
    }
    TcpStream::connect(addr).await
}

/// Bind an outbound UDP socket. On Android, applies the installed
/// `SocketProtector` (if any) to the socket fd before `bind()`. On every
/// other target this is equivalent to [`UdpSocket::bind`].
pub async fn bind_udp<A: ToSocketAddrs>(local: A) -> io::Result<UdpSocket> {
    #[cfg(target_os = "android")]
    {
        if let Some(p) = android::socket_protector() {
            let resolved = tokio::net::lookup_host(local)
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "bind_udp: no address resolved")
                })?;
            return android::bind_udp_protected(resolved, p.as_ref());
        }
    }
    UdpSocket::bind(local).await
}

#[cfg(all(test, target_os = "android"))]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::os::fd::RawFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct Counting(AtomicUsize);
    impl SocketProtector for Counting {
        fn protect(&self, _fd: RawFd) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct Failing;
    impl SocketProtector for Failing {
        fn protect(&self, _fd: RawFd) -> io::Result<()> {
            Err(io::Error::other("protect denied"))
        }
    }

    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[tokio::test]
    async fn connect_tcp_invokes_protector() {
        let _g = LOCK.lock();
        let counter = Arc::new(Counting(AtomicUsize::new(0)));
        set_socket_protector(counter.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _stream = connect_tcp(addr).await.expect("connect");
        let _ = accept.await.unwrap();
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        clear_socket_protector();
    }

    #[tokio::test]
    async fn connect_tcp_propagates_protector_failure() {
        let _g = LOCK.lock();
        set_socket_protector(Arc::new(Failing));
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let err = connect_tcp(addr).await.expect_err("protect should fail");
        assert!(err.to_string().contains("protect denied"), "{err}");
        clear_socket_protector();
    }

    #[tokio::test]
    async fn bind_udp_invokes_protector() {
        let _g = LOCK.lock();
        let counter = Arc::new(Counting(AtomicUsize::new(0)));
        set_socket_protector(counter.clone());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sock = bind_udp(addr).await.expect("bind");
        assert!(sock.local_addr().unwrap().port() != 0);
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        clear_socket_protector();
    }
}
