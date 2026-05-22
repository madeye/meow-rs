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

// In production we only compile the protector hook on Android — that's the
// platform whose VPN model demands `VpnService.protect(fd)` and we don't want
// non-Android binaries paying any footprint for it. For tests we additionally
// enable the module on any unix host so CI (which does not target Android)
// can actually exercise the protector path against real loopback sockets.
#[cfg(any(target_os = "android", all(test, unix)))]
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

#[cfg(any(target_os = "android", all(test, unix)))]
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
    #[cfg(any(target_os = "android", all(test, unix)))]
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
    #[cfg(any(target_os = "android", all(test, unix)))]
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::os::fd::RawFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Records every fd handed to it; never fails.
    struct Counting {
        count: AtomicUsize,
        seen_fds: parking_lot::Mutex<Vec<RawFd>>,
    }
    impl Counting {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                count: AtomicUsize::new(0),
                seen_fds: parking_lot::Mutex::new(Vec::new()),
            })
        }
        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }
    impl SocketProtector for Counting {
        fn protect(&self, fd: RawFd) -> io::Result<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.seen_fds.lock().push(fd);
            Ok(())
        }
    }

    /// Always errors — used to verify failure propagation.
    struct Failing;
    impl SocketProtector for Failing {
        fn protect(&self, _fd: RawFd) -> io::Result<()> {
            Err(io::Error::other("protect denied"))
        }
    }

    /// Tracks the order of calls — used to verify protect runs BEFORE
    /// connect/bind. The fd argument must already be a valid (created) socket
    /// when protect is called, but the kernel `connect()` syscall must not
    /// have fired yet. We approximate this by observing that the fd is open
    /// (`fcntl(F_GETFD)` succeeds) but `getpeername` returns ENOTCONN.
    struct OrderingProbe {
        was_pre_connect: parking_lot::Mutex<Option<bool>>,
    }
    impl OrderingProbe {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                was_pre_connect: parking_lot::Mutex::new(None),
            })
        }
        fn was_pre_connect(&self) -> Option<bool> {
            *self.was_pre_connect.lock()
        }
    }
    impl SocketProtector for OrderingProbe {
        fn protect(&self, fd: RawFd) -> io::Result<()> {
            // SAFETY: fd is owned by the caller (still in socket2 wrapper);
            // F_GETFD doesn't mutate state, getpeername reads kernel state.
            let fd_open = unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1;
            let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&sa) as libc::socklen_t;
            let getpeer = unsafe {
                libc::getpeername(fd, &mut sa as *mut _ as *mut libc::sockaddr, &mut len)
            };
            let not_yet_connected = getpeer == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOTCONN);
            *self.was_pre_connect.lock() = Some(fd_open && not_yet_connected);
            Ok(())
        }
    }

    /// Serialise tests that touch the process-global protector — they would
    /// otherwise race each other and corrupt count assertions. `tokio::sync`
    /// (not `parking_lot`) so the guard can be held across `.await`.
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    // ─── connect_tcp ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn no_protector_falls_back_to_plain_tokio() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let stream = connect_tcp(addr).await.expect("connect");
        let _ = accept.await.unwrap();
        // Round-trips like a normal stream.
        drop(stream);
    }

    #[tokio::test]
    async fn connect_tcp_invokes_protector_against_real_listener() {
        let _g = LOCK.lock().await;
        let counter = Counting::new();
        set_socket_protector(Arc::clone(&counter) as Arc<dyn SocketProtector>);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let stream = connect_tcp(addr).await.expect("connect");
        let _ = accept.await.unwrap();
        drop(stream);
        assert_eq!(counter.count(), 1, "protector must be called exactly once");
        clear_socket_protector();
    }

    #[tokio::test]
    async fn connect_tcp_propagates_protector_failure() {
        let _g = LOCK.lock().await;
        set_socket_protector(Arc::new(Failing) as Arc<dyn SocketProtector>);
        // Real listener so the error can only come from the protector, not
        // a network error masquerading as one.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let err = connect_tcp(addr).await.expect_err("protect should fail");
        assert!(err.to_string().contains("protect denied"), "{err}");
        clear_socket_protector();
    }

    #[tokio::test]
    async fn protect_runs_before_connect_syscall() {
        let _g = LOCK.lock().await;
        let probe = OrderingProbe::new();
        set_socket_protector(Arc::clone(&probe) as Arc<dyn SocketProtector>);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _stream = connect_tcp(addr).await.expect("connect");
        let _ = accept.await.unwrap();
        assert_eq!(
            probe.was_pre_connect(),
            Some(true),
            "fd must be open but not-yet-connected at the moment protect() runs — \
             this is the invariant Android's VpnService.protect relies on"
        );
        clear_socket_protector();
    }

    #[tokio::test]
    async fn connect_tcp_with_string_addr_resolves_then_protects() {
        let _g = LOCK.lock().await;
        let counter = Counting::new();
        set_socket_protector(Arc::clone(&counter) as Arc<dyn SocketProtector>);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        // Pass as "host:port" string — exercises the lookup_host branch.
        let host_port = format!("127.0.0.1:{}", addr.port());
        let _stream = connect_tcp(host_port.as_str()).await.expect("connect");
        let _ = accept.await.unwrap();
        assert_eq!(counter.count(), 1);
        clear_socket_protector();
    }

    // ─── bind_udp ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn bind_udp_invokes_protector() {
        let _g = LOCK.lock().await;
        let counter = Counting::new();
        set_socket_protector(Arc::clone(&counter) as Arc<dyn SocketProtector>);
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sock = bind_udp(addr).await.expect("bind");
        assert!(sock.local_addr().unwrap().port() != 0);
        assert_eq!(counter.count(), 1);
        clear_socket_protector();
    }

    #[tokio::test]
    async fn bind_udp_propagates_protector_failure() {
        let _g = LOCK.lock().await;
        set_socket_protector(Arc::new(Failing) as Arc<dyn SocketProtector>);
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let err = bind_udp(addr).await.expect_err("protect should fail");
        assert!(err.to_string().contains("protect denied"), "{err}");
        clear_socket_protector();
    }

    #[tokio::test]
    async fn bind_udp_no_protector_falls_back_to_plain_tokio() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sock = bind_udp(addr).await.expect("bind");
        assert!(sock.local_addr().unwrap().port() != 0);
    }

    // ─── registry semantics ─────────────────────────────────────────────────

    #[tokio::test]
    async fn protector_set_get_clear_round_trip() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        assert!(socket_protector().is_none());

        let c = Counting::new();
        set_socket_protector(Arc::clone(&c) as Arc<dyn SocketProtector>);
        assert!(socket_protector().is_some(), "registered protector visible");

        clear_socket_protector();
        assert!(
            socket_protector().is_none(),
            "clear must remove the registration"
        );
    }

    #[tokio::test]
    async fn protector_replacement_takes_effect_for_subsequent_lookups() {
        let _g = LOCK.lock().await;
        clear_socket_protector();
        let first = Counting::new();
        set_socket_protector(Arc::clone(&first) as Arc<dyn SocketProtector>);

        let second = Counting::new();
        set_socket_protector(Arc::clone(&second) as Arc<dyn SocketProtector>);

        // The currently-installed pointer is the second one.
        let snap = socket_protector().expect("protector installed");
        let _ = snap.protect(0); // arbitrary fd; Counting accepts any
        assert_eq!(first.count(), 0, "old protector must be detached");
        assert_eq!(second.count(), 1, "new protector receives calls");

        clear_socket_protector();
    }
}
