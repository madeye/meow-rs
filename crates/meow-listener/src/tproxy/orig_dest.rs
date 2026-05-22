use std::io;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Recover the original destination address from a redirected TCP connection.
///
/// On macOS, queries the pf NAT state table via DIOCNATLOOK.
/// On Linux, uses SO_ORIGINAL_DST getsockopt.
pub fn get_original_dst(stream: &TcpStream, listen_addr: SocketAddr) -> io::Result<SocketAddr> {
    #[cfg(target_os = "macos")]
    {
        macos::get_original_dst(stream, listen_addr)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = listen_addr;
        linux::get_original_dst(stream)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (stream, listen_addr);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transparent proxy not supported on this platform",
        ))
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpStream;

    // From <net/pfvar.h>
    const DIOCNATLOOK: libc::c_ulong = 0xC0544417;

    // pf address type
    const PF_ADDR_IPV4: u8 = 2; // AF_INET

    /// pf address union — we only handle IPv4 for now.
    #[repr(C)]
    #[derive(Copy, Clone)]
    union PfAddr {
        v4: libc::in_addr,
        v6: libc::in6_addr,
    }

    impl Default for PfAddr {
        fn default() -> Self {
            PfAddr {
                v6: unsafe { mem::zeroed() },
            }
        }
    }

    /// Mirrors `struct pfioc_natlook` from <net/pfvar.h>.
    /// The exact layout is ABI-sensitive; fields are ordered to match the kernel struct.
    #[repr(C)]
    #[derive(Default)]
    struct PfiocNatlook {
        saddr: PfAddr,
        daddr: PfAddr,
        rsaddr: PfAddr,
        rdaddr: PfAddr,
        sxport: [u8; 2], // source port (network byte order)
        dxport: [u8; 2], // dest port (network byte order)
        rsxport: [u8; 2],
        rdxport: [u8; 2],
        af: u8,    // address family
        proto: u8, // protocol (IPPROTO_TCP)
        proto_variant: u8,
        direction: u8, // PF_IN or PF_OUT
    }

    pub fn get_original_dst(stream: &TcpStream, listen_addr: SocketAddr) -> io::Result<SocketAddr> {
        let peer = stream.peer_addr().map_err(io::Error::other)?;

        // We only support IPv4 currently
        let (peer_ip, peer_port) = match peer {
            SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
            SocketAddr::V6(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "IPv6 transparent proxy not yet supported on macOS",
                ));
            }
        };

        let listen_port = listen_addr.port();

        let pf_fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/pf")?;

        let mut nl = PfiocNatlook {
            af: PF_ADDR_IPV4,
            proto: libc::IPPROTO_TCP as u8,
            direction: 1, // PF_IN
            ..Default::default()
        };

        // Source: the connecting client
        nl.saddr.v4 = libc::in_addr {
            s_addr: u32::from(peer_ip).to_be(),
        };
        nl.sxport = peer_port.to_be_bytes();

        // Destination: the listen address (after redirection)
        let listen_ip = match listen_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => Ipv4Addr::LOCALHOST,
        };
        nl.daddr.v4 = libc::in_addr {
            s_addr: u32::from(listen_ip).to_be(),
        };
        nl.dxport = listen_port.to_be_bytes();

        let ret =
            unsafe { libc::ioctl(pf_fd.as_raw_fd(), DIOCNATLOOK, &mut nl as *mut PfiocNatlook) };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        // Extract original destination from rdaddr/rdxport
        let orig_ip = unsafe {
            let s_addr = nl.rdaddr.v4.s_addr;
            Ipv4Addr::from(u32::from_be(s_addr))
        };
        let orig_port = u16::from_be_bytes(nl.rdxport);

        Ok(SocketAddr::new(IpAddr::V4(orig_ip), orig_port))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpStream;

    const SO_ORIGINAL_DST: libc::c_int = 80;
    const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

    pub fn get_original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
        let fd = stream.as_ref().as_raw_fd();

        // Try IPv4 first
        let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret == 0 {
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            return Ok(SocketAddr::new(IpAddr::V4(ip), port));
        }

        // Try IPv6
        let mut addr6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        let mut len6: libc::socklen_t = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

        let ret6 = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                IP6T_SO_ORIGINAL_DST,
                &mut addr6 as *mut _ as *mut libc::c_void,
                &mut len6,
            )
        };

        if ret6 == 0 {
            let ip = Ipv6Addr::from(addr6.sin6_addr.s6_addr);
            let port = u16::from_be(addr6.sin6_port);
            return Ok(SocketAddr::new(IpAddr::V6(ip), port));
        }

        Err(io::Error::last_os_error())
    }
}
