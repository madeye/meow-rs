//! Platform-specific lookup: which local process owns a given socket?
//!
//! The rule engine calls [`find_process`] for PROCESS-NAME / PROCESS-PATH /
//! UID rules. It receives the connection's local (client-side) address and
//! returns the owning process, if any. Returns `None` on platforms that are
//! not yet supported (everything except Linux and macOS).

use crate::network::Network;
use std::net::SocketAddr;

#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub name: String,
    pub path: String,
    pub uid: Option<u32>,
}

/// Look up the process that owns the socket bound to `local_addr`. `local_addr`
/// is the socket endpoint as seen by meow-rs's inbound — i.e. the client's
/// source address when it connected to the proxy listener.
pub fn find_process(network: Network, local_addr: SocketAddr) -> Option<ProcessInfo> {
    platform::find_process(network, local_addr)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Network, ProcessInfo, SocketAddr};
    use std::fs;
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use tracing::trace;

    pub fn find_process(network: Network, local: SocketAddr) -> Option<ProcessInfo> {
        let (files, ipv6) = match (network, local.is_ipv4()) {
            (Network::Tcp, true) => (vec!["/proc/net/tcp"], false),
            (Network::Tcp, false) => (vec!["/proc/net/tcp6"], true),
            (Network::Udp, true) => (vec!["/proc/net/udp"], false),
            (Network::Udp, false) => (vec!["/proc/net/udp6"], true),
        };

        let mut inode_uid = None;
        for path in &files {
            if let Some(pair) = scan_proc_net(path, local, ipv6) {
                inode_uid = Some(pair);
                break;
            }
        }
        let (inode, uid) = inode_uid?;
        trace!(inode, uid, "process_lookup: matched /proc/net entry");
        let (_pid, name, exe) = find_pid_by_inode(inode)?;
        Some(ProcessInfo {
            name,
            path: exe,
            uid: Some(uid),
        })
    }

    fn scan_proc_net(path: &str, target: SocketAddr, ipv6: bool) -> Option<(u64, u32)> {
        let mut buf = String::new();
        fs::File::open(path).ok()?.read_to_string(&mut buf).ok()?;
        // Header is the first line; data starts on line 2.
        for line in buf.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // local_address is col 1, uid col 7, inode col 9 for the tcp/udp tables.
            if cols.len() < 10 {
                continue;
            }
            let local = cols[1];
            let (addr_hex, port_hex) = local.split_once(':')?;
            let port = u16::from_str_radix(port_hex, 16).ok()?;
            if port != target.port() {
                continue;
            }
            let addr = if ipv6 {
                parse_hex_ipv6(addr_hex)?
            } else {
                parse_hex_ipv4(addr_hex)?
            };
            if !addr_matches(addr, target.ip()) {
                continue;
            }
            let uid: u32 = cols[7].parse().ok()?;
            let inode: u64 = cols[9].parse().ok()?;
            return Some((inode, uid));
        }
        None
    }

    fn parse_hex_ipv4(s: &str) -> Option<IpAddr> {
        // /proc/net/tcp encodes the address as a little-endian 32-bit hex.
        // "0100007F" == 0x7F000001 == 127.0.0.1.
        if s.len() != 8 {
            return None;
        }
        let v = u32::from_str_radix(s, 16).ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(v.swap_bytes())))
    }

    fn parse_hex_ipv6(s: &str) -> Option<IpAddr> {
        if s.len() != 32 {
            return None;
        }
        // Eight 32-bit little-endian groups.
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let word_hex = &s[i * 8..(i + 1) * 8];
            let word = u32::from_str_radix(word_hex, 16).ok()?.swap_bytes();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    }

    fn addr_matches(found: IpAddr, target: IpAddr) -> bool {
        if found == target {
            return true;
        }
        // Kernel often reports the wildcard address (0.0.0.0 / ::) or the
        // IPv4-mapped form when the socket was opened on IPv6. Accept those.
        match (found, target) {
            (IpAddr::V4(f), _) if f.is_unspecified() => true,
            (IpAddr::V6(f), _) if f.is_unspecified() => true,
            (IpAddr::V6(f), IpAddr::V4(t)) => f.to_ipv4_mapped() == Some(t),
            _ => false,
        }
    }

    fn find_pid_by_inode(inode: u64) -> Option<(u32, String, String)> {
        let needle = format!("socket:[{inode}]");
        for entry in fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let fd_dir: PathBuf = entry.path().join("fd");
            let Ok(rd) = fs::read_dir(&fd_dir) else {
                continue;
            };
            for fd in rd.flatten() {
                if let Ok(link) = fs::read_link(fd.path()) {
                    if link.to_string_lossy() == needle {
                        let exe_link = fs::read_link(entry.path().join("exe")).ok();
                        // `/proc/<pid>/comm` is truncated to TASK_COMM_LEN-1 = 15
                        // chars, which mangles long binary names (e.g. cargo test
                        // harnesses like `meow_tunnel-<16hex>`). Prefer the
                        // basename of `/proc/<pid>/exe` and fall back to comm only
                        // when exe is unreadable (kernel threads, perm denied).
                        let name = exe_link
                            .as_ref()
                            .and_then(|p| p.file_name())
                            .map(|s| s.to_string_lossy().into_owned())
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| {
                                fs::read_to_string(entry.path().join("comm"))
                                    .unwrap_or_default()
                                    .trim()
                                    .to_string()
                            });
                        let exe = exe_link
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        return Some((pid, name, exe));
                    }
                }
            }
        }
        None
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{Network, ProcessInfo, SocketAddr};
    use libproc::libproc::bsd_info::BSDInfo;
    use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
    use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
    use libproc::libproc::proc_pid::{listpidinfo, pidinfo, pidpath};
    use libproc::processes::{pids_by_type, ProcFilter};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tracing::trace;

    pub fn find_process(network: Network, local: SocketAddr) -> Option<ProcessInfo> {
        let pids = pids_by_type(ProcFilter::All).ok()?;
        for pid in pids {
            if pid == 0 {
                continue;
            }
            let pid = pid as i32;
            let Ok(info) = pidinfo::<BSDInfo>(pid, 0) else {
                continue;
            };
            let fd_count = info.pbi_nfiles as usize;
            let Ok(fds) = listpidinfo::<ListFDs>(pid, fd_count) else {
                continue;
            };
            for fd in fds {
                if fd.proc_fdtype != ProcFDType::Socket as u32 {
                    continue;
                }
                let Ok(sfd) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) else {
                    continue;
                };
                let sinfo = sfd.psi.soi_proto;
                let kind = SocketInfoKind::from(sfd.psi.soi_kind);
                if !matches_socket(network, local, kind, &sinfo) {
                    continue;
                }
                trace!(pid, "process_lookup: matched socket via libproc");
                let name = pidpath(pid)
                    .ok()
                    .and_then(|p| p.rsplit('/').next().map(std::string::ToString::to_string))
                    .unwrap_or_default();
                let path = pidpath(pid).unwrap_or_default();
                let uid = unsafe {
                    let mut pinfo: libc::proc_bsdinfo = std::mem::zeroed();
                    let ret = libc::proc_pidinfo(
                        pid,
                        libc::PROC_PIDTBSDINFO,
                        0,
                        &mut pinfo as *mut _ as *mut libc::c_void,
                        std::mem::size_of::<libc::proc_bsdinfo>() as i32,
                    );
                    if ret as usize == std::mem::size_of::<libc::proc_bsdinfo>() {
                        Some(pinfo.pbi_uid)
                    } else {
                        None
                    }
                };
                return Some(ProcessInfo { name, path, uid });
            }
        }
        None
    }

    fn matches_socket(
        network: Network,
        local: SocketAddr,
        kind: SocketInfoKind,
        sinfo: &libproc::libproc::net_info::SocketInfoProto,
    ) -> bool {
        unsafe {
            match (network, kind) {
                (Network::Tcp, SocketInfoKind::Tcp) => {
                    let tcp = &sinfo.pri_tcp;
                    sock_matches(local, tcp.tcpsi_ini.insi_lport, &tcp.tcpsi_ini)
                }
                (Network::Udp, SocketInfoKind::In) => {
                    let ini = &sinfo.pri_in;
                    sock_matches(local, ini.insi_lport, ini)
                }
                _ => false,
            }
        }
    }

    fn sock_matches(
        target: SocketAddr,
        lport_net: i32,
        ini: &libproc::libproc::net_info::InSockInfo,
    ) -> bool {
        // `insi_lport` stores the port in network byte order in the low 16 bits.
        let port = (lport_net as u16).swap_bytes();
        if port != target.port() {
            return false;
        }
        // insi_vflag: 0x1 = IPv4, 0x2 = IPv6.
        let is_v6 = ini.insi_vflag & 0x2 != 0;
        let found_ip = unsafe {
            if is_v6 {
                IpAddr::V6(Ipv6Addr::from(ini.insi_laddr.ina_6.s6_addr))
            } else {
                let raw = ini.insi_laddr.ina_46.i46a_addr4.s_addr;
                IpAddr::V4(Ipv4Addr::from(u32::from_be(raw)))
            }
        };
        addr_matches(found_ip, target.ip())
    }

    fn addr_matches(found: IpAddr, target: IpAddr) -> bool {
        if found == target {
            return true;
        }
        match (found, target) {
            (IpAddr::V4(f), _) if f.is_unspecified() => true,
            (IpAddr::V6(f), _) if f.is_unspecified() => true,
            (IpAddr::V6(f), IpAddr::V4(t)) => f.to_ipv4_mapped() == Some(t),
            _ => false,
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use super::{Network, ProcessInfo, SocketAddr};

    pub fn find_process(_network: Network, _local: SocketAddr) -> Option<ProcessInfo> {
        // Process lookup is not yet implemented for this platform. PROCESS-NAME,
        // PROCESS-PATH and UID rules will silently fail to match until it is.
        None
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn finds_self_via_tcp_listener() {
        // Bind a TCP listener on 127.0.0.1:<ephemeral> and then ask
        // `find_process` who owns that endpoint — it must be this test binary.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let info = find_process(Network::Tcp, addr)
            .expect("process lookup should locate the current test process");
        assert!(info.uid.is_some(), "uid should be populated");
        // Exact-match guard-rail: the returned name must equal the full test
        // binary filename. On Linux this catches `/proc/<pid>/comm` truncation
        // (TASK_COMM_LEN=16 → 15-char cap) which mangles `<crate>-<16hex>`
        // cargo-test harness names — the bug fixed by 65f19e5.
        let expected = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .expect("current_exe should be readable in tests");
        assert_eq!(info.name, expected, "process name must not be truncated");
    }

    #[test]
    fn finds_self_via_udp_socket() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let info = find_process(Network::Udp, addr)
            .expect("process lookup should locate the current test process for UDP");
        assert!(!info.name.is_empty());
    }

    #[test]
    fn unknown_endpoint_returns_none() {
        // Port 1 is reserved and should not be bound by any test-run process.
        let fake = "127.0.0.1:1".parse().unwrap();
        assert!(find_process(Network::Tcp, fake).is_none());
    }
}
