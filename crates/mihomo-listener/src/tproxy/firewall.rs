use std::fmt::Write as _;
use std::io;
use std::net::IpAddr;
use std::process::Command;
use tracing::{info, warn};

/// RAII guard that sets up firewall redirect rules on creation
/// and tears them down on drop.
pub struct FirewallGuard {
    inner: PlatformGuard,
}

impl FirewallGuard {
    /// Set up firewall rules to redirect local TCP traffic to the given port.
    ///
    /// Loop avoidance:
    /// - **Linux**: `meta mark` matching — DIRECT adapter sets SO_MARK on outbound sockets,
    ///   nftables skips packets with that mark. Plus IP bypass for upstream proxy servers.
    /// - **macOS**: `user` UID matching (pf has no mark support) + IP bypass.
    pub fn setup(
        listen_port: u16,
        routing_mark: Option<u32>,
        bypass_ips: &[IpAddr],
    ) -> io::Result<Self> {
        info!(
            "Setting up transparent proxy firewall rules (port={}, mark={:?}, bypass={})",
            listen_port,
            routing_mark,
            bypass_ips.len()
        );
        let inner = PlatformGuard::setup(listen_port, routing_mark, bypass_ips)?;
        Ok(FirewallGuard { inner })
    }

    /// Explicitly tear down the firewall rules.
    pub fn teardown(&mut self) -> io::Result<()> {
        self.inner.teardown()
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        if let Err(e) = self.teardown() {
            warn!("Failed to teardown firewall rules: {e}");
        }
    }
}

// ── macOS (pf) ──────────────────────────────────────────────────────────────
// pf has no packet mark support, so we use UID-based bypass.

#[cfg(target_os = "macos")]
struct PlatformGuard {
    anchor: String,
    torn_down: bool,
}

#[cfg(target_os = "macos")]
impl PlatformGuard {
    fn setup(
        listen_port: u16,
        _routing_mark: Option<u32>,
        bypass_ips: &[IpAddr],
    ) -> io::Result<Self> {
        let anchor = "com.mihomo.tproxy".to_string();
        let uid = unsafe { libc::getuid() };

        // pf anchor rules (order matters — first match wins):
        // 1. Skip traffic from our own UID (DIRECT loop avoidance; pf has no mark support)
        // 2. Skip loopback traffic
        // 3. Skip traffic destined to upstream proxy servers
        // 4. Redirect all other outgoing TCP to our listener port
        let mut rules = format!("pass out quick on lo0 proto tcp from any to any user {uid}\n");
        rules.push_str("pass out quick on lo0 proto tcp from any to 127.0.0.0/8\n");
        for ip in bypass_ips {
            let _ = writeln!(rules, "pass out quick on lo0 proto tcp from any to {ip}");
        }
        let _ = writeln!(
            rules,
            "rdr pass on lo0 proto tcp from any to any -> 127.0.0.1 port {listen_port}",
        );

        let tmp_path = format!("/tmp/mihomo_tproxy_{pid}.conf", pid = std::process::id());
        std::fs::write(&tmp_path, &rules)?;

        let output = Command::new("pfctl")
            .args(["-a", &anchor, "-f", &tmp_path])
            .output()?;

        let _ = std::fs::remove_file(&tmp_path);

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!(
                "pfctl load anchor failed: {stderr}"
            )));
        }

        let _ = Command::new("pfctl").arg("-e").output();

        info!(
            "pf anchor '{}' loaded (uid={}, {} bypass IPs)",
            anchor,
            uid,
            bypass_ips.len()
        );
        Ok(PlatformGuard {
            anchor,
            torn_down: false,
        })
    }

    fn teardown(&mut self) -> io::Result<()> {
        if self.torn_down {
            return Ok(());
        }
        self.torn_down = true;

        let output = Command::new("pfctl")
            .args(["-a", &self.anchor, "-F", "all"])
            .output()?;

        if output.status.success() {
            info!("pf anchor '{anchor}' flushed", anchor = self.anchor);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("pfctl flush anchor failed: {stderr}");
        }
        Ok(())
    }
}

// ── Linux (nftables) ────────────────────────────────────────────────────────
// Uses SO_MARK matching — DIRECT adapter marks its outbound sockets,
// nftables skips packets carrying that mark.

#[cfg(target_os = "linux")]
struct PlatformGuard {
    table_name: String,
    torn_down: bool,
}

#[cfg(target_os = "linux")]
impl PlatformGuard {
    fn setup(
        listen_port: u16,
        routing_mark: Option<u32>,
        bypass_ips: &[IpAddr],
    ) -> io::Result<Self> {
        let table_name = "mihomo_tproxy".to_string();

        let mut bypass_rules = String::new();
        for ip in bypass_ips {
            writeln!(bypass_rules, "    ip daddr {ip} accept").expect("write to String");
        }

        // Mark-based bypass for DIRECT connections (SO_MARK set by DirectAdapter)
        let mark_rule = match routing_mark {
            Some(mark) => format!("    meta mark 0x{mark:x} accept\n"),
            None => String::new(),
        };

        // nftables ruleset:
        // 1. Skip marked packets (DIRECT adapter's outbound, avoids loop)
        // 2. Skip loopback traffic
        // 3. Skip traffic destined to upstream proxy servers
        // 4. Redirect all other outgoing TCP
        let ruleset = format!(
            concat!(
                "table inet {table} {{\n",
                "  chain output {{\n",
                "    type nat hook output priority -100; policy accept;\n",
                "{mark_rule}",
                "    ip daddr 127.0.0.0/8 accept\n",
                "    ip6 daddr ::1 accept\n",
                "{bypass}",
                "    tcp dport 1-65535 redirect to :{port}\n",
                "  }}\n",
                "}}\n",
            ),
            table = table_name,
            mark_rule = mark_rule,
            bypass = bypass_rules,
            port = listen_port,
        );

        let output = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(ruleset.as_bytes())?;
                child.wait_with_output()
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!("nft load rules failed: {stderr}")));
        }

        info!(
            "nftables table '{}' created (mark={:?}, {} bypass IPs)",
            table_name,
            routing_mark,
            bypass_ips.len()
        );
        Ok(PlatformGuard {
            table_name,
            torn_down: false,
        })
    }

    fn teardown(&mut self) -> io::Result<()> {
        if self.torn_down {
            return Ok(());
        }
        self.torn_down = true;

        let output = Command::new("nft")
            .args(["delete", "table", "inet", &self.table_name])
            .output()?;

        if output.status.success() {
            info!("nftables table '{name}' deleted", name = self.table_name);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("nft delete table failed: {stderr}");
        }
        Ok(())
    }
}

// ── Unsupported platforms ───────────────────────────────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
struct PlatformGuard;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl PlatformGuard {
    fn setup(
        _listen_port: u16,
        _routing_mark: Option<u32>,
        _bypass_ips: &[IpAddr],
    ) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transparent proxy firewall not supported on this platform",
        ))
    }

    fn teardown(&mut self) -> io::Result<()> {
        Ok(())
    }
}
