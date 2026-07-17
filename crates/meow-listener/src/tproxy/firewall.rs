use std::io;
use std::net::IpAddr;
use tracing::{info, warn};

// Needed by `writeln!` in the `build_*` functions which are compiled under
// `#[cfg(test)]` on every platform for unit testing.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::fmt::Write as _;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

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

/// Build the pf anchor ruleset that the macOS code path feeds to `pfctl`.
///
/// Order matters, but NOT as first-match-wins: `pfctl` requires rules grouped
/// by category — options, normalization, queueing, **translation** (`rdr`),
/// then **filtering** (`pass`/`block`) — and rejects a file that interleaves
/// them ("Rules must be in order…"). So the `rdr` translation rule must come
/// first, followed by the `pass` filter bypasses. (Translation and filtering
/// are evaluated in separate passes regardless of file order, so the relative
/// position of `rdr` vs `pass` does not change matching — only validity.)
///
/// Extracted as a pure function so the macOS-specific syntax can be unit
/// tested without invoking `pfctl(8)`.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn build_pf_ruleset(uid: u32, listen_port: u16, bypass_ips: &[IpAddr]) -> String {
    // Translation first: redirect lo0 TCP to the local tproxy listener.
    let mut rules =
        format!("rdr pass on lo0 proto tcp from any to any -> 127.0.0.1 port {listen_port}\n");
    // Then filtering bypasses (our own uid, loopback, upstream proxy servers).
    let _ = writeln!(
        rules,
        "pass out quick on lo0 proto tcp from any to any user {uid}"
    );
    rules.push_str("pass out quick on lo0 proto tcp from any to 127.0.0.0/8\n");
    for ip in bypass_ips {
        let _ = writeln!(rules, "pass out quick on lo0 proto tcp from any to {ip}");
    }
    rules
}

#[cfg(target_os = "macos")]
impl PlatformGuard {
    fn setup(
        listen_port: u16,
        _routing_mark: Option<u32>,
        bypass_ips: &[IpAddr],
    ) -> io::Result<Self> {
        // Nest under `com.apple/` so the default `/etc/pf.conf`'s
        // `rdr-anchor "com.apple/*"` actually evaluates our rules. A sibling
        // anchor (e.g. `com.meow.tproxy`) loads fine but is never referenced by
        // the active ruleset, so its `rdr` never takes effect (verified: a
        // sibling anchor does not intercept; a `com.apple/*` child does).
        let anchor = "com.apple/com.meow.tproxy".to_string();
        let uid = unsafe { libc::getuid() };

        let rules = build_pf_ruleset(uid, listen_port, bypass_ips);

        let tmp_path = format!("/tmp/meow_tproxy_{pid}.conf", pid = std::process::id());
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

/// Build the nftables ruleset that the Linux code path feeds to `nft -f -`.
///
/// Order of chain rules (top-to-bottom, first match wins):
///   1. Skip marked packets — `meta mark` matches the SO_MARK that
///      `DirectAdapter` puts on its own outbound sockets, breaking the
///      "DIRECT redirects back into the tunnel" loop.
///   2. Loopback bypass (`127.0.0.0/8` and `::1`).
///   3. Per-IP bypass for upstream proxy servers (so meow-rs can reach them).
///   4. Catch-all redirect to `:{listen_port}`.
///
/// Extracted as a pure function so the syntactic shape of the ruleset can be
/// unit tested without invoking `nft(8)` — and a regression that drops, say,
/// the mark-bypass rule (which would silently relay DIRECT traffic through
/// the tunnel) gets caught in CI.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn build_nft_ruleset(
    table: &str,
    listen_port: u16,
    routing_mark: Option<u32>,
    bypass_ips: &[IpAddr],
) -> String {
    let mut bypass_rules = String::new();
    for ip in bypass_ips {
        // In an `inet` table the L3 protocol must be selected explicitly:
        // `ip daddr` only parses IPv4 literals and `ip6 daddr` only IPv6.
        // Emitting `ip daddr <v6>` is a parse error that makes `nft -f -`
        // reject the *entire* ruleset, so the tproxy listener fails to start
        // whenever a proxy host resolves to an IPv6 address.
        match ip {
            IpAddr::V4(v4) => {
                writeln!(bypass_rules, "    ip daddr {v4} accept").expect("write to String");
            }
            IpAddr::V6(v6) => {
                writeln!(bypass_rules, "    ip6 daddr {v6} accept").expect("write to String");
            }
        }
    }
    let mark_rule = match routing_mark {
        Some(mark) => format!("    meta mark 0x{mark:x} accept\n"),
        None => String::new(),
    };
    format!(
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
        table = table,
        mark_rule = mark_rule,
        bypass = bypass_rules,
        port = listen_port,
    )
}

#[cfg(target_os = "linux")]
impl PlatformGuard {
    fn setup(
        listen_port: u16,
        routing_mark: Option<u32>,
        bypass_ips: &[IpAddr],
    ) -> io::Result<Self> {
        let table_name = "meow_tproxy".to_string();
        let ruleset = build_nft_ruleset(&table_name, listen_port, routing_mark, bypass_ips);

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

    #[allow(
        clippy::unnecessary_wraps,
        reason = "matches PlatformGuard API on supported platforms"
    )]
    fn teardown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ─── nftables ───────────────────────────────────────────────────────────

    #[test]
    fn nft_ruleset_contains_expected_skeleton() {
        let rs = build_nft_ruleset("meow_tproxy", 7893, None, &[]);
        assert!(rs.contains("table inet meow_tproxy {"));
        assert!(rs.contains("chain output {"));
        assert!(rs.contains("type nat hook output priority -100; policy accept;"));
        assert!(rs.contains("tcp dport 1-65535 redirect to :7893"));
        // Loopback bypass is non-negotiable — a regression here would
        // recurse the redirect into infinity.
        assert!(rs.contains("ip daddr 127.0.0.0/8 accept"));
        assert!(rs.contains("ip6 daddr ::1 accept"));
    }

    #[test]
    fn nft_routing_mark_emits_meta_mark_rule_in_hex() {
        let rs = build_nft_ruleset("t", 1234, Some(0x42), &[]);
        assert!(
            rs.contains("meta mark 0x42 accept"),
            "mark bypass missing or wrong format:\n{rs}"
        );
    }

    #[test]
    fn nft_no_routing_mark_omits_mark_rule() {
        let rs = build_nft_ruleset("t", 1234, None, &[]);
        assert!(
            !rs.contains("meta mark"),
            "mark rule must not appear when routing_mark is None:\n{rs}"
        );
    }

    #[test]
    fn nft_mark_bypass_appears_before_redirect_catch_all() {
        // pf is first-match-wins; nftables `accept` short-circuits the chain.
        // The mark-bypass must appear ABOVE the catch-all redirect, otherwise
        // every DIRECT-marked packet gets redirected into the tunnel.
        let rs = build_nft_ruleset("t", 7893, Some(0xabcd), &[]);
        let mark_pos = rs.find("meta mark 0xabcd accept").unwrap();
        let redirect_pos = rs.find("tcp dport 1-65535 redirect").unwrap();
        assert!(
            mark_pos < redirect_pos,
            "mark bypass must precede redirect:\n{rs}"
        );
    }

    #[test]
    fn nft_bypass_ips_are_emitted_for_v4_and_v6() {
        let bypass = [
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ];
        let rs = build_nft_ruleset("t", 1, None, &bypass);
        assert!(rs.contains("ip daddr 1.2.3.4 accept"));
        // IPv6 bypass IPs must use `ip6 daddr` — `ip daddr <v6>` is a parse
        // error that aborts the whole `nft -f -` load.
        assert!(rs.contains("ip6 daddr 2001:db8::1 accept"));
        assert!(
            !rs.contains("ip daddr 2001:db8::1"),
            "IPv6 address must not follow `ip daddr`:\n{rs}"
        );
    }

    // ─── pf (macOS) ─────────────────────────────────────────────────────────

    #[test]
    fn pf_ruleset_contains_uid_bypass_and_redirect() {
        let rs = build_pf_ruleset(501, 7893, &[]);
        assert!(
            rs.contains("pass out quick on lo0 proto tcp from any to any user 501"),
            "UID bypass missing:\n{rs}"
        );
        assert!(rs.contains("pass out quick on lo0 proto tcp from any to 127.0.0.0/8"));
        assert!(rs.contains("rdr pass on lo0 proto tcp from any to any -> 127.0.0.1 port 7893"));
    }

    #[test]
    fn pf_rdr_precedes_filter_rules() {
        // pfctl rejects a ruleset that places filtering (`pass`) before
        // translation (`rdr`) — "Rules must be in order: …, translation,
        // filtering". The `rdr` must therefore come first, or the anchor fails
        // to load and the tproxy listener never starts (regression guard).
        let rs = build_pf_ruleset(501, 7893, &[]);
        let rdr_pos = rs.find("rdr pass").unwrap();
        let uid_pos = rs.find("user 501").unwrap();
        assert!(rdr_pos < uid_pos, "rdr must precede filter rules:\n{rs}");
    }

    #[test]
    fn pf_bypass_ips_are_emitted() {
        let bypass = [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let rs = build_pf_ruleset(501, 7893, &bypass);
        assert!(rs.contains("pass out quick on lo0 proto tcp from any to 1.1.1.1"));
    }
}
