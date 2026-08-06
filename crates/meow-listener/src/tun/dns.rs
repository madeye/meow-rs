//! OS DNS resolver configuration for the TUN inbound.
//!
//! When `dns-hijack` is active, the OS resolver must be pointed at a
//! DNS server that returns fake IPs.  On macOS/Linux this is the fake-IP
//! gateway (e.g. `198.18.0.1`) — queries enter the TUN device and are
//! answered by `dns-hijack`.  On Windows a local DNS server
//! (`tun/local_dns.rs`) is bound to `127.0.0.1:53` and `[::1]:53`, and
//! the system DNS is set to those loopback addresses.
//!
//! `DnsGuard` backs up the current resolver configuration at startup,
//! installs the DNS server addresses on all active adapters, and
//! restores the original configuration on drop.
//!
//! Individual failures are logged and skipped: a DNS configuration error
//! does not abort the TUN listener startup, and a recovery failure is
//! similarly non-fatal.

use std::net::IpAddr;
use tracing::{debug, warn};

/// RAII guard that restores original DNS settings on drop.
///
/// When created, it saves the current OS DNS state and replaces it with
/// the loopback DNS addresses on all active network interfaces. On drop,
/// the original configuration is restored. Failed operations are logged
/// at `warn!` level rather than panicking.
pub(super) struct DnsGuard {
    #[cfg(target_os = "windows")]
    backup: String,
    #[cfg(target_os = "macos")]
    backup: Vec<(String, Vec<String>)>,
    #[cfg(target_os = "linux")]
    backup: Option<linux::ResolvConfBackup>,
}

impl DnsGuard {
    /// Save current DNS settings and set all interfaces to `dns_addr`.
    /// Returns `None` on platforms without a supported backend, or when
    /// the backup fails.
    ///
    /// On Windows `dns_addr` is ignored — the system DNS is always set
    /// to `127.0.0.1` (IPv4) and `::1` (IPv6) so queries reach the
    /// local DNS server (`tun/local_dns.rs`).
    pub(super) fn setup(dns_addr: IpAddr) -> Option<Self> {
        #[cfg(target_os = "windows")]
        {
            let _ = dns_addr;
            match windows::backup() {
                Ok(backup) => {
                    if let Err(e) = windows::set_all() {
                        warn!("tun dns-guard: failed to set DNS: {e}");
                    }
                    windows::clear_dns_cache();
                    debug!("tun dns-guard: DNS set to 127.0.0.1 / ::1 (loopback)");
                    Some(Self { backup })
                }
                Err(e) => {
                    warn!("tun dns-guard: failed to back up DNS settings: {e}");
                    None
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            match macos::backup(dns_addr) {
                Ok(backup) => {
                    if let Err(e) = macos::set_all(dns_addr) {
                        warn!("tun dns-guard: failed to set DNS to {dns_addr}: {e}");
                    }
                    debug!("tun dns-guard: DNS set to {dns_addr} on all network services");
                    Some(Self { backup })
                }
                Err(e) => {
                    warn!("tun dns-guard: failed to back up DNS settings: {e}");
                    None
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            match linux::backup_and_set(dns_addr) {
                Ok(backup) => {
                    debug!("tun dns-guard: DNS set to {dns_addr} in /etc/resolv.conf");
                    Some(Self {
                        backup: Some(backup),
                    })
                }
                Err(e) => {
                    warn!("tun dns-guard: failed to configure DNS: {e}");
                    None
                }
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            let _ = dns_addr;
            debug!("tun dns-guard: no DNS backend for this platform; skipping");
            None
        }
    }
}

// Restore runs synchronously in Drop — deliberately. `Tunnel::stop_tun`
// awaits the aborted task, so a config-reload disable→enable cannot start a
// new backup until this restore has finished; offloading to another thread
// would open that race, and the process-exit path must block anyway or the
// restore is lost. The Windows work is batched into two PowerShell
// invocations (reset-all + restore) plus a cache flush to keep the blocked
// interval short.
impl Drop for DnsGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            // Safety net: reset all adapters to DHCP first, so no
            // 127.0.0.1 or ::1 leftovers survive even if an adapter
            // wasn't captured in the backup.
            if let Err(e) = windows::reset_all_dns() {
                warn!("tun dns-guard: failed to reset all DNS to DHCP: {e}");
            }

            let backup_len = self.backup.len();
            if let Err(e) = windows::restore(&self.backup) {
                warn!(
                    "tun dns-guard: failed to restore DNS settings (backup {} bytes): {e}",
                    backup_len
                );
            } else {
                tracing::info!(
                    "tun dns-guard: DNS settings restored (backup {} bytes)",
                    backup_len
                );
            }
            windows::clear_dns_cache();
        }
        #[cfg(target_os = "macos")]
        {
            macos::restore(&self.backup);
            debug!("tun dns-guard: DNS settings restored");
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(backup) = self.backup.take() {
                if let Err(e) = linux::restore(&backup) {
                    warn!("tun dns-guard: failed to restore /etc/resolv.conf: {e}");
                } else {
                    debug!("tun dns-guard: /etc/resolv.conf restored");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows backend — local DNS server on loopback
//
// Sets IPv4 DNS to 127.0.0.1 and IPv6 DNS to ::1 on all adapters.
// A local DNS server (tun/local_dns.rs) bound to these addresses
// answers queries using the same DnsServer::handle_query pipeline as
// the TUN dns-hijack path, returning fake IPs.
//
// This avoids all the problems with previous approaches:
// - No need to clear IPv6 DNS (WSL/Docker re-inject fec0:0:0:ffff::*)
// - No firewall rules (which didn't actually block the queries)
// - No ::1 loopback redirect without a listener (caused ECONNRESET)
// - Both IPv4 and IPv6 queries are handled directly
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows {
    use std::process::Command;

    const IPV6_SEPARATOR: &str = "---IPV6---";
    /// Firewall rule name from the previous (abandoned) approach.
    /// Cleaned up on startup to avoid leftover rules.
    const LEGACY_FW_RULE_NAME: &str = "meow-rs TUN IPv6 DNS Block";

    /// Back up the *statically configured* DNS on all adapters (both IPv4
    /// and IPv6), read from the registry `NameServer` values.
    ///
    /// `Get-DnsClientServerAddress` reports the *effective* servers with no
    /// DHCP/static distinction — restoring its output would statically pin a
    /// snapshot of DHCP-assigned values on adapters that should keep
    /// following DHCP. Only static entries need restoring; every other
    /// adapter is covered by the reset-to-DHCP pass in `DnsGuard::drop`.
    ///
    /// Returns a combined encoding:
    ///   IPv4 lines (one per adapter: `InterfaceAlias|server1,server2,...`)
    ///   `---IPV6---`
    ///   IPv6 lines (same format)
    pub(super) fn backup() -> std::io::Result<String> {
        let v4 = strip_own_entries(&backup_family("Tcpip")?, "127.0.0.1");
        let v6 = strip_own_entries(&backup_family("Tcpip6")?, "::1");
        Ok(format!("{v4}\n{IPV6_SEPARATOR}\n{v6}"))
    }

    /// Drop adapter lines whose server list is exactly the address meow
    /// itself installs (`127.0.0.1` / `::1`). After an unclean shutdown
    /// (crash, SIGKILL, power loss) the previous run's loopback setting is
    /// still in place; backing it up would make a later clean exit
    /// "restore" the broken state permanently. Dropped adapters fall back
    /// to the reset-to-DHCP safety net in `DnsGuard::drop`.
    fn strip_own_entries(section: &str, own: &str) -> String {
        let mut kept = Vec::new();
        for line in section.lines() {
            let is_own = line
                .split_once('|')
                .is_some_and(|(_, servers)| servers.trim() == own);
            if is_own {
                super::warn!(
                    "tun dns-guard: adapter '{}' still points at {own} (leftover from an \
                     unclean shutdown?) — excluding it from the backup, it will be reset \
                     to DHCP on exit",
                    line.split('|').next().unwrap_or(line).trim()
                );
            } else {
                kept.push(line);
            }
        }
        kept.join("\n")
    }

    /// One line per adapter with a non-empty static `NameServer` registry
    /// value under `SYSTEM\CurrentControlSet\Services\<service>\Parameters\
    /// Interfaces\<guid>` — `service` is `Tcpip` (IPv4) or `Tcpip6` (IPv6).
    fn backup_family(service: &str) -> std::io::Result<String> {
        const TEMPLATE: &str = r#"Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { $g = "$($_.InterfaceGuid)"; if ($g -and $g[0] -ne '{') { $g = '{' + $g + '}' }; $ns = (Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\SVCNAME\Parameters\Interfaces\" + $g) -Name NameServer -ErrorAction SilentlyContinue).NameServer; if ($ns) { $_.InterfaceAlias + '|' + ($ns -replace '[ ;]', ',') } }"#;
        let script = TEMPLATE.replace("SVCNAME", service);
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Set IPv4 DNS to `127.0.0.1` and IPv6 DNS to `::1` on all adapters.
    ///
    /// `Set-DnsClientServerAddress` auto-detects the address family from
    /// the IP format, so `127.0.0.1` only touches IPv4 and `::1` only
    /// touches IPv6.
    pub(super) fn set_all() -> std::io::Result<()> {
        // Clean up any leftover firewall rule from the previous approach.
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Remove-NetFirewallRule -DisplayName '{LEGACY_FW_RULE_NAME}' -ErrorAction SilentlyContinue"
                ),
            ])
            .output();

        // Step 1: set IPv4 DNS to 127.0.0.1 on all adapters that have DNS.
        set_dns_on_all("127.0.0.1", "IPv4")?;

        // Step 2: set IPv6 DNS to ::1 on all adapters that have DNS.
        set_dns_on_all("::1", "IPv6")?;

        Ok(())
    }

    fn set_dns_on_all(addr: &str, family: &str) -> std::io::Result<()> {
        let cmd = format!(
            r#"Get-DnsClientServerAddress -AddressFamily {family} -ErrorAction SilentlyContinue | Where-Object {{$_.ServerAddresses.Count -gt 0}} | ForEach-Object {{ Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ServerAddresses ('{addr}') -ErrorAction SilentlyContinue }}"#
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if !stderr.is_empty() {
                return Err(std::io::Error::other(stderr));
            }
        }
        Ok(())
    }

    /// Flush the Windows DNS client cache so stale entries don't
    /// interfere with the new resolver configuration.
    pub(super) fn clear_dns_cache() {
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Clear-DnsClientCache -ErrorAction SilentlyContinue",
            ])
            .output();
    }

    /// Reset all adapters to DHCP-obtained DNS for both IPv4 and IPv6, in a
    /// single PowerShell invocation.
    ///
    /// Used as a safety net in `DnsGuard::drop()` to clear any leftover
    /// loopback DNS entries before restoring from the backup.
    pub(super) fn reset_all_dns() -> std::io::Result<()> {
        const SCRIPT: &str = r#"foreach ($fam in 'IPv4','IPv6') { Get-DnsClientServerAddress -AddressFamily $fam -ErrorAction SilentlyContinue | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ResetServerAddresses -ErrorAction SilentlyContinue } }"#;
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", SCRIPT])
            .output()?;
        check_ps_output(&output)
    }

    /// Restore DNS from the backup string produced by `backup()`.
    ///
    /// The string is split on `---IPV6---` into IPv4 and IPv6 sections; each
    /// line is `InterfaceAlias|server1,server2,...`. All entries are applied
    /// in one batched PowerShell invocation — process spawns dominate the
    /// cost here, and this runs on the teardown path (`DnsGuard::drop`, on
    /// whatever thread drops the TUN task). `Set-DnsClientServerAddress`
    /// auto-detects the address family from the IP format, so both sections
    /// batch into the same script.
    pub(super) fn restore(backup: &str) -> std::io::Result<()> {
        let script = build_restore_script(backup);
        if script.is_empty() {
            return Ok(());
        }

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()?;
        check_ps_output(&output)
    }

    /// Translate the backup string into one PowerShell script (one
    /// `Set-DnsClientServerAddress` line per adapter entry), logging each
    /// entry being restored.
    fn build_restore_script(backup: &str) -> String {
        use std::fmt::Write as _;

        let (v4_section, v6_section) = match backup.split_once(IPV6_SEPARATOR) {
            Some((v4, v6)) => (v4.trim(), v6.trim()),
            None => (backup.trim(), ""),
        };

        let mut script = String::new();
        for line in v4_section.lines().chain(v6_section.lines()) {
            let line = line.trim();
            let Some((iface, server_list)) = line.split_once('|') else {
                continue;
            };
            let iface = iface.trim();
            let servers: Vec<&str> = server_list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if iface.is_empty() || servers.is_empty() {
                continue;
            }
            let quoted: Vec<String> = servers
                .iter()
                .map(|s| format!("'{}'", escape_arg(s)))
                .collect();
            let _ = writeln!(
                script,
                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses ({}) -ErrorAction SilentlyContinue",
                escape_arg(iface),
                quoted.join(","),
            );
            tracing::info!(
                "tun dns-guard: restoring DNS on '{iface}' -> [{}]",
                servers.join(", ")
            );
        }
        script
    }

    fn check_ps_output(output: &std::process::Output) -> std::io::Result<()> {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let trimmed = stderr.trim();
            if !trimmed.is_empty() {
                return Err(std::io::Error::other(trimmed.to_string()));
            }
        }
        Ok(())
    }

    fn escape_arg(s: &str) -> String {
        s.replace('\'', "''")
    }

    // These run on the windows CI job (`cargo test -p meow-listener
    // --features listener-tun --lib`) — the whole module is
    // `cfg(target_os = "windows")`.
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn strip_drops_only_exact_own_entries() {
            let section = "Ethernet|127.0.0.1\nWi-Fi|10.0.0.1,127.0.0.1\nvEthernet|8.8.8.8";
            let kept = strip_own_entries(section, "127.0.0.1");
            // Poisoned line (exactly the address meow installs) dropped;
            // a list that merely *contains* 127.0.0.1 is user config — kept.
            assert_eq!(kept, "Wi-Fi|10.0.0.1,127.0.0.1\nvEthernet|8.8.8.8");
        }

        #[test]
        fn strip_drops_own_v6_entry() {
            let kept = strip_own_entries("Ethernet|::1\nEthernet 2|2400:3200::1", "::1");
            assert_eq!(kept, "Ethernet 2|2400:3200::1");
        }

        #[test]
        fn restore_script_batches_all_entries() {
            let backup =
                format!("Ethernet|8.8.8.8,1.1.1.1\n{IPV6_SEPARATOR}\nEthernet|2400:3200::1");
            let script = build_restore_script(&backup);
            let lines: Vec<&str> = script.lines().collect();
            assert_eq!(lines.len(), 2, "one Set- command per entry, one script");
            assert_eq!(
                lines[0],
                "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses ('8.8.8.8','1.1.1.1') -ErrorAction SilentlyContinue"
            );
            assert!(lines[1].contains("('2400:3200::1')"));
        }

        #[test]
        fn restore_script_escapes_quotes_and_skips_malformed_lines() {
            let script = build_restore_script(
                "It's Ethernet|9.9.9.9\nno-separator-line\n|1.2.3.4\nEthernet|",
            );
            let lines: Vec<&str> = script.lines().collect();
            assert_eq!(lines.len(), 1);
            assert!(
                lines[0].contains("'It''s Ethernet'"),
                "single quotes doubled"
            );
        }

        /// Read-only smoke test of the real PowerShell + registry backup
        /// path on the CI runner: must succeed and produce the documented
        /// line format. Catches PowerShell syntax or registry-path breakage
        /// that host-side compilation cannot.
        #[test]
        fn backup_runs_and_is_wellformed() {
            let backup = backup().expect("backup must succeed on a real Windows host");
            assert!(backup.contains(IPV6_SEPARATOR), "sections are separated");
            for line in backup.lines() {
                let line = line.trim();
                if line.is_empty() || line == IPV6_SEPARATOR {
                    continue;
                }
                assert!(
                    line.contains('|'),
                    "adapter line must be 'InterfaceAlias|servers': {line:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// macOS backend — networksetup
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::net::IpAddr;
    use std::process::Command;

    pub(super) fn backup(dns_addr: IpAddr) -> io::Result<Vec<(String, Vec<String>)>> {
        let services = list_services()?;
        let mut result = Vec::with_capacity(services.len());
        for svc in services {
            match get_dns(&svc) {
                Ok(servers) => {
                    // Never back up the fake-IP gateway meow itself installs:
                    // after an unclean shutdown it is still the active DNS, and
                    // keeping it would make a later clean exit "restore" the
                    // broken state. An emptied list restores to "Empty"
                    // (DHCP/automatic) instead.
                    let filtered: Vec<String> = servers
                        .into_iter()
                        .filter(|s| s.parse::<IpAddr>() != Ok(dns_addr))
                        .collect();
                    result.push((svc, filtered));
                }
                Err(e) => super::warn!("tun dns-guard: failed to get DNS for '{svc}': {e}"),
            }
        }
        Ok(result)
    }

    pub(super) fn set_all(dns_addr: IpAddr) -> io::Result<()> {
        let services = list_services()?;
        let addr = dns_addr.to_string();
        let mut had_error = false;
        for svc in services {
            if let Err(e) = set_dns(&svc, std::slice::from_ref(&addr)) {
                super::warn!("tun dns-guard: failed to set DNS on '{svc}': {e}");
                had_error = true;
            }
        }
        if had_error {
            Err(io::Error::other("some DNS sets failed"))
        } else {
            Ok(())
        }
    }

    pub(super) fn restore(saved: &[(String, Vec<String>)]) {
        for (svc, servers) in saved {
            if let Err(e) = set_dns(svc, servers) {
                super::warn!("tun dns-guard: failed to restore DNS on '{svc}': {e}");
            }
        }
    }

    fn list_services() -> io::Result<Vec<String>> {
        let output = Command::new("networksetup")
            .args(["-listallnetworkservices"])
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .skip(1) // skip "An asterisk (*) denotes..." header
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('*'))
            .collect())
    }

    fn get_dns(service: &str) -> io::Result<Vec<String>> {
        let output = Command::new("networksetup")
            .args(["-getdnsservers", service])
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim() == "There aren't any DNS Servers set on this device." {
            return Ok(vec![]);
        }
        Ok(stdout
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    fn set_dns(service: &str, servers: &[String]) -> io::Result<()> {
        if servers.is_empty() {
            Command::new("networksetup")
                .args(["-setdnsservers", service, "Empty"])
                .output()?;
        } else {
            let mut args: Vec<&str> = vec!["-setdnsservers", service];
            for s in servers {
                args.push(s.as_str());
            }
            Command::new("networksetup").args(&args).output()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Linux backend — /etc/resolv.conf
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io;
    use std::net::IpAddr;
    use std::path::PathBuf;

    const MARKER: &str = "# Generated by meow-rs TUN dns-guard";
    /// On-disk copy of the pre-meow resolv.conf, written before we touch
    /// the real file so the original survives an unclean shutdown.
    const SIDECAR: &str = "/etc/resolv.conf.meow-backup";

    pub(super) struct ResolvConfBackup {
        path: PathBuf,
        content: Vec<u8>,
    }

    pub(super) fn backup_and_set(dns_addr: IpAddr) -> io::Result<ResolvConfBackup> {
        let path = PathBuf::from("/etc/resolv.conf");
        let current = fs::read(&path)?;

        let content = if current.starts_with(MARKER.as_bytes()) {
            // resolv.conf is our own generated file — a previous run exited
            // uncleanly. Recover the true original from the sidecar instead
            // of backing up (and later "restoring") the broken state.
            match fs::read(SIDECAR) {
                Ok(original) => {
                    super::warn!(
                        "tun dns-guard: /etc/resolv.conf was left over from an unclean \
                         shutdown; recovered the original from {SIDECAR}"
                    );
                    original
                }
                Err(e) => {
                    super::warn!(
                        "tun dns-guard: /etc/resolv.conf was left over from an unclean \
                         shutdown and no sidecar backup exists ({e}); will restore public \
                         resolvers on exit — reconfigure your resolver manually if needed"
                    );
                    b"# meow-rs tun dns-guard: the original /etc/resolv.conf was lost in an\n\
                      # unclean shutdown; falling back to public resolvers.\n\
                      nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
                        .to_vec()
                }
            }
        } else {
            fs::write(SIDECAR, &current)?;
            current
        };

        let new_content = format!("{MARKER}\nnameserver {dns_addr}\n");
        fs::write(&path, new_content.as_bytes())?;
        Ok(ResolvConfBackup { path, content })
    }

    pub(super) fn restore(backup: &ResolvConfBackup) -> io::Result<()> {
        fs::write(&backup.path, &backup.content)?;
        let _ = fs::remove_file(SIDECAR);
        Ok(())
    }
}
