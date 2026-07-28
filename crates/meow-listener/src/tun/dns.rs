//! OS DNS resolver configuration for the TUN inbound.
//!
//! When `dns-hijack` is active, the OS resolver must be pointed at an
//! address inside the routed fake-IP range (by default `198.18.0.1`) so
//! that DNS queries enter the TUN device and are answered with fake IPs.
//!
//! `DnsGuard` backs up the current resolver configuration at startup,
//! installs the fake-IP gateway as the sole DNS server on all active
//! adapters, and restores the original configuration on drop.
//!
//! Individual failures are logged and skipped: a DNS configuration error
//! does not abort the TUN listener startup, and a recovery failure is
//! similarly non-fatal.

use std::net::IpAddr;
use tracing::{debug, warn};

/// RAII guard that restores original DNS settings on drop.
///
/// When created, it saves the current OS DNS state and replaces it with
/// `dns_addr` on all active network interfaces. On drop, the original
/// configuration is restored. Failed operations are logged at `warn!`
/// level rather than panicking.
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
    pub(super) fn setup(dns_addr: IpAddr) -> Option<Self> {
        #[cfg(target_os = "windows")]
        {
            match windows::backup() {
                Ok(backup) => {
                    if let Err(e) = windows::set_all(dns_addr) {
                        warn!("tun dns-guard: failed to set DNS to {dns_addr}: {e}");
                        // Still return the guard so we can restore what's left.
                    }
                    debug!("tun dns-guard: DNS set to {dns_addr} on all IPv4 adapters");
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
            match macos::backup() {
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

impl Drop for DnsGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            if let Err(e) = windows::restore(&self.backup) {
                warn!("tun dns-guard: failed to restore DNS settings: {e}");
            } else {
                debug!("tun dns-guard: DNS settings restored");
            }
        }
        #[cfg(target_os = "macos")]
        {
            if let Err(e) = macos::restore(&self.backup) {
                warn!("tun dns-guard: failed to restore DNS settings: {e}");
            } else {
                debug!("tun dns-guard: DNS settings restored");
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(backup) = self.backup.take() {
                if let Err(e) = linux::restore(backup) {
                    warn!("tun dns-guard: failed to restore /etc/resolv.conf: {e}");
                } else {
                    debug!("tun dns-guard: /etc/resolv.conf restored");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows backend — PowerShell Get/Set-DnsClientServerAddress
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows {
    use std::net::IpAddr;
    use std::process::Command;

    const IPV6_SEPARATOR: &str = "---IPV6---";

    /// Back up current DNS on all adapters (both IPv4 and IPv6).
    ///
    /// Returns a combined encoding:
    ///   IPv4 lines (one per adapter: `InterfaceAlias|server1,server2,...`)
    ///   `---IPV6---`
    ///   IPv6 lines (same format)
    ///
    /// An empty server list means the adapter uses DHCP.
    pub(super) fn backup() -> std::io::Result<String> {
        let v4 = backup_family(4)?;
        let v6 = backup_family(6)?;
        Ok(format!("{v4}\n{IPV6_SEPARATOR}\n{v6}"))
    }

    fn backup_family(family: u8) -> std::io::Result<String> {
        let family_str = if family == 4 { "IPv4" } else { "IPv6" };
        let script = format!(
            r#"Get-DnsClientServerAddress -AddressFamily {family_str} -ErrorAction SilentlyContinue | Where-Object {{$_.ServerAddresses.Count -gt 0}} | ForEach-Object {{ "$($_.InterfaceAlias)|$(($_.ServerAddresses -join ','))" }}"#
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()?;
        Ok(String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_string())
    }

    /// Set IPv4 DNS to `dns_addr` and clear all IPv6 DNS servers on every
    /// adapter.  Windows DNS Client prefers IPv6-resolved results when
    /// IPv6 DNS servers are available; leaving them untouched means
    /// queries bypass the TUN entirely.
    pub(super) fn set_all(dns_addr: IpAddr) -> std::io::Result<()> {
        let addr = dns_addr.to_string();

        // Step 1: set IPv4 DNS on every adapter that had DNS servers.
        let cmd_v4 = format!(
            r#"Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{$_.ServerAddresses.Count -gt 0}} | ForEach-Object {{ Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ServerAddresses ('{addr}') -ErrorAction SilentlyContinue }}"#
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd_v4])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if !stderr.is_empty() {
                return Err(std::io::Error::other(stderr));
            }
        }

        // Step 2: clear IPv6 DNS on every adapter that has them.
        // Set-DnsClientServerAddress without -AddressFamily defaults to
        // IPv4, so we must explicitly pass -AddressFamily IPv6.
        let cmd_v6 =
            r#"Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {$_.ServerAddresses.Count -gt 0} | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ResetServerAddresses -ErrorAction SilentlyContinue }"#.to_string();
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd_v6])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if !stderr.is_empty() {
                return Err(std::io::Error::other(stderr));
            }
        }

        // Step 3: re-apply IPv4 DNS on adapters that were just reset
        // by step 2 (ResetServerAddresses clears both families).
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd_v4])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if !stderr.is_empty() {
                return Err(std::io::Error::other(stderr));
            }
        }

        Ok(())
    }

    /// Restore DNS from the backup string produced by `backup()`.
    ///
    /// The string is split on `---IPV6---` into IPv4 and IPv6 sections.
    /// Each line is `InterfaceAlias|server1,server2,...`. An empty server
    /// list resets the adapter to DHCP.
    pub(super) fn restore(backup: &str) -> std::io::Result<()> {
        let mut had_error = false;

        let (v4_section, v6_section) = match backup.split_once(IPV6_SEPARATOR) {
            Some((v4, v6)) => (v4.trim(), v6.trim()),
            // Backward compat: pre-IPv6 backups have no separator.
            None => (backup.trim(), ""),
        };

        restore_family(v4_section, 4, &mut had_error);
        restore_family(v6_section, 6, &mut had_error);

        if had_error {
            Err(std::io::Error::other(
                "one or more DNS restores failed",
            ))
        } else {
            Ok(())
        }
    }

    fn restore_family(section: &str, family: u8, had_error: &mut bool) {
        for line in section.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(2, '|').collect();
            if parts.len() != 2 {
                continue;
            }
            let iface = parts[0].trim();
            let servers: Vec<&str> = parts[1]
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();

            let result = if servers.is_empty() {
                reset_dns(iface)
            } else {
                set_dns(iface, &servers, family)
            };

            if let Err(e) = result {
                super::warn!(
                    "tun dns-guard: failed to restore AF{family} DNS on '{iface}': {e}"
                );
                *had_error = true;
            }
        }
    }

    fn reset_dns(iface: &str) -> std::io::Result<()> {
        let cmd = format!(
            r#"Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses -ErrorAction SilentlyContinue"#,
            escape_arg(iface)
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output()?;
        check_ps_output(&output)
    }

    fn set_dns(iface: &str, servers: &[&str], family: u8) -> std::io::Result<()> {
        let quoted: Vec<String> = servers
            .iter()
            .map(|s| format!("'{}'", escape_arg(s)))
            .collect();
        let family_arg = if family == 6 {
            "-AddressFamily IPv6"
        } else {
            ""
        };
        let cmd = format!(
            r#"Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses ({}) {} -ErrorAction SilentlyContinue"#,
            escape_arg(iface),
            quoted.join(","),
            family_arg,
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output()?;
        check_ps_output(&output)
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

    /// Escape single quotes in a PowerShell string argument.
    fn escape_arg(s: &str) -> String {
        s.replace('\'', "''")
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

    pub(super) fn backup() -> io::Result<Vec<(String, Vec<String>)>> {
        let services = list_services()?;
        let mut result = Vec::with_capacity(services.len());
        for svc in services {
            match get_dns(&svc) {
                Ok(servers) => result.push((svc, servers)),
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
            if let Err(e) = set_dns(&svc, &[addr.clone()]) {
                super::warn!("tun dns-guard: failed to set DNS on '{svc}': {e}");
                had_error = true;
            }
        }
        if had_error {
            Err(io::Error::new(io::ErrorKind::Other, "some DNS sets failed"))
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
        Ok(stdout.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
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

    pub(super) struct ResolvConfBackup {
        path: PathBuf,
        content: Vec<u8>,
    }

    pub(super) fn backup_and_set(dns_addr: IpAddr) -> io::Result<ResolvConfBackup> {
        let path = PathBuf::from("/etc/resolv.conf");
        let content = fs::read(&path)?;
        let new_content = format!(
            "# Generated by meow-rs TUN dns-guard\nnameserver {dns_addr}\n"
        );
        fs::write(&path, new_content.as_bytes())?;
        Ok(ResolvConfBackup { path, content })
    }

    pub(super) fn restore(backup: ResolvConfBackup) -> io::Result<()> {
        fs::write(&backup.path, &backup.content)
    }
}
