use crate::sniffer::SnifferRuntime;
use base64::Engine;
use meow_common::{AuthConfig, ConnType, Metadata, Network};
use meow_tunnel::{copy_bidirectional_buf_tracked, ConnectionGuard, Tunnel, RELAY_BUF_SIZE};
use smallvec::smallvec;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub async fn handle_http(
    tunnel: &Tunnel,
    mut stream: TcpStream,
    src_addr: SocketAddr,
    sniffer: Option<&SnifferRuntime>,
    auth: Option<&AuthConfig>,
    in_name: &str,
    in_port: u16,
) {
    if let Err(e) = handle_http_inner(
        tunnel,
        &mut stream,
        src_addr,
        sniffer,
        auth,
        in_name,
        in_port,
    )
    .await
    {
        debug!("HTTP proxy error from {}: {}", src_addr, e);
    }
}

async fn handle_http_inner(
    tunnel: &Tunnel,
    stream: &mut TcpStream,
    src_addr: SocketAddr,
    sniffer: Option<&SnifferRuntime>,
    auth: Option<&AuthConfig>,
    in_name: &str,
    in_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Relay scratch buffers on the future's stack — zero per-relay heap allocation
    // (ADR-0011 T6). Declared up front so both the CONNECT and plain-HTTP paths share them.
    let mut relay_buf_up = [0u8; RELAY_BUF_SIZE];
    let mut relay_buf_dn = [0u8; RELAY_BUF_SIZE];

    // Read the HTTP request line and headers in chunks until we find
    // \r\n\r\n. Reading one byte at a time costs ~100 syscalls per CONNECT;
    // chunked reads cap the syscall count at ceil(headers / 1024).
    //
    // Bytes that arrive past the marker (e.g. POST body in a single TCP
    // segment) are sliced off into `leftover` so the relay path can re-emit
    // them after sending the rewritten request line.
    const CHUNK: usize = 1024;
    const MAX_HEADERS: usize = 8192;
    let mut request_buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; CHUNK];
    let read_headers = async {
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err::<usize, Box<dyn std::error::Error + Send + Sync>>(
                    "connection closed before headers complete".into(),
                );
            }
            // Overlap the previous tail by 3 bytes so a marker straddling two
            // reads (e.g. "\r\n\r" then "\n…") is still detected.
            let search_start = request_buf.len().saturating_sub(3);
            request_buf.extend_from_slice(&chunk[..n]);
            if let Some(rel) = find_crlf_crlf(&request_buf[search_start..]) {
                return Ok(search_start + rel + 4);
            }
            if request_buf.len() > MAX_HEADERS {
                return Err::<usize, Box<dyn std::error::Error + Send + Sync>>(
                    "request headers too large".into(),
                );
            }
        }
    };
    let header_end = tokio::time::timeout(crate::DEFAULT_HANDSHAKE_TIMEOUT, read_headers)
        .await
        .map_err(|_| "HTTP proxy handshake timed out")??;
    let leftover: Vec<u8> = request_buf[header_end..].to_vec();
    request_buf.truncate(header_end);

    // Auth check: verify Proxy-Authorization before dispatching.
    let in_user: Option<String> = if let Some(auth) = auth
        .filter(|a| !a.credentials.is_empty())
        .filter(|a| !a.should_skip(&src_addr.ip()))
    {
        match parse_proxy_authorization(&request_buf) {
            None => {
                stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"meow-rs\"\r\n\
                          Content-Length: 0\r\n\r\n",
                    )
                    .await?;
                return Err("proxy authentication required".into());
            }
            Some((username, password)) => {
                if !auth.credentials.verify(&username, &password) {
                    stream
                        .write_all(
                            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                              Proxy-Authenticate: Basic realm=\"meow-rs\"\r\n\
                              Content-Length: 0\r\n\r\n",
                        )
                        .await?;
                    return Err(format!("HTTP auth failed for user {username:?}").into());
                }
                Some(username)
            }
        }
    } else {
        None
    };

    // Parse the request line from the buffer — no heap allocation.
    let request_str = String::from_utf8_lossy(&request_buf);
    let request_line = request_str.lines().next().ok_or("empty request")?;

    let mut parts = [""; 3];
    for (i, part) in request_line.split_whitespace().take(3).enumerate() {
        parts[i] = part;
    }
    if parts[2].is_empty() {
        return Err("invalid HTTP request line".into());
    }

    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS CONNECT
        let (host, port) = parse_host_port(target, 443);

        let mut metadata = Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Https,
            src_ip: Some(src_addr.ip()),
            src_port: src_addr.port(),
            // When the CONNECT target is an IP literal (common for the Netflix
            // OCA video CDN and other SNI-less clients), populate dst_ip so
            // IP-CIDR / GEOIP rules can match — mirrors the SOCKS5 IPv4/IPv6
            // ATYP path. Without this the connection falls through to MATCH.
            dst_ip: host_to_ip(host),
            host: Metadata::lower_host(host),
            dst_port: port,
            in_name: in_name.into(),
            in_port,
            in_user: in_user.as_deref().map(Into::into),
            ..Default::default()
        };

        debug!("HTTP CONNECT to {}:{}", host, port);

        // Send 200 Connection Established — the client will then send its
        // application data (e.g., TLS ClientHello) which we can peek at.
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;

        // Sniff TLS SNI from the client's TLS ClientHello (if applicable).
        if let Some(rt) = sniffer {
            rt.sniff(stream, &mut metadata).await;
        }

        // Hand off to tunnel
        let inner = tunnel.inner();
        inner.pre_handle_metadata(&mut metadata);
        let Some((proxy, rule_name, rule_payload)) = inner.resolve_proxy_lazy(&mut metadata).await
        else {
            return Err("no matching rule".into());
        };

        info!(
            "{} --> {} match {}({}) using {}",
            metadata.source_address(),
            metadata.remote_address(),
            rule_name,
            rule_payload,
            proxy.name()
        );

        let _guard = ConnectionGuard::track(
            &inner.stats,
            metadata.pure(),
            rule_name,
            rule_payload,
            smallvec![Arc::from(proxy.name())],
        );

        match proxy.dial_tcp(&metadata).await {
            Ok(mut remote) => {
                // Per RFC 7230 the client must wait for 200 OK before sending
                // application data, but if a client pipelined bytes ahead of
                // that we already read them — forward before relaying.
                let up = Arc::clone(_guard.counters());
                let dn = Arc::clone(_guard.counters());
                if !leftover.is_empty() {
                    remote.write_all(&leftover).await?;
                    inner
                        .stats
                        .record_upload(&up, leftover.len() as meow_common::atomic::Int);
                }
                match copy_bidirectional_buf_tracked(
                    stream,
                    &mut remote,
                    &mut relay_buf_up,
                    &mut relay_buf_dn,
                    |n| {
                        inner
                            .stats
                            .record_upload(&up, n as meow_common::atomic::Int);
                    },
                    |n| {
                        inner
                            .stats
                            .record_download(&dn, n as meow_common::atomic::Int);
                    },
                )
                .await
                {
                    Ok((up, down)) => {
                        debug!("HTTP CONNECT relay closed: up={up} down={down}");
                    }
                    Err(e) => debug!("HTTP CONNECT relay error: {}", e),
                }
            }
            Err(e) => warn!(
                "{} HTTP CONNECT dial error: {}",
                metadata.remote_address(),
                e
            ),
        }
        // _guard drops here, removing the entry from Statistics.
    } else {
        // Plain HTTP proxy (GET/POST/etc via proxy)
        let url = target;
        let (host, port) = parse_url_host_port(url);

        let mut metadata = Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Http,
            src_ip: Some(src_addr.ip()),
            src_port: src_addr.port(),
            // Same IP-literal handling as the CONNECT path above, so plain
            // HTTP proxied to a raw IP still matches IP-CIDR / GEOIP rules.
            dst_ip: host_to_ip(host),
            host: Metadata::lower_host(host),
            dst_port: port,
            in_name: in_name.into(),
            in_port,
            in_user: in_user.as_deref().map(Into::into),
            ..Default::default()
        };

        // For plain HTTP, sniff_http on the already-read buffer so IP-literal
        // destinations still benefit from Host-header routing.
        if let Some(rt) = sniffer {
            if let Some(sniffed) = meow_common::sniffer::sniff_http(&request_buf) {
                rt.maybe_apply_sniff(&sniffed, &mut metadata);
            }
        }

        debug!("HTTP {} to {}:{}", method, host, port);

        let inner = tunnel.inner();
        inner.pre_handle_metadata(&mut metadata);
        let Some((proxy, rule_name, rule_payload)) = inner.resolve_proxy_lazy(&mut metadata).await
        else {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            return Err("no matching rule".into());
        };

        info!(
            "{} --> {} match {}({}) using {}",
            metadata.source_address(),
            metadata.remote_address(),
            rule_name,
            rule_payload,
            proxy.name()
        );

        let _guard = ConnectionGuard::track(
            &inner.stats,
            metadata.pure(),
            rule_name,
            rule_payload,
            smallvec![Arc::from(proxy.name())],
        );

        match proxy.dial_tcp(&metadata).await {
            Ok(mut remote) => {
                // Rewrite the request line: remove the absolute URI scheme+host,
                // keep the path. Rebuild headers without Proxy-* headers.
                let path = extract_path_from_url(url);
                // Capacity hint: the rewrite never grows beyond the original
                // request (the absolute URI shrinks to a path; headers only
                // ever drop).
                let mut rewritten = String::with_capacity(request_str.len());
                {
                    use std::fmt::Write as _;
                    let _ = write!(rewritten, "{} {} {}\r\n", method, path, parts[2]);
                }
                for line in request_str.lines().skip(1) {
                    if line.is_empty() {
                        break;
                    }
                    // Skip proxy-specific headers — case-insensitive compare
                    // on the slice, no per-line lowercased copy.
                    if starts_with_ignore_ascii_case(line, "proxy-connection")
                        || starts_with_ignore_ascii_case(line, "proxy-authorization")
                    {
                        continue;
                    }
                    rewritten.push_str(line);
                    rewritten.push_str("\r\n");
                }
                rewritten.push_str("\r\n");

                // Send the rewritten request to remote, then any body bytes
                // that arrived in the same TCP segment as the headers (POST
                // payloads typically do).
                remote.write_all(rewritten.as_bytes()).await?;
                let up = Arc::clone(_guard.counters());
                let dn = Arc::clone(_guard.counters());
                if !leftover.is_empty() {
                    remote.write_all(&leftover).await?;
                    inner
                        .stats
                        .record_upload(&up, leftover.len() as meow_common::atomic::Int);
                }

                // Relay bidirectionally
                match copy_bidirectional_buf_tracked(
                    stream,
                    &mut remote,
                    &mut relay_buf_up,
                    &mut relay_buf_dn,
                    |n| {
                        inner
                            .stats
                            .record_upload(&up, n as meow_common::atomic::Int);
                    },
                    |n| {
                        inner
                            .stats
                            .record_download(&dn, n as meow_common::atomic::Int);
                    },
                )
                .await
                {
                    Ok((up, down)) => {
                        debug!("HTTP relay closed: up={up} down={down}");
                    }
                    Err(e) => debug!("HTTP relay error: {}", e),
                }
            }
            Err(e) => {
                warn!("{}:{} HTTP dial error: {}", host, port, e);
                stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
            }
        }
        // _guard drops here, removing the entry from Statistics.
    }

    Ok(())
}

/// Locate `b"\r\n\r\n"` in `buf` and return the index of the first `\r`.
fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse an HTTP host token as an IP literal, returning `Some(ip)` when it is
/// one. Strips the surrounding brackets of an IPv6 literal (`[2606:..]`) so it
/// parses; returns `None` for hostnames, which are resolved later by the
/// adapter. Used to populate `Metadata::dst_ip` so IP-CIDR / GEOIP rules match
/// IP-literal destinations (e.g. Netflix OCA video servers connected by raw IP).
fn host_to_ip(host: &str) -> Option<IpAddr> {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
        .ok()
}

fn parse_host_port(target: &str, default_port: u16) -> (&str, u16) {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host, port);
        }
    }
    (target, default_port)
}

/// Parse host and port from an absolute HTTP URL like "http://ipinfo.io/json"
fn parse_url_host_port(url: &str) -> (&str, u16) {
    // Strip scheme
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    // Take the authority part (before first /)
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    let default_port = if url.starts_with("https://") { 443 } else { 80 };
    parse_host_port(authority, default_port)
}

/// Extract the path from an absolute URL: "http://ipinfo.io/json" -> "/json"
fn extract_path_from_url(url: &str) -> &str {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    without_scheme
        .find('/')
        .map_or("/", |i| &without_scheme[i..])
}

/// Case-insensitive ASCII prefix test without allocating a lowercased copy.
/// Byte-wise so a multi-byte UTF-8 char at the boundary can't panic a slice.
fn starts_with_ignore_ascii_case(line: &str, prefix: &str) -> bool {
    line.len() >= prefix.len()
        && line.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// Parse `Proxy-Authorization: Basic <base64>` from raw request headers.
/// Returns `(username, password)` on success.
fn parse_proxy_authorization(headers: &[u8]) -> Option<(String, String)> {
    const PROXY_AUTH_PREFIX: &str = "proxy-authorization:";

    let headers_str = std::str::from_utf8(headers).ok()?;
    for line in headers_str.lines() {
        if !starts_with_ignore_ascii_case(line, PROXY_AUTH_PREFIX) {
            continue;
        }
        let value = line[PROXY_AUTH_PREFIX.len()..].trim();
        let encoded = value
            .strip_prefix("Basic ")
            .or_else(|| value.strip_prefix("basic "))?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let (user, pass) = decoded_str.split_once(':')?;
        return Some((user.to_string(), pass.to_string()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn host_to_ip_parses_ipv4_literal() {
        // Regression: Netflix OCA servers are connected by raw IP via CONNECT.
        // dst_ip must be populated so IP-CIDR rules (e.g. 23.246.0.0/18) match
        // instead of falling through to MATCH.
        assert_eq!(
            host_to_ip("23.246.15.143"),
            Some(IpAddr::V4(Ipv4Addr::new(23, 246, 15, 143)))
        );
    }

    #[test]
    fn host_to_ip_parses_bracketed_ipv6_literal() {
        assert_eq!(
            host_to_ip("[2606:2800:220:1:248:1893:25c8:1946]"),
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946
            )))
        );
    }

    #[test]
    fn host_to_ip_returns_none_for_hostname() {
        // Hostnames stay None — resolved later by the adapter / pre_resolve.
        assert_eq!(host_to_ip("www.netflix.com"), None);
        assert_eq!(host_to_ip("nflxvideo.net"), None);
    }

    #[test]
    fn parse_proxy_authorization_ignores_non_ascii_header_without_panic() {
        let headers = concat!(
            "GET http://example.com/ HTTP/1.1\r\n",
            "aaaaaaaaaaaaaaaaaaaé: value\r\n",
            "\r\n"
        );
        assert_eq!(parse_proxy_authorization(headers.as_bytes()), None);
    }
}
