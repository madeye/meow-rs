use crate::sniffer::SnifferRuntime;
use base64::Engine;
use meow_common::{AuthConfig, ConnType, Metadata, Network};
use meow_tunnel::{copy_bidirectional_buf_tracked, ConnectionGuard, Tunnel, RELAY_BUF_SIZE};
use smallvec::smallvec;
use std::io;
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
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before headers complete",
                ));
            }
            // Overlap the previous tail by 3 bytes so a marker straddling two
            // reads (e.g. "\r\n\r" then "\n…") is still detected.
            let search_start = request_buf.len().saturating_sub(3);
            request_buf.extend_from_slice(&chunk[..n]);
            let header_end = find_crlf_crlf(&request_buf[search_start..])
                .map(|relative| search_start + relative + 4);
            let bytes_to_validate = header_end.unwrap_or(request_buf.len());
            if has_bare_line_ending(&request_buf[..bytes_to_validate]) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bare CR or LF in request headers",
                ));
            }
            if let Some(header_end) = header_end {
                if header_end > MAX_HEADERS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request headers too large",
                    ));
                }
                return Ok(header_end);
            }
            if request_buf.len() > MAX_HEADERS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request headers too large",
                ));
            }
        }
    };
    let header_end =
        match tokio::time::timeout(crate::DEFAULT_HANDSHAKE_TIMEOUT, read_headers).await {
            Err(_) => return Err("HTTP proxy handshake timed out".into()),
            Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => {
                write_bad_request(stream).await?;
                return Err(error.into());
            }
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(header_end)) => header_end,
        };
    let leftover: Vec<u8> = request_buf[header_end..].to_vec();
    request_buf.truncate(header_end);

    let request = match parse_request_head(&request_buf) {
        Ok(request) => request,
        Err(error) => {
            write_bad_request(stream).await?;
            return Err(error.into());
        }
    };

    // Auth check: verify Proxy-Authorization before dispatching.
    let in_user: Option<String> = if let Some(auth) = auth
        .filter(|a| !a.credentials.is_empty())
        .filter(|a| !a.should_skip(&src_addr.ip()))
    {
        match parse_proxy_authorization(&request.headers) {
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

    let method = request.method;
    let target = request.target;

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
                // keep the path. Rebuild headers without Proxy-* headers while
                // preserving all other field bytes exactly.
                let path = extract_path_from_url(url);
                let rewritten = rewrite_plain_request(&request, path);

                // Send the rewritten request to remote, then any body bytes
                // that arrived in the same TCP segment as the headers (POST
                // payloads typically do).
                remote.write_all(&rewritten).await?;
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

/// Return true once a CR or LF can no longer be part of a CRLF pair. A final
/// CR is left undecided because its LF may arrive in the next socket read.
fn has_bare_line_ending(buf: &[u8]) -> bool {
    buf.iter().enumerate().any(|(index, byte)| match *byte {
        b'\n' => index == 0 || buf[index - 1] != b'\r',
        b'\r' => index + 1 < buf.len() && buf[index + 1] != b'\n',
        _ => false,
    })
}

#[derive(Debug)]
struct HeaderField<'a> {
    name: &'a [u8],
    value: &'a [u8],
    raw: &'a [u8],
}

#[derive(Debug)]
struct RequestHead<'a> {
    method: &'a str,
    target: &'a str,
    version: &'a str,
    headers: Vec<HeaderField<'a>>,
}

fn parse_request_head(head: &[u8]) -> Result<RequestHead<'_>, &'static str> {
    if !head.ends_with(b"\r\n\r\n") || has_bare_line_ending(head) {
        return Err("invalid HTTP line ending");
    }

    let mut lines = Vec::new();
    let mut remaining = &head[..head.len() - 4];
    loop {
        if let Some(end) = remaining.windows(2).position(|window| window == b"\r\n") {
            lines.push(&remaining[..end]);
            remaining = &remaining[end + 2..];
        } else {
            lines.push(remaining);
            break;
        }
    }
    let (request_line, header_lines) = lines.split_first().ok_or("empty HTTP request")?;
    let request_line =
        std::str::from_utf8(request_line).map_err(|_| "non-ASCII HTTP request line")?;
    if !request_line.is_ascii() {
        return Err("non-ASCII HTTP request line");
    }
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || target.is_empty()
        || version.is_empty()
        || parts.next().is_some()
        || !method.as_bytes().iter().copied().all(is_tchar)
        || !target.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err("invalid HTTP request line");
    }

    let mut headers = Vec::with_capacity(header_lines.len());
    for &line in header_lines {
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or("HTTP header missing colon")?;
        let (name, value_with_colon) = line.split_at(colon);
        if name.is_empty() || !name.iter().copied().all(is_tchar) {
            return Err("invalid HTTP header name");
        }
        let value = &value_with_colon[1..];
        if !value
            .iter()
            .all(|byte| *byte == b'\t' || (*byte >= 0x20 && *byte != 0x7f))
        {
            return Err("invalid HTTP header value");
        }
        headers.push(HeaderField {
            name,
            value,
            raw: line,
        });
    }
    validate_message_framing(&headers)?;

    Ok(RequestHead {
        method,
        target,
        version,
        headers,
    })
}

fn validate_message_framing(headers: &[HeaderField<'_>]) -> Result<(), &'static str> {
    let mut content_length = None;
    let mut has_content_length = false;
    let mut transfer_codings = Vec::new();

    for header in headers {
        if header.name.eq_ignore_ascii_case(b"content-length") {
            has_content_length = true;
            for value in header.value.split(|byte| *byte == b',') {
                let value = trim_ows(value);
                if value.is_empty() {
                    return Err("invalid Content-Length");
                }
                let parsed = value.iter().try_fold(0u64, |length, byte| {
                    byte.is_ascii_digit()
                        .then(|| length.checked_mul(10)?.checked_add(u64::from(*byte - b'0')))
                        .flatten()
                });
                let parsed = parsed.ok_or("invalid Content-Length")?;
                if content_length.is_some_and(|length| length != parsed) {
                    return Err("conflicting Content-Length values");
                }
                content_length = Some(parsed);
            }
        } else if header.name.eq_ignore_ascii_case(b"transfer-encoding") {
            parse_transfer_codings(header.value, &mut transfer_codings)?;
        }
    }

    if has_content_length && !transfer_codings.is_empty() {
        return Err("Transfer-Encoding with Content-Length is ambiguous");
    }
    if !transfer_codings.is_empty() {
        let chunked_count = transfer_codings
            .iter()
            .filter(|coding| coding.name.eq_ignore_ascii_case(b"chunked"))
            .count();
        if chunked_count != 1
            || !transfer_codings.last().is_some_and(|coding| {
                coding.name.eq_ignore_ascii_case(b"chunked") && !coding.has_parameters
            })
        {
            return Err("invalid request Transfer-Encoding");
        }
    }
    Ok(())
}

#[derive(Debug)]
struct TransferCoding<'a> {
    name: &'a [u8],
    has_parameters: bool,
}

/// Parse the RFC 9110 transfer-coding list without treating commas inside a
/// quoted parameter value as list separators.
fn parse_transfer_codings<'a>(
    value: &'a [u8],
    codings: &mut Vec<TransferCoding<'a>>,
) -> Result<(), &'static str> {
    let mut cursor = 0;
    skip_ows(value, &mut cursor);

    loop {
        let name = parse_token(value, &mut cursor).ok_or("invalid Transfer-Encoding")?;
        let mut has_parameters = false;

        loop {
            skip_ows(value, &mut cursor);
            if value.get(cursor) != Some(&b';') {
                break;
            }
            has_parameters = true;
            cursor += 1;
            skip_ows(value, &mut cursor);
            parse_token(value, &mut cursor).ok_or("invalid Transfer-Encoding parameter")?;
            skip_ows(value, &mut cursor);
            if value.get(cursor) != Some(&b'=') {
                return Err("invalid Transfer-Encoding parameter");
            }
            cursor += 1;
            skip_ows(value, &mut cursor);
            if value.get(cursor) == Some(&b'"') {
                parse_quoted_string(value, &mut cursor)?;
            } else {
                parse_token(value, &mut cursor)
                    .ok_or("invalid Transfer-Encoding parameter value")?;
            }
        }

        codings.push(TransferCoding {
            name,
            has_parameters,
        });
        skip_ows(value, &mut cursor);
        match value.get(cursor) {
            None => return Ok(()),
            Some(b',') => {
                cursor += 1;
                skip_ows(value, &mut cursor);
                if cursor == value.len() {
                    return Err("invalid Transfer-Encoding");
                }
            }
            _ => return Err("invalid Transfer-Encoding"),
        }
    }
}

fn parse_token<'a>(value: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let start = *cursor;
    while value.get(*cursor).is_some_and(|byte| is_tchar(*byte)) {
        *cursor += 1;
    }
    (*cursor != start).then_some(&value[start..*cursor])
}

fn parse_quoted_string(value: &[u8], cursor: &mut usize) -> Result<(), &'static str> {
    debug_assert_eq!(value.get(*cursor), Some(&b'"'));
    *cursor += 1;
    loop {
        match value.get(*cursor).copied() {
            Some(b'"') => {
                *cursor += 1;
                return Ok(());
            }
            Some(b'\\') => {
                *cursor += 1;
                let escaped = value
                    .get(*cursor)
                    .copied()
                    .ok_or("unterminated Transfer-Encoding quoted string")?;
                if !matches!(escaped, b'\t' | b' '..=b'~' | 0x80..=0xff) {
                    return Err("invalid Transfer-Encoding quoted pair");
                }
                *cursor += 1;
            }
            Some(b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff) => {
                *cursor += 1;
            }
            Some(_) => return Err("invalid Transfer-Encoding quoted string"),
            None => return Err("unterminated Transfer-Encoding quoted string"),
        }
    }
}

fn skip_ows(value: &[u8], cursor: &mut usize) {
    while value
        .get(*cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        *cursor += 1;
    }
}

fn rewrite_plain_request(request: &RequestHead<'_>, path: &str) -> Vec<u8> {
    let mut rewritten = Vec::with_capacity(
        request.method.len() + path.len() + request.version.len() + 4 + request.headers.len() * 2,
    );
    rewritten.extend_from_slice(request.method.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(path.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(request.version.as_bytes());
    rewritten.extend_from_slice(b"\r\n");
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case(b"proxy-connection")
            || header.name.eq_ignore_ascii_case(b"proxy-authorization")
        {
            continue;
        }
        rewritten.extend_from_slice(header.raw);
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"\r\n");
    rewritten
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

async fn write_bad_request(stream: &mut TcpStream) -> io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 400 Bad Request\r\n\
              Connection: close\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await
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

/// Parse `Proxy-Authorization: Basic <base64>` from parsed request headers.
/// Returns `(username, password)` on success.
fn parse_proxy_authorization(headers: &[HeaderField<'_>]) -> Option<(String, String)> {
    for header in headers {
        if !header.name.eq_ignore_ascii_case(b"proxy-authorization") {
            continue;
        }
        let value = trim_ows(header.value);
        let separator = value.iter().position(|byte| matches!(byte, b' ' | b'\t'))?;
        if !value[..separator].eq_ignore_ascii_case(b"basic") {
            return None;
        }
        let encoded = std::str::from_utf8(trim_ows(&value[separator..])).ok()?;
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
    fn strict_parser_rejects_bare_lf_and_bare_cr() {
        assert!(parse_request_head(
            b"GET http://example.com/ HTTP/1.1\r\nX-A: 1\nContent-Length: 0\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"GET http://example.com/ HTTP/1.1\r\nX-A: 1\rContent-Length: 0\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"GET http://example.com/ HTTP/1.1\r\nX-A: 1\n\nX-Dropped: yes\r\n\r\n"
        )
        .is_err());
    }

    #[test]
    fn rewrite_preserves_obs_text_and_only_drops_proxy_headers() {
        let request = parse_request_head(
            b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nX-Word: caf\xe9\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic dTpw\r\n\r\n",
        )
        .unwrap();
        let rewritten = rewrite_plain_request(&request, "/path");
        assert_eq!(
            rewritten,
            b"GET /path HTTP/1.1\r\nHost: example.com\r\nX-Word: caf\xe9\r\n\r\n"
        );
    }

    #[test]
    fn parser_rejects_ambiguous_message_framing() {
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 5, 5\r\nContent-Length: 5\r\n\r\n"
        )
        .is_ok());
    }

    #[test]
    fn parser_accepts_parameterized_transfer_codings() {
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: gzip; level=1, chunked\r\n\r\n"
        )
        .is_ok());
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: custom ; note = \"a,b\\\"c\", chunked\r\n\r\n"
        )
        .is_ok());
    }

    #[test]
    fn parser_rejects_malformed_transfer_coding_parameters() {
        for value in [
            b"gzip; level, chunked".as_slice(),
            b"gzip; level=, chunked",
            b"gzip; note=\"unterminated, chunked",
            b"gzip; note=\"bad\\",
            b"gzip,,chunked",
            b"gzip,",
        ] {
            let mut codings = Vec::new();
            assert!(
                parse_transfer_codings(value, &mut codings).is_err(),
                "unexpectedly accepted {value:?}"
            );
        }
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked; extension=yes\r\n\r\n"
        )
        .is_err());
    }

    #[test]
    fn parse_proxy_authorization_ignores_obs_text_value_without_panic() {
        let request =
            parse_request_head(b"GET http://example.com/ HTTP/1.1\r\nX-Word: caf\xe9\r\n\r\n")
                .unwrap();
        assert_eq!(parse_proxy_authorization(&request.headers), None);
    }
}
