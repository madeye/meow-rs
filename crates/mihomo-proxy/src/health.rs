use mihomo_common::ProxyAdapter;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace, warn};

pub use mihomo_common::ProxyHealth;

/// Outcome of a single [`url_test`] probe. Callers distinguish transport
/// failure from deadline expiry to pick the right HTTP status code
/// (upstream: 503 vs 504 — see `docs/specs/api-delay-endpoints.md`).
#[derive(Debug, Clone)]
pub enum UrlTestError {
    Timeout,
    Transport(String),
}

/// Probe a proxy by dialing the target, issuing an HTTP/1.1 `GET`, and
/// reading the status line. Returns the total elapsed milliseconds on
/// success (status within `expected`), otherwise a classified error.
///
/// `expected` is a comma-separated list of status-code ranges
/// (e.g. `"200"`, `"200-299"`, `"200,204-206"`). When `None`, any 2xx
/// status counts as success — matching upstream Go mihomo's default in
/// `component/proxydialer/http.go::httpHealthCheck`.
///
/// `https://` targets are tunneled through a client-side TLS handshake
/// (rustls + webpki-roots) before the GET. HTTP targets go over the raw
/// dialed connection.
pub async fn url_test(
    adapter: &dyn ProxyAdapter,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
) -> Result<u16, UrlTestError> {
    let Some(parsed) = ParsedUrl::parse(url) else {
        return Err(UrlTestError::Transport(format!("invalid url: {url}")));
    };
    let ranges = match parse_expected(expected) {
        Ok(r) => r,
        Err(e) => return Err(UrlTestError::Transport(e)),
    };

    let start = Instant::now();
    let metadata = mihomo_common::Metadata {
        network: mihomo_common::Network::Tcp,
        host: parsed.host.as_str().into(),
        dst_port: parsed.port,
        ..Default::default()
    };

    let fut = probe_once(adapter, metadata, parsed, ranges);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(())) => {
            let delay = start.elapsed().as_millis().min(u16::MAX as u128) as u16;
            // Collapse sub-millisecond probes to 1 so callers can treat 0 as
            // the "probe did not complete" sentinel when they choose to.
            let delay = delay.max(1);
            debug!("{} URL test: {}ms", adapter.name(), delay);
            Ok(delay)
        }
        Ok(Err(e)) => {
            warn!("{} URL test transport error: {}", adapter.name(), e);
            Err(UrlTestError::Transport(e))
        }
        Err(_) => {
            warn!("{} URL test timeout after {:?}", adapter.name(), timeout);
            Err(UrlTestError::Timeout)
        }
    }
}

async fn probe_once(
    adapter: &dyn ProxyAdapter,
    metadata: mihomo_common::Metadata,
    parsed: ParsedUrl,
    ranges: Vec<(u16, u16)>,
) -> Result<(), String> {
    let conn = adapter
        .dial_tcp(&metadata)
        .await
        .map_err(|e| format!("dial: {e}"))?;

    if parsed.https {
        let connector = tls_connector();
        let server_name = rustls::pki_types::ServerName::try_from(parsed.host.clone())
            .map_err(|e| format!("tls sni: {e}"))?;
        let tls = connector
            .connect(server_name, conn)
            .await
            .map_err(|e| format!("tls: {e}"))?;
        send_get_and_check(tls, &parsed, &ranges).await
    } else {
        send_get_and_check(conn, &parsed, &ranges).await
    }
}

async fn send_get_and_check<S>(
    mut stream: S,
    parsed: &ParsedUrl,
    ranges: &[(u16, u16)],
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Host header includes the non-default port so virtual-hosted origins
    // route correctly; mirrors Go net/http's default behaviour.
    let default_port = if parsed.https { 443 } else { 80 };
    let host_header = if parsed.port == default_port {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: clash.meta/{version}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n",
        path = parsed.path,
        host = host_header,
        version = env!("CARGO_PKG_VERSION"),
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;

    let status = read_status_line(&mut stream).await?;
    trace!(status, "url_test: received status");
    if ranges.iter().any(|(lo, hi)| status >= *lo && status <= *hi) {
        Ok(())
    } else {
        Err(format!("unexpected status {status}"))
    }
}

async fn read_status_line<S>(stream: &mut S) -> Result<u16, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    // The status line is at most a few dozen bytes; cap reads so a hostile
    // peer can't stream megabytes of header into us.
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("eof before status line".into());
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") || buf.len() >= 1024 {
            break;
        }
    }
    let line = std::str::from_utf8(&buf).map_err(|_| "status line not utf-8".to_string())?;
    // HTTP/1.x status line: "HTTP/1.1 204 No Content\r\n"
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(format!("malformed status line: {line:?}"));
    }
    let code_str = parts
        .next()
        .ok_or_else(|| format!("missing status code: {line:?}"))?;
    code_str
        .parse::<u16>()
        .map_err(|_| format!("bad status code: {code_str:?}"))
}

fn tls_connector() -> tokio_rustls::TlsConnector {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    // Be explicit about the provider: when `ech-tls-tunnel` (or any other
    // feature that pulls aws-lc-rs) is on, rustls' `builder()` would panic
    // because two providers are compiled in.
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("rustls protocol versions are safe defaults")
    .with_root_certificates(root_store)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[derive(Debug, Clone)]
struct ParsedUrl {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

impl ParsedUrl {
    fn parse(url: &str) -> Option<Self> {
        let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return None;
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return None;
        }
        // IPv6 literals wrap in `[...]`.
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let end = rest.find(']')?;
            let host = &rest[..end];
            let tail = &rest[end + 1..];
            let port = if let Some(p) = tail.strip_prefix(':') {
                p.parse().ok()?
            } else if https {
                443
            } else {
                80
            };
            (host.to_string(), port)
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            (h.to_string(), p.parse().ok()?)
        } else {
            (authority.to_string(), if https { 443 } else { 80 })
        };
        Some(Self {
            https,
            host,
            port,
            path: path.to_string(),
        })
    }
}

/// Parse an `expected` query-param value into inclusive status-code ranges.
/// Empty / `None` defaults to `[200..=299]`, matching upstream.
fn parse_expected(spec: Option<&str>) -> Result<Vec<(u16, u16)>, String> {
    let s = spec.unwrap_or("").trim();
    if s.is_empty() {
        return Ok(vec![(200, 299)]);
    }
    let mut out = Vec::new();
    for piece in s.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = piece.split_once('-') {
            let lo: u16 = lo
                .trim()
                .parse()
                .map_err(|_| format!("expected: bad range {piece:?}"))?;
            let hi: u16 = hi
                .trim()
                .parse()
                .map_err(|_| format!("expected: bad range {piece:?}"))?;
            if lo > hi {
                return Err(format!("expected: inverted range {piece:?}"));
            }
            out.push((lo, hi));
        } else {
            let code: u16 = piece
                .parse()
                .map_err(|_| format!("expected: bad code {piece:?}"))?;
            out.push((code, code));
        }
    }
    if out.is_empty() {
        return Err("expected: empty".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_url() {
        let p = ParsedUrl::parse("http://www.gstatic.com/generate_204").unwrap();
        assert!(!p.https);
        assert_eq!(p.host, "www.gstatic.com");
        assert_eq!(p.port, 80);
        assert_eq!(p.path, "/generate_204");
    }

    #[test]
    fn parses_https_default_port() {
        let p = ParsedUrl::parse("https://cp.cloudflare.com/generate_204").unwrap();
        assert!(p.https);
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parses_explicit_port_and_empty_path() {
        let p = ParsedUrl::parse("http://example.com:8080").unwrap();
        assert_eq!(p.port, 8080);
        assert_eq!(p.path, "/");
    }

    #[test]
    fn parses_ipv6_literal() {
        let p = ParsedUrl::parse("http://[::1]:8080/x").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.path, "/x");
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(ParsedUrl::parse("ftp://x").is_none());
        assert!(ParsedUrl::parse("example.com").is_none());
    }

    #[test]
    fn expected_default_is_2xx() {
        assert_eq!(parse_expected(None).unwrap(), vec![(200, 299)]);
        assert_eq!(parse_expected(Some("")).unwrap(), vec![(200, 299)]);
    }

    #[test]
    fn expected_parses_mixed_list() {
        let r = parse_expected(Some("200,204-206,301")).unwrap();
        assert_eq!(r, vec![(200, 200), (204, 206), (301, 301)]);
    }

    #[test]
    fn expected_rejects_inverted_range() {
        assert!(parse_expected(Some("300-200")).is_err());
    }

    #[test]
    fn expected_rejects_garbage() {
        assert!(parse_expected(Some("abc")).is_err());
    }
}
