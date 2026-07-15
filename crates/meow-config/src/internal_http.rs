//! Tiny HTTP/1.1 GET client that tunnels through a meow-rs `Proxy` adapter.
//!
//! Used by rule-provider and geodata downloaders so that internal HTTP fetches
//! (which often target GFW-blocked hosts like `raw.githubusercontent.com` and
//! `github.com` release assets) can route through one of the user's configured
//! upstream nodes instead of going direct.
//!
//! Scope is intentionally minimal:
//!   * `GET` only.
//!   * HTTP/1.1, `Connection: close`, `Accept-Encoding: identity`.
//!   * Follows up to 5 redirects (`3xx` with `Location`).
//!   * No streaming — full body buffered in memory (matches the existing
//!     `reqwest::bytes()` semantics on every call site).

use anyhow::{anyhow, bail, Result};
use futures_util::StreamExt;
use meow_common::adapter::Proxy;
use meow_common::metadata::Metadata;
use meow_common::{ConnType, Network};
use smol_str::SmolStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

const MAX_REDIRECTS: u8 = 5;
/// Bounds the proxy dial and the TLS handshake. Without it, a fetch through
/// an unreachable upstream (e.g. rule-provider load at startup while the
/// network is down) inherits the adapter's connect behaviour — which for some
/// protocols never times out — and stalls the caller indefinitely
/// (BaoLianDeng#79: config update froze the app until force quit).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const USER_AGENT: &str = concat!("clash.meta/", env!("CARGO_PKG_VERSION"));
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024 * 1024; // 256 MiB hard ceiling

pub(crate) async fn response_text_with_limit(resp: reqwest::Response) -> Result<String> {
    if resp
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        bail!("response exceeds max body size ({MAX_BODY_BYTES} bytes)");
    }

    let mut bytes = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > MAX_BODY_BYTES.saturating_sub(bytes.len()) {
            bail!("response exceeds max body size ({MAX_BODY_BYTES} bytes)");
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|e| anyhow!("response body is not UTF-8: {e}"))
}

/// Fetch `url` via `proxy` and return the response body.
///
/// Follows up to 5 redirects (302/301/307/308). Returns an
/// error for non-2xx terminal responses, oversize bodies, or transport errors.
pub async fn fetch_via_proxy(url: &str, proxy: &Arc<dyn Proxy>) -> Result<Vec<u8>> {
    let mut current = Url::parse(url).map_err(|e| anyhow!("invalid URL '{url}': {e}"))?;
    for _ in 0..=MAX_REDIRECTS {
        match fetch_one(&current, proxy).await? {
            Outcome::Body(bytes) => return Ok(bytes),
            Outcome::Redirect(next) => {
                current = current
                    .join(&next)
                    .map_err(|e| anyhow!("bad redirect Location '{next}': {e}"))?;
            }
        }
    }
    bail!("too many redirects (> {MAX_REDIRECTS}) starting from {url}")
}

enum Outcome {
    Body(Vec<u8>),
    Redirect(String),
}

async fn fetch_one(url: &Url, proxy: &Arc<dyn Proxy>) -> Result<Outcome> {
    let scheme = url.scheme();
    let is_https = match scheme {
        "https" => true,
        "http" => false,
        other => bail!("unsupported URL scheme '{other}': {url}"),
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL has no host: {url}"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL has no port: {url}"))?;
    let path_and_query = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };

    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Http,
        host: SmolStr::from(&host),
        dst_port: port,
        ..Metadata::default()
    };

    let conn = tokio::time::timeout(CONNECT_TIMEOUT, proxy.dial_tcp(&metadata))
        .await
        .map_err(|_| {
            anyhow!(
                "dial via proxy '{}' timed out after {CONNECT_TIMEOUT:?}",
                proxy.name()
            )
        })?
        .map_err(|e| anyhow!("dial via proxy '{}': {e}", proxy.name()))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: {ua}\r\n\
         Accept: */*\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\
         \r\n",
        path = path_and_query,
        host_header = host_header(&host, port, is_https),
        ua = USER_AGENT,
    );

    if is_https {
        let tls = tls_connector();
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| anyhow!("invalid TLS server name '{host}': {e}"))?;
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, tls.connect(server_name, conn))
            .await
            .map_err(|_| anyhow!("TLS handshake to {host} timed out after {CONNECT_TIMEOUT:?}"))?
            .map_err(|e| anyhow!("TLS handshake to {host}: {e}"))?;
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        read_response(&mut stream).await
    } else {
        let mut stream = conn;
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        read_response(&mut stream).await
    }
}

fn host_header(host: &str, port: u16, is_https: bool) -> String {
    let default_port = if is_https { 443 } else { 80 };
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

async fn read_response<S>(stream: &mut S) -> Result<Outcome>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Read until EOF with a wall-clock timeout. Connection: close means
    // the server signals end-of-body by closing the socket.
    let mut buf = Vec::with_capacity(64 * 1024);
    let read = async {
        let mut tmp = [0u8; 16 * 1024];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            if buf.len() + n > MAX_BODY_BYTES {
                bail!("response exceeds max body size ({MAX_BODY_BYTES} bytes)");
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        Result::<()>::Ok(())
    };
    tokio::time::timeout(READ_TIMEOUT, read)
        .await
        .map_err(|_| anyhow!("response read timed out after {READ_TIMEOUT:?}"))??;

    parse_response(&buf)
}

fn parse_response(buf: &[u8]) -> Result<Outcome> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let parsed = resp
        .parse(buf)
        .map_err(|e| anyhow!("response parse error: {e}"))?;
    let body_start = match parsed {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => bail!("incomplete HTTP response (no header terminator)"),
    };
    let status = resp
        .code
        .ok_or_else(|| anyhow!("response missing status code"))?;

    if (300..400).contains(&status) {
        for h in resp.headers.iter() {
            if h.name.eq_ignore_ascii_case("location") {
                let loc = std::str::from_utf8(h.value)
                    .map_err(|e| anyhow!("non-UTF-8 Location header: {e}"))?;
                return Ok(Outcome::Redirect(loc.to_string()));
            }
        }
        bail!("HTTP {status} redirect without Location header");
    }
    if !(200..300).contains(&status) {
        bail!("HTTP {status}");
    }
    let chunked = resp.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(header.value).is_ok_and(|value| {
                value
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("chunked"))
            })
    });
    let body = if chunked {
        decode_chunked(&buf[body_start..])?
    } else {
        buf[body_start..].to_vec()
    };
    Ok(Outcome::Body(body))
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("incomplete chunk-size line"))?;
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|e| anyhow!("non-UTF-8 chunk size: {e}"))?;
        let size =
            usize::from_str_radix(size_text.split(';').next().unwrap_or_default().trim(), 16)
                .map_err(|e| anyhow!("invalid chunk size '{size_text}': {e}"))?;
        input = &input[line_end + 2..];

        if size == 0 {
            // A zero chunk is followed by optional trailers and a final CRLF.
            if input == b"\r\n" || input.windows(4).any(|w| w == b"\r\n\r\n") {
                return Ok(body);
            }
            bail!("incomplete chunked response trailers");
        }
        if size > MAX_BODY_BYTES.saturating_sub(body.len()) {
            bail!("response exceeds max body size ({MAX_BODY_BYTES} bytes)");
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            bail!("incomplete chunk data");
        }
        body.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

fn tls_connector() -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// Pick the first proxy named in the user's `proxies:` config block and look
/// it up in the live proxy registry.
///
/// Returns `None` if there are no `proxies:` entries, if the first entry has
/// no `name:` field, or if that name isn't in the registry (e.g. it failed to
/// load during proxy construction).
pub fn first_named_proxy(
    raw_proxies: Option<&[std::collections::HashMap<String, serde_yaml::Value>]>,
    proxies: &std::collections::HashMap<smol_str::SmolStr, Arc<dyn Proxy>>,
) -> Option<Arc<dyn Proxy>> {
    let entry = raw_proxies?.first()?;
    let name = entry.get("name")?.as_str()?;
    proxies.get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_decodes_chunked_body_and_extensions() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: yes\r\n\r\n";
        match parse_response(response).unwrap() {
            Outcome::Body(body) => assert_eq!(body, b"Wikipedia"),
            Outcome::Redirect(_) => panic!("unexpected redirect"),
        }
    }

    #[test]
    fn parse_response_rejects_truncated_chunk() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc";
        assert!(parse_response(response).is_err());
    }

    /// `Proxy` whose `dial_tcp` never completes — models an adapter dialing an
    /// unreachable upstream with no protocol-level connect timeout.
    struct HangingProxy {
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for HangingProxy {
        fn name(&self) -> &str {
            "hang"
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            _m: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            std::future::pending().await
        }
        async fn dial_udp(
            &self,
            _m: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            Err(meow_common::MeowError::NotSupported(
                "hang: dial_udp".into(),
            ))
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl Proxy for HangingProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            Vec::new()
        }
    }

    // start_paused: tokio auto-advances the clock when every task is idle, so
    // the CONNECT_TIMEOUT fires immediately instead of after a real 15 s.
    #[tokio::test(start_paused = true)]
    async fn connect_timeout_bounds_hung_dial() {
        let proxy: Arc<dyn Proxy> = Arc::new(HangingProxy {
            health: meow_common::ProxyHealth::new(),
        });
        let err = fetch_via_proxy("http://192.0.2.1/rules.yaml", &proxy)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("timed out"),
            "expected connect timeout, got: {err}"
        );
    }
}
