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
use meow_common::adapter::Proxy;
use meow_common::metadata::Metadata;
use meow_common::{ConnType, Network};
use smol_str::SmolStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

const MAX_REDIRECTS: u8 = 5;
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const USER_AGENT: &str = concat!("clash.meta/", env!("CARGO_PKG_VERSION"));
const MAX_BODY_BYTES: usize = 256 * 1024 * 1024; // 256 MiB hard ceiling

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

    let conn = proxy
        .dial_tcp(&metadata)
        .await
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
        let mut stream = tls
            .connect(server_name, conn)
            .await
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
    Ok(Outcome::Body(buf[body_start..].to_vec()))
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
    proxies: &std::collections::HashMap<String, Arc<dyn Proxy>>,
) -> Option<Arc<dyn Proxy>> {
    let entry = raw_proxies?.first()?;
    let name = entry.get("name")?.as_str()?;
    proxies.get(name).cloned()
}
