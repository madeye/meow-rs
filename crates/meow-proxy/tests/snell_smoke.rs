//! End-to-end smoke test against a real Snell server.
//!
//! Gated behind the `SNELL_SMOKE` env var so CI doesn't dial anyone.
//! Example:
//!
//! ```bash
//! SNELL_SMOKE=1 SNELL_SERVER=82.40.35.29:63689 SNELL_PSK=... \
//!     cargo test -p meow-proxy --features snell --test snell_smoke -- --nocapture
//! ```

#![cfg(feature = "snell")]

use meow_proxy::snell::protocol::{write_header, Snell};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

fn opt_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Transparent wrapper that prints every chunk of bytes that flows across
/// the TCP stream in both directions. Useful for spotting wire-format bugs.
struct Sniffer {
    inner: TcpStream,
    label: &'static str,
}

impl AsyncRead for Sniffer {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                eprintln!("[{}] READ ERR: {e}", self.label);
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len() - before;
                if n > 0 {
                    let slice = &buf.filled()[before..];
                    eprintln!(
                        "[{}] READ {} bytes: {}",
                        self.label,
                        n,
                        hex::encode(&slice[..slice.len().min(64)])
                    );
                } else {
                    eprintln!("[{}] READ 0 (EOF)", self.label);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for Sniffer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => {
                eprintln!(
                    "[{}] WRITE {} bytes: {}",
                    self.label,
                    n,
                    hex::encode(&buf[..n.min(64)])
                );
                Poll::Ready(Ok(n))
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snell_dial_real_server() {
    if opt_env("SNELL_SMOKE").is_none() {
        eprintln!("SNELL_SMOKE not set; skipping. Set it to run this test.");
        return;
    }
    let server_addr =
        opt_env("SNELL_SERVER").expect("SNELL_SERVER (host:port) required when SNELL_SMOKE=1");
    let psk = opt_env("SNELL_PSK").expect("SNELL_PSK required when SNELL_SMOKE=1");

    let target_host = opt_env("SNELL_TARGET_HOST").unwrap_or_else(|| "httpbin.org".to_string());
    let target_port: u16 = opt_env("SNELL_TARGET_PORT")
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let target_path = opt_env("SNELL_TARGET_PATH").unwrap_or_else(|| "/ip".to_string());

    eprintln!("snell smoke: dialing {target_host}:{target_port} via {server_addr} (reuse=false)");

    let tcp = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(&server_addr))
        .await
        .expect("tcp connect timeout")
        .expect("tcp connect ok");
    tcp.set_nodelay(true).ok();
    let sniffer = Sniffer {
        inner: tcp,
        label: "snell-tcp",
    };

    let mut snell = Snell::new(sniffer, Arc::from(psk.as_bytes()));

    // Snell CONNECT request (reuse=false).
    write_header(&mut snell, &target_host, target_port, false)
        .await
        .expect("write snell header");
    snell.flush().await.expect("flush snell header");

    // HTTP/1.0 GET.
    let request =
        format!("GET {target_path} HTTP/1.0\r\nHost: {target_host}\r\nConnection: close\r\n\r\n");
    snell
        .write_all(request.as_bytes())
        .await
        .expect("write http req");
    snell.flush().await.expect("flush http req");

    // Read up to 4 KiB; we read in a loop so a mid-stream snell error
    // doesn't discard the bytes we already have.
    let mut buf = Vec::with_capacity(4096);
    let mut scratch = [0u8; 1024];
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(10), snell.read(&mut scratch)).await
        {
            Err(_) => {
                eprintln!("read timed out after {} bytes", buf.len());
                break;
            }
            Ok(Err(e)) => {
                eprintln!("read error after {} bytes: {e}", buf.len());
                break;
            }
            Ok(Ok(0)) => {
                eprintln!("read EOF (snell zero-chunk) after {} bytes", buf.len());
                break;
            }
            Ok(Ok(n)) => n,
        };
        buf.extend_from_slice(&scratch[..n]);
        if buf.len() >= 4096 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    eprintln!("--- decoded server response (first 400 B) ---");
    eprintln!("{}", &head[..head.len().min(400)]);
    eprintln!("--- end ({} B total) ---", buf.len());
    assert!(
        head.starts_with("HTTP/1."),
        "expected HTTP response head, got: {:?}",
        &head[..head.len().min(80)]
    );
}
