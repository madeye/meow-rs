use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::body::BodyCipher;

/// Spawn a VMess relay task that handles AEAD body record framing.
///
/// Returns a `DuplexStream` that the caller reads/writes plain bytes on.
/// The background task encrypts writes into body records and decrypts
/// reads from body records on the underlying stream.
pub fn spawn_vmess_relay(
    stream: Box<dyn meow_transport::Stream>,
    mut read_cipher: BodyCipher,
    mut write_cipher: BodyCipher,
    resp_v: u8,
) -> DuplexStream {
    let (client, proxy) = tokio::io::duplex(32768);

    tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(stream);

        // Read and validate the 4-byte response header
        let mut hdr = [0u8; 4];
        if rd.read_exact(&mut hdr).await.is_err() {
            return;
        }
        if hdr[0] != resp_v {
            tracing::warn!("vmess: response validation byte mismatch");
            return;
        }

        let (mut proxy_rd, mut proxy_wr) = tokio::io::split(proxy);

        // Upstream: stream → decrypt → proxy_wr
        let read_task = tokio::spawn(async move {
            while let Ok(plaintext) = read_cipher.read_record(&mut rd).await {
                if proxy_wr.write_all(&plaintext).await.is_err() {
                    break;
                }
            }
            let _ = proxy_wr.shutdown().await;
        });

        // Downstream: proxy_rd → encrypt → stream
        let write_task = tokio::spawn(async move {
            let mut buf = vec![0u8; BodyCipher::max_plaintext()];
            loop {
                let n = match proxy_rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if write_cipher.write_record(&mut wr, &buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });

        let _ = read_task.await;
        write_task.abort();
    });

    client
}
