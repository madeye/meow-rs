use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::body::BodyCipher;
use super::header::{read_aead_response_header, response_body_keys};

/// Spawn a VMess relay task that handles AEAD body record framing.
///
/// Returns a `DuplexStream` that the caller reads/writes plain bytes on.
/// The background task first consumes the AEAD-sealed response header
/// (validating the per-connection `resp_v` byte), then encrypts writes into
/// body records and decrypts reads from body records on the underlying stream.
pub fn spawn_vmess_relay(
    stream: Box<dyn meow_transport::Stream>,
    mut read_cipher: BodyCipher,
    mut write_cipher: BodyCipher,
    req_key: [u8; 16],
    req_iv: [u8; 16],
    resp_v: u8,
) -> DuplexStream {
    let (client, proxy) = tokio::io::duplex(32768);

    tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(stream);

        // Consume and validate the AEAD-sealed response header. The response
        // body keys are SHA-256 of the request body key/iv.
        let (resp_body_key, resp_body_iv) = response_body_keys(&req_key, &req_iv);
        if let Err(e) =
            read_aead_response_header(&mut rd, &resp_body_key, &resp_body_iv, resp_v).await
        {
            tracing::warn!("vmess: response header decode failed: {e}");
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
