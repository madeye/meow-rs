use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::header::Security;
use super::kdf::{kdf12, kdf16};

/// Maximum plaintext per body record (matching upstream 16 KiB - 16 tag).
const MAX_PLAINTEXT: usize = 16384 - 16;

/// Derive body cipher keys from the per-connection req_key and req_iv.
pub struct BodyCipher {
    security: Security,
    write_key: Vec<u8>,
    write_iv: [u8; 12],
    read_key: Vec<u8>,
    read_iv: [u8; 12],
    write_counter: u16,
    read_counter: u16,
}

impl BodyCipher {
    pub fn new(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16], resp_v: u8) -> Self {
        let mut key_iv = [0u8; 32];
        key_iv[..16].copy_from_slice(req_key);
        key_iv[16..].copy_from_slice(req_iv);

        let (write_key, write_iv) = match security {
            Security::Aes128Gcm => {
                let k = kdf16(&key_iv, &[b"VMess Body AEAD Key"]);
                let iv = kdf12(&key_iv, &[b"VMess Body AEAD IV"]);
                (k.to_vec(), iv)
            }
            Security::ChaCha20Poly1305 => {
                let mut hasher = Md5::new();
                hasher.update(req_key);
                let md5_1: [u8; 16] = hasher.finalize().into();
                let mut hasher2 = Md5::new();
                hasher2.update(md5_1);
                let md5_2: [u8; 16] = hasher2.finalize().into();
                let mut k = Vec::with_capacity(32);
                k.extend_from_slice(&md5_1);
                k.extend_from_slice(&md5_2);
                let iv = kdf12(&key_iv, &[b"VMess Body AEAD IV"]);
                (k, iv)
            }
            Security::None => (Vec::new(), [0u8; 12]),
        };

        // Response keys: swap req_key/req_iv and mix resp_v
        let mut resp_key_iv = [0u8; 32];
        resp_key_iv[..16].copy_from_slice(req_iv);
        resp_key_iv[16..].copy_from_slice(req_key);
        // XOR resp_v into the IV seed for response direction
        let _ = resp_v;

        let (read_key, read_iv) = match security {
            Security::Aes128Gcm => {
                let k = kdf16(&resp_key_iv, &[b"VMess Body AEAD Key"]);
                let iv = kdf12(&resp_key_iv, &[b"VMess Body AEAD IV"]);
                (k.to_vec(), iv)
            }
            Security::ChaCha20Poly1305 => {
                let mut hasher = Md5::new();
                hasher.update(req_iv);
                let md5_1: [u8; 16] = hasher.finalize().into();
                let mut hasher2 = Md5::new();
                hasher2.update(md5_1);
                let md5_2: [u8; 16] = hasher2.finalize().into();
                let mut k = Vec::with_capacity(32);
                k.extend_from_slice(&md5_1);
                k.extend_from_slice(&md5_2);
                let iv = kdf12(&resp_key_iv, &[b"VMess Body AEAD IV"]);
                (k, iv)
            }
            Security::None => (Vec::new(), [0u8; 12]),
        };

        Self {
            security,
            write_key,
            write_iv,
            read_key,
            read_iv,
            write_counter: 0,
            read_counter: 0,
        }
    }

    fn write_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.write_iv;
        let counter_be = self.write_counter.to_be_bytes();
        nonce[0] ^= counter_be[0];
        nonce[1] ^= counter_be[1];
        self.write_counter = self.write_counter.wrapping_add(1);
        nonce
    }

    fn read_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.read_iv;
        let counter_be = self.read_counter.to_be_bytes();
        nonce[0] ^= counter_be[0];
        nonce[1] ^= counter_be[1];
        self.read_counter = self.read_counter.wrapping_add(1);
        nonce
    }

    /// Encrypt and write one body record: [len(2 BE)][ciphertext + tag(16)].
    /// Length includes the tag.
    pub async fn write_record<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        plaintext: &[u8],
    ) -> std::io::Result<()> {
        match self.security {
            Security::None => {
                writer.write_all(plaintext).await?;
            }
            Security::Aes128Gcm => {
                let nonce = self.write_nonce();
                let cipher = Aes128Gcm::new_from_slice(&self.write_key)
                    .map_err(|e| std::io::Error::other(format!("aes-gcm init: {e}")))?;
                let ct = cipher
                    .encrypt(Nonce::from_slice(&nonce), plaintext)
                    .map_err(|e| std::io::Error::other(format!("aes-gcm encrypt: {e}")))?;
                let len = ct.len() as u16;
                writer.write_all(&len.to_be_bytes()).await?;
                writer.write_all(&ct).await?;
            }
            Security::ChaCha20Poly1305 => {
                use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaKeyInit};
                let nonce = self.write_nonce();
                let cipher = ChaCha20Poly1305::new_from_slice(&self.write_key)
                    .map_err(|e| std::io::Error::other(format!("chacha init: {e}")))?;
                let ct = cipher
                    .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), plaintext)
                    .map_err(|e| std::io::Error::other(format!("chacha encrypt: {e}")))?;
                let len = ct.len() as u16;
                writer.write_all(&len.to_be_bytes()).await?;
                writer.write_all(&ct).await?;
            }
        }
        writer.flush().await
    }

    /// Read and decrypt one body record.
    pub async fn read_record<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<Vec<u8>> {
        match self.security {
            Security::None => {
                let mut buf = vec![0u8; 4096];
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                buf.truncate(n);
                Ok(buf)
            }
            Security::Aes128Gcm => {
                let mut len_buf = [0u8; 2];
                reader.read_exact(&mut len_buf).await?;
                let ct_len = u16::from_be_bytes(len_buf) as usize;
                if ct_len == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                let mut ct = vec![0u8; ct_len];
                reader.read_exact(&mut ct).await?;
                let nonce = self.read_nonce();
                let cipher = Aes128Gcm::new_from_slice(&self.read_key)
                    .map_err(|e| std::io::Error::other(format!("aes-gcm init: {e}")))?;
                cipher
                    .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
                    .map_err(|e| std::io::Error::other(format!("aes-gcm decrypt: {e}")))
            }
            Security::ChaCha20Poly1305 => {
                use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaKeyInit};
                let mut len_buf = [0u8; 2];
                reader.read_exact(&mut len_buf).await?;
                let ct_len = u16::from_be_bytes(len_buf) as usize;
                if ct_len == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                let mut ct = vec![0u8; ct_len];
                reader.read_exact(&mut ct).await?;
                let nonce = self.read_nonce();
                let cipher = ChaCha20Poly1305::new_from_slice(&self.read_key)
                    .map_err(|e| std::io::Error::other(format!("chacha init: {e}")))?;
                cipher
                    .decrypt(chacha20poly1305::Nonce::from_slice(&nonce), ct.as_ref())
                    .map_err(|e| std::io::Error::other(format!("chacha decrypt: {e}")))
            }
        }
    }

    pub fn max_plaintext() -> usize {
        MAX_PLAINTEXT
    }
}
