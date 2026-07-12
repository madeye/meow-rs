use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::header::{response_body_keys, Security};

/// Maximum plaintext per body record (matching upstream 16 KiB - 16 tag).
const MAX_PLAINTEXT: usize = 16384 - 16;

/// Body keys/IVs derived from the per-connection req_key and req_iv. The IVs
/// are the full 16-byte seeds; each record nonce is `count(2 BE) || iv[2..12]`.
struct DerivedKeys {
    write_key: Vec<u8>,
    write_iv: [u8; 16],
    read_key: Vec<u8>,
    read_iv: [u8; 16],
}

/// Expand a 16-byte AEAD seed key into the actual cipher key for `security`.
///
/// - AES-128-GCM: the 16-byte key is used directly.
/// - ChaCha20-Poly1305: 32-byte key `MD5(k) || MD5(MD5(k))`.
///
/// upstream: `transport/vmess/conn.go` (`sendRequest`, per-security branch).
fn expand_body_key(security: Security, key16: &[u8; 16]) -> Vec<u8> {
    match security {
        Security::Aes128Gcm => key16.to_vec(),
        Security::ChaCha20Poly1305 => {
            let md5_1: [u8; 16] = Md5::digest(key16).into();
            let md5_2: [u8; 16] = Md5::digest(md5_1).into();
            let mut k = Vec::with_capacity(32);
            k.extend_from_slice(&md5_1);
            k.extend_from_slice(&md5_2);
            k
        }
        Security::None => Vec::new(),
    }
}

fn derive_keys(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16]) -> DerivedKeys {
    // Request (write) direction uses the raw per-connection key/iv directly —
    // there is NO "VMess Body AEAD Key" KDF in the wire protocol.
    let write_key = expand_body_key(security, req_key);
    let write_iv = *req_iv;

    // Response (read) direction keys come from SHA-256 of the request key/iv.
    let (resp_key, resp_iv) = response_body_keys(req_key, req_iv);
    let read_key = expand_body_key(security, &resp_key);

    DerivedKeys {
        write_key,
        write_iv,
        read_key,
        read_iv: resp_iv,
    }
}

/// One direction's AEAD state. The cipher object (the expanded key schedule)
/// is built once per connection — only the nonce changes per record.
#[derive(Clone)]
enum RecordCipher {
    None,
    /// Boxed: the AES key schedule is ~10× the size of the other variants.
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl RecordCipher {
    fn new(security: Security, key: &[u8]) -> Self {
        match security {
            Security::None => Self::None,
            Security::Aes128Gcm => Self::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(key).expect("derived AES-128 key is 16 bytes"),
            )),
            Security::ChaCha20Poly1305 => Self::ChaCha20Poly1305(Box::new(
                ChaCha20Poly1305::new_from_slice(key).expect("derived ChaCha20 key is 32 bytes"),
            )),
        }
    }

    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::None => Err(std::io::Error::other("seal called with Security::None")),
            Self::Aes128Gcm(c) => c
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|e| std::io::Error::other(format!("aes-gcm encrypt: {e}"))),
            Self::ChaCha20Poly1305(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|e| std::io::Error::other(format!("chacha encrypt: {e}"))),
        }
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::None => Err(std::io::Error::other("open called with Security::None")),
            Self::Aes128Gcm(c) => c
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|e| std::io::Error::other(format!("aes-gcm decrypt: {e}"))),
            Self::ChaCha20Poly1305(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|e| std::io::Error::other(format!("chacha decrypt: {e}"))),
        }
    }
}

/// Build a 16-byte-seed record nonce: `count(2 BE) || iv[2..12]`. The first
/// two IV bytes are discarded (overwritten by the counter), matching mihomo
/// `aead.go` — a scheme that XORs the counter into the full IV only agrees
/// when `iv[0]==iv[1]==0`, so its records fail to authenticate on real servers.
fn record_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

/// Per-connection body cipher state for both directions.
pub struct BodyCipher {
    write: RecordCipher,
    write_iv: [u8; 16],
    read: RecordCipher,
    read_iv: [u8; 16],
    write_counter: u16,
    read_counter: u16,
}

impl BodyCipher {
    pub fn new(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16], resp_v: u8) -> Self {
        // resp_v gates the response *header* validation (in header.rs), not the
        // body IV; the parameter is kept for call-site signature stability.
        let _ = resp_v;
        let keys = derive_keys(security, req_key, req_iv);

        Self {
            write: RecordCipher::new(security, &keys.write_key),
            write_iv: keys.write_iv,
            read: RecordCipher::new(security, &keys.read_key),
            read_iv: keys.read_iv,
            write_counter: 0,
            read_counter: 0,
        }
    }

    /// Test hook: make the read direction decrypt what the write direction
    /// encrypts (real connections derive read keys from SHA-256 of req material).
    #[cfg(test)]
    fn mirror_write_to_read(&mut self) {
        self.read = self.write.clone();
        self.read_iv = self.write_iv;
        self.read_counter = self.write_counter;
    }

    fn write_nonce(&mut self) -> [u8; 12] {
        let nonce = record_nonce(&self.write_iv, self.write_counter);
        self.write_counter = self.write_counter.wrapping_add(1);
        nonce
    }

    fn read_nonce(&mut self) -> [u8; 12] {
        let nonce = record_nonce(&self.read_iv, self.read_counter);
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
        if matches!(self.write, RecordCipher::None) {
            writer.write_all(plaintext).await?;
            return writer.flush().await;
        }

        let nonce = self.write_nonce();
        let ct = self.write.seal(&nonce, plaintext)?;
        let len = ct.len() as u16;
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&ct).await?;
        writer.flush().await
    }

    /// Read and decrypt one body record.
    pub async fn read_record<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<Vec<u8>> {
        if matches!(self.read, RecordCipher::None) {
            let mut buf = vec![0u8; 4096];
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            buf.truncate(n);
            return Ok(buf);
        }

        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let ct_len = u16::from_be_bytes(len_buf) as usize;
        if ct_len == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        let mut ct = vec![0u8; ct_len];
        reader.read_exact(&mut ct).await?;
        let nonce = self.read_nonce();
        self.read.open(&nonce, &ct)
    }

    pub fn max_plaintext() -> usize {
        MAX_PLAINTEXT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> ([u8; 16], [u8; 16]) {
        let req_key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let req_iv = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20,
        ];
        (req_key, req_iv)
    }

    #[tokio::test]
    async fn aes_128_gcm_record_round_trip() {
        let (req_key, req_iv) = test_keys();
        let mut writer_cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        let plaintext = b"hello vmess aes-128-gcm body";

        let mut wire = Vec::new();
        writer_cipher
            .write_record(&mut wire, plaintext)
            .await
            .unwrap();

        // Wire must be: 2-byte length + ciphertext(plaintext_len + 16 tag)
        let expected_ct_len = plaintext.len() + 16;
        let wire_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        assert_eq!(
            wire_len, expected_ct_len,
            "record length must include the 16-byte tag"
        );
        assert_eq!(wire.len(), 2 + expected_ct_len);

        // Now read it back — use WRITE keys since we're decrypting what we wrote
        // (read_cipher uses response keys derived from swapped req_iv/req_key)
        // For self-round-trip, we need a cipher with matching keys.
        let mut read_cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        read_cipher.mirror_write_to_read();

        let mut cursor = std::io::Cursor::new(wire);
        let decrypted = read_cipher.read_record(&mut cursor).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn chacha20_poly1305_record_round_trip() {
        let (req_key, req_iv) = test_keys();
        let mut writer_cipher =
            BodyCipher::new(Security::ChaCha20Poly1305, &req_key, &req_iv, 0x42);
        let plaintext = b"hello vmess chacha20 body";

        let mut wire = Vec::new();
        writer_cipher
            .write_record(&mut wire, plaintext)
            .await
            .unwrap();

        let expected_ct_len = plaintext.len() + 16;
        let wire_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        assert_eq!(wire_len, expected_ct_len);

        let mut read_cipher = BodyCipher::new(Security::ChaCha20Poly1305, &req_key, &req_iv, 0x42);
        read_cipher.mirror_write_to_read();

        let mut cursor = std::io::Cursor::new(wire);
        let decrypted = read_cipher.read_record(&mut cursor).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn none_is_passthrough() {
        let (req_key, req_iv) = test_keys();
        let mut cipher = BodyCipher::new(Security::None, &req_key, &req_iv, 0x42);
        let plaintext = b"raw bytes no framing";

        let mut wire = Vec::new();
        cipher.write_record(&mut wire, plaintext).await.unwrap();
        assert_eq!(wire, plaintext, "security:none must not add framing");
    }

    #[tokio::test]
    async fn nonce_counter_increments_per_record() {
        let (req_key, req_iv) = test_keys();
        let mut cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        let data = b"x";

        let mut wire1 = Vec::new();
        cipher.write_record(&mut wire1, data).await.unwrap();
        let mut wire2 = Vec::new();
        cipher.write_record(&mut wire2, data).await.unwrap();
        let mut wire3 = Vec::new();
        cipher.write_record(&mut wire3, data).await.unwrap();

        // Same plaintext with different nonces must produce different ciphertext
        assert_ne!(wire1, wire2);
        assert_ne!(wire2, wire3);
        assert_ne!(wire1, wire3);
    }

    #[test]
    fn chacha_key_uses_md5_cascade_not_kdf() {
        let (req_key, req_iv) = test_keys();
        let keys = derive_keys(Security::ChaCha20Poly1305, &req_key, &req_iv);
        // ChaCha20 body_key = MD5(req_key) || MD5(MD5(req_key)) — 32 bytes
        assert_eq!(
            keys.write_key.len(),
            32,
            "chacha key must be 32 bytes (double MD5)"
        );

        let mut hasher = Md5::new();
        hasher.update(req_key);
        let md5_1: [u8; 16] = hasher.finalize().into();
        let mut hasher2 = Md5::new();
        hasher2.update(md5_1);
        let md5_2: [u8; 16] = hasher2.finalize().into();

        assert_eq!(&keys.write_key[..16], &md5_1);
        assert_eq!(&keys.write_key[16..], &md5_2);
    }

    #[test]
    fn aes_write_key_is_raw_req_key() {
        // upstream: AES-128-GCM request body key = reqBodyKey verbatim (no KDF).
        let (req_key, req_iv) = test_keys();
        let keys = derive_keys(Security::Aes128Gcm, &req_key, &req_iv);
        assert_eq!(keys.write_key.as_slice(), &req_key);
        assert_eq!(keys.write_iv, req_iv);
    }

    #[test]
    fn aes_read_key_is_sha256_of_req_key() {
        // upstream: respBodyKey = SHA256(reqBodyKey)[..16], respBodyIV = SHA256(reqBodyIV)[..16].
        use sha2::{Digest, Sha256};
        let (req_key, req_iv) = test_keys();
        let keys = derive_keys(Security::Aes128Gcm, &req_key, &req_iv);
        let bk: [u8; 32] = Sha256::digest(req_key).into();
        let bi: [u8; 32] = Sha256::digest(req_iv).into();
        assert_eq!(keys.read_key.as_slice(), &bk[..16]);
        assert_eq!(&keys.read_iv, &bi[..16]);
    }

    #[test]
    fn record_nonce_overwrites_first_two_iv_bytes() {
        // nonce = count(2 BE) || iv[2..12]; iv[0]/iv[1] discarded.
        let iv = [
            0xAA, 0xBB, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let n = super::record_nonce(&iv, 0x1234);
        assert_eq!(n[0], 0x12);
        assert_eq!(n[1], 0x34);
        assert_eq!(&n[2..], &iv[2..12]);
    }

    /// End-to-end read-direction interop: a hand-rolled "server" encrypts a
    /// response record with the response keys (SHA-256 of req material) and
    /// the client's `read_record` must decrypt it. This fails if the read
    /// derivation or the nonce construction diverges from the wire spec —
    /// unlike the mirror-based round-trip which hides both.
    #[tokio::test]
    async fn read_record_decrypts_independently_encoded_response() {
        use aes_gcm::aead::Aead;
        use sha2::{Digest, Sha256};

        let (req_key, req_iv) = test_keys();
        let bk: [u8; 32] = Sha256::digest(req_key).into();
        let bi: [u8; 32] = Sha256::digest(req_iv).into();
        let resp_key: [u8; 16] = bk[..16].try_into().unwrap();
        let resp_iv: [u8; 16] = bi[..16].try_into().unwrap();

        // Server seals record 0 with nonce = count(0) || resp_iv[2..12].
        let plaintext = b"response payload from server";
        let nonce = super::record_nonce(&resp_iv, 0);
        let cipher = Aes128Gcm::new_from_slice(&resp_key).unwrap();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();
        let mut wire = (ct.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(&ct);

        let mut client = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        let mut cursor = std::io::Cursor::new(wire);
        let decrypted = client.read_record(&mut cursor).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn record_length_includes_tag() {
        let (req_key, req_iv) = test_keys();
        let mut cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        let plaintext = vec![0xAB; 100];

        let mut wire = Vec::new();
        cipher.write_record(&mut wire, &plaintext).await.unwrap();

        let wire_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        // upstream: len = plaintext_len + 16 (tag), NOT just plaintext_len
        assert_eq!(
            wire_len,
            100 + 16,
            "record length must be plaintext + 16 (tag)"
        );
    }
}
