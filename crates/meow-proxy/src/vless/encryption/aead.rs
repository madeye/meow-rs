//! Record-layer AEAD, BLAKE3 key derivation, framing helpers, and padding —
//! a direct port of the shared pieces of Xray/mihomo `encryption/common.go`.

use std::time::Duration;

use aes::Aes256;
use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use ctr::cipher::KeyIvInit;

/// AES-256 in CTR mode with a 128-bit big-endian counter — matches Go's
/// `cipher.NewCTR(aes.NewCipher(k), iv)`.
pub(crate) type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// X25519 public key / shared-secret length.
pub(crate) const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation-key (public key) length.
pub(crate) const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub(crate) const MLKEM768_CT_LEN: usize = 1088;
/// AEAD tag length (both AES-256-GCM and ChaCha20-Poly1305).
pub(crate) const TAG_LEN: usize = 16;

/// All-`0xFF` nonce used as an explicit, counter-independent nonce for the
/// handshake's fixed-position seals (`Seal(..., MaxNonce, ...)`).
const MAX_NONCE: [u8; 12] = [0xFF; 12];

/// BLAKE3 keyed derivation with an arbitrary-bytes context.
///
/// Go calls `blake3.DeriveKey(out, string(ctx), key)` where `ctx` is raw bytes
/// (an IV, a public key, a record, …) reinterpreted as a Go string. BLAKE3's
/// derive-key mode only ever feeds the context through `context.as_bytes()`, so
/// viewing the same bytes as a `&str` reproduces the Go output exactly.
fn derive_key(ctx: &[u8], key_material: &[u8]) -> [u8; 32] {
    // SAFETY: the bytes are used solely as hash input (`context.as_bytes()`);
    // no UTF-8 invariant is relied upon downstream, so an unchecked view is
    // sound and byte-for-byte equivalent to Go's `string(ctx)`.
    let ctx_str = unsafe { std::str::from_utf8_unchecked(ctx) };
    blake3::derive_key(ctx_str, key_material)
}

/// BLAKE3-256 hash — Go's `blake3.Sum256`.
pub(crate) fn blake3_sum256(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// `NewCTR(key, iv)` — AES-256-CTR keyed by `DeriveKey("VLESS", key)`.
pub(crate) fn new_ctr(key: &[u8], iv: &[u8; 16]) -> Aes256Ctr {
    let k = blake3::derive_key("VLESS", key);
    Aes256Ctr::new((&k).into(), iv.into())
}

/// An AEAD instance with a per-instance auto-incrementing nonce counter,
/// mirroring Go's `encryption.AEAD`.
pub(crate) struct Aead {
    cipher: Cipher,
    nonce: [u8; 12],
}

enum Cipher {
    Aes(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

impl Aead {
    /// `NewAEAD(ctx, key, useAES)` — derives a 32-byte key via BLAKE3 and
    /// selects AES-256-GCM or ChaCha20-Poly1305.
    pub(crate) fn new(ctx: &[u8], key: &[u8], use_aes: bool) -> Self {
        let k = derive_key(ctx, key);
        let cipher = if use_aes {
            Cipher::Aes(Box::new(Aes256Gcm::new((&k).into())))
        } else {
            Cipher::Chacha(Box::new(ChaCha20Poly1305::new((&k).into())))
        };
        Self {
            cipher,
            nonce: [0u8; 12],
        }
    }

    /// Pre-increment the big-endian nonce counter (Go's `IncreaseNonce`).
    fn increment_nonce(&mut self) {
        for i in 0..12 {
            let idx = 11 - i;
            self.nonce[idx] = self.nonce[idx].wrapping_add(1);
            if self.nonce[idx] != 0 {
                break;
            }
        }
    }

    /// `true` when the counter sits at the maximum nonce — the record layer
    /// re-keys on the boundary (`bytes.Equal(Nonce, MaxNonce)`).
    pub(crate) fn is_exhausted(&self) -> bool {
        self.nonce == MAX_NONCE
    }

    fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let payload = Payload {
            msg: plaintext,
            aad: ad,
        };
        match &self.cipher {
            Cipher::Aes(c) => c.encrypt(nonce.into(), payload),
            Cipher::Chacha(c) => c.encrypt(nonce.into(), payload),
        }
        .expect("AEAD seal is infallible for valid inputs")
    }

    fn decrypt(&self, nonce: &[u8; 12], ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let payload = Payload { msg: ct, aad: ad };
        match &self.cipher {
            Cipher::Aes(c) => c.decrypt(nonce.into(), payload),
            Cipher::Chacha(c) => c.decrypt(nonce.into(), payload),
        }
    }

    /// Seal with the auto-incrementing counter and no associated data.
    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.encrypt(&nonce, plaintext, &[])
    }

    /// Seal with the auto-incrementing counter and associated data (record header).
    pub(crate) fn seal_ad(&mut self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.encrypt(&nonce, plaintext, ad)
    }

    /// Seal with the explicit all-`0xFF` nonce (counter untouched).
    ///
    /// Only the server seals at `MaxNonce` (the client reads it via
    /// [`Self::open_max`]), so this is exercised solely by the reference test
    /// server today.
    #[cfg(test)]
    pub(crate) fn seal_max(&self, plaintext: &[u8]) -> Vec<u8> {
        self.encrypt(&MAX_NONCE, plaintext, &[])
    }

    /// Open with the auto-incrementing counter and no associated data.
    pub(crate) fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.decrypt(&nonce, ct, &[])
    }

    /// Open with the auto-incrementing counter and associated data (record header).
    pub(crate) fn open_ad(&mut self, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.decrypt(&nonce, ct, ad)
    }

    /// Open with the explicit all-`0xFF` nonce (counter untouched).
    pub(crate) fn open_max(&self, ct: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.decrypt(&MAX_NONCE, ct, &[])
    }
}

// ─── Length / header framing (`common.go`) ────────────────────────────────────

/// `EncodeLength(l)` — 2-byte big-endian.
pub(crate) fn encode_length(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, l as u8]
}

/// `DecodeLength(b)` — 2-byte big-endian.
pub(crate) fn decode_length(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | (b[1] as usize)
}

/// `EncodeHeader(h, l)` — a fake TLS 1.3 application-data record header.
pub(crate) fn encode_header(l: usize) -> [u8; 5] {
    [23, 3, 3, (l >> 8) as u8, l as u8]
}

/// `DecodeHeader(h)` — returns the record body length (17..=16640) or an error
/// for an out-of-range / malformed header. Matches Go byte-for-byte.
pub(crate) fn decode_header(h: &[u8; 5]) -> Result<usize, std::io::Error> {
    let mut l = ((h[3] as usize) << 8) | (h[4] as usize);
    if h[0] != 23 || h[1] != 3 || h[2] != 3 {
        l = 0;
    }
    // TLS 1.3 max record: 16384 + 256 (RFC 8446 §5.2).
    if !(17..=16640).contains(&l) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("vless-encryption: invalid record header: {h:?}"),
        ));
    }
    Ok(l)
}

// ─── Padding (`ParsePadding` / `CreatPadding`) ────────────────────────────────

/// Parsed padding schedule: alternating length triples and gap triples.
#[derive(Default, Clone)]
pub(crate) struct Padding {
    lens: Vec<[i64; 3]>,
    gaps: Vec<[i64; 3]>,
}

/// `ParsePadding` — parses a `100-111-1111.75-0-111.50-0-3333` style string.
pub(crate) fn parse_padding(padding: &str) -> Result<Padding, String> {
    let mut out = Padding::default();
    if padding.is_empty() {
        return Ok(out);
    }
    let mut max_len: i64 = 0;
    for (i, s) in padding.split('.').enumerate() {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
            return Err(format!("invalid padding length/gap parameter: {s}"));
        }
        let mut y = [0i64; 3];
        for (k, p) in parts.iter().take(3).enumerate() {
            y[k] = p
                .parse::<i64>()
                .map_err(|_| format!("invalid padding number: {p}"))?;
        }
        if i == 0 && (y[0] < 100 || y[1] < 18 + 17 || y[2] < 18 + 17) {
            return Err("first padding length must not be smaller than 35".into());
        }
        if i % 2 == 0 {
            out.lens.push(y);
            max_len += y[1].max(y[2]);
        } else {
            out.gaps.push(y);
        }
    }
    if max_len > 18 + 65535 {
        return Err("total padding length must not be larger than 65553".into());
    }
    Ok(out)
}

/// `CreatPadding` — samples concrete padding lengths and inter-fragment gaps.
///
/// The exact random values need not match the Go implementation: the padding
/// content is random and its length is signalled to the peer via an encrypted
/// length prefix, so any in-range sample interoperates.
pub(crate) fn create_padding(p: &Padding) -> (usize, Vec<usize>, Vec<Duration>) {
    let (lens_spec, gaps_spec) = if p.lens.is_empty() {
        (vec![[100, 111, 1111], [50, 0, 3333]], vec![[75, 0, 111]])
    } else {
        (p.lens.clone(), p.gaps.clone())
    };

    let mut lens = Vec::with_capacity(lens_spec.len());
    let mut length = 0usize;
    for y in &lens_spec {
        let mut l = 0i64;
        if y[0] >= rand_between(0, 100) {
            l = rand_between(y[1], y[2]);
        }
        lens.push(l as usize);
        length += l as usize;
    }
    let mut gaps = Vec::with_capacity(gaps_spec.len());
    for y in &gaps_spec {
        let mut g = 0i64;
        if y[0] >= rand_between(0, 100) {
            g = rand_between(y[1], y[2]);
        }
        gaps.push(Duration::from_millis(g as u64));
    }
    (length, lens, gaps)
}

/// `crypto.RandBetween(from, to)` — a uniform sample in `[from, to)`
/// (`to == from` yields `from`).
fn rand_between(from: i64, to: i64) -> i64 {
    if to <= from {
        return from;
    }
    let span = (to - from) as u64;
    from + (rand::random::<u64>() % span) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_increments_big_endian_and_wraps() {
        let mut a = Aead::new(b"ctx", b"key", true);
        assert_eq!(a.nonce, [0u8; 12]);
        a.increment_nonce();
        assert_eq!(a.nonce[11], 1);
        // Force a carry.
        a.nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF];
        a.increment_nonce();
        assert_eq!(a.nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
        // Wrap from max to zero.
        a.nonce = MAX_NONCE;
        assert!(a.is_exhausted());
        a.increment_nonce();
        assert_eq!(a.nonce, [0u8; 12]);
    }

    #[test]
    fn aead_round_trip_both_ciphers() {
        for use_aes in [true, false] {
            let mut enc = Aead::new(b"iv", b"key", use_aes);
            let mut dec = Aead::new(b"iv", b"key", use_aes);
            let ct = enc.seal_ad(b"hello world", b"\x17\x03\x03\x00\x1b");
            let pt = dec.open_ad(&ct, b"\x17\x03\x03\x00\x1b").unwrap();
            assert_eq!(pt, b"hello world");
        }
    }

    #[test]
    fn header_round_trip_and_bounds() {
        let h = encode_header(20);
        assert_eq!(decode_header(&h).unwrap(), 20);
        // Too short / too long / wrong prefix are rejected.
        assert!(decode_header(&encode_header(16)).is_err());
        assert!(decode_header(&[0, 3, 3, 0, 20]).is_err());
    }

    #[test]
    fn parse_padding_rejects_short_first() {
        assert!(parse_padding("10-20-30").is_err());
        assert!(parse_padding("100-111-1111.75-0-111").is_ok());
        assert!(parse_padding("").is_ok());
    }
}
