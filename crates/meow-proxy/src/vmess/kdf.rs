use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// VMess KDF — HMAC-SHA256 cascade keyed by label and path segments.
///
/// upstream: transport/vmess/aead/encrypt.go::KDF
pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current_key = {
        let mut mac =
            HmacSha256::new_from_slice(b"VMess AEAD KDF").expect("HMAC accepts any key length");
        mac.update(key);
        mac.finalize().into_bytes()
    };
    for seg in path {
        let mut mac =
            HmacSha256::new_from_slice(&current_key).expect("HMAC accepts any key length");
        mac.update(seg);
        current_key = mac.finalize().into_bytes();
    }
    current_key.into()
}

pub fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let full = kdf(key, path);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_produces_deterministic_output() {
        let k1 = kdf(b"test-key", &[b"label1"]);
        let k2 = kdf(b"test-key", &[b"label1"]);
        assert_eq!(k1, k2);
    }

    #[test]
    fn kdf_different_paths_differ() {
        let k1 = kdf(b"test-key", &[b"label1"]);
        let k2 = kdf(b"test-key", &[b"label2"]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn kdf_multi_segment_path() {
        let k1 = kdf(b"key", &[b"a", b"b"]);
        let k2 = kdf(b"key", &[b"a"]);
        assert_ne!(k1, k2);
    }
}
