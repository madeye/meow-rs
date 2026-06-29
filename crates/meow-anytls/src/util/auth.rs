//! Authentication utilities for AnyTLS protocol

use crate::padding::PaddingFactory;
use crate::util::{AnyTlsError, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Compute SHA256 hash of password
pub fn hash_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

/// Authenticate a client connection (server side)
///
/// Reads authentication data from the connection:
/// - SHA256(password) (32 bytes)
/// - padding0_length (2 bytes, big-endian)
/// - padding0 (variable length)
pub async fn authenticate_client<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    expected_password_hash: &[u8; 32],
    _padding_factory: &Arc<PaddingFactory>,
) -> Result<()> {
    // Read SHA256(password)
    let mut password_hash = [0u8; 32];
    reader.read_exact(&mut password_hash).await?;

    // Verify password
    if password_hash != *expected_password_hash {
        return Err(AnyTlsError::AuthenticationFailed);
    }

    // Read padding0_length
    let mut padding_len_bytes = [0u8; 2];
    reader.read_exact(&mut padding_len_bytes).await?;
    let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;

    // Read padding0
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        reader.read_exact(&mut padding).await?;
        // Padding is discarded
    }

    Ok(())
}

/// Send authentication data (client side)
///
/// Writes authentication data to the connection:
/// - SHA256(password) (32 bytes)
/// - padding0_length (2 bytes, big-endian)
/// - padding0 (variable length)
pub async fn send_authentication<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    password_hash: &[u8; 32],
    padding_factory: &Arc<PaddingFactory>,
) -> Result<()> {
    // Write SHA256(password)
    writer.write_all(password_hash).await?;

    // Get padding0 length from padding scheme
    let padding_sizes = padding_factory.generate_record_payload_sizes(0);
    let padding_len = padding_sizes.first().copied().unwrap_or(0);

    // Ensure padding_len is non-negative
    let padding_len = if padding_len < 0 {
        0
    } else {
        padding_len as u16
    };

    // Write padding0_length
    writer.write_all(&padding_len.to_be_bytes()).await?;

    // Write padding0
    if padding_len > 0 {
        let padding = vec![0u8; padding_len as usize];
        writer.write_all(&padding).await?;
    }

    writer.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::PaddingFactory;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_authentication_success() {
        let password = "test_password";
        let password_hash = hash_password(password);

        let (mut client, mut server) = duplex(1024);
        let padding = PaddingFactory::default();

        // Client sends authentication
        send_authentication(&mut client, &password_hash, &padding)
            .await
            .unwrap();

        // Server authenticates
        authenticate_client(&mut server, &password_hash, &padding)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_authentication_failure() {
        let password = "test_password";
        let password_hash = hash_password(password);
        let wrong_hash = hash_password("wrong_password");

        let (mut client, mut server) = duplex(1024);
        let padding = PaddingFactory::default();

        // Client sends authentication with correct password
        send_authentication(&mut client, &password_hash, &padding)
            .await
            .unwrap();

        // Server authenticates with wrong password - should fail
        let result = authenticate_client(&mut server, &wrong_hash, &padding).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnyTlsError::AuthenticationFailed
        ));
    }

    #[tokio::test]
    async fn test_hash_password() {
        let hash1 = hash_password("test");
        let hash2 = hash_password("test");
        let hash3 = hash_password("different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
