use thiserror::Error;

/// AnyTLS protocol errors
#[derive(Error, Debug)]
pub enum AnyTlsError {
    /// IO error from underlying system calls
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// TLS-related error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Protocol violation or parsing error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Authentication failed (wrong password or credentials)
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Stream ID not found in session
    #[error("Stream not found: {0}")]
    StreamNotFound(u32),

    /// Session has been closed
    #[error("Session closed")]
    SessionClosed,

    /// Invalid or malformed frame
    #[error("Invalid frame: {0}")]
    InvalidFrame(String),

    /// Padding scheme error
    #[error("Padding scheme error: {0}")]
    PaddingScheme(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, AnyTlsError>;
