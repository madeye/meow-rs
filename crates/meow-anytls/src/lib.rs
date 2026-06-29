//! AnyTLS protocol implementation in Rust
//!
//! A proxy protocol attempting to mitigate TLS in TLS fingerprinting issues.
//!
//! # Architecture
//!
//! - **protocol**: Frame and codec implementation
//! - **session**: Session and stream management
//! - **padding**: Traffic obfuscation padding
//! - **util**: Utilities (error handling, auth, TLS config)
//! - **client**: Client implementation
//! - **server**: Server implementation

/// Client implementation
pub mod client;
/// Padding module for traffic obfuscation
pub mod padding;
/// Protocol layer: Frame and codec implementation
pub mod protocol;
/// Server implementation
pub mod server;
/// Session layer: Session and stream management
pub mod session;
/// Utility modules (error, auth, TLS, etc.)
pub mod util;

pub use client::*;
pub use padding::*;
pub use protocol::*;
pub use session::*;
pub use util::*;

// Re-export commonly used types
pub use util::auth::{authenticate_client, hash_password, send_authentication};
pub use util::error::{AnyTlsError, Result};
