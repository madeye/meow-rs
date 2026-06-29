/// Padding factory for traffic obfuscation
pub mod factory;

pub use factory::*;

/// Check mark in padding scheme, indicates should check if data remains
pub const CHECK_MARK: i32 = -1;
