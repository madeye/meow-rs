use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Credential store: username → plain-text password.
/// Matches upstream Go mihomo which stores credentials as plain text.
#[derive(Debug)]
pub struct Credentials {
    inner: HashMap<String, String>,
}

impl Credentials {
    pub fn new(inner: HashMap<String, String>) -> Self {
        Self { inner }
    }

    /// Constant-time password comparison to prevent timing attacks.
    pub fn verify(&self, username: &str, password: &str) -> bool {
        match self.inner.get(username) {
            Some(stored) => stored.as_bytes().ct_eq(password.as_bytes()).into(),
            None => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Authentication configuration built from config at load time.
#[derive(Debug)]
pub struct AuthConfig {
    pub credentials: Arc<Credentials>,
    /// Source IP ranges that bypass auth. Always includes 127.0.0.1/32 and ::1/128.
    pub skip_prefixes: Vec<IpNet>,
}

impl AuthConfig {
    pub fn new(credentials: Arc<Credentials>, skip_prefixes: Vec<IpNet>) -> Self {
        Self {
            credentials,
            skip_prefixes,
        }
    }

    pub fn should_skip(&self, src_ip: &IpAddr) -> bool {
        self.skip_prefixes.iter().any(|net| net.contains(src_ip))
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self::new(
            Arc::new(Credentials::new(HashMap::new())),
            vec!["127.0.0.1/32".parse().unwrap(), "::1/128".parse().unwrap()],
        )
    }
}
