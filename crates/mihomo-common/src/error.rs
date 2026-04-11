use thiserror::Error;

#[derive(Error, Debug)]
pub enum MihomoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Config error: {0}")]
    Config(String),
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("Proxy error: {0}")]
    Proxy(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
    #[error("proxy authentication failed")]
    ProxyAuthFailed,
    #[error("HTTP CONNECT failed with status {0}")]
    HttpConnectFailed(u16),
    #[error("SOCKS5 connect failed with reply code {0:#04x}")]
    Socks5ConnectFailed(u8),
    #[error("SOCKS5: no acceptable authentication method")]
    NoAcceptableMethod,
    #[error("no proxy available")]
    NoProxyAvailable,
    #[error("relay chain failed at hop {hop}: {source}")]
    RelayHopFailed {
        hop: usize,
        source: Box<MihomoError>,
    },
    #[error("UDP not supported by this relay chain")]
    UdpNotSupported,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, MihomoError>;
