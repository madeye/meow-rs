use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("config: {0}")]
    Config(String),

    #[error("resolve: {0}")]
    Resolve(String),

    #[error("tls: {0}")]
    Tls(String),

    #[error("quic: {0}")]
    Quic(String),

    #[error("http3: {0}")]
    Http3(String),

    #[error("auth: {0}")]
    Auth(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("closed")]
    Closed,
}

impl Error {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn tls(message: impl Into<String>) -> Self {
        Self::Tls(message.into())
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
