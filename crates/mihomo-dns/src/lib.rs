pub mod cache;
pub mod client;
pub mod fakeip;
pub mod resolver;
pub mod server;
pub mod upstream;

pub use cache::DnsCache;
pub use client::{set_socket_factory, ClientError, DnsClient, SocketFactory};
pub use fakeip::{FileStore, MemoryStore, Pool, PoolError, Skipper, SkipperMode, Store};
pub use resolver::{BootstrapError, FallbackFilter, NameserverPolicy, PolicyEntry, Resolver};
pub use server::DnsServer;
pub use upstream::{HostOrIp, NameServerEntry, NameServerParseError, NameServerUrl};
