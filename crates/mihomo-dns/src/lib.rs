pub mod cache;
pub mod fakeip;
pub mod resolver;
pub mod server;
pub mod upstream;

pub use cache::DnsCache;
pub use fakeip::{FileStore, MemoryStore, Pool, PoolError, Skipper, SkipperMode, Store};
pub use resolver::{BootstrapError, FallbackFilter, NameserverPolicy, PolicyEntry, Resolver};
pub use server::DnsServer;
pub use upstream::{HostOrIp, NameServerParseError, NameServerUrl};
