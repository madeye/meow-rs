#[derive(Debug, Clone, Default)]
pub struct Config {
    pub server_addr: String,
    pub server_name: String,
    pub auth: String,
    pub insecure: bool,
    pub rx_bps: u64,
    pub obfs_password: String,
    pub hop_ports: String,
    pub hop_interval_min_secs: u64,
    pub hop_interval_max_secs: u64,
    pub pin_sha256: String,
    // Accepted for config/API compatibility. On the quiche path writes are
    // never gated on the TCP response, so a proxied stream is already
    // effectively fast-open; the flag's payload-bundling micro-optimization is
    // not separately implemented.
    #[allow(
        dead_code,
        reason = "fast-open payload bundling not implemented on the quiche path"
    )]
    pub fast_open: bool,
}
