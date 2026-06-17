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
    pub fast_open: bool,
}
