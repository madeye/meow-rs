# Type-Size Baseline — M2 Starting Line

## Reference: commit 9419421578f808c59db37fc7ec056a8971a741b9

Platform: aarch64-apple-darwin (Apple Silicon), macOS 25.4.0, Rust stable 1.88  
Profile: `dev` (debug) — sizes are layout sizes, not stack-frame sizes.  
All sizes measured via `std::mem::size_of` in #[cfg(test)] within the owning crate.

---

## Hot-path types (per-connection, per-relay-buffer)

| Type | Crate | Size (bytes) | Notes |
|------|-------|-------------|-------|
| `ConnectionInfo` | meow-tunnel | **408** | Embeds full `Metadata` (272 B) + 4 × String + Vec<String> |
| `Metadata` | meow-common | **272** | 9 × String/Vec<String> + 2 × Option<IpAddr> + misc |
| `TunnelInner` | meow-tunnel | 232 | Singleton; not per-connection |
| `UdpSession` | meow-tunnel | 48 | Box<dyn ProxyPacketConn> + String + AtomicU64 |
| `Tunnel` | meow-tunnel | 8 | Arc pointer to TunnelInner |

### `Metadata` field breakdown (272 bytes total)

`Metadata` is the dominant allocation source. Field layout (estimated, aarch64):

| Field | Type | Size |
|-------|------|------|
| `network` | Network (1-byte enum) | 1 |
| `conn_type` | ConnType (1-byte enum) | 1 |
| padding | — | 2 |
| `src_port` | u16 | 2 |
| `dst_port` | u16 | 2 |
| `src_ip` | Option<IpAddr> | 17+pad = 24 |
| `dst_ip` | Option<IpAddr> | 24 |
| `host` | String | 24 |
| `dns_mode` | DnsMode (1-byte enum) | 1+pad | 
| `process` | String | 24 |
| `process_path` | String | 24 |
| `uid` | Option<u32> | 8 |
| `dscp` | Option<u8> | 2+pad |
| `src_geo_ip` | Vec<String> | 24 |
| `dst_geo_ip` | Vec<String> | 24 |
| `sniff_host` | String | 24 |
| `in_name` | String | 24 |
| `in_port` | u16 | 2+pad |
| `in_user` | Option<String> | 24 |
| `special_proxy` | String | 24 |

Total: 272 B (confirmed by `size_of::<Metadata>()`).

M2 target (#34): replace `String` fields with `SmolStr` (stack-allocated ≤23 B, 24-B struct),
`Vec<String>` with `SmallVec<[String; 0]>` for rarely-used GeoIP lists.
`Option<IpAddr>` could become `Option<IpAddr>` stored as 20 B with niche optimization.
Expected reduction: ~80–120 B.

### `ConnectionInfo` field breakdown (408 bytes total)

| Field | Type | Size |
|-------|------|------|
| `id` | String | 24 |
| `metadata` | Metadata | 272 |
| `upload` | i64 | 8 |
| `download` | i64 | 8 |
| `start` | String | 24 |
| `chains` | Vec<String> | 24 |
| `rule` | String | 24 |
| `rule_payload` | String | 24 |

Total: 408 B. The `metadata` embed accounts for 272/408 = 67% of size.
M2 target (#35): replace `metadata: Metadata` with `metadata: Arc<Metadata>` (8 B pointer).
Expected reduction: ~260 B → ~148 B total.

### `UdpSession` field breakdown (48 bytes total)

| Field | Type | Size |
|-------|------|------|
| `conn` | Box<dyn ProxyPacketConn> | 16 (fat pointer) |
| `proxy_name` | String | 24 |
| `last_activity_ms` | AtomicU64 | 8 |

M2 target (#36): `proxy_name: String → Arc<str>` saves 16 B (String→Arc<str> = 16 B fat pointer).
Expected reduction: 48 → 32 B (−33%).

---

## `MeowError` pre-probe (lead directive 2026-05-12)

**`MeowError` total: 32 bytes** — **NEGATIVE RESULT: no escalation.**

Threshold is 64 B; 32 B is well under it. No `M2.enum-variant-mihomo-error` subtask needed.

| Variant | Payload type | Payload size |
|---------|-------------|-------------|
| `Io` | `std::io::Error` | 8 B (box on macOS) |
| `Config(String)` | String | 24 B |
| `Dns(String)` | String | 24 B |
| `Proxy(String)` | String | 24 B |
| `NotSupported(String)` | String | 24 B |
| `ProxyAuthFailed` | unit | 0 B |
| `HttpConnectFailed(u16)` | u16 | 2 B |
| `Socks5ConnectFailed(u8)` | u8 | 1 B |
| `NoAcceptableMethod` | unit | 0 B |
| `NoProxyAvailable` | unit | 0 B |
| `RelayHopFailed` | `{hop: usize, source: Box<MeowError>}` | 16 B |
| `UdpNotSupported` | unit | 0 B |
| `Other(String)` | String | 24 B |

The largest variant data is `String` (24 B). Total enum size = 24 (largest payload) + 8 (discriminant/padding) = 32 B.
The `RelayHopFailed` variant carries 16 B (usize + Box), smaller than String (24 B).

`large_enum_variant` lint (threshold default 200 B) does not fire — 32 B is far below.

---

## `AdapterType` negative finding (lead directive 2026-05-12)

`AdapterType` (`meow-common/src/adapter_type.rs:5`) has 14 unit variants and measures **1 byte**.
No per-connection inline sum-type allocation occurs — adapter dispatch is done via
`Box<dyn ProxyAdapter>` (16-byte fat pointer), which places all variant data on the heap and
is not part of any per-connection hot struct. This is already optimal; do not attempt further
reduction. Recorded here to prevent relitigating in M2 code review.

---

## Other types ≥ 64 B (workspace-wide survey)

| Type | Crate | Size (bytes) |
|------|-------|-------------|
| `ConnectionInfo` | meow-tunnel | 408 |
| `Metadata` | meow-common | 272 |
| `TunnelInner` | meow-tunnel | 232 |
| `tracing::Metadata<'_>` | tracing (dep) | 120 |
| `UdpSession` | meow-tunnel | 48 |

Note: `tracing::Metadata` is a static (zero per-connection allocation); excluded from M2 targets.
`TunnelInner` is a singleton; excluded.

---

## M2 reduction targets summary

| Type | Baseline | Expected post-M2 | Delta |
|------|----------|-------------------|-------|
| `Metadata` | 272 B | ~152–192 B | −80–120 B |
| `ConnectionInfo` | 408 B | ~148 B | −260 B |
| `UdpSession` | 48 B | 32 B | −16 B |
