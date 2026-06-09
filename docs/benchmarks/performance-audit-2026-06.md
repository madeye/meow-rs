# Performance Audit — June 2026

Code-inspection audit of all workspace crates, focused on hot-path performance:
per-connection setup, per-packet/per-byte relay, rule matching, DNS, and the
control plane. Findings are ordered by severity; each was verified against the
source at the cited location. No runtime profiling was performed — severities
reflect reasoning about call frequency and should be confirmed with the
`meow-bench` workloads (ADR-0006 W1–W5) before optimizing.

Overall: the hot paths are in very good shape. The ADR-0008 zero-alloc relay
invariant holds (stack relay buffers, tuple NAT keys, `ArcSwap` route table,
`Relaxed` atomics, SmolStr everywhere). The issues below are the residue, not
the rule.

## High severity

### H1. HTTP/SOCKS5 outbound adapters rebuild the rustls `ClientConfig` on every dial

`crates/meow-proxy/src/http_adapter.rs:96`, `crates/meow-proxy/src/socks5_adapter.rs:104`

`dial_stream()` constructs `TlsConfig` + `TlsLayer::new(&tls_cfg)` inside the
per-connection dial path. `TlsLayer::new` → `build_rustls_config()` clones the
webpki root store (~50 KB) and builds a verifier + provider per call. Trojan
(`trojan.rs:77`) and Shadowsocks plugins (`shadowsocks_adapter.rs:101,114`)
already do this once in the constructor — HTTP and SOCKS5 adapters should hoist
the `TlsLayer` into the adapter the same way. This is the single largest
per-connection CPU/allocation cost found in the audit (only for TLS-enabled
http/socks5 upstreams).

### H2. `IpCidrRuleSet` matches by linear scan over all CIDRs

`crates/meow-rules/src/rule_set.rs:248-282`

```rust
self.cidrs.iter().any(|net| net.contains(&ip))
```

Rule-providers with `behavior: ipcidr` commonly carry thousands of entries
(country/ASN lists). Every connection reaching such a rule pays O(N)
comparisons. The `iprange` Patricia trie is already a workspace dependency and
already used by `country_index.rs`; switching `Vec<IpNet>` to split
`IpRange<Ipv4Net>` / `IpRange<Ipv6Net>` sets makes this O(prefix-depth).
This is the biggest algorithmic win available in the rule engine.

### H3. DNS server question parsing allocates a `Vec<String>` per query

`crates/meow-dns/src/server.rs:199-227`

`parse_question` pushes `String::from_utf8_lossy(..).to_string()` per label
(double allocation per label) into a `Vec`, then `labels.join(".")` allocates
again. That is ~2·labels + 2 heap allocations on the per-query UDP fast path,
before resolution even starts. Decode directly into one pre-sized `String`
(or `SmolStr` buffer) instead.

## Medium severity

### M1. Per-adapter rustls `ClientConfig` duplication (memory)

`crates/meow-transport/src/tls.rs:387-388`

Even when built once per adapter (Trojan/SS/VLESS), each `TlsLayer` owns its
own `ClientConfig` with its own root-store clone (~50 KB). 100 TLS proxies ≈
5 MB of identical root stores. The BoringSSL path already refcount-shares its
X509 store (`shared_root_store()`, tls.rs:768-781); the rustls path should
cache `Arc<ClientConfig>` keyed by (skip_cert_verify, ALPN, fingerprint, ECH).

### M2. HTTP proxy header rewrite lowercases every header line

`crates/meow-listener/src/http_proxy.rs:277`

`line.to_ascii_lowercase()` allocates a discarded `String` per header line per
plain-HTTP request just to test two prefixes. Use case-insensitive byte
comparison (`eq_ignore_ascii_case`), as `parse_proxy_authorization` in the same
file already does. Also: the rewritten request is accumulated with
`format!` + `push_str` — fine, but a capacity hint from the original request
length would avoid regrowth.

### M3. Sniffers return `String`, callers immediately convert to `SmolStr`

`crates/meow-common/src/sniffer/tls.rs:79`, `sniffer/http.rs:6`,
consumer at `crates/meow-listener/src/sniffer.rs:103`

`sniff_tls`/`sniff_http` allocate a `String` (plus an avoidable intermediate
`name_bytes.to_vec()` before `String::from_utf8`) which the caller converts to
`SmolStr`. Returning `SmolStr` directly makes typical hostnames (≤23 B)
allocation-free per sniffed handshake.

### M4. DNS cache-hit path clones the IP list; miss path does a double lookup

`crates/meow-dns/src/cache.rs:99-110`

Every hit clones `Box<[IpAddr]>` into a fresh `Vec` (`entry.ips.to_vec()`).
Acceptable if callers need ownership, but a `SmallVec<[IpAddr; 2]>` return (or
an `Arc<[IpAddr]>` entry) would make the common 1–2-IP hit allocation-free.
Separately, on a miss the code falls through to `cache.pop(domain)` — a second
hash lookup per miss that only matters for the expired case; restructure so
the clean-miss path skips it.

### M5. HttpUpgrade reads the 101 response one byte per syscall

`crates/meow-transport/src/httpupgrade.rs:94-103`

Header parsing issues a 1-byte `read()` per byte (~hundreds of syscalls per
connection setup). Read into a small buffer and scan for `\r\n\r\n`, keeping
any overrun bytes as initial stream data.

### M6. WebSocket transport copies every write into a fresh `Vec`

`crates/meow-transport/src/ws.rs:491`

`Message::Binary(buf.to_vec())` allocates per outbound frame — a per-chunk
allocation on the relay path for WS-wrapped proxies. Known limitation of
tokio-tungstenite 0.24 (tracked against ADR-0008 HP-3); upgrading to ≥0.26
(`Bytes` payloads) removes it. Related: gRPC `pending_frame` reassembly
(`grpc.rs:342`) grows a `Vec` by `extend_from_slice` per read — bounded by the
16 MB frame cap, but `reserve` from the frame header would avoid regrowth.

### M7. VMess body cipher re-keyed on every record

`crates/meow-proxy/src/vmess/body.rs:111-145`

`Aes128Gcm::new_from_slice(&self.write_key)` runs AES key scheduling per
16 KB record on the relay path. Construct the cipher once per direction at
connection setup and store it in `BodyCipher`.

### M8. Control-plane endpoints build `serde_json::Value` trees per snapshot

`crates/meow-api/src/routes.rs:369-388` (GET /connections),
`routes.rs:1412-1428` (memory websocket)

`/connections` maps every `ConnectionInfo` through `serde_json::json!` —
with thousands of connections and a dashboard polling at 1 Hz this is a steady
allocation churn that also contends with `active_connections()`
(`crates/meow-tunnel/src/statistics.rs:141-143`, which clones the full
DashMap snapshot per call). Derive `Serialize` on a borrow-based view struct
and serialize straight to the response body. The memory websocket serializes
per-socket per-tick; serialize once and share. The log websocket already does
this correctly (single serialization, broadcast fan-out) — use it as a model.

### M9. Fake-IP store takes two locks per lookup

`crates/meow-dns/src/fakeip.rs:90-93`

`get_by_host` locks `by_host`, then locks `by_ip` just to touch LRU recency.
Two sequential mutex acquisitions per fake-IP DNS query; merge into one lock
or accept one-sided LRU touch. Also `fakeip.rs:300-308`: `put_by_ip`
deliberately skips persistence assuming `put_by_host` follows — a documented
but fragile ordering contract.

## Low severity / observations

- **`Tunnel::proxies()` clones the whole proxy map** per call
  (`crates/meow-tunnel/src/tunnel.rs:291`); REST handlers should iterate the
  `ArcSwap` snapshot instead. Same pattern: `rules_info()` allocates 3 Strings
  per rule per call (tunnel.rs:308-322). Control plane only.
- **Trie search** collects labels into a `SmallVec<[&str; 8]>`
  (`crates/meow-trie/src/trie.rs:183,214`) — inline in the common case;
  iterating `rsplit('.')` directly would drop it. The mixed-case fallback
  allocates (`trie.rs:156-158`) but `search_normalized()` exists; the match
  engine could call it since `Metadata` hosts are already lowercased.
- **`DomainIndex::build`** allocates 2–3 Strings per domain rule
  (`crates/meow-tunnel/src/match_engine.rs:40-62`) — config-reload only.
- **DNS error paths** allocate `format!` strings per failed upstream attempt
  (`crates/meow-dns/src/resolver.rs:266-268`) — use a unit error enum.
- **`SeqCst` on the fake-IP dirty flag** (`fakeip.rs:225,237`) — Relaxed/AcqRel
  suffices; negligible but free to fix.
- **macOS TProxy opens `/dev/pf` per connection**
  (`crates/meow-listener/src/tproxy/orig_dest.rs:94-97`) — cache the fd.
- **`opt-level = "z"` + fat LTO** in the release profile (root `Cargo.toml`):
  deliberate per ADR-0007 size caps, but note it leaves throughput on the
  table (auto-vectorization, inlining). If ADR-0006 medians ever regress,
  comparing `"z"` vs `"s"`/`3` per-crate (`[profile.release.package.*]`) on
  the relay crates is a cheap experiment.

## Verified as healthy (no action)

- Zero-per-relay-allocation invariant holds: relay buffers are stack arrays in
  the spawned task frame (`meow-tunnel/src/relay.rs`, `tcp.rs`); listener
  relays do the same.
- Route table is `ArcSwap` — rule matching and proxy resolution take no locks
  and hold nothing across `.await` (`tunnel.rs:15-45`).
- UDP NAT keys are `(SocketAddr, SocketAddr)` tuples; per-packet fast path is
  alloc-free; `last_activity` is a Relaxed `AtomicU64` (`udp.rs`).
- DNS cache is 16-way sharded with FNV-1a shard selection; forward key
  `Arc<str>` is shared with reverse entries; singleflight (DashMap +
  broadcast) prevents thundering herd; UDP server uses a bounded pre-spawned
  worker pool (`resolver.rs`, `server.rs`, `cache.rs`).
- GeoIP uses a pre-built Patricia trie, not per-match MMDB lookups
  (`meow-rules/src/geoip.rs`, `country_index.rs`); regexes compile once at
  rule construction; process lookup runs once per connection and only when a
  PROCESS rule exists.
- Health-check TLS connector is a process-wide `OnceLock` singleton
  (`meow-proxy/src/health.rs:208-230`); BoringSSL root store is shared.
- Log websocket serializes once and broadcasts; auth uses constant-time
  comparison (`meow-api`).
- Trojan header builds into a caller-provided stack `[u8; 320]`; URLTest
  `pick_for_dial` is single-pass with no Vec allocation.

## Suggested fix order

1. H1 — hoist `TlsLayer` out of HTTP/SOCKS5 dial paths (small, isolated).
2. H3 — single-buffer DNS question decode (small, isolated).
3. H2 — `IpRange` trie for ipcidr rule-sets (medium; add a bench first).
4. M2 + M3 — listener/sniffer allocation trims (small).
5. M7 — cache VMess body ciphers (small; verify with trojan/vless relays).
6. M1 — shared rustls `ClientConfig` cache (medium).
7. M8 — serialize API snapshots without `Value` trees (medium, control plane).

Items H1–H3 and M2/M3/M7 are all measurable with the existing `meow-bench`
workloads and the ADR-0008 allocation reproducers; per ADR-0006 any fix PR
should carry before/after numbers.
