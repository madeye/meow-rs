# Allocation Baseline — M2 Starting Line

## Reference: commit 9419421578f808c59db37fc7ec056a8971a741b9

Platform: aarch64-apple-darwin (Apple Silicon), macOS 25.4.0, Rust stable 1.88  
Binary: `--features dhat-heap --profile dhat` build of meow-app, commit `9419421578f808c59db37fc7ec056a8971a741b9`  
Workload: W3 — 64-concurrent SOCKS5 connection-rate, 20 s run via `meow-bench --concurrency 64 --duration 20`  
Tool: `dhat` crate 0.3.3, `dhat::Profiler::new_heap()` guard in `main()`, writes `dhat-heap.json` on process exit

---

## dhat Instrumentation Wiring

Feature gate added in this baseline sprint:

```toml
# Cargo.toml (workspace)
dhat = "0.3"

[profile.dhat]
inherits = "release"
lto = false
strip = false
debug = 1
opt-level = 1

# crates/meow-app/Cargo.toml
[features]
dhat-heap = ["dhat"]

[dependencies]
dhat = { workspace = true, optional = true }
```

```rust
// crates/meow-app/src/main.rs
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> Result<()> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();
    // ...
}
```

Build command: `cargo build -p meow-app --features dhat-heap --profile dhat`

---

## Global Statistics

| Metric | Value |
|--------|-------|
| Total bytes allocated | 243,216,316 (232 MB over 20 s) |
| Bytes at peak (t-gmax) | 2,929,922 (~2.8 MB live) |
| Bytes at process end | 73,072 (72 KB — expected leaks: tokio runtime, DNS cache) |
| Total program points | 339 |
| Connection rate | 408.9 conn/s (8,178 total) |

The 232 MB total is throughput (allocate + free per connection), not resident. Peak live is 2.8 MB, consistent with the RSS baseline of 9.2 MB idle (remainder is stack, code, mmap).

---

## Top-20 Allocation Sites by Total Bytes

| # | Total B | Max Live B | Gmax B | Blks | Call site |
|---|---------|-----------|--------|------|-----------|
| 1 | 87,424,896 | 1,083,648 | 1,083,648 | 8,229 | `tokio::runtime::task::core::Cell::new` — per-task allocation |
| 2 | 66,396,160 | 458,752 | 450,560 | 8,105 | `alloc_zeroed` → relay buffer (`Vec<u8>::with_capacity_zeroed`) |
| 3 | 66,396,160 | 417,792 | 294,912 | 8,105 | `alloc_zeroed` → relay buffer (second direction) |
| 4 | 12,769,856 | 57,424 | 9,312 | 8,228 | `DirectAdapter::dial_tcp` → `Box::pin` of async future |
| 5 | 2,106,624 | 26,368 | 26,368 | 8,229 | `tokio::runtime::io::RegistrationSet::allocate` (inbound socket) |
| 6 | 2,074,880 | 17,664 | 16,384 | 8,105 | `tokio::runtime::io::RegistrationSet::allocate` (outbound socket) |
| 7 | 1,851,300 | 615 | 30 | 32,912 | `LogBroadcastLayer::record_debug` → `String::extend_from_slice` (log formatting) |
| 8 | 592,416 | 240 | 32 | 49,368 | `String::push_str` via `fmt::Write` (log message assembly) |
| 9 | 557,064 | 557,064 | 557,064 | 1 | `DnsCache::new` — initial hashbrown table (single alloc, persistent) |
| 10 | 461,142 | 180 | 0 | 16,837 | `LogBroadcastLayer::record_debug` → `String::extend_from_slice` (second path) |
| 11 | 296,208 | 2,376 | 2,340 | 8,228 | `Statistics::track_connection` → `String::clone` (connection id field) |
| 12 | 296,208 | 2,376 | 2,340 | 8,228 | `Statistics::track_connection` → `String::clone` (start_time field) |
| 13 | 296,208 | 2,412 | 2,340 | 8,228 | `Statistics::track_connection` → `String::push_str` (uuid formatting) |
| 14 | 259,360 | 1,888 | 1,856 | 8,105 | `DirectAdapter::dial_tcp` closure → `Box::new` (async relay future) |
| 15 | 197,472 | 1,608 | 1,560 | 8,228 | `socks5::handle_socks5_inner` → `Box::new_uninit` (Metadata allocation) |
| 16 | 159,968 | 137,348 | 125,216 | 78 | `Statistics::track_connection` → hashbrown resize (connection map) |
| 17 | 147,104 | 512 | 0 | 3,128 | `tokio::RegistrationSet::deregister` → `Vec::push` (deregister queue) |
| 18 | 139,272 | 139,272 | 139,272 | 1 | `DnsCache::new` — second hashbrown table (single alloc, persistent) |
| 19 | 125,536 | 512 | 32 | 2,806 | `tokio::RegistrationSet::deregister` → `Vec::push` (second path) |
| 20 | 82,280 | 660 | 650 | 8,228 | `Statistics::chrono_now` → `String` (timestamp formatting) |

---

## Analysis: Project-Owned Hotspots

Sites 1–3 and 5–6 are tokio runtime internals (task allocation, relay buffers, I/O registration) — expected and not reducible without changing the async model.

**Actionable M2 targets identified:**

| Site | Source | M2 task | Expected saving |
|------|--------|---------|----------------|
| #7, #8, #10 | Log formatting: `String` allocation per event | Out-of-scope (tracing API constraint) | — |
| #11, #12 | `Statistics::track_connection` clones `ConnectionInfo.id` (String) and `start` (String) | #35: `ConnectionInfo.id` → `Arc<str>` eliminates clone | ~296 KB total over run |
| #13 | `Statistics::track_connection` formats UUID into String | #35: `ConnectionInfo.id` → `Uuid` (128-bit) eliminates format alloc | ~296 KB total |
| #15 | `handle_socks5_inner` → Metadata allocation (197 KB, 8,228 blks) | #34: SmolStr shrinks inline fields; #35: Arc<Metadata> shares across Statistics | Reduces per-conn heap by ~264 B |
| #20 | `chrono_now` String timestamp per connection | #35: `start` → `DateTime` or `Arc<str>` shared | ~82 KB total |

**Sites #9, #16, #18**: DNS cache and Statistics hashmap initial allocations — singleton cost, not per-connection.

**Sites #4, #14**: `Box::pin` for async future in `DirectAdapter::dial_tcp` — unavoidable cost of async dispatch; 12.7 MB total but fully transient (0 B at gmax).

---

## Allocation Lints Probe (ADR-0010 addendum A §A1)

All 9 allocation-focused lints at 0 hits at M2 open baseline (see `m1-addendum-lint-probe.md`):

| Lint | Hits |
|------|------|
| `clone_on_ref_ptr` | 0 |
| `needless_collect` | 0 |
| `format_push_string` | 0 |
| `string_add` | 0 |
| `useless_format` | 0 |
| `large_enum_variant` | 0 |
| `large_types_passed_by_value` | 0 |
| `unnecessary_box_returns` | 0 |
| `vec_init_then_push` | 0 |

---

## M2 Close Plan

Re-run with the same command after M2 tasks #34–#36 land:

```
cargo build -p meow-app --features dhat-heap --profile dhat
cargo run -p meow-bench -- --rust-binary ./target/dhat/meow \
  --config config-bench.yaml --duration 20 --concurrency 64 --only connrate
```

Compare sites #11, #12, #13, #15, #20 — these are the direct M2 targets.
Record delta in `footprint-alloc-post-m2.md`.
