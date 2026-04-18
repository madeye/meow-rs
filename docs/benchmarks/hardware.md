# Benchmark Hardware Record

This file documents the reference machine used for M2 benchmark runs.
Engineer-b (or whoever runs the bench) fills in actual values before
committing the first baseline JSON. See ADR-0006 for the rationale on
why hardware documentation is mandatory for reproducible comparison.

## Reference machine

| Field | Value |
|-------|-------|
| CPU model | *(e.g., Apple M3 Pro, AMD EPYC 7763, Intel Core i9-13900K)* |
| Core count (physical / logical) | *(e.g., 11P + 2E / 14)* |
| RAM | *(e.g., 18 GB LPDDR5)* |
| OS / distro | *(e.g., macOS 15.4, Ubuntu 24.04 LTS)* |
| Kernel version | *(e.g., Darwin 25.4.0, Linux 6.8.0)* |
| CPU governor | *(e.g., performance, powersave, N/A on Apple Silicon)* |
| NUMA topology | *(e.g., single-node, or NUMA node assignments if pinned)* |
| Storage | *(e.g., NVMe SSD — not relevant to network benchmarks but useful context)* |

## Build environment

| Field | Value |
|-------|-------|
| Rust toolchain | *(e.g., stable 1.88.0 x86_64-unknown-linux-gnu)* |
| zig version | *(e.g., 0.13.0 — used by cargo-zigbuild for musl targets)* |
| mihomo-rust commit SHA | *(filled in per-run; also captured in results JSON)* |
| mihomo-rust build flags | `cargo build --release --locked` |
| Go mihomo version | *(e.g., v1.19.2)* |
| Go mihomo download | `gh release download` from MetaCubeX/mihomo |

## Allocator

| Implementation | Allocator |
|----------------|-----------|
| mihomo-rust | system allocator (default; no jemalloc/mimalloc unless changed) |
| Go mihomo | Go runtime GC allocator |

Document any change to the Rust allocator (e.g., switching to `tikv-jemallocator`)
in the commit that changes it, and record the new allocator here.

## Run conditions

- Both implementations run as foreground processes; no other significant workloads.
- CPU frequency scaling: note governor setting above.
- Warmup: `bench.sh` runs a 5-second warmup before measurement (if applicable).
- Repetitions: single run per baseline commit; use `--duration` env var to extend.
- Network: loopback only (both upstream proxy and load generator on same host).

## Per-run fields (captured in baseline JSON, not this file)

The baseline JSON (`baseline-YYYY-MM-DD.json`) includes `machine` as a string
summary (e.g., `"aarch64, 11 cores, 18 GB, macOS 25.4"`). This file provides
the full human-readable record. Both must be committed together.
