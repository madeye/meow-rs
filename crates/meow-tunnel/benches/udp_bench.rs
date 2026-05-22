/// UDP NAT fast-path benchmark — before/after Direction A key fix (ADR-0008 §6)
///
/// BEFORE: `format!("{}:{}", src, metadata.remote_address())` → String heap alloc
///         on every packet including the hot path (existing session lookup).
/// AFTER:  `(src_addr, dst_addr)` tuple key → zero heap allocation.
///
/// The `key_alloc_before` / `lookup_hit_before` groups measure the old approach.
/// The `key_tuple_after` / `lookup_hit_after` groups measure Direction A.
/// The delta is the PR's before/after proof required by ADR-0008.
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use meow_common::Metadata;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

fn make_src() -> SocketAddr {
    SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), 54321)
}

fn make_dst() -> SocketAddr {
    SocketAddr::new("93.184.216.34".parse::<IpAddr>().unwrap(), 53)
}

fn make_metadata() -> Metadata {
    Metadata {
        host: "example.com".into(),
        dst_port: 53,
        dst_ip: Some("93.184.216.34".parse().unwrap()),
        src_ip: Some("127.0.0.1".parse().unwrap()),
        src_port: 54321,
        ..Default::default()
    }
}

// ── BEFORE: String-keyed DashMap ─────────────────────────────────────────────

#[inline(never)]
fn nat_key_string(src: SocketAddr, metadata: &Metadata) -> String {
    format!("{}:{}", src, metadata.remote_address())
}

// ── AFTER: (SocketAddr, SocketAddr) tuple key ─────────────────────────────────

#[inline(always)]
fn nat_key_tuple(src: SocketAddr, dst: SocketAddr) -> (SocketAddr, SocketAddr) {
    (src, dst)
}

fn bench_udp_nat_key(c: &mut Criterion) {
    let src = make_src();
    let dst = make_dst();
    let metadata = make_metadata();

    // ── Key construction only ──────────────────────────────────────────────────

    let mut group = c.benchmark_group("udp_nat_key_construction");

    group.bench_function("before_string_alloc", |b| {
        b.iter(|| black_box(nat_key_string(black_box(src), black_box(&metadata))));
    });

    group.bench_function("after_tuple_noalloc", |b| {
        b.iter(|| black_box(nat_key_tuple(black_box(src), black_box(dst))));
    });

    group.finish();

    // ── DashMap hit path (most common case) ───────────────────────────────────

    let mut group = c.benchmark_group("udp_nat_lookup_hit");

    {
        let table: Arc<DashMap<String, u64>> = Arc::new(DashMap::new());
        let key = nat_key_string(src, &metadata);
        table.insert(key, 42u64);

        group.bench_function("before_string_key", |b| {
            b.iter(|| {
                let key = nat_key_string(black_box(src), black_box(&metadata));
                black_box(table.get(&key).map(|v| *v))
            });
        });
    }

    {
        let table: Arc<DashMap<(SocketAddr, SocketAddr), u64>> = Arc::new(DashMap::new());
        table.insert(nat_key_tuple(src, dst), 42u64);

        group.bench_function("after_tuple_key", |b| {
            b.iter(|| {
                let key = nat_key_tuple(black_box(src), black_box(dst));
                black_box(table.get(&key).map(|v| *v))
            });
        });
    }

    group.finish();

    // ── DashMap miss path (new session) ───────────────────────────────────────

    let mut group = c.benchmark_group("udp_nat_lookup_miss");

    {
        let table: Arc<DashMap<String, u64>> = Arc::new(DashMap::new());
        group.bench_function("before_string_key", |b| {
            b.iter(|| {
                let key = nat_key_string(black_box(src), black_box(&metadata));
                black_box(table.get(&key))
            });
        });
    }

    {
        let table: Arc<DashMap<(SocketAddr, SocketAddr), u64>> = Arc::new(DashMap::new());
        group.bench_function("after_tuple_key", |b| {
            b.iter(|| {
                let key = nat_key_tuple(black_box(src), black_box(dst));
                black_box(table.get(&key))
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_udp_nat_key);
criterion_main!(benches);
