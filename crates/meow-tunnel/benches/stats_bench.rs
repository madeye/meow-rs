/// Global traffic-accounting benchmark (issue #340).
///
/// Guards the per-chunk relay accounting hot path: `record_upload` /
/// `record_download` run once per relayed chunk per direction, so any change
/// to `Statistics` byte counting must not regress them. Also covers the
/// cold paths (`sample_traffic` ticker, `snapshot` API reads) so moving work
/// off the hot path doesn't silently blow up the readers.
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use meow_tunnel::statistics::ConnCounters;
use meow_tunnel::Statistics;

fn bench_accounting(c: &mut Criterion) {
    let stats = Statistics::new();
    let counters = ConnCounters::default();

    // Hot path: per-chunk accounting (ConnCounters bump + global temp bump).
    c.bench_function("stats_record_upload_chunk", |b| {
        b.iter(|| stats.record_upload(black_box(&counters), black_box(16 * 1024)));
    });
    c.bench_function("stats_record_download_chunk", |b| {
        b.iter(|| stats.record_download(black_box(&counters), black_box(16 * 1024)));
    });

    // Cold path: once-per-second sampler tick (with traffic in flight so the
    // swap/accumulate arms are exercised).
    c.bench_function("stats_sample_traffic_tick", |b| {
        b.iter(|| {
            stats.add_upload(black_box(1024));
            stats.add_download(black_box(2048));
            stats.sample_traffic();
        });
    });

    // Cold path: API readers.
    c.bench_function("stats_live_totals_snapshot", |b| {
        b.iter(|| black_box(stats.snapshot()));
    });
    c.bench_function("stats_traffic_snapshot", |b| {
        b.iter(|| black_box(stats.traffic_snapshot()));
    });
}

criterion_group!(benches, bench_accounting);
criterion_main!(benches);
