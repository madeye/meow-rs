use meow_common::Metadata;
use meow_tunnel::Statistics;
use smallvec::smallvec;
use std::sync::Arc;

#[test]
fn test_statistics_new() {
    let stats = Statistics::new();
    let (up, down) = stats.snapshot();
    assert_eq!(up, 0);
    assert_eq!(down, 0);
    assert!(stats.active_connections().is_empty());
}

#[test]
fn test_statistics_default() {
    let stats = Statistics::default();
    let (up, down) = stats.snapshot();
    assert_eq!(up, 0);
    assert_eq!(down, 0);
}

#[test]
fn test_add_upload() {
    let stats = Statistics::new();
    stats.add_upload(100);
    stats.add_upload(200);
    let (up, _) = stats.snapshot();
    assert_eq!(up, 300);
}

#[test]
fn test_add_download() {
    let stats = Statistics::new();
    stats.add_download(500);
    stats.add_download(1500);
    let (_, down) = stats.snapshot();
    assert_eq!(down, 2000);
}

#[test]
fn test_upload_and_download_independent() {
    let stats = Statistics::new();
    stats.add_upload(100);
    stats.add_download(200);
    let (up, down) = stats.snapshot();
    assert_eq!(up, 100);
    assert_eq!(down, 200);
}

#[test]
fn test_traffic_snapshot_rolls_rates_per_sample() {
    let stats = Statistics::new();
    stats.add_upload(100);
    stats.add_download(200);

    // Nothing published until the sampler ticks.
    assert_eq!(stats.traffic_snapshot(), (0, 0, 0, 0));

    stats.sample_traffic();
    assert_eq!(stats.traffic_snapshot(), (100, 200, 100, 200));

    // Next window: rates reset to the new window's bytes, totals accumulate.
    stats.add_upload(30);
    stats.sample_traffic();
    assert_eq!(stats.traffic_snapshot(), (30, 0, 130, 200));
}

#[test]
fn test_traffic_snapshot_totals_consistent_with_rates() {
    // Issue #338: all four values come from the same sampling tick — traffic
    // written after the tick must not leak into the snapshot until the next
    // sample, so rates and totals stay mutually consistent.
    let stats = Statistics::new();
    stats.add_upload(100);
    stats.sample_traffic();

    stats.add_upload(999);
    stats.add_download(999);
    assert_eq!(stats.traffic_snapshot(), (100, 0, 100, 0));

    // Live totals (used by `/connections`) still see the new bytes.
    assert_eq!(stats.snapshot(), (1099, 999));
}

#[test]
fn test_traffic_totals_derived_from_rates() {
    // Issue #340: snapshot totals are accumulated from the sampled rates, so
    // `total_n - total_{n-1} == rate_n` exactly and a snapshot can never show
    // a rate that outruns its total.
    let stats = Statistics::new();
    let mut expected_total = 0;
    for chunk in [7i64, 1024, 0, 3] {
        stats.add_upload(chunk);
        stats.sample_traffic();
        expected_total += chunk;
        let (rate, _, total, _) = stats.traffic_snapshot();
        assert_eq!(rate, chunk);
        assert_eq!(total, expected_total);
    }
}

#[test]
fn test_traffic_snapshot_invariants_under_concurrency() {
    // Issue #340: sample while writers are mid-flight and assert the
    // published pairs are always mutually consistent — totals monotonic and
    // each tick's total delta equal to that tick's rate.
    const WRITERS: usize = 4;
    const ADDS_PER_WRITER: i64 = 50_000;

    let stats = Arc::new(Statistics::new());
    let writers: Vec<_> = (0..WRITERS)
        .map(|_| {
            let stats = Arc::clone(&stats);
            std::thread::spawn(move || {
                for _ in 0..ADDS_PER_WRITER {
                    stats.add_upload(1);
                    stats.add_download(2);
                }
            })
        })
        .collect();

    let sampler = {
        let stats = Arc::clone(&stats);
        std::thread::spawn(move || {
            let (mut last_up, mut last_down) = (0i64, 0i64);
            for _ in 0..1000 {
                stats.sample_traffic();
                let (up_rate, down_rate, up_total, down_total) = stats.traffic_snapshot();
                assert_eq!(up_total - last_up, up_rate);
                assert_eq!(down_total - last_down, down_rate);
                (last_up, last_down) = (up_total, down_total);
                // Live totals include the not-yet-sampled remainder, so they
                // never trail the published totals.
                let (live_up, live_down) = stats.snapshot();
                assert!(live_up >= up_total);
                assert!(live_down >= down_total);
            }
        })
    };

    for w in writers {
        w.join().unwrap();
    }
    sampler.join().unwrap();

    // Once everything is quiescent, one more tick drains the remainder and
    // every view agrees on the exact byte counts.
    stats.sample_traffic();
    let expected_up = WRITERS as i64 * ADDS_PER_WRITER;
    let (_, _, up_total, down_total) = stats.traffic_snapshot();
    assert_eq!(up_total, expected_up);
    assert_eq!(down_total, expected_up * 2);
    assert_eq!(stats.snapshot(), (expected_up, expected_up * 2));
}

#[test]
fn test_track_connection() {
    let stats = Statistics::new();
    let metadata = Metadata::default();

    let id = stats.track_connection(
        metadata,
        smol_str::SmolStr::new_static("DOMAIN-SUFFIX"),
        smol_str::SmolStr::new_static("google.com"),
        smallvec![Arc::from("DIRECT")],
    );

    assert!(!id.is_nil());
    let conns = stats.active_connections();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].id, id);
    assert_eq!(&*conns[0].rule, "DOMAIN-SUFFIX");
    assert_eq!(&*conns[0].rule_payload, "google.com");
    assert_eq!(&*conns[0].chains[0], "DIRECT");
}

#[test]
fn test_close_connection() {
    let stats = Statistics::new();
    let metadata = Metadata::default();

    let id = stats.track_connection(
        metadata,
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::new_static(""),
        smallvec![Arc::from("DIRECT")],
    );
    assert_eq!(stats.active_connections().len(), 1);

    stats.close_connection(id);
    assert!(stats.active_connections().is_empty());
}

#[test]
fn test_close_nonexistent_connection() {
    let stats = Statistics::new();
    // Should not panic
    stats.close_connection(uuid::Uuid::nil());
    assert!(stats.active_connections().is_empty());
}

#[test]
fn test_multiple_connections() {
    let stats = Statistics::new();

    let id1 = stats.track_connection(
        Metadata::default(),
        smol_str::SmolStr::new_static("DOMAIN"),
        smol_str::SmolStr::new_static("a.com"),
        smallvec![Arc::from("proxy1")],
    );
    let id2 = stats.track_connection(
        Metadata::default(),
        smol_str::SmolStr::new_static("DOMAIN"),
        smol_str::SmolStr::new_static("b.com"),
        smallvec![Arc::from("proxy2")],
    );
    let id3 = stats.track_connection(
        Metadata::default(),
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::new_static(""),
        smallvec![Arc::from("DIRECT")],
    );

    assert_eq!(stats.active_connections().len(), 3);

    stats.close_connection(id2);
    assert_eq!(stats.active_connections().len(), 2);

    // Verify remaining connections
    let conns = stats.active_connections();
    let ids: Vec<uuid::Uuid> = conns.iter().map(|c| c.id).collect();
    assert!(ids.contains(&id1));
    assert!(!ids.contains(&id2));
    assert!(ids.contains(&id3));
}

#[test]
fn test_connection_unique_ids() {
    let stats = Statistics::new();
    let id1 = stats.track_connection(
        Metadata::default(),
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::new_static(""),
        smallvec![Arc::from("DIRECT")],
    );
    let id2 = stats.track_connection(
        Metadata::default(),
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::new_static(""),
        smallvec![Arc::from("DIRECT")],
    );
    assert_ne!(id1, id2, "Connection IDs must be unique");
}

#[test]
fn test_connection_has_start_time() {
    let stats = Statistics::new();
    let _id = stats.track_connection(
        Metadata::default(),
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::new_static(""),
        smallvec![Arc::from("DIRECT")],
    );

    let conns = stats.active_connections();
    assert!(!conns[0].start.is_empty());
    // mihomo exposes connection start times as RFC 3339 strings.
    let start = time::OffsetDateTime::parse(
        &conns[0].start,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("start should be a valid RFC 3339 timestamp");
    assert!(start.unix_timestamp() > 0, "timestamp should be positive");
}

#[test]
fn test_connection_chains() {
    let stats = Statistics::new();
    let _id = stats.track_connection(
        Metadata::default(),
        smol_str::SmolStr::new_static("DOMAIN"),
        smol_str::SmolStr::new_static("example.com"),
        smallvec![Arc::from("proxy-group"), Arc::from("ss-server")],
    );

    let conns = stats.active_connections();
    assert_eq!(conns[0].chains.len(), 2);
    assert_eq!(&*conns[0].chains[0], "proxy-group");
    assert_eq!(&*conns[0].chains[1], "ss-server");
}
