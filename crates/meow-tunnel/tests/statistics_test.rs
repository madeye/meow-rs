use meow_common::Metadata;
use meow_tunnel::Statistics;
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
fn test_track_connection() {
    let stats = Statistics::new();
    let metadata = Metadata::default();

    let id = stats.track_connection(
        metadata,
        "DOMAIN-SUFFIX",
        "google.com",
        vec![Arc::from("DIRECT")],
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

    let id = stats.track_connection(metadata, "MATCH", "", vec![Arc::from("DIRECT")]);
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
        "DOMAIN",
        "a.com",
        vec![Arc::from("proxy1")],
    );
    let id2 = stats.track_connection(
        Metadata::default(),
        "DOMAIN",
        "b.com",
        vec![Arc::from("proxy2")],
    );
    let id3 = stats.track_connection(Metadata::default(), "MATCH", "", vec![Arc::from("DIRECT")]);

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
    let id1 = stats.track_connection(Metadata::default(), "MATCH", "", vec![Arc::from("DIRECT")]);
    let id2 = stats.track_connection(Metadata::default(), "MATCH", "", vec![Arc::from("DIRECT")]);
    assert_ne!(id1, id2, "Connection IDs must be unique");
}

#[test]
fn test_connection_has_start_time() {
    let stats = Statistics::new();
    let _id = stats.track_connection(Metadata::default(), "MATCH", "", vec![Arc::from("DIRECT")]);

    let conns = stats.active_connections();
    assert!(!conns[0].start.is_empty());
    // start is a Unix timestamp string
    let ts: u64 = conns[0]
        .start
        .parse()
        .expect("start should be a valid number");
    assert!(ts > 0, "timestamp should be positive");
}

#[test]
fn test_connection_chains() {
    let stats = Statistics::new();
    let _id = stats.track_connection(
        Metadata::default(),
        "DOMAIN",
        "example.com",
        vec![Arc::from("proxy-group"), Arc::from("ss-server")],
    );

    let conns = stats.active_connections();
    assert_eq!(conns[0].chains.len(), 2);
    assert_eq!(&*conns[0].chains[0], "proxy-group");
    assert_eq!(&*conns[0].chains[1], "ss-server");
}
