//! Integration tests for [`meow_app::geodata_fetch::fetch_missing`].
//!
//! Stands up a hand-rolled HTTP/1.1 server on `127.0.0.1:0` that serves
//! canned bytes per path, then asserts the helper writes the expected
//! file contents (and skips targets whose paths already exist).

use meow_app::geodata_fetch::{fetch_missing, GeoTarget};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const MMDB_BYTES: &[u8] = b"FAKE-MMDB-CONTENTS-1";
const ASN_BYTES: &[u8] = b"FAKE-ASN-CONTENTS-2";
const GEOSITE_BYTES: &[u8] = b"FAKE-GEOSITE-CONTENTS-3";

/// Spawn a minimal HTTP/1.1 server that responds to `GET <path>` with
/// `routes[path]`. Returns the bound socket address.
async fn spawn_origin(routes: HashMap<&'static str, &'static [u8]>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let routes = Arc::clone(&routes);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body): (&str, &[u8]) = match routes.get(path.as_str()) {
                    Some(b) => ("200 OK", b),
                    None => ("404 Not Found", b""),
                };
                let headers = format!(
                    "HTTP/1.1 {status}\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n",
                    body.len()
                );
                let _ = sock.write_all(headers.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn targets_for(dir: &std::path::Path, base_url: &str) -> [GeoTarget; 3] {
    [
        GeoTarget {
            label: "GeoIP MMDB",
            path: dir.join("country.mmdb"),
            url: format!("{base_url}/country.mmdb"),
        },
        GeoTarget {
            label: "ASN MMDB",
            path: dir.join("asn.mmdb"),
            url: format!("{base_url}/asn.mmdb"),
        },
        GeoTarget {
            label: "geosite",
            path: dir.join("geosite.mrs"),
            url: format!("{base_url}/geosite.mrs"),
        },
    ]
}

#[tokio::test]
async fn downloads_all_missing_targets_and_writes_to_disk() {
    let mut routes = HashMap::new();
    routes.insert("/country.mmdb", MMDB_BYTES);
    routes.insert("/asn.mmdb", ASN_BYTES);
    routes.insert("/geosite.mrs", GEOSITE_BYTES);
    let addr = spawn_origin(routes).await;
    let base = format!("http://{addr}");

    let dir = tempfile::tempdir().unwrap();
    let targets = targets_for(dir.path(), &base);
    let downloaded = fetch_missing(&targets, None).await;

    assert_eq!(downloaded.len(), 3, "all three targets must be fetched");
    assert_eq!(std::fs::read(&targets[0].path).unwrap(), MMDB_BYTES);
    assert_eq!(std::fs::read(&targets[1].path).unwrap(), ASN_BYTES);
    assert_eq!(std::fs::read(&targets[2].path).unwrap(), GEOSITE_BYTES);
}

#[tokio::test]
async fn skips_targets_already_present() {
    let mut routes = HashMap::new();
    routes.insert("/country.mmdb", MMDB_BYTES);
    routes.insert("/asn.mmdb", ASN_BYTES);
    routes.insert("/geosite.mrs", GEOSITE_BYTES);
    let addr = spawn_origin(routes).await;
    let base = format!("http://{addr}");

    let dir = tempfile::tempdir().unwrap();
    let targets = targets_for(dir.path(), &base);
    // Pre-create the geosite file with sentinel contents.
    std::fs::write(&targets[2].path, b"SENTINEL-DO-NOT-OVERWRITE").unwrap();

    let downloaded = fetch_missing(&targets, None).await;
    assert_eq!(downloaded.len(), 2, "should fetch only the missing two");
    assert!(downloaded.contains(&"GeoIP MMDB"));
    assert!(downloaded.contains(&"ASN MMDB"));

    assert_eq!(
        std::fs::read(&targets[2].path).unwrap(),
        b"SENTINEL-DO-NOT-OVERWRITE",
        "pre-existing file must not be touched"
    );
}

#[tokio::test]
async fn one_failed_target_does_not_block_the_others() {
    // ASN route returns 404 → expected to be reported as failed but the
    // other two still complete.
    let mut routes = HashMap::new();
    routes.insert("/country.mmdb", MMDB_BYTES);
    routes.insert("/geosite.mrs", GEOSITE_BYTES);
    // intentionally no /asn.mmdb
    let addr = spawn_origin(routes).await;
    let base = format!("http://{addr}");

    let dir = tempfile::tempdir().unwrap();
    let targets = targets_for(dir.path(), &base);
    let downloaded = fetch_missing(&targets, None).await;

    assert_eq!(downloaded.len(), 2);
    assert!(downloaded.contains(&"GeoIP MMDB"));
    assert!(downloaded.contains(&"geosite"));
    assert!(!downloaded.contains(&"ASN MMDB"));

    assert!(targets[0].path.exists(), "mmdb should be written");
    assert!(!targets[1].path.exists(), "asn (404) must not be written");
    assert!(targets[2].path.exists(), "geosite should be written");
}

#[tokio::test]
async fn empty_target_list_returns_empty() {
    let downloaded = fetch_missing(&[] as &[GeoTarget], None).await;
    assert!(downloaded.is_empty());
}

#[test]
fn geo_target_is_constructible_for_callers() {
    // The public type is what main.rs hands to fetch_missing — guard the
    // shape so a future refactor that flips a field private breaks here.
    let t = GeoTarget {
        label: "GeoIP MMDB",
        path: PathBuf::from("/tmp/x.mmdb"),
        url: "http://example.test/x.mmdb".into(),
    };
    assert_eq!(t.label, "GeoIP MMDB");
}
