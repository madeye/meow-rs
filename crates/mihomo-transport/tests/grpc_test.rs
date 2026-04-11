//! Integration tests for the gRPC (gun) transport layer.
//!
//! All tests require `--features grpc` (enforced via `required-features` in
//! Cargo.toml).
//!
//! # Test plan coverage
//!
//! | ID | Description |
//! |----|-------------|
//! | A  | `grpc_framing_matches_upstream` — byte-for-byte wire format comparison with a hand-rolled reference encoder |
//! | B  | `grpc_service_name_in_path` — `:path` must be `/{service_name}/Tun` |
//! | C  | `grpc_content_type_header` — request must carry `content-type: application/grpc` |
//! | D  | `grpc_round_trip` — 4 MiB loopback echo through a real h2 server |

mod support;

use std::time::Duration;

use mihomo_transport::grpc::{decode_gun_frame, encode_gun_frame, GrpcConfig, GrpcLayer};
use mihomo_transport::Transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use support::loopback::spawn_grpc_server;

// ─── A: Reference framing test ────────────────────────────────────────────────
//
// Port of `transport/gun/gun.go`'s WriteBytes / ReadBytes encoding.
// Asserts byte-for-byte equality with a hand-rolled reference encoder so any
// upstream divergence is caught before it silently breaks VMess/VLESS-over-gRPC.

/// Encode `payload` using the spec definition:
///   `[0x00] [BE32(inner_len)] [0x0A] [uleb128(payload.len())] [payload]`
///
/// This is the independent reference framer — it intentionally does NOT call
/// `encode_gun_frame`; the two results are compared byte-for-byte in the test.
fn reference_encode(payload: &[u8]) -> Vec<u8> {
    // uleb128(n): emit 7 bits per byte, MSB = 1 if more bytes follow.
    fn uleb128(mut n: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        loop {
            let mut byte = (n & 0x7F) as u8;
            n >>= 7;
            if n != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if n == 0 {
                break;
            }
        }
        out
    }

    let varint = uleb128(payload.len() as u64);
    // inner = [field-1 tag] + varint + payload
    let inner_len = 1 + varint.len() + payload.len();

    let mut buf = Vec::with_capacity(5 + inner_len);
    buf.push(0x00u8); // grpc compression flag — always 0x00 (no compression)
    let n = inner_len as u32;
    buf.extend_from_slice(&n.to_be_bytes()); // BE32(inner_len)
    buf.push(0x0Au8); // proto field 1, wire type 2 (length-delimited)
    buf.extend_from_slice(&varint); // uleb128(payload.len())
    buf.extend_from_slice(payload); // raw payload bytes
    buf
}

/// A: `grpc_framing_matches_upstream`
///
/// Encodes a 1 KiB payload with both the crate's `encode_gun_frame` and the
/// inline reference framer, then asserts byte-for-byte equality.  Also verifies
/// that `decode_gun_frame` fully recovers the original payload.
#[test]
fn grpc_framing_matches_upstream() {
    // 1 KiB of a repeating pattern — non-zero to catch off-by-one in byte slices.
    let payload: Vec<u8> = (0u8..=255).cycle().take(1024).collect();

    let encoded = encode_gun_frame(&payload);
    let reference = reference_encode(&payload);

    assert_eq!(
        encoded, reference,
        "encode_gun_frame must match reference wire format byte-for-byte"
    );

    // Spot-check the 5-byte gRPC header manually.
    // uleb128(1024): 1024 = 0b10000000000; first 7 bits = 0 (need more) → 0x80;
    // next 7 bits = 8 → 0x08.  inner_len = 1 + 2 + 1024 = 1027 = 0x403.
    assert_eq!(encoded[0], 0x00, "compression flag must be 0x00");
    assert_eq!(
        &encoded[1..5],
        &[0x00, 0x00, 0x04, 0x03],
        "BE32(inner_len=1027)"
    );
    assert_eq!(encoded[5], 0x0A, "proto field tag must be 0x0A");
    assert_eq!(&encoded[6..8], &[0x80, 0x08], "uleb128(1024)");
    assert_eq!(&encoded[8..], payload.as_slice(), "payload bytes");

    // decode must be the exact inverse.
    let decoded = decode_gun_frame(&encoded).expect("decode_gun_frame");
    assert_eq!(decoded, payload.as_slice());
}

// ─── B: Service name in :path ─────────────────────────────────────────────────

/// B: `grpc_service_name_in_path`
///
/// Connects via `GrpcLayer` with `service_name = "TestService"` and asserts
/// that the h2 request `:path` is `/TestService/Tun`.
///
/// upstream: transport/gun/gun.go — path is always `/{svcName}/Tun`.
#[tokio::test]
async fn grpc_service_name_in_path() {
    let (addr, info_rx) = spawn_grpc_server().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = GrpcLayer::new(GrpcConfig {
        service_name: "TestService".into(),
        ..Default::default()
    });
    let _stream = layer.connect(Box::new(tcp)).await.expect("grpc connect");

    let info = tokio::time::timeout(Duration::from_secs(5), info_rx)
        .await
        .expect("timeout waiting for grpc conn info")
        .expect("server dropped sender");

    assert_eq!(
        info.path, "/TestService/Tun",
        ":path must be /<service_name>/Tun"
    );
}

// ─── C: content-type header ───────────────────────────────────────────────────

/// C: `grpc_content_type_header`
///
/// Connects via `GrpcLayer` and asserts that the HTTP/2 request carries
/// `content-type: application/grpc`.
///
/// upstream: transport/gun/gun.go — sends `application/grpc`, not
/// `application/grpc+proto` (no codec suffix).
#[tokio::test]
async fn grpc_content_type_header() {
    let (addr, info_rx) = spawn_grpc_server().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = GrpcLayer::new(GrpcConfig::default());
    let _stream = layer.connect(Box::new(tcp)).await.expect("grpc connect");

    let info = tokio::time::timeout(Duration::from_secs(5), info_rx)
        .await
        .expect("timeout waiting for grpc conn info")
        .expect("server dropped sender");

    assert_eq!(
        info.content_type.as_deref(),
        Some("application/grpc"),
        "content-type must be application/grpc (no codec suffix)"
    );
}

// ─── D: Round-trip 4 MiB ─────────────────────────────────────────────────────

/// D: `grpc_round_trip`
///
/// Streams 4 MiB through a real h2 echo server via `GrpcLayer`.  The write
/// and read halves run concurrently (via `tokio::io::split`) to avoid
/// deadlocking on h2 flow-control.  Asserts the received bytes equal the
/// sent bytes.
#[tokio::test]
async fn grpc_round_trip() {
    const PAYLOAD_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

    let (addr, _info_rx) = spawn_grpc_server().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = GrpcLayer::new(GrpcConfig::default());
    let gun_stream = layer.connect(Box::new(tcp)).await.expect("grpc connect");

    // Split the GunStream so write and read can proceed concurrently.
    let (mut read_half, mut write_half) = tokio::io::split(gun_stream);

    // Build the send buffer: repeating 0x00..=0xFF pattern.
    let send_buf: Vec<u8> = (0u8..=255).cycle().take(PAYLOAD_SIZE).collect();
    let send_clone = send_buf.clone();

    // Write task: send all bytes, then signal EOF.
    let write_task = tokio::spawn(async move {
        write_half
            .write_all(&send_clone)
            .await
            .expect("write_all 4 MiB");
        write_half.shutdown().await.expect("shutdown");
    });

    // Read until EOF (server echoes back the gun-framed data, GunStream decodes).
    let mut recv_buf = Vec::with_capacity(PAYLOAD_SIZE);
    read_half
        .read_to_end(&mut recv_buf)
        .await
        .expect("read_to_end 4 MiB");

    write_task.await.expect("write task");

    assert_eq!(
        recv_buf.len(),
        PAYLOAD_SIZE,
        "received byte count must match sent byte count"
    );
    assert_eq!(recv_buf, send_buf, "round-trip bytes must be identical");
}
