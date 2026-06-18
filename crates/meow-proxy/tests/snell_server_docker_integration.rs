#![cfg(feature = "snell")]

use meow_common::{Metadata, Network, ProxyAdapter, ProxyPacketConn};
use meow_proxy::{SnellAdapter, SnellObfs, SnellVersion};
use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{sleep, timeout, Duration, Instant};

const IMAGE_SNELL_V3: &str = "geekdada/snell-server:3.0.1";
const PSK: &str = "meow-snell-docker-psk";
const T: Duration = Duration::from_secs(30);

fn docker_required() -> bool {
    std::env::var_os("MEOW_REQUIRE_DOCKER").is_some()
        || std::env::var_os("MIHOMO_REQUIRE_INTEGRATION_BINS").is_some()
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn skip_or_panic(reason: impl AsRef<str>) -> bool {
    let reason = reason.as_ref();
    if docker_required() {
        panic!("{reason}");
    }
    eprintln!("skipping snell docker integration test: {reason}");
    false
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct SnellServer {
    _dir: TempDir,
    child: std::process::Child,
    log_path: PathBuf,
}

impl SnellServer {
    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for SnellServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ensure_snell_binary(dir: &Path) -> Option<PathBuf> {
    let bin = dir.join("snell-server");
    if bin.exists() {
        return Some(bin);
    }

    let pull = Command::new("docker")
        .args(["pull", IMAGE_SNELL_V3])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if pull.is_err() || !pull.unwrap_or_default().success() {
        return None;
    }

    let extract_name = format!("meow-snell-v3-extract-{}", std::process::id());
    let _ = Command::new("docker")
        .args(["rm", "-f", &extract_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let create = Command::new("docker")
        .args(["create", "--name", &extract_name, IMAGE_SNELL_V3])
        .output()
        .ok()?;
    if !create.status.success() {
        return None;
    }

    let copy = Command::new("docker")
        .args([
            "cp",
            &format!("{extract_name}:/usr/bin/snell-server"),
            &bin.to_string_lossy(),
        ])
        .output()
        .ok()?;
    let _ = Command::new("docker")
        .args(["rm", "-f", &extract_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !copy.status.success() {
        return None;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&bin) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&bin, perms);
        }
    }
    Some(bin)
}

fn write_server_config(dir: &Path, port: u16) -> PathBuf {
    let config_path = dir.join("snell-server.conf");
    let config = format!(
        concat!(
            "[snell-server]\n",
            "listen = 127.0.0.1:{port}\n",
            "psk = {psk}\n",
            "obfs = off\n",
        ),
        port = port,
        psk = PSK,
    );
    std::fs::write(&config_path, config).unwrap();
    config_path
}

fn start_snell_server(port: u16) -> Option<SnellServer> {
    if !cfg!(target_os = "linux") {
        skip_or_panic("test requires Linux snell-server binary from Docker image");
        return None;
    }
    if !docker_available() {
        skip_or_panic("docker daemon is not available");
        return None;
    }

    let dir = TempDir::new().unwrap();
    let Some(snell_bin) = ensure_snell_binary(dir.path()) else {
        skip_or_panic(format!(
            "failed to extract snell-server from {IMAGE_SNELL_V3}"
        ));
        return None;
    };
    let config_path = write_server_config(dir.path(), port);
    let log_path = dir.path().join("server.log");
    let log_file = match File::create(&log_path) {
        Ok(file) => file,
        Err(e) => {
            skip_or_panic(format!("failed to create snell-server log file: {e}"));
            return None;
        }
    };
    let stdout = log_file.try_clone().map_or(Stdio::null(), Stdio::from);
    let child = match Command::new(&snell_bin)
        .args(["-c", &config_path.to_string_lossy()])
        .stdout(stdout)
        .stderr(Stdio::from(log_file))
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            skip_or_panic(format!("failed to start snell-server process: {e}"));
            return None;
        }
    };

    Some(SnellServer {
        _dir: dir,
        child,
        log_path,
    })
}

async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, handle)
}

async fn start_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    (addr, handle)
}

fn adapter(port: u16) -> SnellAdapter {
    SnellAdapter::new(
        "docker-snell-v3",
        "127.0.0.1",
        port,
        PSK,
        SnellObfs::None,
        SnellVersion::V3,
        true,
        false,
    )
    .expect("snell adapter must build")
}

fn metadata_for(addr: SocketAddr, network: Network) -> Metadata {
    Metadata {
        network,
        host: addr.ip().to_string().into(),
        dst_port: addr.port(),
        ..Default::default()
    }
}

async fn dial_tcp_with_retry(
    adapter: &SnellAdapter,
    metadata: &Metadata,
) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
    let deadline = Instant::now() + T;
    loop {
        match adapter.dial_tcp(metadata).await {
            Ok(conn) => return Ok(conn),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => {}
        }
        sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snell_v3_docker_tcp_and_udp_round_trip() {
    let server_port = free_tcp_port();
    let Some(server) = start_snell_server(server_port) else {
        return;
    };
    sleep(Duration::from_millis(500)).await;
    let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
    let (udp_echo, _udp_h) = start_udp_echo_server().await;
    let adapter = adapter(server_port);

    let tcp_metadata = metadata_for(tcp_echo, Network::Tcp);
    let mut conn = match timeout(T, dial_tcp_with_retry(&adapter, &tcp_metadata)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => panic!("snell v3 TCP dial failed: {e}\n{}", server.logs()),
        Err(_) => panic!("snell v3 TCP dial timed out\n{}", server.logs()),
    };
    let tcp_payload = b"meow snell docker tcp";
    timeout(T, conn.write_all(tcp_payload))
        .await
        .expect("tcp write timed out")
        .expect("tcp write failed");
    timeout(T, conn.flush())
        .await
        .expect("tcp flush timed out")
        .expect("tcp flush failed");
    let mut tcp_buf = vec![0u8; tcp_payload.len()];
    timeout(T, conn.read_exact(&mut tcp_buf))
        .await
        .expect("tcp read timed out")
        .expect("tcp read failed");
    assert_eq!(&tcp_buf, tcp_payload);

    let udp_metadata = metadata_for(udp_echo, Network::Udp);
    let packet_conn: Box<dyn ProxyPacketConn> = timeout(T, adapter.dial_udp(&udp_metadata))
        .await
        .expect("udp associate timed out")
        .unwrap_or_else(|e| panic!("udp associate failed: {e}\n{}", server.logs()));
    let udp_payload = b"meow snell docker udp";
    timeout(T, packet_conn.write_packet(udp_payload, &udp_echo))
        .await
        .expect("udp write timed out")
        .expect("udp write failed");
    let mut udp_buf = [0u8; 1500];
    let (n, src) = timeout(T, packet_conn.read_packet(&mut udp_buf))
        .await
        .unwrap_or_else(|_| panic!("udp read timed out\n{}", server.logs()))
        .expect("udp read failed");
    assert_eq!(src, udp_echo);
    assert_eq!(&udp_buf[..n], udp_payload);
}
