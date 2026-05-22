use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Minimal SOCKS5 CONNECT client. Returns a stream tunneled to `target` via `proxy`.
pub async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;

    // Auth negotiation: version 5, 1 method, no-auth (0x00)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 || buf[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 auth failed: {:02x} {:02x}",
            buf[0], buf[1]
        )));
    }

    // CONNECT request
    match target {
        SocketAddr::V4(addr) => {
            let mut req = [0u8; 10];
            req[0] = 0x05; // version
            req[1] = 0x01; // CONNECT
            req[2] = 0x00; // reserved
            req[3] = 0x01; // IPv4
            req[4..8].copy_from_slice(&addr.ip().octets());
            req[8..10].copy_from_slice(&addr.port().to_be_bytes());
            stream.write_all(&req).await?;
        }
        SocketAddr::V6(addr) => {
            let mut req = [0u8; 22];
            req[0] = 0x05;
            req[1] = 0x01;
            req[2] = 0x00;
            req[3] = 0x04; // IPv6
            req[4..20].copy_from_slice(&addr.ip().octets());
            req[20..22].copy_from_slice(&addr.port().to_be_bytes());
            stream.write_all(&req).await?;
        }
    }

    // Read reply (minimum 10 bytes for IPv4 reply)
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 connect failed: reply status {:02x}",
            reply[1]
        )));
    }

    Ok(stream)
}
