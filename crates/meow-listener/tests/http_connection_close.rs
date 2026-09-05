//! Plain HTTP has its own dial/write/relay path and must honour closure too.
#![cfg(feature = "listener-http")]
mod common;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn close_stalled_plain_http_response_terminates_sockets() {
    timeout(Duration::from_secs(5), async {
        let tunnel = common::direct_tunnel();
        let stats = std::sync::Arc::clone(tunnel.statistics());
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = origin.local_addr().unwrap();
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = inbound.local_addr().unwrap();
        let mut client = TcpStream::connect(inbound_addr).await.unwrap();
        let (server, peer) = inbound.accept().await.unwrap();
        let task = tokio::spawn(async move {
            meow_listener::http_proxy::handle_http(
                &tunnel,
                server,
                peer,
                None,
                None,
                "http",
                inbound_addr.port(),
            )
            .await;
        });
        client
            .write_all(
                format!("GET http://{destination}/ HTTP/1.1\r\nHost: {destination}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let (mut remote, _) = origin.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(remote.read_u8().await.unwrap());
        }
        assert!(header.starts_with(b"GET / HTTP/1.1\r\n"));
        let id = stats.active_connections()[0].id;
        stats.close_connection(id);
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(remote.read(&mut [0; 1]).await.unwrap(), 0);
        task.await.unwrap();
        assert_eq!(stats.active_connection_count(), 0);
    })
    .await
    .expect("plain HTTP ignored the close request");
}
