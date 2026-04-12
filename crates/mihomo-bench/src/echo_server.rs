use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub async fn start_echo_server() -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });

    Ok((addr, handle))
}
