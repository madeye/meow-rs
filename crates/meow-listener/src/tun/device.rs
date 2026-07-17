//! Packet pumps between a [`tun_rs::AsyncDevice`] and the netstack.
//!
//! `netstack-smoltcp` exposes the stack as a `Stream`/`Sink` of raw IP
//! packets (`Vec<u8>`), while `tun-rs` exposes a packet-oriented
//! `recv`/`send` pair on the device. Two tasks shuttle packets in each
//! direction; either task exiting means the device or the stack is gone,
//! which `run()` treats as fatal for the listener.

use std::io;
use std::sync::Arc;

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::Stack;
use tokio::task::JoinHandle;
use tun_rs::AsyncDevice;

/// One IP packet. UDP/TCP over IPv4/v6 tops out below 64 KiB regardless of
/// the device MTU, and a fixed buffer sidesteps MTU-change races.
const PACKET_BUF: usize = 65535;

pub(super) fn spawn_pumps(
    device: Arc<AsyncDevice>,
    stack: Stack,
) -> (JoinHandle<io::Result<()>>, JoinHandle<io::Result<()>>) {
    let (stack_sink, stack_stream) = stack.split();
    let dev = Arc::clone(&device);
    let inbound = tokio::spawn(device_to_stack(dev, stack_sink));
    let outbound = tokio::spawn(stack_to_device(device, stack_stream));
    (inbound, outbound)
}

/// device → stack. The per-packet `to_vec` is imposed by the netstack's
/// `Sink<Vec<u8>>` API; this path is not covered by the zero-alloc relay
/// invariant (ADR-0008), which starts at the terminated TCP stream.
async fn device_to_stack(
    device: Arc<AsyncDevice>,
    mut sink: SplitSink<Stack, Vec<u8>>,
) -> io::Result<()> {
    let mut buf = vec![0u8; PACKET_BUF];
    loop {
        let n = device.recv(&mut buf).await?;
        if n == 0 {
            continue;
        }
        sink.send(buf[..n].to_vec())
            .await
            .map_err(|e| io::Error::other(format!("netstack ingress closed: {e}")))?;
    }
}

/// stack → device.
async fn stack_to_device(
    device: Arc<AsyncDevice>,
    mut stream: SplitStream<Stack>,
) -> io::Result<()> {
    while let Some(pkt) = stream.next().await {
        device.send(&pkt?).await?;
    }
    Err(io::Error::other("netstack egress closed"))
}
