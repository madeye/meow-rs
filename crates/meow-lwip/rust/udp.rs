use std::{io, net::SocketAddr, pin::Pin};

use futures::stream::Stream;
use futures::task::{Context, Poll};
use futures::StreamExt;
use tokio::sync::mpsc::{error::TrySendError, Receiver, Sender, UnboundedSender};

use super::core::{Cmd, UdpOut};

pub type UdpPkt = (Vec<u8>, SocketAddr, SocketAddr);

/// Pure-channel UDP handle. Inbound datagrams are pushed by `udp_recv_cb` on
/// the core task; outbound datagrams travel a bounded channel the core drains
/// into `udp_sendto`.
pub struct UdpSocket {
    local_addr: SocketAddr,
    in_rx: Receiver<UdpPkt>,
    out_tx: Sender<UdpOut>,
    cmd_tx: UnboundedSender<Cmd>,
}

impl UdpSocket {
    pub(crate) fn new(
        local_addr: SocketAddr,
        in_rx: Receiver<UdpPkt>,
        out_tx: Sender<UdpOut>,
        cmd_tx: UnboundedSender<Cmd>,
    ) -> Box<Self> {
        Box::new(UdpSocket {
            local_addr,
            in_rx,
            out_tx,
            cmd_tx,
        })
    }

    pub fn split(self: Box<Self>) -> (SendHalf, RecvHalf) {
        (
            SendHalf {
                out_tx: self.out_tx.clone(),
                cmd_tx: self.cmd_tx.clone(),
            },
            RecvHalf { socket: self },
        )
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::RemoveUdp);
    }
}

impl Stream for UdpSocket {
    type Item = UdpPkt;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.in_rx.poll_recv(cx)
    }
}

pub struct SendHalf {
    out_tx: Sender<UdpOut>,
    cmd_tx: UnboundedSender<Cmd>,
}

impl SendHalf {
    /// Queue a datagram for the core to `udp_sendto`. Fire-and-forget like a
    /// real UDP socket; a saturated queue drops the datagram and reports it,
    /// preserving the caller-side "datagram dropped" diagnostic signal the
    /// old under-lock send path produced on lwIP memory exhaustion.
    pub fn send_to(
        &self,
        data: &[u8],
        src_addr: &SocketAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<()> {
        let pkt = UdpOut {
            data: data.to_vec(),
            src: *src_addr,
            dst: *dst_addr,
        };
        match self.out_tx.try_send(pkt) {
            Ok(()) => {
                let _ = self.cmd_tx.send(Cmd::UdpKick);
                Ok(())
            }
            Err(TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "udp out queue full (datagram dropped)",
            )),
            Err(TrySendError::Closed(_)) => {
                Err(io::Error::other("udp send failed: netstack core gone"))
            }
        }
    }
}

pub struct RecvHalf {
    pub(crate) socket: Box<UdpSocket>,
}

impl RecvHalf {
    pub async fn recv_from(&mut self) -> io::Result<UdpPkt> {
        match self.socket.next().await {
            Some(pkt) => Ok(pkt),
            None => Err(io::Error::other("recv_from udp socket failed: tx closed")),
        }
    }
}

impl Stream for RecvHalf {
    type Item = UdpPkt;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.socket).poll_next(cx)
    }
}
