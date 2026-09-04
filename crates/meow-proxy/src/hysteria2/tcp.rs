use super::{proto, Error, Result};
use quinn::{RecvStream, SendStream};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type ReadResponseFuture = Pin<Box<dyn Future<Output = (RecvStream, Result<()>)> + Send>>;

pub struct DuplexStream {
    read_state: ReadState,
    send: SendStream,
}

impl DuplexStream {
    pub(crate) fn new(send: SendStream, recv: RecvStream, response_read: bool) -> Self {
        Self {
            read_state: if response_read {
                ReadState::Open(recv)
            } else {
                ReadState::NeedResponse(Some(recv))
            },
            send,
        }
    }
}

impl AsyncRead for DuplexStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.read_state {
                ReadState::NeedResponse(recv) => {
                    let recv = recv
                        .take()
                        .ok_or_else(|| io::Error::other("hysteria2 TCP receive stream missing"))?;
                    this.read_state = ReadState::Reading(read_response(recv));
                }
                ReadState::Reading(future) => {
                    let (recv, result) = match future.as_mut().poll(cx) {
                        Poll::Ready(result) => result,
                        Poll::Pending => return Poll::Pending,
                    };
                    match result {
                        Ok(()) => this.read_state = ReadState::Open(recv),
                        Err(e) => {
                            this.read_state = ReadState::Failed;
                            return Poll::Ready(Err(error_to_io(e)));
                        }
                    }
                }
                ReadState::Open(recv) => return Pin::new(recv).poll_read(cx, buf),
                ReadState::Failed => {
                    return Poll::Ready(Err(io::Error::other("hysteria2 TCP stream read failed")));
                }
            }
        }
    }
}

impl AsyncWrite for DuplexStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

impl Unpin for DuplexStream {}

enum ReadState {
    NeedResponse(Option<RecvStream>),
    Reading(ReadResponseFuture),
    Open(RecvStream),
    Failed,
}

fn read_response(mut recv: RecvStream) -> ReadResponseFuture {
    Box::pin(async move {
        let result = read_initial_response(&mut recv).await;
        (recv, result)
    })
}

pub(crate) async fn read_initial_response(recv: &mut RecvStream) -> Result<()> {
    proto::read_tcp_response(recv).await
}

pub(crate) async fn write_initial_request(send: &mut SendStream, target: &str) -> Result<()> {
    let frame = proto::encode_tcp_request(target, &[])?;
    send.write_all(&frame).await.map_err(io::Error::from)?;
    Ok(())
}

fn error_to_io(error: Error) -> io::Error {
    match error {
        Error::Io(e) => e,
        other => io::Error::other(other),
    }
}
