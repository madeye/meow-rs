use super::{proto, Error, Result};
use quinn::{RecvStream, SendStream};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type ReadResponseFuture = Pin<Box<dyn Future<Output = (RecvStream, Result<()>)> + Send>>;
type WriteOpenFuture = Pin<Box<dyn Future<Output = (SendStream, io::Result<()>)> + Send>>;

pub struct DuplexStream {
    target: String,
    read_state: ReadState,
    write_state: WriteState,
}

impl DuplexStream {
    pub(crate) fn new(
        send: SendStream,
        recv: RecvStream,
        target: String,
        request_written: bool,
    ) -> Self {
        Self {
            target,
            read_state: ReadState::NeedResponse(Some(recv)),
            write_state: if request_written {
                WriteState::Open(send)
            } else {
                WriteState::NeedRequest(Some(send))
            },
        }
    }

    fn poll_open_write(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.write_state {
                WriteState::Open(_) => return Poll::Ready(Ok(())),
                WriteState::NeedRequest(_) => {
                    return Poll::Ready(Ok(()));
                }
                WriteState::Opening { future, .. } => {
                    let (send, result) = match future.as_mut().poll(cx) {
                        Poll::Ready(result) => result,
                        Poll::Pending => return Poll::Pending,
                    };
                    this.write_state = match result {
                        Ok(()) => WriteState::Open(send),
                        Err(e) => WriteState::Failed(e.kind()),
                    };
                }
                WriteState::Failed(kind) => {
                    return Poll::Ready(Err(io::Error::new(
                        *kind,
                        "hysteria2 TCP stream write failed",
                    )));
                }
            }
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
        let this = self.get_mut();
        loop {
            match &mut this.write_state {
                WriteState::NeedRequest(send) => {
                    let send = send
                        .take()
                        .ok_or_else(|| io::Error::other("hysteria2 TCP send stream missing"))?;
                    let frame =
                        proto::encode_tcp_request(&this.target, buf).map_err(error_to_io)?;
                    let payload_len = buf.len();
                    this.write_state = WriteState::Opening {
                        future: write_open(send, frame),
                        payload_len,
                    };
                }
                WriteState::Opening {
                    future,
                    payload_len,
                } => {
                    let (send, result) = match future.as_mut().poll(cx) {
                        Poll::Ready(result) => result,
                        Poll::Pending => return Poll::Pending,
                    };
                    match result {
                        Ok(()) => {
                            let n = *payload_len;
                            this.write_state = WriteState::Open(send);
                            return Poll::Ready(Ok(n));
                        }
                        Err(e) => {
                            let kind = e.kind();
                            this.write_state = WriteState::Failed(kind);
                            return Poll::Ready(Err(e));
                        }
                    }
                }
                WriteState::Open(send) => {
                    return tokio::io::AsyncWrite::poll_write(Pin::new(send), cx, buf);
                }
                WriteState::Failed(kind) => {
                    return Poll::Ready(Err(io::Error::new(
                        *kind,
                        "hysteria2 TCP stream write failed",
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self;
        match this.as_mut().poll_open_write(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        match &mut this.get_mut().write_state {
            WriteState::Open(send) => Pin::new(send).poll_flush(cx),
            WriteState::NeedRequest(_) => Poll::Ready(Ok(())),
            WriteState::Opening { .. } => Poll::Pending,
            WriteState::Failed(kind) => Poll::Ready(Err(io::Error::new(
                *kind,
                "hysteria2 TCP stream write failed",
            ))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self;
        match this.as_mut().poll_open_write(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        match &mut this.get_mut().write_state {
            WriteState::Open(send) => Pin::new(send).poll_shutdown(cx),
            WriteState::NeedRequest(send) => {
                let Some(mut send) = send.take() else {
                    return Poll::Ready(Err(io::Error::other("hysteria2 TCP send stream missing")));
                };
                Poll::Ready(send.finish().map_err(io::Error::from))
            }
            WriteState::Opening { .. } => Poll::Pending,
            WriteState::Failed(kind) => Poll::Ready(Err(io::Error::new(
                *kind,
                "hysteria2 TCP stream write failed",
            ))),
        }
    }
}

impl Unpin for DuplexStream {}

enum ReadState {
    NeedResponse(Option<RecvStream>),
    Reading(ReadResponseFuture),
    Open(RecvStream),
    Failed,
}

enum WriteState {
    NeedRequest(Option<SendStream>),
    Opening {
        future: WriteOpenFuture,
        payload_len: usize,
    },
    Open(SendStream),
    Failed(io::ErrorKind),
}

fn read_response(mut recv: RecvStream) -> ReadResponseFuture {
    Box::pin(async move {
        let result = proto::read_tcp_response(&mut recv).await;
        (recv, result)
    })
}

fn write_open(mut send: SendStream, frame: Vec<u8>) -> WriteOpenFuture {
    Box::pin(async move {
        let result = send.write_all(&frame).await.map_err(io::Error::from);
        (send, result)
    })
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
