//! The I/O abstraction shared by the blocking and async APIs.
//!
//! The protocol engines are written once as async code over [`Source`] and [`Sink`].
//! The async API implements them with tokio's traits. The blocking API implements
//! them with `std::io`, whose futures complete on their first poll, and drives the
//! engines with [`block_on`].

use std::future::{ready, Future};
use std::io::{self, Read, Write};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use crate::error::{Error, Result};
use crate::packet::{packet_length, Request, Response, PACKET_PREFIX_LENGTH};

/// Something bytes can be read from.
pub(crate) trait Source {
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>>;
}

/// Something bytes can be written to.
pub(crate) trait Sink {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = io::Result<()>>;

    fn flush(&mut self) -> impl Future<Output = io::Result<()>>;
}

/// Adapts blocking `std::io` types.
pub(crate) struct Blocking<T>(pub(crate) T);

impl<T: Read> Source for Blocking<T> {
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> {
        ready(self.0.read(buf))
    }
}

impl<T: Write> Sink for Blocking<T> {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = io::Result<()>> {
        ready(self.0.write_all(buf))
    }

    fn flush(&mut self) -> impl Future<Output = io::Result<()>> {
        ready(self.0.flush())
    }
}

/// Adapts tokio's async I/O types.
#[cfg(feature = "tokio")]
pub(crate) struct Tokio<T>(pub(crate) T);

#[cfg(feature = "tokio")]
impl<T: ::tokio::io::AsyncRead + Unpin> Source for Tokio<T> {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        ::tokio::io::AsyncReadExt::read(&mut self.0, buf).await
    }
}

#[cfg(feature = "tokio")]
impl<T: ::tokio::io::AsyncWrite + Unpin> Sink for Tokio<T> {
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        ::tokio::io::AsyncWriteExt::write_all(&mut self.0, buf).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        ::tokio::io::AsyncWriteExt::flush(&mut self.0).await
    }
}

/// Discards everything written to it and reads as empty.
pub(crate) struct Discard;

impl Source for Discard {
    fn read(&mut self, _buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> {
        ready(Ok(0))
    }
}

impl Sink for Discard {
    fn write_all(&mut self, _buf: &[u8]) -> impl Future<Output = io::Result<()>> {
        ready(Ok(()))
    }

    fn flush(&mut self) -> impl Future<Output = io::Result<()>> {
        ready(Ok(()))
    }
}

/// Runs a future built only from [`Blocking`] I/O to completion.
///
/// Blocking I/O does its work when the future is created, so the whole engine
/// future completes on its first poll and no real executor is needed.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("blocking I/O futures complete on their first poll"),
    }
}

const READ_BUFFER_LENGTH: usize = u16::MAX as usize + 1;

/// Splits a byte stream into OBEX packets. See [`crate::transport`] for details.
pub(crate) struct Framed<T> {
    inner: T,
    buffer: Vec<u8>,
    scratch: Box<[u8]>,
}

impl<T> Framed<T> {
    pub(crate) fn new(inner: T) -> Framed<T> {
        Framed {
            inner,
            buffer: Vec::new(),
            scratch: vec![0u8; READ_BUFFER_LENGTH].into_boxed_slice(),
        }
    }

    pub(crate) fn get_ref(&self) -> &T {
        &self.inner
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub(crate) fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Source> Framed<T> {
    pub(crate) async fn read_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(length) = packet_length(&self.buffer) {
                if length < PACKET_PREFIX_LENGTH {
                    return Err(Error::Malformed(nom::error::ErrorKind::LengthValue));
                }

                if self.buffer.len() == length {
                    return Ok(std::mem::take(&mut self.buffer));
                }

                if self.buffer.len() > length {
                    let rest = self.buffer.split_off(length);
                    return Ok(std::mem::replace(&mut self.buffer, rest));
                }
            }

            // Reads always offer room for the largest packet, so sequenced packet
            // sockets never truncate a message.
            let read = match self.inner.read(&mut self.scratch).await {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };

            if read == 0 {
                return Err(if self.buffer.is_empty() {
                    Error::Disconnected
                } else {
                    Error::Io(io::ErrorKind::UnexpectedEof.into())
                });
            }

            self.buffer.extend_from_slice(&self.scratch[..read]);
        }
    }

    pub(crate) async fn read_request(&mut self) -> Result<Request> {
        let packet = self.read_packet().await?;
        let (_, request) = Request::parse(&packet)?;

        Ok(request)
    }

    pub(crate) async fn read_response(&mut self) -> Result<Response> {
        let packet = self.read_packet().await?;
        let (_, response) = Response::parse(&packet)?;

        Ok(response)
    }

    pub(crate) async fn read_connect_response(&mut self) -> Result<Response> {
        let packet = self.read_packet().await?;
        let (_, response) = Response::parse_connect(&packet)?;

        Ok(response)
    }
}

impl<T: Sink> Framed<T> {
    /// Writes one complete packet in a single `write_all` and flushes it.
    pub(crate) async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.inner.write_all(packet).await?;
        self.inner.flush().await?;

        Ok(())
    }

    pub(crate) async fn write_request(&mut self, request: &Request) -> Result<()> {
        self.write_packet(&request.to_bytes()?).await
    }

    pub(crate) async fn write_response(&mut self, response: &Response) -> Result<()> {
        self.write_packet(&response.to_bytes()?).await
    }
}
