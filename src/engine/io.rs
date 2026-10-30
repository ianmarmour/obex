//! The I/O abstraction shared by the blocking and async APIs.
//!
//! The protocol engines are written once as async code over [`Source`] and [`Sink`].
//! The async APIs implement them with tokio's or `embedded-io-async`'s traits. The
//! blocking API implements them with `std::io`, whose futures complete on their first
//! poll, and drives the engines with [`block_on`].
//!
//! Each adapter turns its transport's errors into an [`Error`] and retries reads and
//! writes that were interrupted, so the engines never see transport specific errors.

use core::future::{ready, Future};

use crate::error::{Error, Result};
use crate::packet::{packet_length, Request, Response, PACKET_PREFIX_LENGTH};
use crate::prelude::*;

/// Something bytes can be read from.
pub(crate) trait Source {
    /// Whether a read may deliver a whole packet at once and discard what does not
    /// fit in the buffer, as sequenced packet sockets do. Framing such sources needs
    /// a buffer for the largest possible packet; stream sources are read only as far
    /// as the current packet goes.
    const WHOLE_PACKET_READS: bool = false;

    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize>>;

    /// The error for a stream that ends in the middle of a packet.
    fn unexpected_end(&self) -> Error {
        Error::Disconnected
    }
}

/// Something bytes can be written to.
pub(crate) trait Sink {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<()>>;

    fn flush(&mut self) -> impl Future<Output = Result<()>>;
}

/// Adapts blocking `std::io` types.
#[cfg(feature = "std")]
pub(crate) struct Blocking<T>(pub(crate) T);

/// Repeats an `std::io` call until it is not interrupted.
#[cfg(feature = "std")]
fn retry<R>(mut call: impl FnMut() -> std::io::Result<R>) -> Result<R> {
    loop {
        match call() {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => return result.map_err(Error::Io),
        }
    }
}

#[cfg(feature = "std")]
impl<T: std::io::Read> Source for Blocking<T> {
    // The transport may be an L2CAP `SOCK_SEQPACKET` socket.
    const WHOLE_PACKET_READS: bool = true;

    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize>> {
        ready(retry(|| self.0.read(buf)))
    }

    fn unexpected_end(&self) -> Error {
        Error::Io(std::io::ErrorKind::UnexpectedEof.into())
    }
}

#[cfg(feature = "std")]
impl<T: std::io::Write> Sink for Blocking<T> {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<()>> {
        ready(retry(|| self.0.write_all(buf)))
    }

    fn flush(&mut self) -> impl Future<Output = Result<()>> {
        ready(retry(|| self.0.flush()))
    }
}

/// Adapts tokio's async I/O types.
#[cfg(feature = "tokio")]
pub(crate) struct Tokio<T>(pub(crate) T);

#[cfg(feature = "tokio")]
impl<T: ::tokio::io::AsyncRead + Unpin> Source for Tokio<T> {
    const WHOLE_PACKET_READS: bool = true;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            match ::tokio::io::AsyncReadExt::read(&mut self.0, buf).await {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => return result.map_err(Error::Io),
            }
        }
    }

    fn unexpected_end(&self) -> Error {
        Error::Io(std::io::ErrorKind::UnexpectedEof.into())
    }
}

#[cfg(feature = "tokio")]
impl<T: ::tokio::io::AsyncWrite + Unpin> Sink for Tokio<T> {
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        ::tokio::io::AsyncWriteExt::write_all(&mut self.0, buf)
            .await
            .map_err(Error::Io)
    }

    async fn flush(&mut self) -> Result<()> {
        ::tokio::io::AsyncWriteExt::flush(&mut self.0)
            .await
            .map_err(Error::Io)
    }
}

/// Adapts `embedded-io-async` types. Their reads have stream semantics, keeping
/// whatever does not fit in the buffer for the next read, so memory use follows the
/// size of the packets exchanged.
#[cfg(feature = "embedded-io-async")]
pub(crate) struct Embedded<T>(pub(crate) T);

#[cfg(feature = "embedded-io-async")]
fn transport_error(error: impl embedded_io_async::Error) -> Error {
    Error::Transport(error.kind())
}

#[cfg(feature = "embedded-io-async")]
impl<T: embedded_io_async::Read> Source for Embedded<T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            match self.0.read(buf).await {
                Err(error)
                    if embedded_io_async::Error::kind(&error)
                        == embedded_io_async::ErrorKind::Interrupted =>
                {
                    continue
                }
                result => return result.map_err(transport_error),
            }
        }
    }

    fn unexpected_end(&self) -> Error {
        Error::Transport(embedded_io_async::ErrorKind::ConnectionAborted)
    }
}

#[cfg(feature = "embedded-io-async")]
impl<T: embedded_io_async::Write> Sink for Embedded<T> {
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.0.write_all(buf).await.map_err(transport_error)
    }

    async fn flush(&mut self) -> Result<()> {
        self.0.flush().await.map_err(transport_error)
    }
}

/// An in-memory body, read from the start.
#[cfg_attr(not(any(feature = "embedded-io-async", test)), allow(dead_code))]
pub(crate) struct Bytes {
    data: Vec<u8>,
    position: usize,
}

#[cfg_attr(not(any(feature = "embedded-io-async", test)), allow(dead_code))]
impl Bytes {
    pub(crate) fn new(data: Vec<u8>) -> Bytes {
        Bytes { data, position: 0 }
    }
}

impl Source for Bytes {
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize>> {
        let rest = &self.data[self.position..];
        let length = rest.len().min(buf.len());
        buf[..length].copy_from_slice(&rest[..length]);
        self.position += length;

        ready(Ok(length))
    }
}

/// Collects everything written to it in memory.
#[cfg_attr(not(feature = "embedded-io-async"), allow(dead_code))]
pub(crate) struct Collect<'a>(pub(crate) &'a mut Vec<u8>);

impl Sink for Collect<'_> {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<()>> {
        self.0.extend_from_slice(buf);
        ready(Ok(()))
    }

    fn flush(&mut self) -> impl Future<Output = Result<()>> {
        ready(Ok(()))
    }
}

/// Discards everything written to it and reads as empty.
pub(crate) struct Discard;

impl Source for Discard {
    fn read(&mut self, _buf: &mut [u8]) -> impl Future<Output = Result<usize>> {
        ready(Ok(0))
    }
}

impl Sink for Discard {
    fn write_all(&mut self, _buf: &[u8]) -> impl Future<Output = Result<()>> {
        ready(Ok(()))
    }

    fn flush(&mut self) -> impl Future<Output = Result<()>> {
        ready(Ok(()))
    }
}

/// Runs a future built only from [`Blocking`] I/O to completion.
///
/// Blocking I/O does its work when the future is created, so the whole engine
/// future completes on its first poll and no real executor is needed.
#[cfg(any(feature = "std", test))]
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("blocking I/O futures complete on their first poll"),
    }
}

const READ_BUFFER_LENGTH: usize = u16::MAX as usize + 1;

/// Splits a byte stream into OBEX packets. See `crate::transport` for details.
pub(crate) struct Framed<T> {
    inner: T,
    buffer: Vec<u8>,
    /// Room for the largest packet, allocated on first use for sources with
    /// [`Source::WHOLE_PACKET_READS`].
    scratch: Vec<u8>,
}

impl<T> Framed<T> {
    pub(crate) fn new(inner: T) -> Framed<T> {
        Framed {
            inner,
            buffer: Vec::new(),
            scratch: Vec::new(),
        }
    }

    pub(crate) fn get_ref(&self) -> &T {
        &self.inner
    }

    #[cfg_attr(not(feature = "std"), allow(dead_code))]
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
                    return Ok(core::mem::take(&mut self.buffer));
                }

                if self.buffer.len() > length {
                    let rest = self.buffer.split_off(length);
                    return Ok(core::mem::replace(&mut self.buffer, rest));
                }
            }

            let read = if T::WHOLE_PACKET_READS {
                // Reads always offer room for the largest packet, so sequenced packet
                // sockets never truncate a message.
                if self.scratch.is_empty() {
                    self.scratch = vec![0u8; READ_BUFFER_LENGTH];
                }

                let read = self.inner.read(&mut self.scratch).await?;
                self.buffer.extend_from_slice(&self.scratch[..read]);
                read
            } else {
                // Read the prefix, then the rest of the packet, never beyond it.
                let end = packet_length(&self.buffer).unwrap_or(PACKET_PREFIX_LENGTH);
                let mut filling = Filling::new(&mut self.buffer, end);

                let read = self.inner.read(filling.unfilled()).await?;
                filling.filled(read);
                read
            };

            if read == 0 {
                return Err(if self.buffer.is_empty() {
                    Error::Disconnected
                } else {
                    self.inner.unexpected_end()
                });
            }
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

/// Extends a buffer with room for a read, and on drop trims it back to the bytes
/// actually read, so a failed or cancelled read leaves it as it was.
struct Filling<'a> {
    buffer: &'a mut Vec<u8>,
    length: usize,
}

impl<'a> Filling<'a> {
    fn new(buffer: &'a mut Vec<u8>, end: usize) -> Filling<'a> {
        let length = buffer.len();
        buffer.resize(end, 0);

        Filling { buffer, length }
    }

    fn unfilled(&mut self) -> &mut [u8] {
        &mut self.buffer[self.length..]
    }

    fn filled(&mut self, read: usize) {
        self.length += read;
    }
}

impl Drop for Filling<'_> {
    fn drop(&mut self) {
        self.buffer.truncate(self.length);
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

#[cfg(test)]
mod tests {
    use core::pin::pin;
    use core::task::{Context, Waker};

    use super::*;
    use crate::header::Header;
    use crate::response::ResponseCode;

    /// A stream delivering at most `chunk` bytes per read, which stalls forever at
    /// `stall_at` and records the largest buffer it was offered.
    struct Trickle {
        data: Vec<u8>,
        position: usize,
        chunk: usize,
        stall_at: Option<usize>,
        largest_read: usize,
    }

    impl Trickle {
        fn new(data: Vec<u8>, chunk: usize) -> Trickle {
            Trickle {
                data,
                position: 0,
                chunk,
                stall_at: None,
                largest_read: 0,
            }
        }
    }

    impl Source for Trickle {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.largest_read = self.largest_read.max(buf.len());

            if self.stall_at == Some(self.position) {
                self.stall_at = None;
                core::future::pending::<()>().await;
            }

            let rest = &self.data[self.position..];
            let length = rest.len().min(buf.len()).min(self.chunk);
            buf[..length].copy_from_slice(&rest[..length]);
            self.position += length;

            Ok(length)
        }
    }

    fn packet(name: &str) -> Vec<u8> {
        Response::with_headers(ResponseCode::Success, [Header::Name(name.to_string())])
            .to_bytes()
            .unwrap()
    }

    #[test]
    fn stream_reads_stop_at_the_packet_boundary() {
        let (first, second) = (packet("first"), packet("second packet"));
        let mut framed = Framed::new(Trickle::new([first.clone(), second.clone()].concat(), 4));

        assert_eq!(first, block_on(framed.read_packet()).unwrap());
        assert_eq!(second, block_on(framed.read_packet()).unwrap());
        assert!(matches!(
            block_on(framed.read_packet()),
            Err(Error::Disconnected)
        ));
        assert!(framed.scratch.is_empty());
        assert!(framed.get_ref().largest_read <= second.len());
    }

    #[test]
    fn cancelled_reads_lose_nothing() {
        let first = packet("first");
        let mut source = Trickle::new([first.clone(), packet("next")].concat(), 2);
        source.stall_at = Some(5);
        let mut framed = Framed::new(source);

        {
            let read = pin!(framed.read_packet());
            let mut context = Context::from_waker(Waker::noop());
            assert!(read.poll(&mut context).is_pending());
        }
        assert_eq!(5, framed.buffer.len());

        assert_eq!(first, block_on(framed.read_packet()).unwrap());
    }
}
