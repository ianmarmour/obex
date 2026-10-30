//! ## Transports
//!
//! OBEX runs over any reliable, ordered transport: RFCOMM and L2CAP channels on
//! Bluetooth, TinyTP on IrDA, or TCP (port 650). [`PacketStream`] adapts anything that
//! implements [`Read`] and [`Write`] into a stream of whole OBEX packets.
//!
//! It works with both kinds of socket a Bluetooth stack hands out:
//!
//! * Stream sockets (RFCOMM, TCP) may split a packet over several reads or deliver
//!   several packets in one read. Bytes are buffered until the packet length field is
//!   satisfied.
//! * Sequenced packet sockets (L2CAP `SOCK_SEQPACKET`, used by GOEP 2.0 profiles)
//!   discard whatever part of a message does not fit the read buffer, so every read
//!   uses a buffer large enough for the largest possible OBEX packet.
//!
//! When using L2CAP, configure the maximum packet length of the
//! [`Client`](crate::client::Client) or [`Server`](crate::server::Server) to be no
//! larger than the channel MTU so every OBEX packet fits in one L2CAP SDU.
//!
use std::io::{Read, Write};

use crate::engine::io::{block_on, Blocking, Framed};
use crate::error::Result;
use crate::packet::{Request, Response};

/// The `PacketStream` type. See [the module level documentation](index.html) for more.
///
/// # Examples
/// ```
/// # use obex::transport::PacketStream;
/// // Two packets arriving in a single read are split apart.
/// let bytes: &[u8] = &[0xA0, 0x00, 0x03, 0x90, 0x00, 0x03];
/// let mut stream = PacketStream::new(bytes);
///
/// assert_eq!(vec![0xA0, 0x00, 0x03], stream.read_packet().unwrap());
/// assert_eq!(vec![0x90, 0x00, 0x03], stream.read_packet().unwrap());
/// assert!(matches!(stream.read_packet(), Err(obex::Error::Disconnected)));
/// ```
pub struct PacketStream<T> {
    inner: Framed<Blocking<T>>,
}

impl<T> PacketStream<T> {
    /// Wraps a transport.
    pub fn new(inner: T) -> PacketStream<T> {
        PacketStream {
            inner: Framed::new(Blocking(inner)),
        }
    }

    /// A reference to the underlying transport.
    pub fn get_ref(&self) -> &T {
        &self.inner.get_ref().0
    }

    /// A mutable reference to the underlying transport.
    ///
    /// Reading from it directly will desynchronize the packet stream.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner.get_mut().0
    }

    /// Unwraps the underlying transport, discarding any buffered bytes.
    pub fn into_inner(self) -> T {
        self.inner.into_inner().0
    }
}

impl<T: Read> PacketStream<T> {
    /// Reads one complete packet.
    ///
    /// Returns [`Error::Disconnected`](crate::Error::Disconnected) if the transport is
    /// closed between packets.
    pub fn read_packet(&mut self) -> Result<Vec<u8>> {
        block_on(self.inner.read_packet())
    }

    /// Reads and parses a request packet.
    pub fn read_request(&mut self) -> Result<Request> {
        block_on(self.inner.read_request())
    }

    /// Reads and parses a response to any request other than CONNECT.
    pub fn read_response(&mut self) -> Result<Response> {
        block_on(self.inner.read_response())
    }

    /// Reads and parses a response to a CONNECT request.
    pub fn read_connect_response(&mut self) -> Result<Response> {
        block_on(self.inner.read_connect_response())
    }
}

impl<T: Write> PacketStream<T> {
    /// Writes one complete packet in a single `write_all` and flushes it.
    pub fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        block_on(self.inner.write_packet(packet))
    }

    /// Encodes and writes a request.
    pub fn write_request(&mut self, request: &Request) -> Result<()> {
        block_on(self.inner.write_request(request))
    }

    /// Encodes and writes a response.
    pub fn write_response(&mut self, response: &Response) -> Result<()> {
        block_on(self.inner.write_response(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use std::io;

    /// Returns at most one byte per read.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.split_first() {
                Some((byte, rest)) if !buf.is_empty() => {
                    buf[0] = *byte;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    #[test]
    fn packets_split_over_reads_are_reassembled() {
        let mut stream = PacketStream::new(Trickle(&[0x90, 0x00, 0x05, 0x97, 0x01]));

        assert_eq!(
            vec![0x90, 0x00, 0x05, 0x97, 0x01],
            stream.read_packet().unwrap()
        );
    }

    #[test]
    fn eof_inside_a_packet_is_an_error() {
        let mut stream = PacketStream::new(&[0xA0, 0x00, 0x05, 0x00][..]);

        assert!(matches!(stream.read_packet(), Err(Error::Io(_))));
    }

    #[test]
    fn invalid_lengths_are_rejected() {
        let mut stream = PacketStream::new(&[0xA0, 0x00, 0x01][..]);

        assert!(matches!(stream.read_packet(), Err(Error::Malformed(_))));
    }
}
