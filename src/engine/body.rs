//! Splitting headers and object bodies into packets.
//!
//! Both the client (PUT requests, GET request headers) and the server (GET
//! responses) need to break a list of headers and an object body into packets no
//! larger than the remote device can receive, with each header wholly inside one
//! packet (OBEX section 3).

use alloc::collections::VecDeque;

use super::io::Source;
use crate::error::{Error, Result};
use crate::header::Header;
use crate::prelude::*;

/// A body reader with lookahead, so the last chunk can be sent as End-of-Body.
pub(crate) struct BodySource<R> {
    reader: R,
    pending: Vec<u8>,
    eof: bool,
}

impl<R: Source> BodySource<R> {
    pub(crate) fn new(reader: R) -> BodySource<R> {
        BodySource {
            reader,
            pending: Vec::new(),
            eof: false,
        }
    }

    /// Takes up to `capacity` bytes, returning `true` alongside the last chunk.
    async fn take(&mut self, capacity: usize) -> Result<(Vec<u8>, bool)> {
        // Read one byte beyond the capacity to learn whether this chunk is the last.
        while !self.eof && self.pending.len() <= capacity {
            let start = self.pending.len();
            self.pending.resize(capacity + 1, 0);

            match self.reader.read(&mut self.pending[start..]).await {
                Ok(0) => {
                    self.pending.truncate(start);
                    self.eof = true;
                }
                Ok(read) => self.pending.truncate(start + read),
                Err(error) => {
                    self.pending.truncate(start);
                    return Err(error);
                }
            }
        }

        if self.pending.len() <= capacity {
            return Ok((core::mem::take(&mut self.pending), true));
        }

        let rest = self.pending.split_off(capacity);

        Ok((core::mem::replace(&mut self.pending, rest), false))
    }

    /// Puts bytes back in front of the unread body.
    fn unread(&mut self, mut data: Vec<u8>) {
        data.extend_from_slice(&self.pending);
        self.pending = data;
    }
}

/// The headers and body still to be sent for one side of an operation.
pub(crate) struct Outgoing<R> {
    headers: VecDeque<Header>,
    body: Option<BodySource<R>>,
}

impl<R: Source> Outgoing<R> {
    /// `body` is `None` when no Body or End-of-Body header should be sent at all.
    pub(crate) fn new(headers: impl IntoIterator<Item = Header>, body: Option<R>) -> Outgoing<R> {
        Outgoing {
            headers: headers.into_iter().collect(),
            body: body.map(BodySource::new),
        }
    }

    /// Builds the headers of the next packet, returning `true` with the last packet.
    ///
    /// `max_packet` is the remote device's maximum packet length and `prefix` the
    /// number of bytes before the headers.
    pub(crate) async fn next_packet(
        &mut self,
        max_packet: usize,
        prefix: usize,
    ) -> Result<(Vec<Header>, bool)> {
        let capacity = max_packet.saturating_sub(prefix);
        let mut space = capacity;
        let mut packet = Vec::new();

        while let Some(header) = self.headers.front() {
            let length = header.encoded_len();

            if length > capacity {
                return Err(Error::HeaderTooLarge {
                    id: header.id(),
                    length,
                    maximum: capacity,
                });
            }

            if length > space {
                return Ok((packet, false));
            }

            space -= length;
            packet.extend(self.headers.pop_front());
        }

        let Some(body) = self.body.as_mut() else {
            return Ok((packet, true));
        };

        // A body header needs at least its 3 byte prefix.
        if space < 3 {
            return Ok((packet, false));
        }

        let (chunk, last) = body.take(space - 3).await?;

        if last {
            packet.push(Header::EndOfBody(chunk));
        } else if !chunk.is_empty() {
            packet.push(Header::Body(chunk));
        }

        Ok((packet, last))
    }

    /// Puts the headers of a packet back so it can be sent again.
    pub(crate) fn rewind(&mut self, packet: Vec<Header>) {
        for header in packet.into_iter().rev() {
            match (header, self.body.as_mut()) {
                (Header::Body(data) | Header::EndOfBody(data), Some(body)) => body.unread(data),
                (header, _) => self.headers.push_front(header),
            }
        }
    }

    /// Inserts a header after any headers that must lead the operation.
    pub(crate) fn insert_early(&mut self, header: Header) {
        let index = self
            .headers
            .iter()
            .take_while(|header| must_lead(header))
            .count();

        self.headers.insert(index, header);
    }
}

/// Headers the specification requires to be first in a request.
pub(crate) fn must_lead(header: &Header) -> bool {
    matches!(
        header,
        Header::ConnectionID(_)
            | Header::Target(_)
            | Header::SingleResponseMode(_)
            | Header::SingleResponseModeParameters(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::io::{block_on, Bytes};

    fn drain(outgoing: &mut Outgoing<Bytes>, max_packet: usize) -> Vec<Vec<Header>> {
        let mut packets = Vec::new();

        loop {
            let (packet, last) = block_on(outgoing.next_packet(max_packet, 3)).unwrap();
            packets.push(packet);
            if last {
                return packets;
            }
        }
    }

    #[test]
    fn body_is_split_and_terminated() {
        let body = [7u8; 600];
        let mut outgoing = Outgoing::new(
            vec![Header::Name("a".to_string())],
            Some(Bytes::new(body.to_vec())),
        );
        let packets = drain(&mut outgoing, 255);

        let mut received = Vec::new();
        for packet in &packets {
            let length: usize = packet.iter().map(Header::encoded_len).sum();
            assert!(length <= 252);
            for header in packet {
                if let Header::Body(data) | Header::EndOfBody(data) = header {
                    received.extend_from_slice(data);
                }
            }
        }

        assert_eq!(body.to_vec(), received);
        assert!(matches!(
            packets.last().unwrap().last(),
            Some(Header::EndOfBody(_))
        ));
        assert_eq!(Some(&Header::Name("a".to_string())), packets[0].first());
    }

    #[test]
    fn empty_body_sends_empty_end_of_body() {
        let mut outgoing = Outgoing::new(Vec::new(), Some(Bytes::new(Vec::new())));

        assert_eq!(
            vec![vec![Header::EndOfBody(Vec::new())]],
            drain(&mut outgoing, 255)
        );
    }

    #[test]
    fn missing_body_sends_no_body_headers() {
        let mut outgoing: Outgoing<Bytes> = Outgoing::new(vec![Header::Length(0)], None);

        assert_eq!(vec![vec![Header::Length(0)]], drain(&mut outgoing, 255));
    }

    #[test]
    fn headers_that_do_not_fit_are_rejected() {
        let mut outgoing: Outgoing<Bytes> = Outgoing::new(vec![Header::Target(vec![0; 300])], None);

        assert!(matches!(
            block_on(outgoing.next_packet(255, 3)),
            Err(Error::HeaderTooLarge { id: 0x46, .. })
        ));
    }

    #[test]
    fn rewind_replays_the_same_packet() {
        let body = [1u8, 2, 3];
        let mut outgoing = Outgoing::new(
            vec![Header::ConnectionID(1)],
            Some(Bytes::new(body.to_vec())),
        );

        let (first, last) = block_on(outgoing.next_packet(255, 3)).unwrap();
        outgoing.rewind(first.clone());
        outgoing.insert_early(Header::Count(1));

        let (second, _) = block_on(outgoing.next_packet(255, 3)).unwrap();
        assert!(last);
        assert_eq!(
            vec![
                Header::ConnectionID(1),
                Header::Count(1),
                Header::EndOfBody(vec![1, 2, 3])
            ],
            second
        );
    }
}
