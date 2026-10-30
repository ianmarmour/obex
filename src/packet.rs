//! ## Packets
//!
//! OBEX requests and responses (OBEX sections 3.1 and 3.2) are packets made of a one
//! byte opcode or response code, a two byte big-endian packet length that includes
//! those three bytes, optional operation specific fields and a sequence of headers.
//!
//! CONNECT requests and responses carry the OBEX version, flags and maximum packet
//! length before their headers, and SETPATH requests carry flags and a constants byte.
//! Because a CONNECT response cannot be distinguished from any other response by its
//! bytes alone, it is parsed with [`Response::parse_connect`].
//!
//! This module is transport independent: it only converts between packets and bytes,
//! so it can be driven by any I/O model, blocking or async.
//!
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};

use crate::error::{failure, Error, Result};
use crate::header::{Header, Headers};
use crate::opcode::Opcode;
use crate::response::ResponseCode;

/// The OBEX protocol version sent in CONNECT packets (1.0).
pub const OBEX_VERSION: u8 = 0x10;

/// The smallest maximum packet length a device may negotiate, and the default before CONNECT.
pub const MINIMUM_PACKET_LENGTH: u16 = 255;

/// The largest possible OBEX packet length.
pub const MAXIMUM_PACKET_LENGTH: u16 = u16::MAX;

/// The number of bytes before the headers of a regular packet.
pub const PACKET_PREFIX_LENGTH: usize = 3;

/// The fields that follow the length of CONNECT requests and responses.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ConnectParameters {
    /// Major version in the high nibble, minor version in the low nibble.
    pub version: u8,
    /// In responses bit 0 indicates support for multiple IrLMP connections.
    pub flags: u8,
    /// The largest packet the sender can receive.
    pub max_packet_length: u16,
}

impl ConnectParameters {
    /// Creates parameters for the current OBEX version.
    pub fn new(max_packet_length: u16) -> ConnectParameters {
        ConnectParameters {
            version: OBEX_VERSION,
            flags: 0,
            max_packet_length,
        }
    }

    fn parse(i: &[u8]) -> IResult<&[u8], ConnectParameters> {
        let (i, version) = be_u8(i)?;
        let (i, flags) = be_u8(i)?;
        let (i, max_packet_length) = be_u16(i)?;

        Ok((
            i,
            ConnectParameters {
                version,
                flags,
                max_packet_length,
            },
        ))
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.version);
        buf.push(self.flags);
        buf.extend_from_slice(&self.max_packet_length.to_be_bytes());
    }
}

impl Default for ConnectParameters {
    fn default() -> ConnectParameters {
        ConnectParameters::new(MINIMUM_PACKET_LENGTH)
    }
}

/// The flags of a SETPATH request.
///
/// # Examples
/// ```
/// # use obex_protocol::packet::SetPathFlags;
/// let flags = SetPathFlags { backup: true, no_create: true };
///
/// assert_eq!(0x03, u8::from(flags));
/// assert_eq!(flags, SetPathFlags::from(0x03));
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct SetPathFlags {
    /// Back up a level before applying the name, like `cd ..`.
    pub backup: bool,
    /// Do not create the folder if it does not exist; return an error instead.
    pub no_create: bool,
}

impl From<SetPathFlags> for u8 {
    fn from(flags: SetPathFlags) -> u8 {
        u8::from(flags.backup) | (u8::from(flags.no_create) << 1)
    }
}

impl From<u8> for SetPathFlags {
    fn from(flags: u8) -> SetPathFlags {
        SetPathFlags {
            backup: flags & 0x01 != 0,
            no_create: flags & 0x02 != 0,
        }
    }
}

/// An OBEX request packet.
#[derive(Debug, PartialEq, Clone)]
pub struct Request {
    /// The operation this packet belongs to.
    pub opcode: Opcode,
    /// The Final bit; always encoded as set for opcodes that require it.
    pub is_final: bool,
    /// Present for CONNECT requests; defaults are used when encoding one without it.
    pub connect: Option<ConnectParameters>,
    /// Present for SETPATH requests; defaults are used when encoding one without it.
    pub set_path: Option<SetPathFlags>,
    /// The headers carried by this packet.
    pub headers: Headers,
}

impl Request {
    /// Creates a request without operation specific fields.
    pub fn new(opcode: Opcode, is_final: bool, headers: impl Into<Headers>) -> Request {
        Request {
            opcode,
            is_final: is_final || opcode.is_always_final(),
            connect: None,
            set_path: None,
            headers: headers.into(),
        }
    }

    /// Creates a CONNECT request.
    pub fn connect(parameters: ConnectParameters, headers: impl Into<Headers>) -> Request {
        Request {
            connect: Some(parameters),
            ..Request::new(Opcode::Connect, true, headers)
        }
    }

    /// Creates a SETPATH request.
    pub fn set_path(flags: SetPathFlags, headers: impl Into<Headers>) -> Request {
        Request {
            set_path: Some(flags),
            ..Request::new(Opcode::SetPath, true, headers)
        }
    }

    /// The number of bytes between the packet length and the headers.
    fn fields_len(opcode: Opcode) -> usize {
        match opcode {
            Opcode::Connect => 4,
            Opcode::SetPath => 2,
            _ => 0,
        }
    }

    /// The number of bytes before the headers of a request with `opcode`.
    pub fn prefix_len(opcode: Opcode) -> usize {
        PACKET_PREFIX_LENGTH + Request::fields_len(opcode)
    }

    /// The number of bytes this request occupies on the wire.
    pub fn encoded_len(&self) -> usize {
        Request::prefix_len(self.opcode) + self.headers.encoded_len()
    }

    /// Appends the wire representation of this request to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        let length = self.encoded_len();
        let length: u16 = length.try_into().map_err(|_| Error::PacketTooLarge {
            length,
            maximum: MAXIMUM_PACKET_LENGTH as usize,
        })?;

        buf.push(self.opcode.to_byte(self.is_final));
        buf.extend_from_slice(&length.to_be_bytes());

        match self.opcode {
            Opcode::Connect => self.connect.unwrap_or_default().encode(buf),
            Opcode::SetPath => {
                buf.push(self.set_path.unwrap_or_default().into());
                buf.push(0);
            }
            _ => {}
        }

        self.headers.encode(buf)
    }

    /// Converts this request to its wire representation.
    ///
    /// # Examples
    ///
    /// The CONNECT request from OBEX 1.5 section 3.4.1.9:
    /// ```
    /// # use obex_protocol::header::Header;
    /// # use obex_protocol::packet::{ConnectParameters, Request};
    /// let request = Request::connect(
    ///     ConnectParameters::new(0x2000),
    ///     vec![Header::Count(4), Header::Length(0xF483)],
    /// );
    ///
    /// assert_eq!(
    ///     vec![0x80, 0x00, 0x11, 0x10, 0x00, 0x20, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x04, 0xC3, 0x00, 0x00, 0xF4, 0x83],
    ///     request.to_bytes().unwrap()
    /// );
    /// ```
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.encode(&mut bytes)?;

        Ok(bytes)
    }

    /// Attempts to parse a `Request` from a `&[u8]`
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::header::Header;
    /// # use obex_protocol::opcode::Opcode;
    /// # use obex_protocol::packet::Request;
    /// // PUT, Final bit set, with an empty End of Body header
    /// let data: [u8; 6] = [0x82, 0x00, 0x06, 0x49, 0x00, 0x03];
    /// let (data, request) = Request::parse(&data).unwrap();
    ///
    /// assert_eq!(Opcode::Put, request.opcode);
    /// assert!(request.is_final);
    /// assert_eq!(Some(&Header::EndOfBody(Vec::new())), request.headers.iter().next());
    /// ```
    pub fn parse(i: &[u8]) -> IResult<&[u8], Request> {
        let (rest, (opcode, is_final)) = Opcode::parse(i)?;
        let (rest, packet) = packet_body(rest)?;

        let (packet, connect) = match opcode {
            Opcode::Connect => {
                let (packet, parameters) = ConnectParameters::parse(packet)?;
                (packet, Some(parameters))
            }
            _ => (packet, None),
        };

        let (packet, set_path) = match opcode {
            Opcode::SetPath => {
                let (packet, flags) = be_u8(packet)?;
                let (packet, _constants) = be_u8(packet)?;
                (packet, Some(SetPathFlags::from(flags)))
            }
            _ => (packet, None),
        };

        let (_, headers) = Headers::parse(packet)?;

        Ok((
            rest,
            Request {
                opcode,
                is_final,
                connect,
                set_path,
                headers,
            },
        ))
    }
}

/// An OBEX response packet.
#[derive(Debug, PartialEq, Clone)]
pub struct Response {
    /// The outcome of the request.
    pub code: ResponseCode,
    /// The Final bit; OBEX responses always set it.
    pub is_final: bool,
    /// Present for responses to CONNECT requests.
    pub connect: Option<ConnectParameters>,
    /// The headers carried by this packet.
    pub headers: Headers,
}

impl Response {
    /// Creates a response without headers.
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::packet::Response;
    /// # use obex_protocol::response::ResponseCode;
    /// let bytes = Response::new(ResponseCode::Success).to_bytes().unwrap();
    ///
    /// assert_eq!(vec![0xA0, 0x00, 0x03], bytes);
    /// ```
    pub fn new(code: ResponseCode) -> Response {
        Response {
            code,
            is_final: true,
            connect: None,
            headers: Headers::new(),
        }
    }

    /// Creates a response with headers.
    pub fn with_headers(code: ResponseCode, headers: impl Into<Headers>) -> Response {
        Response {
            headers: headers.into(),
            ..Response::new(code)
        }
    }

    /// Appends a header, builder style.
    pub fn with(mut self, header: Header) -> Response {
        self.headers.push(header);
        self
    }

    /// The number of bytes this response occupies on the wire.
    pub fn encoded_len(&self) -> usize {
        let fields = if self.connect.is_some() { 4 } else { 0 };

        PACKET_PREFIX_LENGTH + fields + self.headers.encoded_len()
    }

    /// Appends the wire representation of this response to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        let length = self.encoded_len();
        let length: u16 = length.try_into().map_err(|_| Error::PacketTooLarge {
            length,
            maximum: MAXIMUM_PACKET_LENGTH as usize,
        })?;

        buf.push(self.code.to_byte(self.is_final));
        buf.extend_from_slice(&length.to_be_bytes());

        if let Some(parameters) = self.connect {
            parameters.encode(buf);
        }

        self.headers.encode(buf)
    }

    /// Converts this response to its wire representation.
    ///
    /// # Examples
    ///
    /// The CONNECT response from OBEX 1.5 section 3.4.1.9:
    /// ```
    /// # use obex_protocol::packet::{ConnectParameters, Response};
    /// # use obex_protocol::response::ResponseCode;
    /// let response = Response {
    ///     connect: Some(ConnectParameters::new(0x0400)),
    ///     ..Response::new(ResponseCode::Success)
    /// };
    ///
    /// assert_eq!(vec![0xA0, 0x00, 0x07, 0x10, 0x00, 0x04, 0x00], response.to_bytes().unwrap());
    /// ```
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.encode(&mut bytes)?;

        Ok(bytes)
    }

    /// Attempts to parse a `Response` to any request other than CONNECT from a `&[u8]`
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::packet::Response;
    /// # use obex_protocol::response::ResponseCode;
    /// let data: [u8; 8] = [0x90, 0x00, 0x08, 0xC3, 0x00, 0x00, 0x10, 0x00];
    /// let (data, response) = Response::parse(&data).unwrap();
    ///
    /// assert_eq!(ResponseCode::Continue, response.code);
    /// assert_eq!(Some(0x1000), response.headers.length());
    /// ```
    pub fn parse(i: &[u8]) -> IResult<&[u8], Response> {
        Response::parse_with(i, false)
    }

    /// Attempts to parse a `Response` to a CONNECT request from a `&[u8]`
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::packet::Response;
    /// # use obex_protocol::response::ResponseCode;
    /// let data: [u8; 7] = [0xA0, 0x00, 0x07, 0x10, 0x00, 0x04, 0x00];
    /// let (data, response) = Response::parse_connect(&data).unwrap();
    ///
    /// assert_eq!(ResponseCode::Success, response.code);
    /// assert_eq!(0x0400, response.connect.unwrap().max_packet_length);
    /// ```
    pub fn parse_connect(i: &[u8]) -> IResult<&[u8], Response> {
        Response::parse_with(i, true)
    }

    fn parse_with(i: &[u8], is_connect: bool) -> IResult<&[u8], Response> {
        let (rest, (code, is_final)) = ResponseCode::parse(i)?;
        let (rest, packet) = packet_body(rest)?;

        let (packet, connect) = if is_connect {
            let (packet, parameters) = ConnectParameters::parse(packet)?;
            (packet, Some(parameters))
        } else {
            (packet, None)
        };

        let (_, headers) = Headers::parse(packet)?;

        Ok((
            rest,
            Response {
                code,
                is_final,
                connect,
                headers,
            },
        ))
    }
}

/// Parses the packet length and returns the bytes it covers after the length field.
fn packet_body(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, length) = be_u16(i)?;

    if usize::from(length) < PACKET_PREFIX_LENGTH {
        return failure(i);
    }

    take(usize::from(length) - PACKET_PREFIX_LENGTH)(i)
}

/// Returns the total length of the packet at the start of `buf`, once its length field is available.
///
/// This is all a stream transport needs to split incoming bytes into packets.
///
/// # Examples
/// ```
/// # use obex_protocol::packet::packet_length;
/// assert_eq!(None, packet_length(&[0xA0, 0x00]));
/// assert_eq!(Some(7), packet_length(&[0xA0, 0x00, 0x07]));
/// ```
pub fn packet_length(buf: &[u8]) -> Option<usize> {
    match buf {
        [_, high, low, ..] => Some(usize::from(u16::from_be_bytes([*high, *low]))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::Header;

    #[test]
    fn set_path_round_trips() {
        let request = Request::set_path(
            SetPathFlags {
                backup: true,
                no_create: false,
            },
            vec![Header::Name("notes".to_string())],
        );
        let bytes = request.to_bytes().unwrap();

        assert_eq!([0x85, 0x00, 0x14, 0x01, 0x00], bytes[..5]);
        assert_eq!(request, Request::parse(&bytes).unwrap().1);
    }

    #[test]
    fn put_example_from_specification() {
        // OBEX 1.5 section 3.4.3.3, first packet: 1058 bytes long.
        let request = Request::new(
            Opcode::Put,
            false,
            vec![
                Header::Name("JUMAR.TXT".to_string()),
                Header::Length(0x1000),
                Header::Body(vec![0x55; 1024]),
            ],
        );
        let bytes = request.to_bytes().unwrap();

        assert_eq!([0x02, 0x04, 0x22], bytes[..3]);
        assert_eq!(1058, bytes.len());
        assert_eq!(request, Request::parse(&bytes).unwrap().1);
    }

    #[test]
    fn connect_response_round_trips() {
        let response = Response {
            connect: Some(ConnectParameters::new(0x2000)),
            ..Response::with_headers(
                ResponseCode::Success,
                vec![Header::ConnectionID(1), Header::Who(vec![1, 2, 3])],
            )
        };
        let bytes = response.to_bytes().unwrap();

        assert_eq!(response, Response::parse_connect(&bytes).unwrap().1);
    }

    #[test]
    fn invalid_packet_lengths_are_rejected() {
        assert!(Response::parse(&[0xA0, 0x00, 0x02]).is_err());
        assert!(Response::parse(&[0xA0, 0x00, 0x05, 0xC0]).is_err());
        assert!(Request::parse(&[0x80, 0x00, 0x05, 0x10, 0x00]).is_err());
    }

    #[test]
    fn trailing_bytes_belong_to_the_next_packet() {
        let (rest, response) = Response::parse(&[0xA0, 0x00, 0x03, 0x90]).unwrap();

        assert_eq!(ResponseCode::Success, response.code);
        assert_eq!([0x90], rest);
    }
}
