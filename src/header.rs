//! ## Headers
//!
//! Headers (OBEX section 2) carry everything an OBEX packet says about an object,
//! from its name and type to the object body itself. A header is a one byte header
//! identifier (HI) followed by a header value (HV). The two high bits of the HI select
//! one of four encodings, which makes every header, including user defined and future
//! ones, parseable:
//!
//! | HI bits | Encoding                                                     |
//! |---------|--------------------------------------------------------------|
//! | `00`    | null terminated UTF-16BE text, prefixed with a 2 byte length |
//! | `01`    | byte sequence, prefixed with a 2 byte length                 |
//! | `10`    | 1 byte quantity                                              |
//! | `11`    | 4 byte quantity, big-endian                                  |
//!
//! All lengths and integers are big-endian (network byte order), and length prefixes
//! include the 3 bytes of the HI and the length itself.
//!
//! [`Header`] has a typed variant for every header defined by the specification and
//! [`Header::Other`] for user defined and unknown headers, so unrecognized headers
//! survive a parse and can be skipped or forwarded as the specification requires.
//! [`Headers`] is the ordered collection carried by a packet.
//!
use nom::{
    bytes::complete::take,
    combinator::all_consuming,
    error::ParseError,
    multi::many0,
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};

use crate::action::{ActionID, Permissions};
use crate::error::{failure, Error, Result};
use crate::srm::{SingleResponseMode, SingleResponseModeParameter};
use crate::tlv::{self, ApplicationParameters, TagLengthValue};

/// The encoding of a header value, taken from the two high bits of its identifier.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HeaderEncoding {
    /// Null terminated UTF-16BE text with a 2 byte length prefix.
    Unicode,
    /// A byte sequence with a 2 byte length prefix.
    Bytes,
    /// A single byte.
    U8,
    /// A 4 byte big-endian integer.
    U32,
}

impl From<u8> for HeaderEncoding {
    /// Determines the `HeaderEncoding` of any header identifier
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::header::HeaderEncoding;
    /// assert_eq!(HeaderEncoding::Unicode, HeaderEncoding::from(0x01));
    /// assert_eq!(HeaderEncoding::Bytes, HeaderEncoding::from(0x48));
    /// assert_eq!(HeaderEncoding::U8, HeaderEncoding::from(0xB0));
    /// assert_eq!(HeaderEncoding::U32, HeaderEncoding::from(0xCB));
    /// ```
    fn from(id: u8) -> HeaderEncoding {
        match id & 0xC0 {
            0x00 => HeaderEncoding::Unicode,
            0x40 => HeaderEncoding::Bytes,
            0x80 => HeaderEncoding::U8,
            _ => HeaderEncoding::U32,
        }
    }
}

/// Header identifiers defined by the OBEX specification.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum HeaderID {
    /// Number of objects (used by Connect).
    Count = 0xC0,
    /// Name of the object, often a file name.
    Name = 0x01,
    /// Type of the object as a MIME type.
    Type = 0x42,
    /// Length of the object in bytes.
    Length = 0xC3,
    /// ISO 8601 date/time stamp, the preferred form.
    Time = 0x44,
    /// 4 byte date/time stamp, for compatibility only.
    LegacyTime = 0xC4,
    /// Text description of the object or response.
    Description = 0x05,
    /// Name of the service the operation is targeted to.
    Target = 0x46,
    /// An HTTP 1.x header.
    HTTP = 0x47,
    /// A chunk of the object body.
    Body = 0x48,
    /// The final chunk of the object body.
    EndOfBody = 0x49,
    /// Identifies the OBEX application, used to tell if talking to a peer.
    Who = 0x4A,
    /// Identifier used for OBEX connection multiplexing.
    ConnectionID = 0xCB,
    /// Extended application request and response information.
    ApplicationParameters = 0x4C,
    /// Authentication digest-challenge.
    AuthenticateChallenge = 0x4D,
    /// Authentication digest-response.
    AuthenticateResponse = 0x4E,
    /// Creator of the object.
    CreatorID = 0xCF,
    /// Uniquely identifies the network client (OBEX server).
    WANUUID = 0x50,
    /// OBEX object class of the object.
    ObjectClass = 0x51,
    /// Parameters used in session commands and responses.
    SessionParameters = 0x52,
    /// Sequence number used in each packet of a reliable session.
    SessionSequenceNumber = 0x93,
    /// The action performed by an ACTION operation.
    ActionID = 0x94,
    /// Destination object name used by ACTION operations.
    DestName = 0x15,
    /// 4 byte bit mask for setting permissions.
    Permissions = 0xD6,
    /// 1 byte value to set up Single Response Mode.
    SingleResponseMode = 0x97,
    /// 1 byte value for Single Response Mode parameters.
    SingleResponseModeParameters = 0x98,
}

impl From<HeaderID> for u8 {
    /// Converts a `HeaderID` to a `u8` representation
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::header::HeaderID;
    /// let data: u8 = HeaderID::ConnectionID.into();
    ///
    /// assert_eq!(0xCB, data);
    /// ```
    fn from(id: HeaderID) -> u8 {
        id as u8
    }
}

impl TryFrom<u8> for HeaderID {
    type Error = HeaderIDError;

    /// Attempts to convert a `u8` to a valid `HeaderID`
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::header::HeaderID;
    /// assert_eq!(Ok(HeaderID::Body), HeaderID::try_from(0x48));
    /// assert!(HeaderID::try_from(0x30).is_err()); // User defined
    /// ```
    fn try_from(original: u8) -> std::result::Result<Self, Self::Error> {
        match original {
            0xC0 => Ok(HeaderID::Count),
            0x01 => Ok(HeaderID::Name),
            0x42 => Ok(HeaderID::Type),
            0xC3 => Ok(HeaderID::Length),
            0x44 => Ok(HeaderID::Time),
            0xC4 => Ok(HeaderID::LegacyTime),
            0x05 => Ok(HeaderID::Description),
            0x46 => Ok(HeaderID::Target),
            0x47 => Ok(HeaderID::HTTP),
            0x48 => Ok(HeaderID::Body),
            0x49 => Ok(HeaderID::EndOfBody),
            0x4A => Ok(HeaderID::Who),
            0xCB => Ok(HeaderID::ConnectionID),
            0x4C => Ok(HeaderID::ApplicationParameters),
            0x4D => Ok(HeaderID::AuthenticateChallenge),
            0x4E => Ok(HeaderID::AuthenticateResponse),
            0xCF => Ok(HeaderID::CreatorID),
            0x50 => Ok(HeaderID::WANUUID),
            0x51 => Ok(HeaderID::ObjectClass),
            0x52 => Ok(HeaderID::SessionParameters),
            0x93 => Ok(HeaderID::SessionSequenceNumber),
            0x94 => Ok(HeaderID::ActionID),
            0x15 => Ok(HeaderID::DestName),
            0xD6 => Ok(HeaderID::Permissions),
            0x97 => Ok(HeaderID::SingleResponseMode),
            0x98 => Ok(HeaderID::SingleResponseModeParameters),
            _ => Err(HeaderIDError),
        }
    }
}

impl HeaderID {
    /// Attempts to parse a `HeaderID` from a `&[u8]`
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::header::HeaderID;
    /// let data: [u8; 2] = [0x01, 0x00];
    /// let (data, id) = HeaderID::parse(&data).unwrap();
    ///
    /// assert_eq!(HeaderID::Name, id);
    /// assert_eq!([0x00], data);
    /// ```
    pub fn parse(i: &[u8]) -> IResult<&[u8], HeaderID> {
        let (i, id) = be_u8(i)?;

        match HeaderID::try_from(id) {
            Ok(id) => Ok((i, id)),
            Err(_) => Err(nom::Err::Failure(ParseError::from_error_kind(
                i,
                nom::error::ErrorKind::Fail,
            ))),
        }
    }

    /// The encoding used by this header.
    pub fn encoding(self) -> HeaderEncoding {
        HeaderEncoding::from(u8::from(self))
    }
}

/// The error returned when a byte is not a valid `HeaderID`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HeaderIDError;

/// A header value decoded only by its encoding, used for user defined and unknown headers.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HeaderValue {
    /// Null terminated UTF-16BE text, high bits `00`.
    Unicode(String),
    /// A byte sequence, high bits `01`.
    Bytes(Vec<u8>),
    /// A single byte, high bits `10`.
    U8(u8),
    /// A 4 byte big-endian integer, high bits `11`.
    U32(u32),
}

/// The `Header` type. See [the module level documentation](index.html) for more.
#[derive(Debug, PartialEq, Clone)]
pub enum Header {
    /// Number of objects (used by Connect).
    Count(u32),
    /// Name of the object, often a file name. An empty name is encoded as an empty header.
    Name(String),
    /// Type of the object as a MIME type, e.g. `x-obex/folder-listing`.
    Type(String),
    /// Length of the object in bytes.
    Length(u32),
    /// ISO 8601 timestamp, `YYYYMMDDTHHMMSS` (local) or `YYYYMMDDTHHMMSSZ` (UTC).
    Time(String),
    /// Seconds since January 1, 1970; accepted for compatibility only.
    LegacyTime(u32),
    /// Text description of the object or response.
    Description(String),
    /// Name of the service the operation is targeted to.
    Target(Vec<u8>),
    /// An HTTP 1.x header.
    HTTP(Vec<u8>),
    /// A chunk of the object body.
    Body(Vec<u8>),
    /// The final chunk of the object body.
    EndOfBody(Vec<u8>),
    /// Identifies the OBEX application, used to tell if talking to a peer.
    Who(Vec<u8>),
    /// Identifier used for OBEX connection multiplexing.
    ConnectionID(u32),
    /// Extended application request and response parameters.
    ApplicationParameters(ApplicationParameters),
    /// Authentication digest-challenge, see [`DigestChallenge`](crate::auth::DigestChallenge).
    AuthenticateChallenge(Vec<TagLengthValue>),
    /// Authentication digest-response, see [`DigestResponse`](crate::auth::DigestResponse).
    AuthenticateResponse(Vec<TagLengthValue>),
    /// Creator of the object.
    CreatorID(u32),
    /// Identifies the network client (OBEX server) on stateless networks.
    WANUUID(Vec<u8>),
    /// OBEX object class of the object.
    ObjectClass(Vec<u8>),
    /// Parameters of session commands, see [`session`](crate::session).
    SessionParameters(Vec<TagLengthValue>),
    /// Sequence number of a reliable session packet.
    SessionSequenceNumber(u8),
    /// Action performed by the ACTION operation.
    ActionID(ActionID),
    /// Destination object name used by ACTION operations.
    DestName(String),
    /// Permission bit masks.
    Permissions(Permissions),
    /// Single Response Mode setup.
    SingleResponseMode(SingleResponseMode),
    /// Single Response Mode parameters.
    SingleResponseModeParameters(SingleResponseModeParameter),
    /// A user defined or otherwise unrecognized header.
    Other {
        /// The header identifier, whose high bits select the encoding.
        id: u8,
        /// The header value.
        value: HeaderValue,
    },
}

/// A borrowed view of a header value used for sizing and encoding.
enum Payload<'a> {
    Unicode(&'a str),
    Ascii(&'a str, bool),
    Bytes(&'a [u8]),
    Tlvs(&'a [TagLengthValue]),
    U8(u8),
    U32(u32),
}

impl Payload<'_> {
    fn len(&self) -> usize {
        match self {
            Payload::Unicode("") => 0,
            Payload::Unicode(text) => (text.encode_utf16().count() + 1) * 2,
            Payload::Ascii(text, terminated) => text.len() + usize::from(*terminated),
            Payload::Bytes(bytes) => bytes.len(),
            Payload::Tlvs(tlvs) => tlvs.iter().map(TagLengthValue::encoded_len).sum(),
            Payload::U8(_) => 1,
            Payload::U32(_) => 4,
        }
    }
}

impl Header {
    /// The header identifier, including its encoding bits.
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::header::Header;
    /// assert_eq!(0x01, Header::Name("a".to_string()).id());
    /// assert_eq!(0x30, Header::Other { id: 0x30, value: obex_protocol::header::HeaderValue::Unicode("x".into()) }.id());
    /// ```
    pub fn id(&self) -> u8 {
        let id = match self {
            Header::Count(_) => HeaderID::Count,
            Header::Name(_) => HeaderID::Name,
            Header::Type(_) => HeaderID::Type,
            Header::Length(_) => HeaderID::Length,
            Header::Time(_) => HeaderID::Time,
            Header::LegacyTime(_) => HeaderID::LegacyTime,
            Header::Description(_) => HeaderID::Description,
            Header::Target(_) => HeaderID::Target,
            Header::HTTP(_) => HeaderID::HTTP,
            Header::Body(_) => HeaderID::Body,
            Header::EndOfBody(_) => HeaderID::EndOfBody,
            Header::Who(_) => HeaderID::Who,
            Header::ConnectionID(_) => HeaderID::ConnectionID,
            Header::ApplicationParameters(_) => HeaderID::ApplicationParameters,
            Header::AuthenticateChallenge(_) => HeaderID::AuthenticateChallenge,
            Header::AuthenticateResponse(_) => HeaderID::AuthenticateResponse,
            Header::CreatorID(_) => HeaderID::CreatorID,
            Header::WANUUID(_) => HeaderID::WANUUID,
            Header::ObjectClass(_) => HeaderID::ObjectClass,
            Header::SessionParameters(_) => HeaderID::SessionParameters,
            Header::SessionSequenceNumber(_) => HeaderID::SessionSequenceNumber,
            Header::ActionID(_) => HeaderID::ActionID,
            Header::DestName(_) => HeaderID::DestName,
            Header::Permissions(_) => HeaderID::Permissions,
            Header::SingleResponseMode(_) => HeaderID::SingleResponseMode,
            Header::SingleResponseModeParameters(_) => HeaderID::SingleResponseModeParameters,
            Header::Other { id, .. } => return *id,
        };

        id.into()
    }

    /// The `HeaderID` of this header, or `None` for user defined and unknown headers.
    pub fn header_id(&self) -> Option<HeaderID> {
        HeaderID::try_from(self.id()).ok()
    }

    /// Returns `true` for Body and End-of-Body headers.
    pub fn is_body(&self) -> bool {
        matches!(self, Header::Body(_) | Header::EndOfBody(_))
    }

    fn payload(&self) -> Payload<'_> {
        match self {
            Header::Name(text) | Header::Description(text) | Header::DestName(text) => {
                Payload::Unicode(text)
            }
            Header::Type(text) => Payload::Ascii(text, true),
            Header::Time(text) => Payload::Ascii(text, false),
            Header::Target(bytes)
            | Header::HTTP(bytes)
            | Header::Body(bytes)
            | Header::EndOfBody(bytes)
            | Header::Who(bytes)
            | Header::WANUUID(bytes)
            | Header::ObjectClass(bytes) => Payload::Bytes(bytes),
            Header::ApplicationParameters(parameters) => Payload::Tlvs(&parameters.0),
            Header::AuthenticateChallenge(tlvs)
            | Header::AuthenticateResponse(tlvs)
            | Header::SessionParameters(tlvs) => Payload::Tlvs(tlvs),
            Header::SessionSequenceNumber(value) => Payload::U8(*value),
            Header::ActionID(value) => Payload::U8((*value).into()),
            Header::SingleResponseMode(value) => Payload::U8((*value).into()),
            Header::SingleResponseModeParameters(value) => Payload::U8((*value).into()),
            Header::Count(value)
            | Header::Length(value)
            | Header::LegacyTime(value)
            | Header::ConnectionID(value)
            | Header::CreatorID(value) => Payload::U32(*value),
            Header::Permissions(value) => Payload::U32((*value).into()),
            Header::Other { value, .. } => match value {
                HeaderValue::Unicode(text) => Payload::Unicode(text),
                HeaderValue::Bytes(bytes) => Payload::Bytes(bytes),
                HeaderValue::U8(value) => Payload::U8(*value),
                HeaderValue::U32(value) => Payload::U32(*value),
            },
        }
    }

    /// The number of bytes this header occupies on the wire, including the HI.
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::header::Header;
    /// // HI + 2 byte length + 9 UTF-16 characters + 2 byte null terminator
    /// assert_eq!(0x17, Header::Name("JUMAR.TXT".to_string()).encoded_len());
    /// assert_eq!(5, Header::ConnectionID(1).encoded_len());
    /// ```
    pub fn encoded_len(&self) -> usize {
        match self.payload() {
            Payload::U8(_) => 2,
            Payload::U32(_) => 5,
            payload => 3 + payload.len(),
        }
    }

    /// Appends the wire representation of this header to `buf`.
    ///
    /// # Examples
    ///
    /// Name
    /// ```
    /// # use obex_protocol::header::Header;
    /// let mut bytes: Vec<u8> = Vec::new();
    /// Header::Name("ab".to_string()).encode(&mut bytes).unwrap();
    ///
    /// assert_eq!(vec![0x01, 0x00, 0x09, 0x00, 0x61, 0x00, 0x62, 0x00, 0x00], bytes);
    /// ```
    ///
    /// Empty Name
    /// ```
    /// # use obex_protocol::header::Header;
    /// let mut bytes: Vec<u8> = Vec::new();
    /// Header::Name(String::new()).encode(&mut bytes).unwrap();
    ///
    /// assert_eq!(vec![0x01, 0x00, 0x03], bytes);
    /// ```
    ///
    /// Type
    /// ```
    /// # use obex_protocol::header::Header;
    /// let mut bytes: Vec<u8> = Vec::new();
    /// Header::Type("pdf".to_string()).encode(&mut bytes).unwrap();
    ///
    /// assert_eq!(vec![0x42, 0x00, 0x07, 0x70, 0x64, 0x66, 0x00], bytes);
    /// ```
    ///
    /// Connection Id
    /// ```
    /// # use obex_protocol::header::Header;
    /// let mut bytes: Vec<u8> = Vec::new();
    /// Header::ConnectionID(0x01020304).encode(&mut bytes).unwrap();
    ///
    /// assert_eq!(vec![0xCB, 0x01, 0x02, 0x03, 0x04], bytes);
    /// ```
    pub fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        let id = self.id();
        let payload = self.payload();

        match payload {
            Payload::U8(value) => {
                buf.push(id);
                buf.push(value);
                return Ok(());
            }
            Payload::U32(value) => {
                buf.push(id);
                buf.extend_from_slice(&value.to_be_bytes());
                return Ok(());
            }
            _ => {}
        }

        let length = 3 + payload.len();
        let length: u16 = length.try_into().map_err(|_| Error::HeaderTooLarge {
            id,
            length,
            maximum: u16::MAX as usize,
        })?;

        buf.push(id);
        buf.extend_from_slice(&length.to_be_bytes());

        match payload {
            Payload::Unicode(text) => {
                if !text.is_empty() {
                    for unit in text.encode_utf16() {
                        buf.extend_from_slice(&unit.to_be_bytes());
                    }
                    buf.extend_from_slice(&[0, 0]);
                }
            }
            Payload::Ascii(text, terminated) => {
                buf.extend_from_slice(text.as_bytes());
                if terminated {
                    buf.push(0);
                }
            }
            Payload::Bytes(bytes) => buf.extend_from_slice(bytes),
            Payload::Tlvs(tlvs) => tlv::encode_all(tlvs, buf)?,
            Payload::U8(_) | Payload::U32(_) => unreachable!(),
        }

        Ok(())
    }

    /// Converts this header to its wire representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.encode(&mut bytes)?;

        Ok(bytes)
    }

    /// Attempts to parse a `Header` from a `&[u8]`
    ///
    /// # Examples
    ///
    /// Count
    /// ```
    /// # use obex_protocol::header::Header;
    /// // Big-endian encoded 4 byte integer
    /// let data: [u8; 5] = [0xC0, 0, 0, 0, 4];
    /// let (data, header) = Header::parse(&data).unwrap();
    ///
    /// assert_eq!(Header::Count(4), header);
    /// ```
    ///
    /// Name
    /// ```
    /// # use obex_protocol::header::Header;
    /// // Length prefixed, null terminated UTF-16BE text
    /// let data: [u8; 13] = [0x01, 0, 13, 0, 116, 0, 101, 0, 120, 0, 116, 0, 0];
    /// let (data, header) = Header::parse(&data).unwrap();
    ///
    /// assert_eq!(Header::Name("text".to_string()), header);
    /// ```
    ///
    /// Type
    /// ```
    /// # use obex_protocol::header::Header;
    /// // Length prefixed, null terminated ASCII text
    /// let data: [u8; 7] = [0x42, 0, 7, 112, 100, 102, 0];
    /// let (data, header) = Header::parse(&data).unwrap();
    ///
    /// assert_eq!(Header::Type("pdf".to_string()), header);
    /// ```
    ///
    /// Time
    /// ```
    /// # use obex_protocol::header::Header;
    /// // Length prefixed ISO 8601 ASCII text
    /// let data: [u8; 19] = [0x44, 0, 19, 49, 57, 57, 52, 48, 50, 48, 54, 84, 48, 49, 48, 49, 48, 49, 90];
    /// let (data, header) = Header::parse(&data).unwrap();
    ///
    /// assert_eq!(Header::Time("19940206T010101Z".to_string()), header);
    /// ```
    ///
    /// Body
    /// ```
    /// # use obex_protocol::header::Header;
    /// // Length prefixed byte sequence
    /// let data: [u8; 8] = [0x48, 0, 8, 1, 2, 3, 4, 5];
    /// let (data, header) = Header::parse(&data).unwrap();
    ///
    /// assert_eq!(Header::Body(vec![1, 2, 3, 4, 5]), header);
    /// ```
    ///
    /// Empty End of Body
    /// ```
    /// # use obex_protocol::header::Header;
    /// let data: [u8; 3] = [0x49, 0, 3];
    /// let (data, header) = Header::parse(&data).unwrap();
    ///
    /// assert_eq!(Header::EndOfBody(Vec::new()), header);
    /// ```
    ///
    /// Application Parameters
    /// ```
    /// # use obex_protocol::header::Header;
    /// # use obex_protocol::tlv::ApplicationParameters;
    /// let data: [u8; 7] = [0x4C, 0, 7, 0x01, 0x02, 0x00, 0x0A];
    /// let (data, header) = Header::parse(&data).unwrap();
    ///
    /// assert_eq!(Header::ApplicationParameters(ApplicationParameters::new().with_u16(1, 10)), header);
    /// ```
    ///
    /// Single Response Mode
    /// ```
    /// # use obex_protocol::header::Header;
    /// # use obex_protocol::srm::SingleResponseMode;
    /// let data: [u8; 2] = [0x97, 0x01];
    /// let (data, header) = Header::parse(&data).unwrap();
    ///
    /// assert_eq!(Header::SingleResponseMode(SingleResponseMode::Enable), header);
    /// ```
    ///
    /// User defined
    /// ```
    /// # use obex_protocol::header::{Header, HeaderValue};
    /// let data: [u8; 2] = [0xB0, 0x07];
    /// let (data, header) = Header::parse(&data).unwrap();
    ///
    /// assert_eq!(Header::Other { id: 0xB0, value: HeaderValue::U8(7) }, header);
    /// ```
    pub fn parse(i: &[u8]) -> IResult<&[u8], Header> {
        let (i, id) = be_u8(i)?;
        let known = HeaderID::try_from(id).ok();

        match HeaderEncoding::from(id) {
            HeaderEncoding::U8 => {
                let (rest, value) = be_u8(i)?;

                let header = match known {
                    Some(HeaderID::SessionSequenceNumber) => Header::SessionSequenceNumber(value),
                    Some(HeaderID::ActionID) => match ActionID::try_from(value) {
                        Ok(value) => Header::ActionID(value),
                        Err(_) => return failure(i),
                    },
                    Some(HeaderID::SingleResponseMode) => {
                        match SingleResponseMode::try_from(value) {
                            Ok(value) => Header::SingleResponseMode(value),
                            Err(_) => return failure(i),
                        }
                    }
                    Some(HeaderID::SingleResponseModeParameters) => {
                        match SingleResponseModeParameter::try_from(value) {
                            Ok(value) => Header::SingleResponseModeParameters(value),
                            Err(_) => return failure(i),
                        }
                    }
                    _ => Header::Other {
                        id,
                        value: HeaderValue::U8(value),
                    },
                };

                Ok((rest, header))
            }
            HeaderEncoding::U32 => {
                let (rest, value) = be_u32(i)?;

                let header = match known {
                    Some(HeaderID::Count) => Header::Count(value),
                    Some(HeaderID::Length) => Header::Length(value),
                    Some(HeaderID::LegacyTime) => Header::LegacyTime(value),
                    Some(HeaderID::ConnectionID) => Header::ConnectionID(value),
                    Some(HeaderID::CreatorID) => Header::CreatorID(value),
                    Some(HeaderID::Permissions) => Header::Permissions(value.into()),
                    _ => Header::Other {
                        id,
                        value: HeaderValue::U32(value),
                    },
                };

                Ok((rest, header))
            }
            encoding => {
                let (i, length) = be_u16(i)?;

                if length < 3 {
                    return failure(i);
                }

                let (rest, data) = take(length - 3)(i)?;

                let header = match known {
                    Some(HeaderID::Name) => Header::Name(decode_unicode(data)),
                    Some(HeaderID::Description) => Header::Description(decode_unicode(data)),
                    Some(HeaderID::DestName) => Header::DestName(decode_unicode(data)),
                    Some(HeaderID::Type) => Header::Type(decode_ascii(data)),
                    Some(HeaderID::Time) => Header::Time(decode_ascii(data)),
                    Some(HeaderID::Target) => Header::Target(data.to_vec()),
                    Some(HeaderID::HTTP) => Header::HTTP(data.to_vec()),
                    Some(HeaderID::Body) => Header::Body(data.to_vec()),
                    Some(HeaderID::EndOfBody) => Header::EndOfBody(data.to_vec()),
                    Some(HeaderID::Who) => Header::Who(data.to_vec()),
                    Some(HeaderID::WANUUID) => Header::WANUUID(data.to_vec()),
                    Some(HeaderID::ObjectClass) => Header::ObjectClass(data.to_vec()),
                    Some(HeaderID::ApplicationParameters) => {
                        let (_, tlvs) = TagLengthValue::parse_all(data)?;
                        Header::ApplicationParameters(ApplicationParameters(tlvs))
                    }
                    Some(HeaderID::AuthenticateChallenge) => {
                        Header::AuthenticateChallenge(TagLengthValue::parse_all(data)?.1)
                    }
                    Some(HeaderID::AuthenticateResponse) => {
                        Header::AuthenticateResponse(TagLengthValue::parse_all(data)?.1)
                    }
                    Some(HeaderID::SessionParameters) => {
                        Header::SessionParameters(TagLengthValue::parse_all(data)?.1)
                    }
                    _ => Header::Other {
                        id,
                        value: match encoding {
                            HeaderEncoding::Unicode => HeaderValue::Unicode(decode_unicode(data)),
                            _ => HeaderValue::Bytes(data.to_vec()),
                        },
                    },
                };

                Ok((rest, header))
            }
        }
    }
}

/// Decodes null terminated UTF-16BE text, tolerating a missing terminator.
fn decode_unicode(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|unit| u16::from_be_bytes([unit[0], unit[1]]))
        .take_while(|unit| *unit != 0)
        .collect();

    String::from_utf16_lossy(&units)
}

/// Decodes ASCII text, stopping at a null terminator if one is present.
fn decode_ascii(data: &[u8]) -> String {
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());

    String::from_utf8_lossy(&data[..end]).into_owned()
}

impl From<ApplicationParameters> for Header {
    fn from(parameters: ApplicationParameters) -> Header {
        Header::ApplicationParameters(parameters)
    }
}

/// An ordered collection of headers, as carried by a packet or an operation.
///
/// # Examples
/// ```
/// # use obex_protocol::header::{Header, Headers};
/// let headers = Headers::from(vec![
///     Header::ConnectionID(1),
///     Header::Name("telecom/pb.vcf".to_string()),
///     Header::Type("x-bt/phonebook".to_string()),
/// ]);
///
/// assert_eq!(Some(1), headers.connection_id());
/// assert_eq!(Some("telecom/pb.vcf"), headers.name());
/// assert_eq!(Some("x-bt/phonebook"), headers.content_type());
/// ```
#[derive(Debug, PartialEq, Clone, Default)]
pub struct Headers(Vec<Header>);

impl Headers {
    /// Creates an empty collection.
    pub fn new() -> Headers {
        Headers(Vec::new())
    }

    /// Appends a header.
    pub fn push(&mut self, header: Header) {
        self.0.push(header);
    }

    /// Appends a header, builder style.
    pub fn with(mut self, header: Header) -> Headers {
        self.push(header);
        self
    }

    /// Inserts a header at `index`.
    pub fn insert(&mut self, index: usize, header: Header) {
        self.0.insert(index, header);
    }

    /// Removes and returns the first header with `id`.
    pub fn remove(&mut self, id: HeaderID) -> Option<Header> {
        let index = self
            .0
            .iter()
            .position(|header| header.id() == u8::from(id))?;

        Some(self.0.remove(index))
    }

    /// Returns the first header with `id`.
    pub fn get(&self, id: HeaderID) -> Option<&Header> {
        self.0.iter().find(|header| header.id() == u8::from(id))
    }

    /// Returns `true` if a header with `id` is present.
    pub fn contains(&self, id: HeaderID) -> bool {
        self.get(id).is_some()
    }

    /// Iterates over every header in order.
    pub fn iter(&self) -> std::slice::Iter<'_, Header> {
        self.0.iter()
    }

    /// The headers as a slice.
    pub fn as_slice(&self) -> &[Header] {
        &self.0
    }

    /// The number of headers.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if there are no headers.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the collection, returning the headers.
    pub fn into_vec(self) -> Vec<Header> {
        self.0
    }

    /// The value of the Name header.
    pub fn name(&self) -> Option<&str> {
        self.iter().find_map(|header| match header {
            Header::Name(name) => Some(name.as_str()),
            _ => None,
        })
    }

    /// The value of the Type header.
    pub fn content_type(&self) -> Option<&str> {
        self.iter().find_map(|header| match header {
            Header::Type(value) => Some(value.as_str()),
            _ => None,
        })
    }

    /// The value of the Description header.
    pub fn description(&self) -> Option<&str> {
        self.iter().find_map(|header| match header {
            Header::Description(value) => Some(value.as_str()),
            _ => None,
        })
    }

    /// The value of the Time header.
    pub fn time(&self) -> Option<&str> {
        self.iter().find_map(|header| match header {
            Header::Time(value) => Some(value.as_str()),
            _ => None,
        })
    }

    /// The value of the DestName header.
    pub fn dest_name(&self) -> Option<&str> {
        self.iter().find_map(|header| match header {
            Header::DestName(value) => Some(value.as_str()),
            _ => None,
        })
    }

    /// The value of the Count header.
    pub fn count(&self) -> Option<u32> {
        self.iter().find_map(|header| match header {
            Header::Count(value) => Some(*value),
            _ => None,
        })
    }

    /// The value of the Length header.
    pub fn length(&self) -> Option<u32> {
        self.iter().find_map(|header| match header {
            Header::Length(value) => Some(*value),
            _ => None,
        })
    }

    /// The value of the Connection Id header.
    pub fn connection_id(&self) -> Option<u32> {
        self.iter().find_map(|header| match header {
            Header::ConnectionID(value) => Some(*value),
            _ => None,
        })
    }

    /// The value of the Target header.
    pub fn target(&self) -> Option<&[u8]> {
        self.iter().find_map(|header| match header {
            Header::Target(value) => Some(value.as_slice()),
            _ => None,
        })
    }

    /// The value of the Who header.
    pub fn who(&self) -> Option<&[u8]> {
        self.iter().find_map(|header| match header {
            Header::Who(value) => Some(value.as_slice()),
            _ => None,
        })
    }

    /// The value of the Application Parameters header.
    pub fn application_parameters(&self) -> Option<&ApplicationParameters> {
        self.iter().find_map(|header| match header {
            Header::ApplicationParameters(value) => Some(value),
            _ => None,
        })
    }

    /// The value of the Action Id header.
    pub fn action_id(&self) -> Option<ActionID> {
        self.iter().find_map(|header| match header {
            Header::ActionID(value) => Some(*value),
            _ => None,
        })
    }

    /// The value of the Permissions header.
    pub fn permissions(&self) -> Option<Permissions> {
        self.iter().find_map(|header| match header {
            Header::Permissions(value) => Some(*value),
            _ => None,
        })
    }

    /// The value of the Single Response Mode header.
    pub fn single_response_mode(&self) -> Option<SingleResponseMode> {
        self.iter().find_map(|header| match header {
            Header::SingleResponseMode(value) => Some(*value),
            _ => None,
        })
    }

    /// The value of the Single Response Mode Parameters header.
    pub fn single_response_mode_parameter(&self) -> Option<SingleResponseModeParameter> {
        self.iter().find_map(|header| match header {
            Header::SingleResponseModeParameters(value) => Some(*value),
            _ => None,
        })
    }

    /// The concatenated Body and End-of-Body data, or `None` if neither is present.
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::header::{Header, Headers};
    /// let headers = Headers::from(vec![Header::Body(vec![1, 2]), Header::EndOfBody(vec![3])]);
    ///
    /// assert_eq!(Some(vec![1, 2, 3]), headers.body());
    /// assert_eq!(None, Headers::new().body());
    /// ```
    pub fn body(&self) -> Option<Vec<u8>> {
        let mut body: Option<Vec<u8>> = None;

        for header in self.iter() {
            if let Header::Body(data) | Header::EndOfBody(data) = header {
                body.get_or_insert_with(Vec::new).extend_from_slice(data);
            }
        }

        body
    }

    /// The number of bytes these headers occupy on the wire.
    pub fn encoded_len(&self) -> usize {
        self.iter().map(Header::encoded_len).sum()
    }

    /// Appends the wire representation of every header to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        for header in self.iter() {
            header.encode(buf)?;
        }

        Ok(())
    }

    /// Parses every header in `i`, failing if trailing bytes do not form a header.
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::header::{Header, Headers};
    /// let data: [u8; 10] = [0xC0, 0, 0, 0, 4, 0xC3, 0, 0, 0xF4, 0x83];
    /// let (_, headers) = Headers::parse(&data).unwrap();
    ///
    /// assert_eq!(Some(4), headers.count());
    /// assert_eq!(Some(0xF483), headers.length());
    /// ```
    pub fn parse(i: &[u8]) -> IResult<&[u8], Headers> {
        let (i, headers) = all_consuming(many0(Header::parse))(i)?;

        Ok((i, Headers(headers)))
    }
}

impl From<Vec<Header>> for Headers {
    fn from(headers: Vec<Header>) -> Headers {
        Headers(headers)
    }
}

impl<const N: usize> From<[Header; N]> for Headers {
    fn from(headers: [Header; N]) -> Headers {
        Headers(headers.into())
    }
}

impl From<Headers> for Vec<Header> {
    fn from(headers: Headers) -> Vec<Header> {
        headers.0
    }
}

impl FromIterator<Header> for Headers {
    fn from_iter<I: IntoIterator<Item = Header>>(iter: I) -> Headers {
        Headers(iter.into_iter().collect())
    }
}

impl Extend<Header> for Headers {
    fn extend<I: IntoIterator<Item = Header>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

impl IntoIterator for Headers {
    type Item = Header;
    type IntoIter = std::vec::IntoIter<Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a Header;
    type IntoIter = std::slice::Iter<'a, Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(header: Header) {
        let bytes = header.to_bytes().unwrap();
        assert_eq!(header.encoded_len(), bytes.len(), "{:?}", header);

        let (rest, parsed) = Header::parse(&bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(header, parsed);
    }

    #[test]
    fn every_header_round_trips() {
        let headers = vec![
            Header::Count(4),
            Header::Name("JUMAR.TXT".to_string()),
            Header::Name(String::new()),
            Header::Name("emoji \u{1F600}".to_string()),
            Header::Type("text/x-vcard".to_string()),
            Header::Length(0x1000),
            Header::Time("19940206T010101Z".to_string()),
            Header::LegacyTime(0x41a50016),
            Header::Description("hello".to_string()),
            Header::Target(vec![0xF9, 0xEC]),
            Header::HTTP(b"Content-Length: 5\r\n".to_vec()),
            Header::Body(vec![1, 2, 3]),
            Header::EndOfBody(Vec::new()),
            Header::Who(vec![9; 16]),
            Header::ConnectionID(0xDEADBEEF),
            Header::ApplicationParameters(ApplicationParameters::new().with_u8(1, 2)),
            Header::AuthenticateChallenge(vec![TagLengthValue::new(0, [7; 16])]),
            Header::AuthenticateResponse(vec![TagLengthValue::new(0, [8; 16])]),
            Header::CreatorID(0x50414C4D),
            Header::WANUUID(vec![1; 16]),
            Header::ObjectClass(b"class".to_vec()),
            Header::SessionParameters(vec![TagLengthValue::new(5, [0])]),
            Header::SessionSequenceNumber(255),
            Header::ActionID(ActionID::SetPermissions),
            Header::DestName("dest.txt".to_string()),
            Header::Permissions(Permissions {
                user: Permissions::READ,
                group: 0,
                other: Permissions::MODIFY,
            }),
            Header::SingleResponseMode(SingleResponseMode::Supported),
            Header::SingleResponseModeParameters(SingleResponseModeParameter::Wait),
            Header::Other {
                id: 0x30,
                value: HeaderValue::Unicode("user".to_string()),
            },
            Header::Other {
                id: 0x70,
                value: HeaderValue::Bytes(vec![1]),
            },
            Header::Other {
                id: 0xB0,
                value: HeaderValue::U8(1),
            },
            Header::Other {
                id: 0xF0,
                value: HeaderValue::U32(1),
            },
        ];

        for header in headers {
            round_trip(header);
        }
    }

    #[test]
    fn name_from_put_example_matches_spec() {
        // OBEX 1.5 section 3.4.3.3: Name "JUMAR.TXT" has a header length of 0x0017.
        let bytes = Header::Name("JUMAR.TXT".to_string()).to_bytes().unwrap();

        assert_eq!([0x01, 0x00, 0x17], bytes[..3]);
        assert_eq!([0x00, 0x00], bytes[bytes.len() - 2..]);
    }

    #[test]
    fn unicode_without_terminator_is_accepted() {
        let data: [u8; 7] = [0x01, 0x00, 0x07, 0x00, 0x61, 0x00, 0x62];

        assert_eq!(
            Header::Name("ab".to_string()),
            Header::parse(&data).unwrap().1
        );
    }

    #[test]
    fn name_with_only_terminator_is_empty() {
        let data: [u8; 5] = [0x01, 0x00, 0x05, 0x00, 0x00];

        assert_eq!(Header::Name(String::new()), Header::parse(&data).unwrap().1);
    }

    #[test]
    fn invalid_lengths_are_rejected() {
        assert!(Header::parse(&[0x48, 0x00, 0x02]).is_err());
        assert!(Header::parse(&[0x48, 0x00, 0x05, 0x01]).is_err());
        assert!(Header::parse(&[0xCB, 0x00, 0x00]).is_err());
    }

    #[test]
    fn oversized_headers_are_rejected() {
        let header = Header::Body(vec![0; u16::MAX as usize]);
        let mut bytes = Vec::new();

        assert!(matches!(
            header.encode(&mut bytes),
            Err(Error::HeaderTooLarge { id: 0x48, .. })
        ));
    }

    #[test]
    fn headers_reject_trailing_garbage() {
        assert!(Headers::parse(&[0xC0, 0, 0, 0, 4, 0xC3]).is_err());
    }
}
