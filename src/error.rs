//! ## Errors
//!
//! A single `Error` type is used throughout the crate. Low-level parsers return
//! `nom::IResult` like the rest of the codec layer, while everything that touches a
//! transport or composes packets returns [`Result`].
//!
use std::fmt;
use std::io;

use crate::packet::Response;
use crate::response::ResponseCode;

/// The `Error` type. See [the module level documentation](index.html) for more.
#[derive(Debug)]
pub enum Error {
    /// The underlying transport returned an error.
    Io(io::Error),
    /// The transport was closed by the remote device on a packet boundary.
    Disconnected,
    /// Received bytes could not be parsed as an OBEX packet.
    Malformed(nom::error::ErrorKind),
    /// A header is larger than a single OBEX packet can carry.
    HeaderTooLarge {
        /// The header identifier.
        id: u8,
        /// The encoded length of the header.
        length: usize,
        /// The largest header that fits.
        maximum: usize,
    },
    /// A packet is larger than the negotiated maximum OBEX packet length.
    PacketTooLarge {
        /// The encoded length of the packet.
        length: usize,
        /// The largest packet the receiver accepts.
        maximum: usize,
    },
    /// A tag-length-value triplet carries more than 255 bytes.
    ValueTooLarge {
        /// The tag of the triplet.
        tag: u8,
        /// The length of its value.
        length: usize,
    },
    /// The remote device answered with a response code that is not a success code.
    Response(Box<Response>),
    /// The remote device violated the OBEX protocol.
    Protocol(&'static str),
    /// OBEX digest authentication failed.
    AuthenticationFailed,
}

impl Error {
    /// Returns the response code of a failed operation, if this error was caused by one.
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::Error;
    /// # use obex_protocol::packet::Response;
    /// # use obex_protocol::response::ResponseCode;
    /// let error = Error::Response(Box::new(Response::new(ResponseCode::NotFound)));
    ///
    /// assert_eq!(Some(ResponseCode::NotFound), error.response_code());
    /// ```
    pub fn response_code(&self) -> Option<ResponseCode> {
        match self {
            Error::Response(response) => Some(response.code),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(error) => write!(f, "transport error: {}", error),
            Error::Disconnected => write!(f, "transport disconnected"),
            Error::Malformed(kind) => write!(f, "malformed OBEX packet ({:?})", kind),
            Error::HeaderTooLarge {
                id,
                length,
                maximum,
            } => write!(
                f,
                "header 0x{:02X} is {} bytes but at most {} bytes fit in a packet",
                id, length, maximum
            ),
            Error::PacketTooLarge { length, maximum } => write!(
                f,
                "packet is {} bytes but the maximum packet length is {} bytes",
                length, maximum
            ),
            Error::ValueTooLarge { tag, length } => write!(
                f,
                "tag 0x{:02X} carries {} bytes but at most 255 are allowed",
                tag, length
            ),
            Error::Response(response) => {
                write!(f, "operation failed with response {:?}", response.code)
            }
            Error::Protocol(reason) => write!(f, "protocol violation: {}", reason),
            Error::AuthenticationFailed => write!(f, "authentication failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::Io(error)
    }
}

impl<I> From<nom::Err<nom::error::Error<I>>> for Error {
    fn from(error: nom::Err<nom::error::Error<I>>) -> Error {
        match error {
            nom::Err::Incomplete(_) => Error::Malformed(nom::error::ErrorKind::Eof),
            nom::Err::Error(error) | nom::Err::Failure(error) => Error::Malformed(error.code),
        }
    }
}

/// A `Result` alias where the `Err` case is an OBEX [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Builds a nom failure for values that are syntactically valid but semantically invalid.
pub(crate) fn failure<T>(i: &[u8]) -> nom::IResult<&[u8], T> {
    Err(nom::Err::Failure(nom::error::Error::new(
        i,
        nom::error::ErrorKind::Verify,
    )))
}
