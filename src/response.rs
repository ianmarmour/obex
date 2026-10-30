//! ## Response Codes
//!
//! Every response packet starts with a response code (OBEX section 3.2.1). The low 7
//! bits carry an HTTP status code equivalent and the high bit is the Final bit, which
//! is always set in practice.
//!
use nom::{error::ParseError, number::complete::be_u8, IResult};

use crate::opcode::FINAL_BIT;

/// The `ResponseCode` type. See [the module level documentation](index.html) for more.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ResponseCode {
    Continue = 0x10,
    Success = 0x20,
    Created = 0x21,
    Accepted = 0x22,
    NonAuthoritativeInformation = 0x23,
    NoContent = 0x24,
    ResetContent = 0x25,
    PartialContent = 0x26,
    MultipleChoices = 0x30,
    MovedPermanently = 0x31,
    MovedTemporarily = 0x32,
    SeeOther = 0x33,
    NotModified = 0x34,
    UseProxy = 0x35,
    BadRequest = 0x40,
    Unauthorized = 0x41,
    PaymentRequired = 0x42,
    Forbidden = 0x43,
    NotFound = 0x44,
    MethodNotAllowed = 0x45,
    NotAcceptable = 0x46,
    ProxyAuthenticationRequired = 0x47,
    RequestTimeOut = 0x48,
    Conflict = 0x49,
    Gone = 0x4A,
    LengthRequired = 0x4B,
    PreconditionFailed = 0x4C,
    RequestedEntityTooLarge = 0x4D,
    RequestURLTooLarge = 0x4E,
    UnsupportedMediaType = 0x4F,
    InternalServerError = 0x50,
    NotImplemented = 0x51,
    BadGateway = 0x52,
    ServiceUnavailable = 0x53,
    GatewayTimeout = 0x54,
    HTTPVersionNotSupported = 0x55,
    DatabaseFull = 0x60,
    DatabaseLocked = 0x61,
}

impl ResponseCode {
    /// Returns `true` for the 2xx family of success codes.
    ///
    /// # Examples
    /// ```
    /// # use obex::response::ResponseCode;
    /// assert!(ResponseCode::Success.is_success());
    /// assert!(ResponseCode::PartialContent.is_success());
    /// assert!(!ResponseCode::Continue.is_success());
    /// assert!(!ResponseCode::NotFound.is_success());
    /// ```
    pub fn is_success(self) -> bool {
        (0x20..=0x2F).contains(&(self as u8))
    }

    /// The response code byte as sent on the wire.
    ///
    /// # Examples
    /// ```
    /// # use obex::response::ResponseCode;
    /// assert_eq!(0xA0, ResponseCode::Success.to_byte(true));
    /// assert_eq!(0x90, ResponseCode::Continue.to_byte(true));
    /// ```
    pub fn to_byte(self, is_final: bool) -> u8 {
        if is_final {
            self as u8 | FINAL_BIT
        } else {
            self as u8
        }
    }

    /// Attempts to parse a `ResponseCode` and its Final bit from a `&[u8]`
    ///
    /// # Examples
    /// ```
    /// # use obex::response::ResponseCode;
    /// let data: [u8; 3] = [0xA0, 0x00, 0x03];
    /// let (data, (code, is_final)) = ResponseCode::parse(&data).unwrap();
    ///
    /// assert_eq!(ResponseCode::Success, code);
    /// assert!(is_final);
    /// ```
    pub fn parse(i: &[u8]) -> IResult<&[u8], (ResponseCode, bool)> {
        let (i, byte) = be_u8(i)?;

        match ResponseCode::try_from(byte) {
            Ok(code) => Ok((i, (code, byte & FINAL_BIT != 0))),
            Err(_) => Err(nom::Err::Failure(ParseError::from_error_kind(
                i,
                nom::error::ErrorKind::Fail,
            ))),
        }
    }
}

impl From<ResponseCode> for u8 {
    /// Converts a `ResponseCode` to its value without the Final bit
    ///
    /// # Examples
    /// ```
    /// # use obex::response::ResponseCode;
    /// assert_eq!(0x53, u8::from(ResponseCode::ServiceUnavailable));
    /// ```
    fn from(original: ResponseCode) -> u8 {
        original as u8
    }
}

impl TryFrom<u8> for ResponseCode {
    type Error = ResponseCodeError;

    /// Attempts to convert a `u8` to a `ResponseCode`, ignoring the Final bit
    ///
    /// # Examples
    /// ```
    /// # use obex::response::ResponseCode;
    /// assert_eq!(Ok(ResponseCode::Forbidden), ResponseCode::try_from(0xC3));
    /// assert_eq!(Ok(ResponseCode::Forbidden), ResponseCode::try_from(0x43));
    /// assert!(ResponseCode::try_from(0x00).is_err());
    /// ```
    fn try_from(original: u8) -> Result<Self, Self::Error> {
        match original & !FINAL_BIT {
            0x10 => Ok(ResponseCode::Continue),
            0x20 => Ok(ResponseCode::Success),
            0x21 => Ok(ResponseCode::Created),
            0x22 => Ok(ResponseCode::Accepted),
            0x23 => Ok(ResponseCode::NonAuthoritativeInformation),
            0x24 => Ok(ResponseCode::NoContent),
            0x25 => Ok(ResponseCode::ResetContent),
            0x26 => Ok(ResponseCode::PartialContent),
            0x30 => Ok(ResponseCode::MultipleChoices),
            0x31 => Ok(ResponseCode::MovedPermanently),
            0x32 => Ok(ResponseCode::MovedTemporarily),
            0x33 => Ok(ResponseCode::SeeOther),
            0x34 => Ok(ResponseCode::NotModified),
            0x35 => Ok(ResponseCode::UseProxy),
            0x40 => Ok(ResponseCode::BadRequest),
            0x41 => Ok(ResponseCode::Unauthorized),
            0x42 => Ok(ResponseCode::PaymentRequired),
            0x43 => Ok(ResponseCode::Forbidden),
            0x44 => Ok(ResponseCode::NotFound),
            0x45 => Ok(ResponseCode::MethodNotAllowed),
            0x46 => Ok(ResponseCode::NotAcceptable),
            0x47 => Ok(ResponseCode::ProxyAuthenticationRequired),
            0x48 => Ok(ResponseCode::RequestTimeOut),
            0x49 => Ok(ResponseCode::Conflict),
            0x4A => Ok(ResponseCode::Gone),
            0x4B => Ok(ResponseCode::LengthRequired),
            0x4C => Ok(ResponseCode::PreconditionFailed),
            0x4D => Ok(ResponseCode::RequestedEntityTooLarge),
            0x4E => Ok(ResponseCode::RequestURLTooLarge),
            0x4F => Ok(ResponseCode::UnsupportedMediaType),
            0x50 => Ok(ResponseCode::InternalServerError),
            0x51 => Ok(ResponseCode::NotImplemented),
            0x52 => Ok(ResponseCode::BadGateway),
            0x53 => Ok(ResponseCode::ServiceUnavailable),
            0x54 => Ok(ResponseCode::GatewayTimeout),
            0x55 => Ok(ResponseCode::HTTPVersionNotSupported),
            0x60 => Ok(ResponseCode::DatabaseFull),
            0x61 => Ok(ResponseCode::DatabaseLocked),
            _ => Err(ResponseCodeError),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ResponseCodeError;
