//! ## Reliable Sessions
//!
//! Reliable sessions (OBEX sections 3.4.7 and 10) let a client suspend an OBEX
//! session and resume it later, possibly over another transport. SESSION requests
//! carry a Session-Parameters header whose first triplet is the [`SessionOpcode`].
//!
//! This module provides the session commands, their parameters and session id
//! generation. Sending a session command is a single request/response exchange, see
//! [`Client::session`](crate::client::Client::session). Retransmission after a resume
//! is application specific and is left to the caller.
//!
use nom::{error::ParseError, number::complete::be_u8, IResult};

use crate::header::Header;
use crate::md5;
use crate::tlv::TagLengthValue;

/// A session timeout of infinity, which is the default.
pub const INFINITE_TIMEOUT: u32 = 0xFFFF_FFFF;

/// Session commands, sent in the Session Opcode parameter.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SessionOpcode {
    /// Create a new session.
    CreateSession = 0x00,
    /// Close an active or suspended session.
    CloseSession = 0x01,
    /// Suspend the active session.
    SuspendSession = 0x02,
    /// Resume a suspended session.
    ResumeSession = 0x03,
    /// Negotiate the timeout of a suspended session.
    SetTimeout = 0x04,
}

impl From<SessionOpcode> for u8 {
    fn from(value: SessionOpcode) -> u8 {
        value as u8
    }
}

impl TryFrom<u8> for SessionOpcode {
    type Error = SessionOpcodeError;

    /// Attempts to convert a `u8` to a valid `SessionOpcode`
    ///
    /// # Examples
    /// ```
    /// # use obex::session::SessionOpcode;
    /// assert_eq!(Ok(SessionOpcode::ResumeSession), SessionOpcode::try_from(0x03));
    /// assert!(SessionOpcode::try_from(0x05).is_err());
    /// ```
    fn try_from(original: u8) -> Result<Self, Self::Error> {
        match original {
            0x00 => Ok(SessionOpcode::CreateSession),
            0x01 => Ok(SessionOpcode::CloseSession),
            0x02 => Ok(SessionOpcode::SuspendSession),
            0x03 => Ok(SessionOpcode::ResumeSession),
            0x04 => Ok(SessionOpcode::SetTimeout),
            _ => Err(SessionOpcodeError),
        }
    }
}

impl SessionOpcode {
    /// Attempts to parse a `SessionOpcode` from a `&[u8]`
    pub fn parse(i: &[u8]) -> IResult<&[u8], SessionOpcode> {
        let (i, id) = be_u8(i)?;

        match SessionOpcode::try_from(id) {
            Ok(id) => Ok((i, id)),
            Err(_) => Err(nom::Err::Failure(ParseError::from_error_kind(
                i,
                nom::error::ErrorKind::Fail,
            ))),
        }
    }
}

/// The error returned when a byte is not a valid `SessionOpcode`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SessionOpcodeError;

/// Tags of the Session-Parameters header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SessionParameterTag {
    /// The device address of the sender.
    DeviceAddress = 0x00,
    /// A unique value used to create the session id.
    Nonce = 0x01,
    /// The 16 byte session id.
    SessionID = 0x02,
    /// The next sequence number expected when the session is resumed.
    NextSequenceNumber = 0x03,
    /// Seconds a suspended session is kept.
    Timeout = 0x04,
    /// The session command, always the first triplet of a request.
    SessionOpcode = 0x05,
    /// Number of object body bytes received so far.
    ObjectOffset = 0x06,
}

impl From<SessionParameterTag> for u8 {
    fn from(value: SessionParameterTag) -> u8 {
        value as u8
    }
}

impl TryFrom<u8> for SessionParameterTag {
    type Error = SessionParameterTagError;

    fn try_from(original: u8) -> Result<Self, Self::Error> {
        match original {
            0x00 => Ok(SessionParameterTag::DeviceAddress),
            0x01 => Ok(SessionParameterTag::Nonce),
            0x02 => Ok(SessionParameterTag::SessionID),
            0x03 => Ok(SessionParameterTag::NextSequenceNumber),
            0x04 => Ok(SessionParameterTag::Timeout),
            0x05 => Ok(SessionParameterTag::SessionOpcode),
            0x06 => Ok(SessionParameterTag::ObjectOffset),
            _ => Err(SessionParameterTagError),
        }
    }
}

/// The error returned when a byte is not a valid `SessionParameterTag`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SessionParameterTagError;

/// A typed Session-Parameters triplet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SessionParameter {
    /// The sender's device address: 4 bytes for IrDA, 6 for Bluetooth, an IP address for TCP.
    DeviceAddress(Vec<u8>),
    /// A unique value of 4 to 16 bytes used to create the session id.
    Nonce(Vec<u8>),
    /// The 16 byte session id, see [`session_id`].
    SessionID([u8; 16]),
    /// The next sequence number expected when the session is resumed.
    NextSequenceNumber(u8),
    /// Seconds a suspended session is kept, [`INFINITE_TIMEOUT`] by default.
    Timeout(u32),
    /// The session command, always the first triplet of a SESSION request.
    SessionOpcode(SessionOpcode),
    /// Number of object body bytes received so far.
    ObjectOffset(u64),
}

impl SessionParameter {
    /// The tag of this parameter.
    pub fn tag(&self) -> SessionParameterTag {
        match self {
            SessionParameter::DeviceAddress(_) => SessionParameterTag::DeviceAddress,
            SessionParameter::Nonce(_) => SessionParameterTag::Nonce,
            SessionParameter::SessionID(_) => SessionParameterTag::SessionID,
            SessionParameter::NextSequenceNumber(_) => SessionParameterTag::NextSequenceNumber,
            SessionParameter::Timeout(_) => SessionParameterTag::Timeout,
            SessionParameter::SessionOpcode(_) => SessionParameterTag::SessionOpcode,
            SessionParameter::ObjectOffset(_) => SessionParameterTag::ObjectOffset,
        }
    }
}

impl From<&SessionParameter> for TagLengthValue {
    /// Converts a `SessionParameter` to a `TagLengthValue`
    ///
    /// # Examples
    /// ```
    /// # use obex::session::{SessionParameter, SessionOpcode};
    /// # use obex::tlv::TagLengthValue;
    /// let tlv = TagLengthValue::from(&SessionParameter::SessionOpcode(SessionOpcode::SuspendSession));
    ///
    /// assert_eq!(TagLengthValue::new(0x05, [0x02]), tlv);
    /// ```
    fn from(parameter: &SessionParameter) -> TagLengthValue {
        let value: Vec<u8> = match parameter {
            SessionParameter::DeviceAddress(value) | SessionParameter::Nonce(value) => {
                value.clone()
            }
            SessionParameter::SessionID(value) => value.to_vec(),
            SessionParameter::NextSequenceNumber(value) => vec![*value],
            SessionParameter::Timeout(value) => value.to_be_bytes().to_vec(),
            SessionParameter::SessionOpcode(value) => vec![(*value).into()],
            SessionParameter::ObjectOffset(value) => match u32::try_from(*value) {
                Ok(value) => value.to_be_bytes().to_vec(),
                Err(_) => value.to_be_bytes().to_vec(),
            },
        };

        TagLengthValue::new(parameter.tag().into(), value)
    }
}

impl TryFrom<&TagLengthValue> for SessionParameter {
    type Error = SessionParameterError;

    /// Attempts to convert a `TagLengthValue` to a `SessionParameter`
    ///
    /// # Examples
    /// ```
    /// # use obex::session::SessionParameter;
    /// # use obex::tlv::TagLengthValue;
    /// let parameter = SessionParameter::try_from(&TagLengthValue::new(0x04, [0, 0, 0, 30])).unwrap();
    ///
    /// assert_eq!(SessionParameter::Timeout(30), parameter);
    /// ```
    fn try_from(tlv: &TagLengthValue) -> Result<Self, Self::Error> {
        let tag = SessionParameterTag::try_from(tlv.tag).map_err(|_| SessionParameterError)?;
        let value = tlv.value.as_slice();

        let parameter = match tag {
            SessionParameterTag::DeviceAddress => SessionParameter::DeviceAddress(value.to_vec()),
            SessionParameterTag::Nonce => SessionParameter::Nonce(value.to_vec()),
            SessionParameterTag::SessionID => {
                SessionParameter::SessionID(value.try_into().map_err(|_| SessionParameterError)?)
            }
            SessionParameterTag::NextSequenceNumber => match value {
                [value] => SessionParameter::NextSequenceNumber(*value),
                _ => return Err(SessionParameterError),
            },
            SessionParameterTag::Timeout => SessionParameter::Timeout(u32::from_be_bytes(
                value.try_into().map_err(|_| SessionParameterError)?,
            )),
            SessionParameterTag::SessionOpcode => match value {
                [value] => SessionParameter::SessionOpcode(
                    SessionOpcode::try_from(*value).map_err(|_| SessionParameterError)?,
                ),
                _ => return Err(SessionParameterError),
            },
            SessionParameterTag::ObjectOffset => {
                SessionParameter::ObjectOffset(tlv.as_uint().ok_or(SessionParameterError)?)
            }
        };

        Ok(parameter)
    }
}

/// The error returned when a triplet is not a valid `SessionParameter`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SessionParameterError;

/// The parameters of a SESSION request or response.
///
/// # Examples
///
/// Creating a session over Bluetooth:
/// ```
/// # use obex::header::Header;
/// # use obex::session::{SessionParameters, SessionParameter, SessionOpcode};
/// let parameters = SessionParameters::command(SessionOpcode::CreateSession)
///     .with(SessionParameter::DeviceAddress(vec![0x00, 0x1A, 0x7D, 0xDA, 0x71, 0x13]))
///     .with(SessionParameter::Nonce(vec![1, 2, 3, 4]));
///
/// let header: Header = parameters.clone().into();
///
/// if let Header::SessionParameters(tlvs) = &header {
///     assert_eq!(parameters, SessionParameters::from_tlvs(tlvs).unwrap());
/// }
/// assert_eq!(Some(SessionOpcode::CreateSession), parameters.opcode());
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct SessionParameters(pub Vec<SessionParameter>);

impl SessionParameters {
    /// Creates the parameters of a session command, starting with its opcode.
    pub fn command(opcode: SessionOpcode) -> SessionParameters {
        SessionParameters(vec![SessionParameter::SessionOpcode(opcode)])
    }

    /// Appends a parameter, builder style.
    pub fn with(mut self, parameter: SessionParameter) -> SessionParameters {
        self.0.push(parameter);
        self
    }

    /// Decodes typed parameters, ignoring reserved tags.
    pub fn from_tlvs(tlvs: &[TagLengthValue]) -> Result<SessionParameters, SessionParameterError> {
        tlvs.iter()
            .filter(|tlv| SessionParameterTag::try_from(tlv.tag).is_ok())
            .map(SessionParameter::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map(SessionParameters)
    }

    /// Encodes the parameters as tag-length-value triplets.
    pub fn to_tlvs(&self) -> Vec<TagLengthValue> {
        self.0.iter().map(TagLengthValue::from).collect()
    }

    /// The session command, if present.
    pub fn opcode(&self) -> Option<SessionOpcode> {
        self.0.iter().find_map(|parameter| match parameter {
            SessionParameter::SessionOpcode(opcode) => Some(*opcode),
            _ => None,
        })
    }

    /// The session id, if present.
    pub fn session_id(&self) -> Option<[u8; 16]> {
        self.0.iter().find_map(|parameter| match parameter {
            SessionParameter::SessionID(id) => Some(*id),
            _ => None,
        })
    }

    /// The timeout, or [`INFINITE_TIMEOUT`] if none was sent.
    pub fn timeout(&self) -> u32 {
        self.0
            .iter()
            .find_map(|parameter| match parameter {
                SessionParameter::Timeout(timeout) => Some(*timeout),
                _ => None,
            })
            .unwrap_or(INFINITE_TIMEOUT)
    }
}

impl From<SessionParameters> for Header {
    fn from(parameters: SessionParameters) -> Header {
        Header::SessionParameters(parameters.to_tlvs())
    }
}

/// Computes a session id: `MD5(client address, client nonce, server address, server nonce)`.
///
/// # Examples
/// ```
/// # use obex::session::session_id;
/// let id = session_id(&[1, 2, 3, 4, 5, 6], &[9, 9, 9, 9], &[6, 5, 4, 3, 2, 1], &[7, 7, 7, 7]);
///
/// assert_eq!(16, id.len());
/// ```
pub fn session_id(
    client_address: &[u8],
    client_nonce: &[u8],
    server_address: &[u8],
    server_nonce: &[u8],
) -> [u8; 16] {
    md5::digest(&[client_address, client_nonce, server_address, server_nonce])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_parameter_round_trips() {
        let parameters = SessionParameters::command(SessionOpcode::ResumeSession)
            .with(SessionParameter::DeviceAddress(vec![1, 2, 3, 4, 5, 6]))
            .with(SessionParameter::Nonce(vec![1; 16]))
            .with(SessionParameter::SessionID([3; 16]))
            .with(SessionParameter::NextSequenceNumber(9))
            .with(SessionParameter::Timeout(60))
            .with(SessionParameter::ObjectOffset(1 << 40))
            .with(SessionParameter::ObjectOffset(5));

        assert_eq!(
            parameters,
            SessionParameters::from_tlvs(&parameters.to_tlvs()).unwrap()
        );
    }

    #[test]
    fn small_object_offsets_use_four_bytes() {
        let tlv = TagLengthValue::from(&SessionParameter::ObjectOffset(5));

        assert_eq!(vec![0, 0, 0, 5], tlv.value);
    }

    #[test]
    fn missing_timeout_is_infinite() {
        assert_eq!(
            INFINITE_TIMEOUT,
            SessionParameters::command(SessionOpcode::SetTimeout).timeout()
        );
    }
}
