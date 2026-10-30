//! ## Single Response Mode
//!
//! Single Response Mode (SRM, OBEX section 3.3) removes the per-packet acknowledgement
//! of PUT requests and GET responses, which is what makes OBEX fast over L2CAP. GOEP 2.0
//! based Bluetooth profiles (MAP 1.2+, PBAP 1.2+, FTP 1.3, ...) negotiate SRM for each
//! PUT or GET operation. The [`Client`](crate::client::Client) and
//! [`Server`](crate::server::Server) negotiate it automatically when enabled; these
//! types are the header values exchanged during that negotiation.
//!
use nom::{error::ParseError, number::complete::be_u8, IResult};

/// The value of the Single Response Mode header (0x97).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SingleResponseMode {
    /// Request that SRM is disabled.
    Disable = 0x00,
    /// Request (or confirm) that SRM is enabled.
    Enable = 0x01,
    /// Advertise that SRM is supported without enabling it.
    Supported = 0x02,
}

impl From<SingleResponseMode> for u8 {
    /// Converts a `SingleResponseMode` to a `u8` representation
    ///
    /// # Examples
    /// ```
    /// # use obex::srm::SingleResponseMode;
    /// let data: u8 = SingleResponseMode::Enable.into();
    ///
    /// assert_eq!(0x01, data);
    /// ```
    fn from(original: SingleResponseMode) -> u8 {
        original as u8
    }
}

impl TryFrom<u8> for SingleResponseMode {
    type Error = SingleResponseModeError;

    /// Attempts to convert a `u8` to a valid `SingleResponseMode`
    ///
    /// # Examples
    /// ```
    /// # use obex::srm::SingleResponseMode;
    /// assert_eq!(Ok(SingleResponseMode::Supported), SingleResponseMode::try_from(0x02));
    /// assert!(SingleResponseMode::try_from(0x03).is_err());
    /// ```
    fn try_from(original: u8) -> Result<Self, Self::Error> {
        match original {
            0x00 => Ok(SingleResponseMode::Disable),
            0x01 => Ok(SingleResponseMode::Enable),
            0x02 => Ok(SingleResponseMode::Supported),
            _ => Err(SingleResponseModeError),
        }
    }
}

impl SingleResponseMode {
    /// Attempts to parse a `SingleResponseMode` from a `&[u8]`
    pub fn parse(i: &[u8]) -> IResult<&[u8], SingleResponseMode> {
        let (i, value) = be_u8(i)?;

        match SingleResponseMode::try_from(value) {
            Ok(value) => Ok((i, value)),
            Err(_) => Err(nom::Err::Failure(ParseError::from_error_kind(
                i,
                nom::error::ErrorKind::Fail,
            ))),
        }
    }
}

/// The error returned when a byte is not a valid `SingleResponseMode`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SingleResponseModeError;

/// The value of the Single Response Mode Parameters header (0x98).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SingleResponseModeParameter {
    /// The sender requests one additional packet from the remote device.
    AdditionalPacket = 0x00,
    /// The remote device must wait for the next packet from the sender.
    Wait = 0x01,
    /// Both `AdditionalPacket` and `Wait`.
    AdditionalPacketAndWait = 0x02,
}

impl SingleResponseModeParameter {
    /// Returns `true` if the sender requests an additional packet.
    pub fn requests_additional_packet(self) -> bool {
        matches!(
            self,
            SingleResponseModeParameter::AdditionalPacket
                | SingleResponseModeParameter::AdditionalPacketAndWait
        )
    }

    /// Returns `true` if the sender requests that the remote device waits.
    pub fn requests_wait(self) -> bool {
        matches!(
            self,
            SingleResponseModeParameter::Wait
                | SingleResponseModeParameter::AdditionalPacketAndWait
        )
    }

    /// Attempts to parse a `SingleResponseModeParameter` from a `&[u8]`
    pub fn parse(i: &[u8]) -> IResult<&[u8], SingleResponseModeParameter> {
        let (i, value) = be_u8(i)?;

        match SingleResponseModeParameter::try_from(value) {
            Ok(value) => Ok((i, value)),
            Err(_) => Err(nom::Err::Failure(ParseError::from_error_kind(
                i,
                nom::error::ErrorKind::Fail,
            ))),
        }
    }
}

impl From<SingleResponseModeParameter> for u8 {
    fn from(original: SingleResponseModeParameter) -> u8 {
        original as u8
    }
}

impl TryFrom<u8> for SingleResponseModeParameter {
    type Error = SingleResponseModeParameterError;

    /// Attempts to convert a `u8` to a valid `SingleResponseModeParameter`
    ///
    /// # Examples
    /// ```
    /// # use obex::srm::SingleResponseModeParameter;
    /// let parameter = SingleResponseModeParameter::try_from(0x01).unwrap();
    ///
    /// assert!(parameter.requests_wait());
    /// assert!(!parameter.requests_additional_packet());
    /// ```
    fn try_from(original: u8) -> Result<Self, Self::Error> {
        match original {
            0x00 => Ok(SingleResponseModeParameter::AdditionalPacket),
            0x01 => Ok(SingleResponseModeParameter::Wait),
            0x02 => Ok(SingleResponseModeParameter::AdditionalPacketAndWait),
            _ => Err(SingleResponseModeParameterError),
        }
    }
}

/// The error returned when a byte is not a valid `SingleResponseModeParameter`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SingleResponseModeParameterError;
