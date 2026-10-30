//! ## Opcodes
//!
//! Every request packet starts with an opcode (OBEX section 3.4). The high bit of the
//! opcode byte is the Final bit, which marks the last packet of a request. CONNECT,
//! DISCONNECT, SETPATH, SESSION and ABORT always have it set.
//!
use nom::{error::ParseError, number::complete::be_u8, IResult};

/// The `Opcode` type. See [the module level documentation](index.html) for more.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Opcode {
    /// Choose your partner, negotiate capabilities.
    Connect,
    /// Signal the end of the session.
    Disconnect,
    /// Send an object.
    Put,
    /// Get an object.
    Get,
    /// Modify the current path on the receiving side.
    SetPath,
    /// Perform an action (copy, move/rename, set permissions) on the receiving side.
    Action,
    /// Reliable session support.
    Session,
    /// Abort the current operation.
    Abort,
    /// A user definable opcode in the range 0x10 to 0x1F.
    UserDefined(u8),
}

/// The Final bit of an opcode or response code.
pub const FINAL_BIT: u8 = 0x80;

impl Opcode {
    /// The opcode value without the Final bit.
    ///
    /// # Examples
    /// ```
    /// # use obex::opcode::Opcode;
    /// assert_eq!(0x02, Opcode::Put.value());
    /// assert_eq!(0x7F, Opcode::Abort.value());
    /// ```
    pub fn value(self) -> u8 {
        match self {
            Opcode::Connect => 0x00,
            Opcode::Disconnect => 0x01,
            Opcode::Put => 0x02,
            Opcode::Get => 0x03,
            Opcode::SetPath => 0x05,
            Opcode::Action => 0x06,
            Opcode::Session => 0x07,
            Opcode::Abort => 0x7F,
            Opcode::UserDefined(value) => value,
        }
    }

    /// Returns `true` for opcodes that must always be sent with the Final bit set.
    pub fn is_always_final(self) -> bool {
        matches!(
            self,
            Opcode::Connect
                | Opcode::Disconnect
                | Opcode::SetPath
                | Opcode::Session
                | Opcode::Abort
        )
    }

    /// The opcode byte as sent on the wire.
    ///
    /// # Examples
    /// ```
    /// # use obex::opcode::Opcode;
    /// assert_eq!(0x02, Opcode::Put.to_byte(false));
    /// assert_eq!(0x82, Opcode::Put.to_byte(true));
    /// assert_eq!(0x80, Opcode::Connect.to_byte(false));
    /// assert_eq!(0xFF, Opcode::Abort.to_byte(true));
    /// ```
    pub fn to_byte(self, is_final: bool) -> u8 {
        if is_final || self.is_always_final() {
            self.value() | FINAL_BIT
        } else {
            self.value()
        }
    }

    /// Decodes an opcode byte into the opcode and its Final bit.
    ///
    /// Reserved bits 5 and 6 are ignored as the specification requires, except for
    /// ABORT which sets them.
    ///
    /// # Examples
    /// ```
    /// # use obex::opcode::Opcode;
    /// assert_eq!(Ok((Opcode::Get, true)), Opcode::from_byte(0x83));
    /// assert_eq!(Ok((Opcode::Put, false)), Opcode::from_byte(0x02));
    /// assert_eq!(Ok((Opcode::Abort, true)), Opcode::from_byte(0xFF));
    /// assert_eq!(Ok((Opcode::UserDefined(0x10), true)), Opcode::from_byte(0x90));
    /// assert!(Opcode::from_byte(0x84).is_err());
    /// ```
    pub fn from_byte(byte: u8) -> Result<(Opcode, bool), OpcodeError> {
        let is_final = byte & FINAL_BIT != 0;

        if byte & 0x7F == 0x7F {
            return Ok((Opcode::Abort, is_final));
        }

        Opcode::try_from(byte & 0x1F).map(|opcode| (opcode, is_final))
    }

    /// Attempts to parse an `Opcode` and its Final bit from a `&[u8]`
    ///
    /// # Examples
    /// ```
    /// # use obex::opcode::Opcode;
    /// let data: [u8; 3] = [0x82, 0x00, 0x03];
    /// let (data, (opcode, is_final)) = Opcode::parse(&data).unwrap();
    ///
    /// assert_eq!(Opcode::Put, opcode);
    /// assert!(is_final);
    /// ```
    pub fn parse(i: &[u8]) -> IResult<&[u8], (Opcode, bool)> {
        let (i, byte) = be_u8(i)?;

        match Opcode::from_byte(byte) {
            Ok(value) => Ok((i, value)),
            Err(_) => Err(nom::Err::Failure(ParseError::from_error_kind(
                i,
                nom::error::ErrorKind::Fail,
            ))),
        }
    }
}

impl From<Opcode> for u8 {
    /// Converts an `Opcode` to its value without the Final bit
    fn from(original: Opcode) -> u8 {
        original.value()
    }
}

impl TryFrom<u8> for Opcode {
    type Error = OpcodeError;

    /// Attempts to convert an opcode value without the Final bit to an `Opcode`
    ///
    /// # Examples
    /// ```
    /// # use obex::opcode::Opcode;
    /// assert_eq!(Ok(Opcode::SetPath), Opcode::try_from(0x05));
    /// assert!(Opcode::try_from(0x04).is_err());
    /// ```
    fn try_from(original: u8) -> Result<Self, Self::Error> {
        match original {
            0x00 => Ok(Opcode::Connect),
            0x01 => Ok(Opcode::Disconnect),
            0x02 => Ok(Opcode::Put),
            0x03 => Ok(Opcode::Get),
            0x05 => Ok(Opcode::SetPath),
            0x06 => Ok(Opcode::Action),
            0x07 => Ok(Opcode::Session),
            0x7F => Ok(Opcode::Abort),
            0x10..=0x1F => Ok(Opcode::UserDefined(original)),
            _ => Err(OpcodeError),
        }
    }
}

/// The error returned when a byte is not a valid `Opcode`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpcodeError;
