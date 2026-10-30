//! ## Actions
//!
//! The ACTION operation (OBEX section 3.4.8) performs common file operations on the
//! server without transferring the object: copy, move/rename and setting permissions.
//! The Action Id header selects the action and the Permissions header carries the
//! permission bit masks.
//!
use nom::{error::ParseError, number::complete::be_u8, IResult};

/// The value of the Action Id header (0x94).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ActionID {
    /// Copy the object named by Name to DestName.
    Copy,
    /// Move or rename the object named by Name to DestName.
    MoveRename,
    /// Set the permissions of the object named by Name.
    SetPermissions,
    /// A vendor specific action in the range 0x80 to 0xFF.
    Vendor(u8),
}

impl From<ActionID> for u8 {
    /// Converts an `ActionID` to a `u8` representation
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::action::ActionID;
    /// assert_eq!(0x01, u8::from(ActionID::MoveRename));
    /// assert_eq!(0x80, u8::from(ActionID::Vendor(0x80)));
    /// ```
    fn from(original: ActionID) -> u8 {
        match original {
            ActionID::Copy => 0x00,
            ActionID::MoveRename => 0x01,
            ActionID::SetPermissions => 0x02,
            ActionID::Vendor(value) => value,
        }
    }
}

impl TryFrom<u8> for ActionID {
    type Error = ActionIDError;

    /// Attempts to convert a `u8` to a valid `ActionID`
    ///
    /// # Examples
    /// ```
    /// # use obex_protocol::action::ActionID;
    /// assert_eq!(Ok(ActionID::Copy), ActionID::try_from(0x00));
    /// assert_eq!(Ok(ActionID::Vendor(0xF0)), ActionID::try_from(0xF0));
    /// assert!(ActionID::try_from(0x03).is_err());
    /// ```
    fn try_from(original: u8) -> Result<Self, Self::Error> {
        match original {
            0x00 => Ok(ActionID::Copy),
            0x01 => Ok(ActionID::MoveRename),
            0x02 => Ok(ActionID::SetPermissions),
            0x80..=0xFF => Ok(ActionID::Vendor(original)),
            _ => Err(ActionIDError),
        }
    }
}

impl ActionID {
    /// Attempts to parse an `ActionID` from a `&[u8]`
    pub fn parse(i: &[u8]) -> IResult<&[u8], ActionID> {
        let (i, value) = be_u8(i)?;

        match ActionID::try_from(value) {
            Ok(value) => Ok((i, value)),
            Err(_) => Err(nom::Err::Failure(ParseError::from_error_kind(
                i,
                nom::error::ErrorKind::Fail,
            ))),
        }
    }
}

/// The error returned when a byte is not a valid `ActionID`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ActionIDError;

/// The value of the Permissions header (0xD6).
///
/// Each byte is a bit mask of [`Permissions::READ`], [`Permissions::WRITE`],
/// [`Permissions::DELETE`] and [`Permissions::MODIFY`].
///
/// # Examples
/// ```
/// # use obex_protocol::action::Permissions;
/// let permissions = Permissions {
///     user: Permissions::READ | Permissions::WRITE,
///     group: Permissions::READ,
///     other: 0,
/// };
///
/// assert_eq!(0x0003_0100, u32::from(permissions));
/// assert_eq!(permissions, Permissions::from(0x0003_0100));
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct Permissions {
    /// Permissions of the OBEX client's authenticated user, or a guest.
    pub user: u8,
    /// Permissions of the groups the server assigned to the user.
    pub group: u8,
    /// Permissions of everyone else.
    pub other: u8,
}

impl Permissions {
    /// The object may be read with GET or copied; folders may be entered with SETPATH.
    pub const READ: u8 = 0x01;
    /// The object may be written with PUT.
    pub const WRITE: u8 = 0x02;
    /// The object may be deleted with PUT.
    pub const DELETE: u8 = 0x04;
    /// The permissions of the object may be changed with ACTION.
    pub const MODIFY: u8 = 0x80;
}

impl From<Permissions> for u32 {
    fn from(permissions: Permissions) -> u32 {
        u32::from_be_bytes([0, permissions.user, permissions.group, permissions.other])
    }
}

impl From<u32> for Permissions {
    fn from(value: u32) -> Permissions {
        let [_, user, group, other] = value.to_be_bytes();

        Permissions { user, group, other }
    }
}
