//! ## Well Known Targets and Types
//!
//! A directed connection (OBEX section 4.6) is opened by sending a Target header in
//! CONNECT. The server answers with a Who header holding the same value and a
//! Connection Id that every later request carries. Each profile built on OBEX
//! defines its own Target value; the ones below are the targets from OBEX section
//! 12.4 plus the Bluetooth profiles most commonly layered on this crate.
//!
//! The object type constants are the OBEX defined values of the Type header.
//!

/// IrMC synchronization service (OBEX section 12.4).
pub const IRMC_SYNC: &[u8] = b"IRMC-SYNC";

/// SyncML synchronization service (OBEX section 12.4).
pub const SYNCML_SYNC: &[u8] = b"SYNCML-SYNC";

/// Folder Browsing service, `F9EC7BC4-953C-11D2-984E-525400DC9E09` (OBEX section 12.4).
///
/// This is also the target of the Bluetooth File Transfer Profile (FTP).
pub const FOLDER_BROWSING: [u8; 16] = [
    0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2, 0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09,
];

/// Bluetooth Phone Book Access Profile (PBAP), `796135F0-F0C5-11D8-0966-0800200C9A66`.
pub const PHONE_BOOK_ACCESS: [u8; 16] = [
    0x79, 0x61, 0x35, 0xF0, 0xF0, 0xC5, 0x11, 0xD8, 0x09, 0x66, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66,
];

/// Bluetooth Message Access Profile (MAP) Message Access Service,
/// `BB582B40-420C-11DB-B0DE-0800200C9A66`.
pub const MESSAGE_ACCESS: [u8; 16] = [
    0xBB, 0x58, 0x2B, 0x40, 0x42, 0x0C, 0x11, 0xDB, 0xB0, 0xDE, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66,
];

/// Bluetooth Message Access Profile (MAP) Message Notification Service,
/// `BB582B41-420C-11DB-B0DE-0800200C9A66`.
///
/// The MAP client (MCE) runs the OBEX *server* for this service, which the phone
/// (MSE) connects to in order to deliver event reports.
pub const MESSAGE_NOTIFICATION: [u8; 16] = [
    0xBB, 0x58, 0x2B, 0x41, 0x42, 0x0C, 0x11, 0xDB, 0xB0, 0xDE, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66,
];

/// Type of the Folder Listing object (OBEX section 9.1).
pub const FOLDER_LISTING_TYPE: &str = "x-obex/folder-listing";

/// Type of the Capability object (OBEX section 9.3).
pub const CAPABILITY_TYPE: &str = "x-obex/capability";

/// Type of the Object Profile object (OBEX section 9.4).
pub const OBJECT_PROFILE_TYPE: &str = "x-obex/object-profile";

/// Type of the default vCard object returned by an Inbox GET (OBEX section 8.4).
pub const VCARD_TYPE: &str = "text/x-vcard";
