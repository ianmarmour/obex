//! A native implementation of the IrDA Object Exchange protocol (OBEX 1.5)
//!
//! OBEX is the binary, HTTP-like session protocol underneath the Bluetooth Generic
//! Object Exchange Profile (GOEP) and therefore underneath the Message Access (MAP),
//! Phone Book Access (PBAP), File Transfer (FTP), Object Push (OPP), Basic Imaging
//! (BIP) and Synchronization profiles. This crate is the building block those
//! profiles sit on: it implements OBEX itself and stays out of profile specifics, so
//! a profile is a thin layer choosing Targets, Types, Names and Application
//! Parameters.
//!
//! The crate is organized in two layers.
//!
//! ### The codec
//!
//! Transport independent types that convert between OBEX packets and bytes. They
//! never perform I/O, so they can be driven by blocking, async or embedded code.
//!
//! * [`header`] - every header from the specification, plus user defined headers.
//! * [`packet`] - requests and responses, including CONNECT and SETPATH fields.
//! * [`opcode`] and [`response`] - opcodes and response codes.
//! * [`tlv`] - tag-length-value triplets and typed [`ApplicationParameters`](tlv::ApplicationParameters).
//! * [`auth`] - digest challenges and responses (MD5 based, as the specification requires).
//! * [`srm`] - Single Response Mode header values.
//! * [`session`] - reliable session commands and parameters.
//! * [`action`] - ACTION operation identifiers and permissions.
//! * [`target`] - well known Target UUIDs and object types.
//!
//! ### The protocol engines
//!
//! * [`client::Client`] - drives CONNECT, DISCONNECT, PUT, GET, SETPATH, ACTION,
//!   SESSION and ABORT over any `Read + Write` transport.
//! * [`server::Server`] - answers requests and hands complete operations to a
//!   [`server::Handler`].
//! * [`transport::PacketStream`] - frames packets on stream (RFCOMM, TCP) and
//!   sequenced packet (L2CAP) sockets.
//!
//! Both engines handle packet size negotiation, splitting and reassembling multi
//! packet operations, directed connections with Connection Ids, Single Response
//! Mode, authentication and ABORT.
//!
//! ### Async
//!
//! With the `tokio` feature, `obex_protocol::tokio` provides async versions of the client,
//! server, handler trait and packet stream for transports implementing tokio's
//! `AsyncRead` and `AsyncWrite`. The blocking and async APIs run the same protocol
//! engine, so they behave identically and interoperate freely.
//!
//! ```toml
//! [dependencies]
//! obex-protocol = { version = "0.1", features = ["tokio"] }
//! ```
//!
//! ## Transports
//!
//! OBEX needs a reliable, ordered byte stream. On Bluetooth that is an RFCOMM channel
//! (GOEP 1.x) or an L2CAP channel in Enhanced Retransmission Mode (GOEP 2.x), found
//! through SDP. Opening those sockets is the job of a Bluetooth stack (BlueZ, for
//! example through the `bluer` crate, or the platform APIs); anything that implements
//! [`std::io::Read`] and [`std::io::Write`], or tokio's async equivalents, can be
//! handed to this crate. OBEX over TCP uses port 650.
//!
//! ## Example
//!
//! Pushing a vCard to a phone's inbox (OPP):
//! ```no_run
//! # fn example(socket: std::net::TcpStream) -> obex_protocol::Result<()> {
//! use obex_protocol::client::Client;
//! use obex_protocol::header::Header;
//!
//! let mut client = Client::new(socket);
//! client.connect([])?;
//!
//! let card = b"BEGIN:VCARD\r\nVERSION:2.1\r\nN:Doe;John\r\nEND:VCARD\r\n";
//! client.put(
//!     [
//!         Header::Name("john.vcf".to_string()),
//!         Header::Type("text/x-vcard".to_string()),
//!         Header::Length(card.len() as u32),
//!     ],
//!     card,
//! )?;
//!
//! client.disconnect()?;
//! # Ok(())
//! # }
//! ```
//!
#![warn(missing_docs)]

pub mod action;
pub mod auth;
pub mod client;
pub mod error;
pub mod header;
pub mod opcode;
pub mod packet;
pub mod response;
pub mod server;
pub mod session;
pub mod srm;
pub mod target;
pub mod tlv;
#[cfg(feature = "tokio")]
pub mod tokio;
pub mod transport;

mod engine;
mod md5;

pub use crate::error::{Error, Result};
