//! The protocol engines behind [`crate::client`], [`crate::server`] and, with the
//! `tokio` feature, `crate::tokio`.
//!
//! The engines are written once as async code over the [`io::Source`] and
//! [`io::Sink`] traits, so the blocking and async APIs share every line of protocol
//! logic and only differ in how bytes move.

pub(crate) mod body;
pub(crate) mod client;
pub(crate) mod io;
pub(crate) mod server;
