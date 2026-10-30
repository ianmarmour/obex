//! The protocol engines behind `crate::client`, `crate::server` and, with the `tokio`
//! and `embedded-io-async` features, `crate::tokio` and `crate::embedded`.
//!
//! The engines are written once as async code over the [`io::Source`] and
//! [`io::Sink`] traits, so the blocking and async APIs share every line of protocol
//! logic and only differ in how bytes move.

use crate::auth::{DigestChallenge, NonceGenerator};

pub(crate) mod body;
pub(crate) mod client;
pub(crate) mod io;
pub(crate) mod server;

/// A challenge with a fresh nonce from `generator`, or from the standard library.
pub(crate) fn fresh_challenge(generator: &mut Option<NonceGenerator>) -> DigestChallenge {
    match generator {
        Some(generate) => DigestChallenge::with_nonce(generate()),
        #[cfg(feature = "std")]
        None => DigestChallenge::new(),
        #[cfg(not(feature = "std"))]
        None => unreachable!("the no_std APIs enable authentication with a nonce generator"),
    }
}
