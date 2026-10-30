//! ## Authentication
//!
//! OBEX digest authentication (OBEX section 3.6) proves that both sides share a secret
//! without sending it. The challenger sends an Authenticate Challenge header with a
//! random nonce, and the responder answers with an Authenticate Response header
//! carrying `MD5(nonce ":" password)`.
//!
//! Clients usually challenge servers during CONNECT, while servers may challenge
//! clients on CONNECT or any individual operation by answering `Unauthorized`. The
//! [`Client`](crate::client::Client) and [`Server`](crate::server::Server) run these
//! exchanges automatically when given credentials; this module holds the building
//! blocks for implementations that drive the protocol themselves.
//!
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::header::Header;
use crate::md5;
use crate::tlv::TagLengthValue;

const CHALLENGE_NONCE_TAG: u8 = 0x00;
const CHALLENGE_OPTIONS_TAG: u8 = 0x01;
const CHALLENGE_REALM_TAG: u8 = 0x02;

const RESPONSE_DIGEST_TAG: u8 = 0x00;
const RESPONSE_USER_ID_TAG: u8 = 0x01;
const RESPONSE_NONCE_TAG: u8 = 0x02;

const OPTION_USER_ID_REQUIRED: u8 = 0x01;
const OPTION_READ_ONLY: u8 = 0x02;

/// The longest User Id the specification allows in a digest response.
pub const MAXIMUM_USER_ID_LENGTH: usize = 20;

/// The realm of a digest challenge: a displayable string telling the user which
/// password to use. `charset` uses the IrLMP character set codes, where 0 is ASCII,
/// 1 to 9 are ISO-8859-1 to ISO-8859-9 and 0xFF is UTF-16.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Realm {
    /// The IrLMP character set code of `value`.
    pub charset: u8,
    /// The realm text in that character set.
    pub value: Vec<u8>,
}

impl Realm {
    /// Creates an ASCII realm.
    pub fn ascii(value: &str) -> Realm {
        Realm {
            charset: 0,
            value: value.as_bytes().to_vec(),
        }
    }
}

/// The digest-challenge carried by an Authenticate Challenge header.
///
/// # Examples
/// ```
/// # use obex::auth::DigestChallenge;
/// # use obex::header::Header;
/// let challenge = DigestChallenge::with_nonce([7; 16]);
/// let header: Header = challenge.clone().into();
///
/// assert_eq!(24, header.encoded_len()); // Matches OBEX 1.5 section 3.6.4
///
/// if let Header::AuthenticateChallenge(tlvs) = header {
///     assert_eq!(challenge, DigestChallenge::from_tlvs(&tlvs).unwrap());
/// }
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DigestChallenge {
    /// The random value the responder hashes with the password.
    pub nonce: [u8; 16],
    /// The responder must include a User Id in its digest-response.
    pub user_id_required: bool,
    /// The access offered by the challenger is read only.
    pub read_only: bool,
    /// Tells the user which User Id and password to use.
    pub realm: Option<Realm>,
}

impl DigestChallenge {
    /// Creates a challenge with a fresh random nonce.
    pub fn new() -> DigestChallenge {
        DigestChallenge::with_nonce(generate_nonce())
    }

    /// Creates a challenge with the given nonce.
    pub fn with_nonce(nonce: [u8; 16]) -> DigestChallenge {
        DigestChallenge {
            nonce,
            user_id_required: false,
            read_only: false,
            realm: None,
        }
    }

    /// Decodes a challenge, ignoring unknown tags.
    pub fn from_tlvs(tlvs: &[TagLengthValue]) -> Result<DigestChallenge> {
        let mut nonce: Option<[u8; 16]> = None;
        let mut options: u8 = 0;
        let mut realm: Option<Realm> = None;

        for tlv in tlvs {
            match tlv.tag {
                CHALLENGE_NONCE_TAG => {
                    nonce = Some(
                        tlv.value
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error::Protocol("challenge nonce must be 16 bytes"))?,
                    )
                }
                CHALLENGE_OPTIONS_TAG => options = tlv.value.first().copied().unwrap_or(0),
                CHALLENGE_REALM_TAG => {
                    if let Some((charset, value)) = tlv.value.split_first() {
                        realm = Some(Realm {
                            charset: *charset,
                            value: value.to_vec(),
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(DigestChallenge {
            nonce: nonce.ok_or(Error::Protocol("challenge is missing a nonce"))?,
            user_id_required: options & OPTION_USER_ID_REQUIRED != 0,
            read_only: options & OPTION_READ_ONLY != 0,
            realm,
        })
    }

    /// Encodes the challenge as tag-length-value triplets.
    pub fn to_tlvs(&self) -> Vec<TagLengthValue> {
        let mut options = 0;
        if self.user_id_required {
            options |= OPTION_USER_ID_REQUIRED;
        }
        if self.read_only {
            options |= OPTION_READ_ONLY;
        }

        let mut tlvs = vec![
            TagLengthValue::new(CHALLENGE_NONCE_TAG, self.nonce),
            TagLengthValue::new(CHALLENGE_OPTIONS_TAG, [options]),
        ];

        if let Some(realm) = &self.realm {
            let mut value = Vec::with_capacity(realm.value.len() + 1);
            value.push(realm.charset);
            value.extend_from_slice(&realm.value);
            tlvs.push(TagLengthValue::new(CHALLENGE_REALM_TAG, value));
        }

        tlvs
    }

    /// Answers this challenge with `credentials`.
    ///
    /// # Examples
    /// ```
    /// # use obex::auth::{Credentials, DigestChallenge};
    /// let challenge = DigestChallenge::new();
    /// let response = challenge.respond(&Credentials::new("1234"));
    ///
    /// assert!(response.verify(&challenge, b"1234"));
    /// assert!(!response.verify(&challenge, b"0000"));
    /// ```
    pub fn respond(&self, credentials: &Credentials) -> DigestResponse {
        DigestResponse {
            request_digest: request_digest(&self.nonce, &credentials.password),
            user_id: credentials.user_id.clone(),
            nonce: Some(self.nonce),
        }
    }

    /// Finds and decodes every Authenticate Challenge header in `headers`.
    pub fn find_all<'a>(
        headers: impl IntoIterator<Item = &'a Header>,
    ) -> Result<Vec<DigestChallenge>> {
        headers
            .into_iter()
            .filter_map(|header| match header {
                Header::AuthenticateChallenge(tlvs) => Some(DigestChallenge::from_tlvs(tlvs)),
                _ => None,
            })
            .collect()
    }
}

impl Default for DigestChallenge {
    fn default() -> DigestChallenge {
        DigestChallenge::new()
    }
}

impl From<DigestChallenge> for Header {
    fn from(challenge: DigestChallenge) -> Header {
        Header::AuthenticateChallenge(challenge.to_tlvs())
    }
}

/// The digest-response carried by an Authenticate Response header.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DigestResponse {
    /// `MD5(nonce ":" password)`.
    pub request_digest: [u8; 16],
    /// The User Id, required when the challenge asked for one.
    pub user_id: Option<Vec<u8>>,
    /// The nonce of the challenge being answered, when several were sent.
    pub nonce: Option<[u8; 16]>,
}

impl DigestResponse {
    /// Decodes a response, ignoring unknown tags.
    pub fn from_tlvs(tlvs: &[TagLengthValue]) -> Result<DigestResponse> {
        let mut request_digest: Option<[u8; 16]> = None;
        let mut user_id: Option<Vec<u8>> = None;
        let mut nonce: Option<[u8; 16]> = None;

        for tlv in tlvs {
            match tlv.tag {
                RESPONSE_DIGEST_TAG => {
                    request_digest = Some(
                        tlv.value
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error::Protocol("request digest must be 16 bytes"))?,
                    )
                }
                RESPONSE_USER_ID_TAG => user_id = Some(tlv.value.clone()),
                RESPONSE_NONCE_TAG => nonce = tlv.value.as_slice().try_into().ok(),
                _ => {}
            }
        }

        Ok(DigestResponse {
            request_digest: request_digest
                .ok_or(Error::Protocol("response is missing a request digest"))?,
            user_id,
            nonce,
        })
    }

    /// Encodes the response as tag-length-value triplets.
    pub fn to_tlvs(&self) -> Vec<TagLengthValue> {
        let mut tlvs = vec![TagLengthValue::new(
            RESPONSE_DIGEST_TAG,
            self.request_digest,
        )];

        if let Some(user_id) = &self.user_id {
            tlvs.push(TagLengthValue::new(RESPONSE_USER_ID_TAG, user_id.clone()));
        }

        if let Some(nonce) = self.nonce {
            tlvs.push(TagLengthValue::new(RESPONSE_NONCE_TAG, nonce));
        }

        tlvs
    }

    /// Checks the request digest against `challenge` and the expected `password`.
    pub fn verify(&self, challenge: &DigestChallenge, password: &[u8]) -> bool {
        if self.nonce.is_some_and(|nonce| nonce != challenge.nonce) {
            return false;
        }

        let expected = request_digest(&challenge.nonce, password);

        // Compare without short-circuiting on the first differing byte.
        expected
            .iter()
            .zip(self.request_digest.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    /// Finds and decodes the first Authenticate Response header in `headers`.
    pub fn find<'a>(
        headers: impl IntoIterator<Item = &'a Header>,
    ) -> Option<Result<DigestResponse>> {
        headers.into_iter().find_map(|header| match header {
            Header::AuthenticateResponse(tlvs) => Some(DigestResponse::from_tlvs(tlvs)),
            _ => None,
        })
    }
}

impl From<DigestResponse> for Header {
    fn from(response: DigestResponse) -> Header {
        Header::AuthenticateResponse(response.to_tlvs())
    }
}

/// A shared secret, optionally tied to a User Id.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Credentials {
    /// Sent when the challenge requires it; at most 20 bytes of UTF-8.
    pub user_id: Option<Vec<u8>>,
    /// The UTF-8 encoded password, without a null terminator.
    pub password: Vec<u8>,
}

impl Credentials {
    /// Creates credentials without a User Id.
    pub fn new(password: impl Into<Vec<u8>>) -> Credentials {
        Credentials {
            user_id: None,
            password: password.into(),
        }
    }

    /// Creates credentials with a User Id.
    pub fn with_user_id(user_id: impl Into<Vec<u8>>, password: impl Into<Vec<u8>>) -> Credentials {
        Credentials {
            user_id: Some(user_id.into()),
            password: password.into(),
        }
    }
}

/// Computes the request-digest `MD5(nonce ":" password)`.
///
/// # Examples
/// ```
/// # use obex::auth::request_digest;
/// assert_eq!(request_digest(b"nonce", b"secret"), request_digest(b"nonce", b"secret"));
/// assert_ne!(request_digest(b"nonce", b"secret"), request_digest(b"nonce", b"other"));
/// ```
pub fn request_digest(nonce: &[u8], password: &[u8]) -> [u8; 16] {
    md5::digest(&[nonce, b":", password])
}

/// Generates a 16 byte nonce that is unique for every call.
///
/// The nonce hashes the current time and a process wide counter, keyed by the
/// randomly seeded hasher from the standard library, so it is unpredictable to the
/// remote device without additional dependencies.
pub fn generate_nonce() -> [u8; 16] {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(counter);
    hasher.write_u128(time);
    let secret = hasher.finish();

    md5::digest(&[
        &time.to_be_bytes(),
        b":",
        &counter.to_be_bytes(),
        &secret.to_be_bytes(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_unique() {
        assert_ne!(generate_nonce(), generate_nonce());
    }

    #[test]
    fn challenge_with_realm_round_trips() {
        let challenge = DigestChallenge {
            user_id_required: true,
            read_only: true,
            realm: Some(Realm::ascii("Phone")),
            ..DigestChallenge::with_nonce([1; 16])
        };

        let tlvs = challenge.to_tlvs();
        assert_eq!(vec![0x03], tlvs[1].value);
        assert_eq!(challenge, DigestChallenge::from_tlvs(&tlvs).unwrap());
    }

    #[test]
    fn response_round_trips() {
        let response =
            DigestChallenge::with_nonce([2; 16]).respond(&Credentials::with_user_id("me", "pw"));

        assert_eq!(
            response,
            DigestResponse::from_tlvs(&response.to_tlvs()).unwrap()
        );
    }

    #[test]
    fn response_for_another_nonce_is_rejected() {
        let first = DigestChallenge::with_nonce([1; 16]);
        let second = DigestChallenge::with_nonce([2; 16]);
        let response = first.respond(&Credentials::new("pw"));

        assert!(!response.verify(&second, b"pw"));
    }

    #[test]
    fn challenge_without_nonce_is_rejected() {
        assert!(DigestChallenge::from_tlvs(&[TagLengthValue::new(1, [0])]).is_err());
    }
}
