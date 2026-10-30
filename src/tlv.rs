//! ## Tag-Length-Value Triplets
//!
//! Application Parameters, Authenticate Challenge, Authenticate Response and
//! Session-Parameters headers all carry a sequence of tag-length-value triplets. The
//! tag and length are a single byte each, so a value is at most 255 bytes long.
//!
//! [`ApplicationParameters`] is the building block profiles layered on OBEX use for
//! their request and response parameters (MAP's `MaxListCount`, PBAP's `Filter`, and
//! so on). Tags are only meaningful to the profile, so this type deliberately
//! exposes raw tags with typed accessors for the integer encodings profiles use, which
//! are always big-endian (network byte order).
//!
use nom::{
    combinator::all_consuming,
    multi::{count, many0},
    number::complete::be_u8,
    IResult,
};

use crate::error::{Error, Result};

/// The `TagLengthValue` type. See [the module level documentation](index.html) for more.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TagLengthValue {
    /// The tag, meaningful only to the application or profile using it.
    pub tag: u8,
    /// The value, at most 255 bytes.
    pub value: Vec<u8>,
}

impl TagLengthValue {
    /// Creates a new `TagLengthValue` triplet.
    pub fn new(tag: u8, value: impl Into<Vec<u8>>) -> TagLengthValue {
        TagLengthValue {
            tag,
            value: value.into(),
        }
    }

    /// The number of bytes this triplet occupies on the wire.
    pub fn encoded_len(&self) -> usize {
        2 + self.value.len()
    }

    /// Appends the wire representation of this triplet to `buf`.
    ///
    /// # Examples
    /// ```
    /// # use obex::tlv::TagLengthValue;
    /// let mut bytes: Vec<u8> = Vec::new();
    /// TagLengthValue::new(0x01, [0x00, 0x0A]).encode(&mut bytes).unwrap();
    ///
    /// assert_eq!(vec![0x01, 0x02, 0x00, 0x0A], bytes);
    /// ```
    pub fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        let length: u8 = self
            .value
            .len()
            .try_into()
            .map_err(|_| Error::ValueTooLarge {
                tag: self.tag,
                length: self.value.len(),
            })?;

        buf.push(self.tag);
        buf.push(length);
        buf.extend_from_slice(&self.value);

        Ok(())
    }

    /// Attempts to parse a `TagLengthValue` from a `&[u8]`
    ///
    /// # Examples
    /// ```
    /// # use obex::tlv::TagLengthValue;
    /// let data: [u8; 5] = [0x01, 0x02, 0x00, 0x0A, 0xFF];
    /// let (rest, tlv) = TagLengthValue::parse(&data).unwrap();
    ///
    /// assert_eq!(0x01, tlv.tag);
    /// assert_eq!(vec![0x00, 0x0A], tlv.value);
    /// assert_eq!([0xFF], rest);
    /// ```
    pub fn parse(i: &[u8]) -> IResult<&[u8], TagLengthValue> {
        let (i, tag) = be_u8(i)?;
        let (i, length) = be_u8(i)?;
        let (i, value) = count(be_u8, length.into())(i)?;

        Ok((i, TagLengthValue { tag, value }))
    }

    /// Parses every triplet in `i`, failing if trailing bytes do not form a triplet.
    pub fn parse_all(i: &[u8]) -> IResult<&[u8], Vec<TagLengthValue>> {
        all_consuming(many0(TagLengthValue::parse))(i)
    }

    /// Interprets the value as a big-endian unsigned integer of up to 8 bytes.
    ///
    /// # Examples
    /// ```
    /// # use obex::tlv::TagLengthValue;
    /// assert_eq!(Some(0x0102), TagLengthValue::new(0, [0x01, 0x02]).as_uint());
    /// assert_eq!(None, TagLengthValue::new(0, [0u8; 9]).as_uint());
    /// ```
    pub fn as_uint(&self) -> Option<u64> {
        if self.value.len() > 8 {
            return None;
        }

        Some(
            self.value
                .iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
        )
    }
}

impl From<TagLengthValue> for Vec<u8> {
    /// Converts a `TagLengthValue` to a `Vec<u8>`, truncating values longer than 255 bytes.
    fn from(value: TagLengthValue) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(value.encoded_len());

        bytes.push(value.tag);
        bytes.push(value.value.len().min(255) as u8);
        bytes.extend(value.value.into_iter().take(255));

        bytes
    }
}

/// Encodes a sequence of triplets back to back.
pub(crate) fn encode_all(tlvs: &[TagLengthValue], buf: &mut Vec<u8>) -> Result<()> {
    for tlv in tlvs {
        tlv.encode(buf)?;
    }

    Ok(())
}

/// The `ApplicationParameters` type. See [the module level documentation](index.html) for more.
///
/// # Examples
///
/// Building the parameters for a MAP `GetMessagesListing` request:
/// ```
/// # use obex::tlv::ApplicationParameters;
/// const MAX_LIST_COUNT: u8 = 0x01;
/// const SUBJECT_LENGTH: u8 = 0x13;
///
/// let parameters = ApplicationParameters::new()
///     .with_u16(MAX_LIST_COUNT, 10)
///     .with_u8(SUBJECT_LENGTH, 64);
///
/// assert_eq!(Some(10), parameters.get_u16(MAX_LIST_COUNT));
/// assert_eq!(Some(64), parameters.get_u8(SUBJECT_LENGTH));
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ApplicationParameters(pub Vec<TagLengthValue>);

impl ApplicationParameters {
    /// Creates an empty parameter list.
    pub fn new() -> ApplicationParameters {
        ApplicationParameters(Vec::new())
    }

    /// Appends a triplet.
    pub fn push(&mut self, tlv: TagLengthValue) {
        self.0.push(tlv);
    }

    /// Appends a raw byte value.
    pub fn with_bytes(mut self, tag: u8, value: impl Into<Vec<u8>>) -> ApplicationParameters {
        self.push(TagLengthValue::new(tag, value));
        self
    }

    /// Appends a 1 byte value.
    pub fn with_u8(self, tag: u8, value: u8) -> ApplicationParameters {
        self.with_bytes(tag, [value])
    }

    /// Appends a 2 byte big-endian value.
    pub fn with_u16(self, tag: u8, value: u16) -> ApplicationParameters {
        self.with_bytes(tag, value.to_be_bytes())
    }

    /// Appends a 4 byte big-endian value.
    pub fn with_u32(self, tag: u8, value: u32) -> ApplicationParameters {
        self.with_bytes(tag, value.to_be_bytes())
    }

    /// Appends an 8 byte big-endian value.
    pub fn with_u64(self, tag: u8, value: u64) -> ApplicationParameters {
        self.with_bytes(tag, value.to_be_bytes())
    }

    /// Returns the first triplet with `tag`.
    pub fn get(&self, tag: u8) -> Option<&TagLengthValue> {
        self.0.iter().find(|tlv| tlv.tag == tag)
    }

    /// Returns the raw value of the first triplet with `tag`.
    pub fn get_bytes(&self, tag: u8) -> Option<&[u8]> {
        self.get(tag).map(|tlv| tlv.value.as_slice())
    }

    /// Returns the value of `tag` if it is exactly 1 byte long.
    pub fn get_u8(&self, tag: u8) -> Option<u8> {
        self.get_array::<1>(tag).map(u8::from_be_bytes)
    }

    /// Returns the value of `tag` if it is exactly 2 bytes long.
    pub fn get_u16(&self, tag: u8) -> Option<u16> {
        self.get_array::<2>(tag).map(u16::from_be_bytes)
    }

    /// Returns the value of `tag` if it is exactly 4 bytes long.
    pub fn get_u32(&self, tag: u8) -> Option<u32> {
        self.get_array::<4>(tag).map(u32::from_be_bytes)
    }

    /// Returns the value of `tag` if it is exactly 8 bytes long.
    pub fn get_u64(&self, tag: u8) -> Option<u64> {
        self.get_array::<8>(tag).map(u64::from_be_bytes)
    }

    fn get_array<const N: usize>(&self, tag: u8) -> Option<[u8; N]> {
        self.get_bytes(tag).and_then(|value| value.try_into().ok())
    }

    /// Iterates over every triplet in order.
    pub fn iter(&self) -> std::slice::Iter<'_, TagLengthValue> {
        self.0.iter()
    }

    /// The number of triplets.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if there are no triplets.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<TagLengthValue>> for ApplicationParameters {
    fn from(tlvs: Vec<TagLengthValue>) -> ApplicationParameters {
        ApplicationParameters(tlvs)
    }
}

impl FromIterator<TagLengthValue> for ApplicationParameters {
    fn from_iter<I: IntoIterator<Item = TagLengthValue>>(iter: I) -> ApplicationParameters {
        ApplicationParameters(iter.into_iter().collect())
    }
}

impl IntoIterator for ApplicationParameters {
    type Item = TagLengthValue;
    type IntoIter = std::vec::IntoIter<TagLengthValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_rejects_truncated_triplets() {
        assert!(TagLengthValue::parse_all(&[0x01, 0x02, 0x00]).is_err());
        assert_eq!(
            vec![TagLengthValue::new(1, []), TagLengthValue::new(2, [7])],
            TagLengthValue::parse_all(&[0x01, 0x00, 0x02, 0x01, 0x07])
                .unwrap()
                .1
        );
    }

    #[test]
    fn encode_rejects_oversized_values() {
        let mut bytes = Vec::new();
        assert!(TagLengthValue::new(9, vec![0u8; 256])
            .encode(&mut bytes)
            .is_err());
        assert!(bytes.is_empty());
    }

    #[test]
    fn typed_accessors_require_exact_lengths() {
        let parameters = ApplicationParameters::new().with_u32(1, 7).with_u64(2, 9);

        assert_eq!(Some(7), parameters.get_u32(1));
        assert_eq!(None, parameters.get_u16(1));
        assert_eq!(Some(9), parameters.get_u64(2));
        assert_eq!(None, parameters.get_u8(3));
    }
}
