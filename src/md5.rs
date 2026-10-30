//! A small RFC 1321 MD5 implementation.
//!
//! OBEX mandates MD5 for digest authentication (section 3.6.3) and reliable session
//! identifiers (section 3.4.7.6). It is implemented here to keep the crate free of
//! additional dependencies. MD5 is not collision resistant and must not be used for
//! anything beyond what the OBEX specification requires.

const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const CONSTANTS: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

use crate::prelude::*;

/// Computes the MD5 digest of the concatenation of `parts`.
pub(crate) fn digest(parts: &[&[u8]]) -> [u8; 16] {
    let length: usize = parts.iter().map(|part| part.len()).sum();
    let mut message: Vec<u8> = Vec::with_capacity(length + 72);

    for part in parts {
        message.extend_from_slice(part);
    }

    // Pad with a single 1 bit, zeros up to 56 bytes mod 64, then the bit length.
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((length as u64).wrapping_mul(8)).to_le_bytes());

    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

    for block in message.chunks_exact(64) {
        let mut words = [0u32; 16];
        for (word, bytes) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }

        let [mut a, mut b, mut c, mut d] = state;

        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };

            let rotated = a
                .wrapping_add(f)
                .wrapping_add(CONSTANTS[i])
                .wrapping_add(words[g])
                .rotate_left(SHIFTS[i]);

            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut output = [0u8; 16];
    for (bytes, word) in output.chunks_exact_mut(4).zip(state.iter()) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: [u8; 16]) -> String {
        bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    #[test]
    fn rfc_1321_test_suite() {
        let vectors: [(&str, &str); 7] = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];

        for (input, expected) in vectors {
            assert_eq!(expected, hex(digest(&[input.as_bytes()])), "{:?}", input);
        }
    }

    #[test]
    fn parts_are_concatenated() {
        assert_eq!(
            digest(&[b"message digest"]),
            digest(&[b"message", b" ", b"digest"])
        );
    }

    #[test]
    fn constants_match_sine_table() {
        for (i, constant) in CONSTANTS.iter().enumerate() {
            let expected = (((i + 1) as f64).sin().abs() * 4294967296.0) as u32;
            assert_eq!(expected, *constant);
        }
    }
}
