/*
 *  The RC5 Encryption algorithm implementation
 *
 */
use std::convert::{Into, TryInto};
use std::num::Wrapping;

pub type Word = u32;

const BYTES_IN_WORD: usize = (Word::BITS / u8::BITS) as usize;
const MAGIC_P: Word = 0xB7E15163;
const MAGIC_Q: Word = 0x9E3779B9;

/*
 *  RC5 struct provides functionality to encode/decode data back and forth.
 *  Input plain text and output cipher both must be 2-word size.
 *  RC5 instance can be reused to encode/decode multiple times for the same key.
 *
 *  In order to properly setup the RC5 following parameters should be provided:
 *    - key: up to 256 bytes. Empty key is not valid, but the key with all 0's is acceptable
 *    - rounds_number: value 0 to 255. Nominal choice is 12.
 *
 *  Note: currently the algorithm supports only 32-bit words.
 *
 *  Nominal setup to use is RC5-32/12/16
 *
 */
pub struct RC5 {
    key_table: Vec<Word>,
    rounds_number: u8,
}

impl RC5 {
    /*
     *  Creates RC5 instance for a given key and rounds number.
     *
     */
    pub fn new(key: Vec<u8>, rounds_number: u8) -> Self {
        let secret_key = SecretKey::new(key);
        let expanded_key_table = key_expansion(&secret_key, rounds_number);
        RC5 {
            key_table: expanded_key_table,
            rounds_number: rounds_number,
        }
    }

    /*
     * This function should return a cipher text for a given plaintext.
     * Can be called multiple times.
     *
     */
    pub fn encode(&self, plaintext: [u8; BYTES_IN_WORD * 2]) -> [u8; BYTES_IN_WORD * 2] {
        let mut a = Word::from_le_bytes(plaintext[..BYTES_IN_WORD].try_into().unwrap())
            .wrapping_add(self.key_table[0]);

        let mut b = Word::from_le_bytes(plaintext[BYTES_IN_WORD..].try_into().unwrap())
            .wrapping_add(self.key_table[1]);

        for i in 1..=self.rounds_number.into() {
            a = (a ^ b).rotate_left(b).wrapping_add(self.key_table[2 * i]);
            b = (b ^ a)
                .rotate_left(a)
                .wrapping_add(self.key_table[2 * i + 1]);
        }

        let mut ciphertext = [0u8; BYTES_IN_WORD * 2];
        ciphertext[..BYTES_IN_WORD].copy_from_slice(&Word::to_le_bytes(a));
        ciphertext[BYTES_IN_WORD..].copy_from_slice(&Word::to_le_bytes(b));
        ciphertext
    }

    /*
     * This function should return a plaintext for a given ciphertext.
     * Can be called multiple times.
     *
     */
    pub fn decode(&self, ciphertext: [u8; BYTES_IN_WORD * 2]) -> [u8; BYTES_IN_WORD * 2] {
        let mut a = Word::from_le_bytes(ciphertext[..BYTES_IN_WORD].try_into().unwrap());
        let mut b = Word::from_le_bytes(ciphertext[BYTES_IN_WORD..].try_into().unwrap());

        for i in (1..=self.rounds_number.into()).rev() {
            b = b.wrapping_sub(self.key_table[2 * i + 1]).rotate_right(a) ^ a;
            a = a.wrapping_sub(self.key_table[2 * i]).rotate_right(b) ^ b;
        }

        let mut plaintext = [0u8; BYTES_IN_WORD * 2];
        plaintext[..BYTES_IN_WORD]
            .copy_from_slice(&Word::to_le_bytes(a.wrapping_sub(self.key_table[0])));
        plaintext[BYTES_IN_WORD..]
            .copy_from_slice(&Word::to_le_bytes(b.wrapping_sub(self.key_table[1])));
        plaintext
    }
}

// Internal representation of a Secret key.
// For now it is only useful for validating key properties.
struct SecretKey {
    key: Vec<u8>,
}

impl SecretKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        assert!(!bytes.is_empty(), "Key should not be empty");
        assert!(
            bytes.len() <= 256,
            "Key is limited in size to 256 per specification"
        );
        SecretKey { key: bytes }
    }
}

// Key expansion subroutine that for the given secret tree returns expanded key table necessary for further
// encryption/decryption.
fn key_expansion(key: &SecretKey, rounds_number: u8) -> Vec<Word> {
    let mut expanded_key_table: Vec<Word> = vec![0; 2 * (rounds_number as usize + 1)];

    // 1. Convert key bytes to words
    let key_len = key.key.len();
    let mut key_words: Vec<Word> = vec![0; key_len / BYTES_IN_WORD];
    for (i, w) in key_words.iter_mut().enumerate() {
        let byte_index = i * BYTES_IN_WORD;
        *w = Word::from_le_bytes(
            key.key[byte_index..byte_index + BYTES_IN_WORD]
                .try_into()
                .unwrap(),
        )
    }

    // 2. Initialize expanded key table
    expanded_key_table[0] = MAGIC_P;
    for i in 1..expanded_key_table.len() {
        expanded_key_table[i] = expanded_key_table[i - 1].wrapping_add(MAGIC_Q);
    }

    // 3. Mixing in the secret key
    let (mut a, mut b, mut i, mut j): (Wrapping<Word>, Wrapping<Word>, usize, usize) =
        (Wrapping::default(), Wrapping::default(), 0, 0);
    for _ in 0..3 * expanded_key_table.len() {
        a = Wrapping(((a + b) + Wrapping(expanded_key_table[i])).0.rotate_left(3));
        expanded_key_table[i] = a.0;

        b = Wrapping(((a + b) + Wrapping(key_words[j])).0.rotate_left((a + b).0));
        key_words[j] = b.0;

        i = (i + 1) % expanded_key_table.len();
        j = (j + 1) % key_words.len();
    }

    expanded_key_table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = [0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];

        let rc5 = RC5::new(key, 12);
        let res = rc5.encode(pt);
        assert!(ct == res);
    }

    #[test]
    fn encode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = [0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = [0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];

        let rc5 = RC5::new(key, 12);
        let res = rc5.encode(pt);
        assert!(ct == res);
    }

    #[test]
    fn decode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        let rc5 = RC5::new(key, 12);
        let res = rc5.decode(ct);
        assert!(pt == res);
    }

    #[test]
    fn decode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = [0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = [0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];

        let rc5 = RC5::new(key, 12);
        let res = rc5.decode(ct);
        assert!(pt == res);
    }

    #[test]
    fn roundtrip() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let rc5 = RC5::new(key, 12);
        let ct = rc5.encode(pt);
        let res = rc5.decode(ct);
        assert!(pt == res);
    }

    #[test]
    fn encode_twice() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let rc5 = RC5::new(key, 12);
        let ct1 = rc5.encode(pt);
        let ct2 = rc5.encode(pt);
        assert!(ct1 == ct2);
    }

    #[test]
    fn decode_twice() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = [0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = [0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];

        let rc5 = RC5::new(key, 12);
        let res1 = rc5.decode(ct);
        let res2 = rc5.decode(ct);
        assert!(pt == res1);
        assert!(pt == res2);
    }

    #[test]
    fn encode_with_zero_key() {
        let key = vec![0; 16];

        let pt = [0; 8];
        let ct = [0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];

        let rc5 = RC5::new(key, 12);
        let res = rc5.encode(pt);
        assert!(ct == res);
    }

    #[test]
    #[should_panic]
    fn encode_with_empty_key() {
        let key = Vec::new();
        let _rc5 = RC5::new(key, 12);
    }

    #[test]
    fn encode_zero_rounds() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = [0x22, 0x0A, 0xB5, 0x63, 0x40, 0xDA, 0x89, 0x14];

        let rc5 = RC5::new(key, 0);
        let res = rc5.encode(pt);
        assert!(ct == res);
    }

    #[test]
    #[should_panic]
    fn encode_with_too_big_key() {
        let key = vec![0; 257];
        RC5::new(key, 12);
    }
}
