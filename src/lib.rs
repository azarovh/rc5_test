//
// The RC5 Encryption algorithm implementation
//
use num_traits::{identities::Zero, int::PrimInt, WrappingAdd, WrappingSub};
use std::{
    convert::{Into, TryFrom, TryInto},
    fmt::Debug,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, PartialEq)]
pub enum Error {
    EmptyKey,
    KeyIsTooBig,
    InvalidInput,
    BytesToWordsFail,
}

///
///  RC5 struct provides functionality to encode/decode data back and forth.
///  RC5 instance can be reused to encode/decode multiple times for the same key.
///  Input plain text must be a multiple of BLOCK_SIZE, which is 2 * (bytes in a word).
///
///  RC5 struct can be used with several word sizes: u16/u32/u64
///
///  In order to properly setup the RC5 following parameters should be provided:
///  * 'key' - up to 256 bytes. Empty key is not valid, but the key with all 0's is acceptable
///  * 'rounds_number' - value 0 to 255. Nominal choice is 12.
///
///  Nominal setup to use is RC5-32/12/16
///
#[derive(Debug)]
pub struct RC5<W> {
    key_table: Vec<W>,
    rounds_number: u8,
}

impl<W> RC5<W>
where
    W: Word,
    <<W as Word>::Bytes as TryFrom<Vec<u8>>>::Error: Debug,
{
    ///
    ///  Creates RC5 instance for a given key and rounds number.
    ///
    pub fn new(key: Vec<u8>, rounds_number: u8) -> Result<Self, Error> {
        let secret_key = SecretKey::new(key)?;
        let expanded_key_table = key_expansion(secret_key, rounds_number);
        Ok(Self {
            key_table: expanded_key_table,
            rounds_number: rounds_number,
        })
    }

    ///
    /// This function returns a cipher text for a given plaintext.
    /// Can be called multiple times.
    ///
    pub fn encode(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        for_each_block::<_, W>(plaintext, |b| self.encode_block(b))
    }

    ///
    /// This function returns a plaintext for a given ciphertext.
    /// Can be called multiple times.
    ///
    pub fn decode(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        for_each_block::<_, W>(ciphertext, |b| self.decode_block(b))
    }

    /// Encode a single block of data
    fn encode_block(&self, block: &[u8]) -> Result<(W, W), Error> {
        let (mut a, mut b): (W, W) = block_from_bytes(block)?;
        a = a.wrapping_add(&self.key_table[0]);
        b = b.wrapping_add(&self.key_table[1]);

        for i in 1..=self.rounds_number.into() {
            a = (a ^ b)
                .rotate_left((b % W::BITS.into()).to_u32().unwrap())
                .wrapping_add(&self.key_table[2 * i]);
            b = (b ^ a)
                .rotate_left((a % W::BITS.into()).to_u32().unwrap())
                .wrapping_add(&self.key_table[2 * i + 1]);
        }

        Ok((a, b))
    }

    /// Decode a single block of data
    fn decode_block(&self, block: &[u8]) -> Result<(W, W), Error> {
        let (mut a, mut b): (W, W) = block_from_bytes(block)?;

        for i in (1..=self.rounds_number.into()).rev() {
            b = b
                .wrapping_sub(&self.key_table[2 * i + 1])
                .rotate_right((a % W::BITS.into()).to_u32().unwrap())
                ^ a;
            a = a
                .wrapping_sub(&self.key_table[2 * i])
                .rotate_right((b % W::BITS.into()).to_u32().unwrap())
                ^ b;
        }

        Ok((
            a.wrapping_sub(&self.key_table[0]),
            b.wrapping_sub(&self.key_table[1]),
        ))
    }
}

/// Word describes the required set of operations for word types in order to work with RC5.
/// Currently this trait is implemented for 3 types: u16/u32/u64
pub trait Word: Zero + Copy + WrappingAdd + WrappingSub + PrimInt + From<u8> {
    const BITS: u8;
    const BYTES_IN_WORD: usize = (Self::BITS / u8::BITS as u8) as usize;

    /// The algorithm by design works with fixed-size blocks for input and output
    type Block;
    const BLOCK_SIZE: usize = 2 * Self::BYTES_IN_WORD;

    /// Magic constants per specification
    fn magic_constants() -> (Self, Self);

    type Bytes: TryFrom<Vec<u8>> + AsRef<[u8]>;
    fn to_le_bytes(w: Self) -> Self::Bytes;
    fn from_le_bytes(bytes: Self::Bytes) -> Self;
}

impl Word for u16 {
    const BITS: u8 = Self::BITS as u8;

    type Block = [u8; Self::BLOCK_SIZE];
    type Bytes = [u8; (Self::BITS / u8::BITS) as usize];

    fn magic_constants() -> (Self, Self) {
        (0xB7E1, 0x9E37)
    }

    fn to_le_bytes(v: Self) -> Self::Bytes {
        Self::to_le_bytes(v)
    }

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        Self::from_le_bytes(bytes)
    }
}

impl Word for u32 {
    const BITS: u8 = Self::BITS as u8;

    type Block = [u8; Self::BLOCK_SIZE];
    type Bytes = [u8; (Self::BITS / u8::BITS) as usize];

    fn magic_constants() -> (Self, Self) {
        (0xB7E15163, 0x9E3779B9)
    }

    fn to_le_bytes(v: Self) -> Self::Bytes {
        Self::to_le_bytes(v)
    }

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        Self::from_le_bytes(bytes)
    }
}

impl Word for u64 {
    const BITS: u8 = Self::BITS as u8;

    type Block = [u8; Self::BLOCK_SIZE];
    type Bytes = [u8; (Self::BITS / u8::BITS) as usize];

    fn magic_constants() -> (Self, Self) {
        (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)
    }

    fn to_le_bytes(v: Self) -> Self::Bytes {
        Self::to_le_bytes(v)
    }

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        Self::from_le_bytes(bytes)
    }
}

/// Internal representation of a Secret key.
/// For now it is only useful for validating key properties.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretKey {
    key: Vec<u8>,
}

impl SecretKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyKey);
        }
        if bytes.len() > 256 {
            return Err(Error::KeyIsTooBig);
        }
        Ok(SecretKey { key: bytes })
    }
}

/// Key expansion subroutine that for the given secret tree returns expanded key table necessary for further
/// encryption/decryption.
fn key_expansion<W>(secret_key: SecretKey, rounds_number: u8) -> Vec<W>
where
    W: Word,
    <<W as Word>::Bytes as TryFrom<Vec<u8>>>::Error: Debug,
{
    let mut expanded_key_table: Vec<W> = vec![W::zero(); 2 * (rounds_number as usize + 1)];

    // 1. Convert key bytes to words
    let key_len = secret_key.key.len();
    let mut key_words = vec![W::zero(); key_len / W::BYTES_IN_WORD];
    for (i, w) in key_words.iter_mut().enumerate() {
        let byte_index = i * W::BYTES_IN_WORD;
        *w = Word::from_le_bytes(
            secret_key.key[byte_index..byte_index + W::BYTES_IN_WORD]
                .to_owned()
                .try_into()
                .unwrap(),
        )
    }

    // 2. Initialize expanded key table
    let (p, q) = W::magic_constants();
    expanded_key_table[0] = p;
    for i in 1..expanded_key_table.len() {
        expanded_key_table[i] = expanded_key_table[i - 1].wrapping_add(&q);
    }

    // 3. Mixing in the secret key
    let (mut a, mut b, mut i, mut j): (W, W, usize, usize) = (W::zero(), W::zero(), 0, 0);
    for _ in 0..3 * expanded_key_table.len() {
        a = a
            .wrapping_add(&b)
            .wrapping_add(&expanded_key_table[i])
            .rotate_left(3);
        expanded_key_table[i] = a;

        let ab = a.wrapping_add(&b);
        b = ab
            .wrapping_add(&key_words[j])
            .rotate_left((ab % W::BITS.into()).to_u32().unwrap());
        key_words[j] = b;

        i = (i + 1) % expanded_key_table.len();
        j = (j + 1) % key_words.len();
    }

    expanded_key_table
}

/// Helper subroutine to iterate over byte sequence
/// and apply functor to each block (which effectively encodes/decodes it)
fn for_each_block<F, W>(input: &[u8], f: F) -> Result<Vec<u8>, Error>
where
    W: Word,
    F: Fn(&[u8]) -> Result<(W, W), Error>,
{
    // TODO: remove this constraint
    if input.len() % W::BLOCK_SIZE > 0 {
        return Err(Error::InvalidInput);
    }

    let mut output = Vec::with_capacity(input.len());
    input.chunks(W::BLOCK_SIZE).try_for_each(|block| {
        let (w1, w2) = f(block)?;
        output.extend(Word::to_le_bytes(w1).as_ref());
        output.extend(Word::to_le_bytes(w2).as_ref());
        Ok(())
    })?;

    Ok(output)
}

/// Utility function to convert sequence of bytes to a block (i.e. 2 Words)
fn block_from_bytes<W: Word>(bytes: &[u8]) -> Result<(W, W), Error> {
    if let Ok(left_bytes) = bytes[..W::BYTES_IN_WORD].to_owned().try_into() {
        if let Ok(right_bytes) = bytes[W::BYTES_IN_WORD..].to_owned().try_into() {
            return Ok((
                Word::from_le_bytes(left_bytes),
                Word::from_le_bytes(right_bytes),
            ));
        }
    }
    return Err(Error::BytesToWordsFail);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_16() {
        let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let pt = vec![0x00, 0x01, 0x02, 0x03];
        let ct = vec![0x23, 0xA8, 0xD7, 0x2E];

        let rc5 = RC5::<u16>::new(key, 16).unwrap();
        let res = rc5.encode(&pt).unwrap();
        assert!(ct == res);
    }

    #[test]
    fn encode_32_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        let res = rc5.encode(&pt).unwrap();
        assert!(ct == res);
    }

    #[test]
    fn encode_32_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        let res = rc5.encode(&pt).unwrap();
        assert!(ct == res);
    }

    #[test]
    fn encode_64() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let pt = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let ct = vec![
            0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02, 0x35, 0xAB, 0xEA, 0x32, 0xAE, 0x71,
            0x78, 0xDA,
        ];

        let rc5 = RC5::<u64>::new(key, 24).unwrap();
        let res = rc5.encode(&pt).unwrap();
        assert!(ct == res);
    }

    #[test]
    fn encode_4words() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![
            0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84, 0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C,
            0x4D, 0x84,
        ];
        let ct = vec![
            0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64, 0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31,
            0xEA, 0x64,
        ];

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        let res = rc5.encode(&pt).unwrap();
        assert!(ct == res);
    }

    #[test]
    fn decode_16() {
        let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let pt = vec![0x00, 0x01, 0x02, 0x03];
        let ct = vec![0x23, 0xA8, 0xD7, 0x2E];

        let rc5 = RC5::<u16>::new(key, 16).unwrap();
        let res = rc5.decode(&ct).unwrap();
        assert!(pt == res);
    }

    #[test]
    fn decode_32_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        let res = rc5.decode(&ct).unwrap();
        assert!(pt == res);
    }

    #[test]
    fn decode_32_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        let res = rc5.decode(&ct).unwrap();
        assert!(pt == res);
    }

    #[test]
    fn decode_64() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let pt = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let ct = vec![
            0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02, 0x35, 0xAB, 0xEA, 0x32, 0xAE, 0x71,
            0x78, 0xDA,
        ];

        let rc5 = RC5::<u64>::new(key, 24).unwrap();
        let res = rc5.decode(&ct).unwrap();
        assert!(pt == res);
    }

    #[test]
    fn decode_4words() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![
            0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F, 0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B,
            0x66, 0x3F,
        ];
        let ct = vec![
            0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84, 0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C,
            0x4D, 0x84,
        ];

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        let res = rc5.decode(&ct).unwrap();
        assert!(pt == res);
    }

    #[test]
    fn roundtrip() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        let ct = rc5.encode(&pt).unwrap();
        let res = rc5.decode(&ct).unwrap();
        assert!(pt == res);
    }

    #[test]
    fn encode_twice() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        let ct1 = rc5.encode(&pt).unwrap();
        let ct2 = rc5.encode(&pt).unwrap();
        assert!(ct1 == ct2);
    }

    #[test]
    fn decode_twice() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        let res1 = rc5.decode(&ct).unwrap();
        let res2 = rc5.decode(&ct).unwrap();
        assert!(pt == res1);
        assert!(pt == res2);
    }

    #[test]
    fn encode_with_zero_key() {
        let key = vec![0; 16];

        let pt = vec![0; 8];
        let ct = vec![0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        let res = rc5.encode(&pt).unwrap();
        assert!(ct == res);
    }

    #[test]
    fn encode_with_empty_key() {
        let key = Vec::new();
        assert_eq!(RC5::<u32>::new(key, 12).unwrap_err(), Error::EmptyKey);
    }

    #[test]
    fn encode_zero_rounds() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x22, 0x0A, 0xB5, 0x63, 0x40, 0xDA, 0x89, 0x14];

        let rc5 = RC5::<u32>::new(key, 0).unwrap();
        let res = rc5.encode(&pt).unwrap();
        assert!(ct == res);
    }

    #[test]
    fn encode_with_too_big_key() {
        let key = vec![0; 257];
        assert_eq!(RC5::<u32>::new(key, 12).unwrap_err(), Error::KeyIsTooBig);
    }

    #[test]
    fn encode_uneven_data() {
        let key = vec![0; 16];
        let pt = vec![0; 7]; // 7 bytes

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        assert_eq!(rc5.encode(&pt).unwrap_err(), Error::InvalidInput);
    }

    #[test]
    fn decode_uneven_data() {
        let key = vec![0; 16];
        let ct = vec![0; 7]; // 7 bytes

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        assert_eq!(rc5.decode(&ct).unwrap_err(), Error::InvalidInput);
    }

    #[test]
    fn encode_3words() {
        let key = vec![0; 16];
        let pt = vec![0; 12]; // 3 words

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        assert_eq!(rc5.encode(&pt).unwrap_err(), Error::InvalidInput);
    }

    #[test]
    fn decode_3words() {
        let key = vec![0; 16];
        let ct = vec![0; 12]; // 3 words

        let rc5 = RC5::<u32>::new(key, 12).unwrap();
        assert_eq!(rc5.decode(&ct).unwrap_err(), Error::InvalidInput);
    }
}
