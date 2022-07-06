use crate::{error::Error, secret_key::SecretKey, word::Word};

use std::{
    convert::{Into, TryFrom, TryInto},
    fmt::Debug,
};

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
