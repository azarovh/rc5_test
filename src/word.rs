use num_traits::{identities::Zero, int::PrimInt, WrappingAdd, WrappingSub};
use std::convert::TryFrom;

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
