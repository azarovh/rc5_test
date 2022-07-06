use crate::error::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Internal representation of a Secret key.
/// For now it is only useful for validating key properties.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretKey {
    pub(crate) key: Vec<u8>,
}

impl SecretKey {
    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyKey);
        }
        if bytes.len() > 256 {
            return Err(Error::KeyIsTooBig);
        }
        Ok(SecretKey { key: bytes })
    }
}
