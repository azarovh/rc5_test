//
// The RC5 Encryption algorithm implementation
//

mod error;
pub use crate::error::Error;

mod word;
pub use crate::word::Word;

mod secret_key;

mod rc5;
pub use crate::rc5::RC5;

#[cfg(test)]
mod test;
