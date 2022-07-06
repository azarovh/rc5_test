#[derive(Debug, PartialEq)]
pub enum Error {
    EmptyKey,
    KeyIsTooBig,
    InvalidInput,
    BytesToWordsFail,
}
