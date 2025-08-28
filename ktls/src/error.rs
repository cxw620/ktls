//! Error types for the `ktls` crate

use std::io;

use rustls::SupportedCipherSuite;

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
/// Unified error type for this crate
pub enum Error {
    #[error(transparent)]
    /// Invalid crypto material, e.g., wrong size key or IV.
    InvalidCryptoInfo(#[from] InvalidCryptoInfo),

    #[error(transparent)]
    /// General IO error.
    IO(#[from] io::Error),
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::IO(error) => error,
            _ => Self::other(error),
        }
    }
}

#[derive(Debug)]
#[derive(thiserror::Error)]
/// Crypto material is invalid, e.g., wrong size key or IV.
#[non_exhaustive]
pub enum InvalidCryptoInfo {
    #[error("Wrong size key")]
    /// The provided key has an incorrect size (unlikely).
    WrongSizeKey,

    #[error("Wrong size iv")]
    /// The provided IV has an incorrect size (unlikely).
    WrongSizeIv,

    #[error("the negotiated cipher suite [{0:?}] is not supported")]
    /// The negotiated cipher suite is not supported by this crate.
    UnsupportedCipherSuite(SupportedCipherSuite),
}