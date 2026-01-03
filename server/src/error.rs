//! errors

use ytls_record::BuilderError;
use ytls_record::RecordError;

/// yTLS Server Context Errors
#[derive(Debug, PartialEq)]
pub enum TlsServerCtxError {
    /// Record Error
    Record(RecordError),
    /// Builder Error
    Builder(BuilderError),
    /// Encountered Bug
    Bug(&'static str),
    /// Unexpected Application Data record
    UnexpectedAppData,
    /// Attempted to send hanshake out without AEAD Iv
    MissingHandshakeIv,
    /// Attempted to send hanshake out without AEAD Key
    MissingHandshakeKey,
    /// Iv is exhausted for any further record generation
    ExhaustedIv,
    /// Cryptography provider related error. Usually a bug.
    Crypto,
    /// Private Key related error, typically wrong length.
    PrivateKey,
}
