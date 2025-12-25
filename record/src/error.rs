//! errors

#[derive(Debug, PartialEq)]
pub enum RecordError {
    /// Record not valid
    Validity,
    /// Record not aligned
    Alignment,
    /// Record size error
    Size,
    /// RFC 8446 s. 5. Record size > MUST NOT exceed 2^14 bytes
    OverflowLength,
    /// Client Hello within Record
    ClientHello(ClientHelloError),
}

#[derive(Debug, PartialEq)]
pub enum ClientHelloError {
    /// Session Id <= 32 bytes
    OverflowSesId,
    /// Cipher Suites <= 65534 bytes
    OverflowCipherSuites,
    /// One of the extensions is invalid
    Extensions(ExtensionsError),
    /// One of the Cipher Suites is invalid
    CipherSuites(CipherSuitesError),
}

#[derive(Debug, PartialEq)]
pub enum ExtensionsError {
    /// Extension length field overflows
    OverflowExtensionLen,
}

#[derive(Debug, PartialEq)]
pub enum CipherSuitesError {
    /// Provided Cipher Suites were invalid length. Must be % 4 == 0
    InvalidLength,
}

use zerocopy::{error::TryCastError, TryFromBytes};

impl RecordError {
    pub(crate) fn from_zero_copy<Src, Dst: ?Sized + TryFromBytes>(
        e: TryCastError<Src, Dst>,
    ) -> Self {
        match e {
            TryCastError::Alignment(..) => Self::Alignment,
            TryCastError::Validity(..) => Self::Validity,
            TryCastError::Size(..) => Self::Size,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum BuilderError {
    /// Static buffer is not long enough to hold the buffered record.
    Overflow,
    /// Session Id length is one byte but size was > 255
    SessionIdOverflow,
}
