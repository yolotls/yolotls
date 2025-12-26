//! Handhsake Record

use ytls_traits::ClientHelloProcessor;

use crate::error::RecordError;

use zerocopy::byteorder::network_endian::U16 as N16;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}

#[derive(Debug, PartialEq)]
pub struct AlertMsg<'r> {
    alert: &'r Alert,
}

impl<'r> AlertMsg<'r> {
    /// Alert Level
    pub fn level(&self) -> AlertLevel {
        self.alert.level
    }
    /// Alert Description
    pub fn description(&self) -> AlertDescription {
        self.alert.description
    }
    /// Parse Client Record
    pub fn client_parse<P: ClientHelloProcessor>(
        prc: &mut P,
        bytes: &'r [u8],
    ) -> Result<(Self, &'r [u8]), RecordError> {
        let (msg, rest) =
            Alert::try_ref_from_prefix(bytes).map_err(|e| RecordError::from_zero_copy(e))?;

        Ok((Self { alert: msg }, rest))
    }
}
