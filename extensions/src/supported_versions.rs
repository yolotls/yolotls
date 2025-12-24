//! yTLS Extension (13) Signature Algorithms

use crate::TlsExtError;
use ytls_typed::Version;

/// Downstream Supported Versions Processor
pub trait ExtVersionProcessor {
    ///
    fn supported_version(&mut self, _: Version) -> bool;
}

/// TLS Extension 43 Supported Verison handling
pub struct TlsExtVersion {}

impl TlsExtVersion {
    /// Client Hello supported versions callback
    #[inline]
    pub fn client_supported_version_cb<P: ExtVersionProcessor>(
        p: &mut P,
        versions_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if versions_raw.len() < 1 {
            return Err(TlsExtError::InvalidLength);
        }

        let versions_len = versions_raw[0];

        if versions_len == 0 {
            return Err(TlsExtError::NoData);
        }

        if versions_raw.len() < 2 {
            return Err(TlsExtError::InvalidLength);
        }

        let remaining = &versions_raw[1..];
        let expected_len = remaining.len();

        if expected_len != versions_len as usize {
            return Err(TlsExtError::InvalidLength);
        }

        let mut versions_i = remaining.chunks(2);

        while let Some(version_raw) = versions_i.next() {
            let version = u16::from_be_bytes([version_raw[0], version_raw[1]]);
            p.supported_version(version.into());
        }
        Ok(())
    }
}
