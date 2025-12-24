//! yTLS Extension (51) Key Share
//! https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc8446bis-14#section-4.2.8

use crate::TlsExtError;
use ytls_typed::Group;

/// Downstream Key Share Processor
pub trait ExtKeyShareProcessor {
    fn key_share(&mut self, _: Group, _: &[u8]) -> bool;
}

/// TLS Extension 51 Key Share handling
pub struct TlsExtKeyShare {}

impl TlsExtKeyShare {
    #[inline]
    pub fn client_key_share_cb<P: ExtKeyShareProcessor>(
        p: &mut P,
        key_share_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if key_share_raw.len() < 2 {
            return Err(TlsExtError::InvalidLength);
        }

        let mut remaining = &key_share_raw[0..];
        let expected_len: usize = remaining.len();

        let mut processed: usize = 0;

        loop {
            if remaining.len() < 4 {
                return Err(TlsExtError::InvalidLength);
            }
            let ks_data_len = u16::from_be_bytes([remaining[0], remaining[1]]);
            let ks_id = u16::from_be_bytes([remaining[2], remaining[3]]);

            if ks_data_len < 2 {
                return Err(TlsExtError::InvalidLength);
            }

            let group: Group = ks_id.into();

            if ks_data_len as usize > remaining.len() {
                return Err(TlsExtError::EntryOverflow);
            }

            remaining = &remaining[4..];

            let idx_pt: usize = ks_data_len as usize - 2;

            let ks_data = &remaining[..idx_pt];
            processed += ks_data_len as usize + 4;

            p.key_share(group, ks_data);

            if processed >= expected_len {
                break;
            }

            remaining = &remaining[idx_pt..];
        }

        Ok(())
    }
}
