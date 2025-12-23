//! yTLS Extension (51) Key Share
//! https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc8446bis-14#section-4.2.8

use crate::TlsExtError;
use ytls_typed::Alpn;

/// Downstream Key Share Processor
pub trait ExtAlpnProcessor {
    fn alpn<'r>(&mut self, _: Alpn<'r>) -> bool;
}

/// TLS Extension 51 Key Share handling
pub struct TlsExtAlpn {}

impl TlsExtAlpn {
    #[inline]
    pub fn client_alpn_cb<P: ExtAlpnProcessor>(
        p: &mut P,
        alpn_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if alpn_raw.len() < 2 {
            return Err(TlsExtError::InvalidLength);
        }

        let alpns_expected_len = u16::from_be_bytes([alpn_raw[0], alpn_raw[1]]);

        let alpns_raw_len_remaining = alpn_raw.len() - 2;

        if alpns_raw_len_remaining == 0 {
            return Err(TlsExtError::NoData);
        }
        
        if alpns_expected_len as usize != alpns_raw_len_remaining {
            return Err(TlsExtError::InvalidLength);
        }
                
        let mut remaining = &alpn_raw[2..];        

        let expected_len: usize = remaining.len();
        
        
        let mut processed: usize = 0;

        loop {
            if remaining.len() < 2 {
                return Err(TlsExtError::InvalidLength);
            }
            let alpn_len = remaining[0] as usize;

            remaining = &remaining[1..];
            
            if alpn_len > remaining.len() {
                return Err(TlsExtError::EntryOverflow);
            }

            let (alpn, remaining_next) = remaining.split_at(alpn_len as usize);

            p.alpn(alpn.into());
            
            remaining = remaining_next;

            if remaining.len() == 0 {
                break;
            }

        }

        Ok(())
    }
}
