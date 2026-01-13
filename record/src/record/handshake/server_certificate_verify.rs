//! Server Certificate Verify Handshake record

use crate::RecordError;
use ytls_traits::ServerCertificateVerifyProcessor;
use ytls_traits::ServerWrappedRecordProcessor;

#[derive(Debug, PartialEq)]
pub struct ServerCertificateVerify;

impl ServerCertificateVerify {
    /// Parse wrapped Server Certificate
    #[inline]
    pub fn parse_wrapped<P: ServerWrappedRecordProcessor>(
        prc: &mut P,
        mut raw: &[u8],
    ) -> Result<(), RecordError> {
        let sh = prc.server_certificate_verify();

        let algo_r = raw.split_off(..2).ok_or(RecordError::Size)?;
        let algo: [u8; 2] = [algo_r[0], algo_r[1]];

        let sl_bytes = raw.split_off(..2).ok_or(RecordError::Size)?;
        let sig_len_u16 = u16::from_be_bytes([sl_bytes[0], sl_bytes[1]]);

        if sig_len_u16 as usize != raw.len() {
            return Err(RecordError::Size);
        }

        sh.handle_server_certificate_verify(algo, raw);

        Ok(())
    }
}
