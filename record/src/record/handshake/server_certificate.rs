//! Server Certificate Handshake record

use crate::RecordError;
use ytls_traits::ServerCertificateProcessor;
use ytls_traits::ServerWrappedRecordProcessor;

#[derive(Debug, PartialEq)]
pub struct ServerCertificate;

impl ServerCertificate {
    /// Parse wrapped Server Certificate
    #[inline]
    pub fn parse_wrapped<P: ServerWrappedRecordProcessor>(
        prc: &mut P,
        mut raw: &[u8],
    ) -> Result<(), RecordError> {
        let sh = prc.server_certificate();

        // annoying u24
        let cl_bytes = raw.split_off(..3).ok_or(RecordError::Size)?;
        let cert_len_u32 = u32::from_be_bytes([0, cl_bytes[0], cl_bytes[1], cl_bytes[2]]);

        if cert_len_u32 as usize != raw.len() {
            return Err(RecordError::Size);
        }

        loop {
            let cl_bytes = raw.split_off(..3).ok_or(RecordError::Size)?;
            let cert_len_u32 = u32::from_be_bytes([0, cl_bytes[0], cl_bytes[1], cl_bytes[2]]);
            let cert_data = raw
                .split_off(..cert_len_u32 as usize)
                .ok_or(RecordError::Size)?;

            let el_bytes = raw.split_off(..2).ok_or(RecordError::Size)?;
            let ext_len_u16 = u16::from_be_bytes([el_bytes[0], el_bytes[1]]);

            let ext_data = raw
                .split_off(..ext_len_u16 as usize)
                .ok_or(RecordError::Size)?;

            sh.handle_server_certificate(cert_data, ext_data);

            if raw.len() == 0 {
                break;
            }
        }

        Ok(())
    }
}
