//! yTLS Extension (10) supported groups
//! https://datatracker.ietf.org/doc/html/rfc8422
//! https://datatracker.ietf.org/doc/html/rfc4492#section-5.1.1
//! FFDHE https://datatracker.ietf.org/doc/html/rfc7919#section-2
//! Hybrids https://datatracker.ietf.org/doc/html/draft-kwiatkowski-tls-ecdhe-mlkem-03

use crate::TlsExtError;
use ytls_typed::Group;

/// Downstream Group Processor
pub trait ExtGroupProcessor {
    /// Check whether any of the provided groups matches.
    /// When any of the entries matches, result will be
    /// true and otherwise false.
    fn group(&mut self, _: Group) -> bool;
}

/// TLS Extension 10 (EC) Group handling
pub struct TlsExtGroup {}

impl TlsExtGroup {
    /// Check with the provided Processor whether
    /// any of the Client Hello provided SNIs matches
    #[inline]
    pub fn client_group_cb<P: ExtGroupProcessor>(
        p: &mut P,
        group_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if group_raw.len() < 2 {
            return Err(TlsExtError::InvalidLength);
        }
        let group_len = u16::from_be_bytes([group_raw[0], group_raw[1]]);

        if group_len == 0 {
            return Err(TlsExtError::NoData);
        }

        let remaining = &group_raw[2..];
        let expected_len = remaining.len();

        if group_len as usize != expected_len {
            return Err(TlsExtError::InvalidLength);
        }

        let mut group_i = remaining.chunks(2);

        while let Some(group) = group_i.next() {
            let g_id = u16::from_be_bytes([group[0], group[1]]);
            p.group(g_id.into());
        }
        Ok(())
    }
}
