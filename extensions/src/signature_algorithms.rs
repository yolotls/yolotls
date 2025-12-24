//! yTLS Extension (13) Signature Algorithms

use crate::TlsExtError;
use ytls_typed::SignatureAlgorithm;

/// Downstream Group Processor
pub trait ExtSigAlgProcessor {
    /// Indicate support for the given Signature Algorithm.
    fn signature_algorithm(&mut self, _: SignatureAlgorithm) -> bool;
}

/// TLS Extension 10 (EC) Group handling
pub struct TlsExtSigAlg {}

impl TlsExtSigAlg {
    /// Parse all the signature algorithms from the Client Hello extension data
    #[inline]
    pub fn client_signature_algorithm_cb<P: ExtSigAlgProcessor>(
        p: &mut P,
        sig_alg_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if sig_alg_raw.len() < 2 {
            return Err(TlsExtError::InvalidLength);
        }
        let sig_algs_len = u16::from_be_bytes([sig_alg_raw[0], sig_alg_raw[1]]);

        if sig_algs_len == 0 {
            return Err(TlsExtError::NoData);
        }

        let remaining = &sig_alg_raw[2..];
        let expected_len = remaining.len();

        if sig_algs_len as usize != expected_len {
            return Err(TlsExtError::InvalidLength);
        }

        let mut sig_algs_i = remaining.chunks(2);

        while let Some(sig_alg) = sig_algs_i.next() {
            let sig_alg_id = u16::from_be_bytes([sig_alg[0], sig_alg[1]]);
            p.signature_algorithm(sig_alg_id.into());
        }
        Ok(())
    }
}
