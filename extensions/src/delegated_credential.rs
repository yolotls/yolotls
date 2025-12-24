//! yTLS Extension (34) Delegated Credential support

use crate::TlsExtError;
use ytls_typed::SignatureAlgorithm;

/// Downstream Group Processor
pub trait ExtDelegatedCredentialProcessor {
    /// Indicate support for the given Signature Algorithm.
    fn delegated_credential_signature_algorithm(&mut self, _: SignatureAlgorithm) -> bool;
}

/// TLS Extension 34 Delegated Credential Support
pub struct TlsExtDelegatedCredential {}

impl TlsExtDelegatedCredential {
    /// Parse all the signature algorithms from the Client Hello extension data
    #[inline]
    pub fn client_delegated_credential_cb<P: ExtDelegatedCredentialProcessor>(
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
            p.delegated_credential_signature_algorithm(sig_alg_id.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;
    use ytls_typed::SignatureAlgorithm as Sa;

    #[derive(Debug, Default, PartialEq)]
    struct Tester {
        seen: Vec<Sa>,
    }

    impl ExtDelegatedCredentialProcessor for Tester {
        fn delegated_credential_signature_algorithm(&mut self, dgsa: Sa) -> bool {
            self.seen.push(dgsa);
            true
        }
    }

    #[rstest]
    #[case(
        "00080403050306030203",
        Tester { seen: vec![Sa::EcdsaSecp256r1Sha256, Sa::EcdsaSecp384r1Sha384, Sa::EcdsaSecp521r1Sha512, Sa::EcdsaSha1] },
        Ok(())
    )]
    #[case(
        "",
        Tester { seen: vec![] },
        Err(TlsExtError::InvalidLength)
    )]
    fn client_delegated_credential_dgsa(
        #[case] raw_t: &str,
        #[case] expected_tester: Tester,
        #[case] expected_res: Result<(), TlsExtError>,
    ) {
        let in_raw = hex::decode(raw_t).unwrap();
        let mut tester = Tester::default();
        let res = TlsExtDelegatedCredential::client_delegated_credential_cb(&mut tester, &in_raw);
        assert_eq!(expected_tester, tester);
        assert_eq!(expected_res, res);
    }
}
