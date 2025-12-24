//! yTLS Extension (65037) Encrypted Client Hello handling

use crate::TlsExtError;

use ytls_typed::{HaeadKind, HkdfKind};

/// Downstream Encrypted Client Hello Processor
pub trait ExtEncryptedClientHelloProcessor {
    /// Encrypted Client Hello Outer
    fn encrypted_client_hello_outer(
        &mut self,
        _: u8,
        _: HkdfKind,
        _: HaeadKind,
        _: &[u8],
        _: &[u8],
    ) -> ();
}

/// TLS Encrypted CLient Hello handling
pub struct TlsExtEncryptedClientHello {}

impl TlsExtEncryptedClientHello {
    #[inline]
    pub fn client_encrypted_hello_cb<P: ExtEncryptedClientHelloProcessor>(
        p: &mut P,
        ec_hello_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if ec_hello_raw.len() < 1 {
            return Err(TlsExtError::InvalidLength);
        }

        let inner_outer_kind = ec_hello_raw[0];

        if inner_outer_kind == 0 {
            if ec_hello_raw.len() < 11 {
                return Err(TlsExtError::InvalidLength);
            }

            let hpke_kdf_id: HkdfKind =
                u16::from_be_bytes([ec_hello_raw[1], ec_hello_raw[2]]).into();
            let hpke_aead_id: HaeadKind =
                u16::from_be_bytes([ec_hello_raw[3], ec_hello_raw[4]]).into();

            let config_id = ec_hello_raw[5];

            let enc_len = u16::from_be_bytes([ec_hello_raw[6], ec_hello_raw[7]]);

            let (enc, remaining) = ec_hello_raw[8..].split_at(enc_len as usize);
            let payload_len = u16::from_be_bytes([remaining[0], remaining[1]]);

            let payload = &remaining[2..];

            if payload_len as usize != payload.len() || payload_len == 0 {
                return Err(TlsExtError::InvalidLength);
            }

            p.encrypted_client_hello_outer(config_id, hpke_kdf_id, hpke_aead_id, enc, payload);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;
    use ytls_typed::{HaeadKind, HkdfKind};

    #[derive(Debug, PartialEq)]
    struct Outer {
        config_id: u8,
        kdf: HkdfKind,
        aead: HaeadKind,
        enc: Vec<u8>,
        payload: Vec<u8>,
    }

    #[derive(Debug, Default, PartialEq)]
    struct Tester {
        outers: Vec<Outer>,
    }

    impl ExtEncryptedClientHelloProcessor for Tester {
        fn encrypted_client_hello_outer(
            &mut self,
            config_id: u8,
            kdf: HkdfKind,
            aead: HaeadKind,
            enc: &[u8],
            payload: &[u8],
        ) -> () {
            self.outers.push(Outer {
                config_id,
                kdf,
                aead,
                enc: enc.to_vec(),
                payload: payload.to_vec(),
            });
        }
    }

    #[rstest]
    #[case(
        "0000010001e700201f0ccafd25d84fb8e366073175f75c5d679d02b73743dff24a7478053233542d00efd8bf0fd70a2e2b4ff2d8dad3b9bbbd0f15b48916269a84b8bbee033e0d4be473fcd77f33283a1f8d1bca94347d6906d7cddec6bfc828432af8be84196800bdc41987e869b5667be6d7b36c2bf3325731f16faeea249132b5b5bbde0b15f3f664145b4a27737533f7cb35100a2ef9e22274595c23256de677f0305b86266445d776a790714b21854c44bb148acbc9681be792f863b95c44232a0f897e7dc771e3c1286e8afc55d0187d67871cb18a1cd8f3d78bd637933a782d65890da3af5ed4fb72a44565f1afa82db23671775c5f064a7a48349cd3e763f12d120180c566fd33c82e38eaab7c71fcf1150bc40967",
        Ok(())
    )]
    fn encrypted_client_hello(
        #[case] sni_raw_t: &str,
        #[case] expected_res: Result<(), TlsExtError>,
    ) {
        let sni_raw = hex::decode(sni_raw_t).unwrap();
        let mut tester = Tester::default();
        let res = TlsExtEncryptedClientHello::client_encrypted_hello_cb(&mut tester, &sni_raw);
        insta::assert_debug_snapshot!(tester);
        assert_eq!(expected_res, res);
    }
}
