//! CipherSuites parsing
//! This does not validate IANA registry conformance
//! which is the responsibility of the downstream
//! impl HelloProcessor.

use ytls_traits::ClientHelloProcessor;

use crate::error::CipherSuitesError;

use zerocopy::byteorder::network_endian::U16 as N16;

/// CipherSuites parsing & building
pub struct CipherSuites {}

impl CipherSuites {
    /// Parse cipher suites from the byte slice and pass them to the provided ClientHelloProcessor
    pub fn parse_cipher_suites<P: ClientHelloProcessor>(
        prc: &mut P,
        bytes: &[u8],
    ) -> Result<(), CipherSuitesError> {
        if bytes.len() % 2 != 0 || bytes.len() == 0 {
            return Err(CipherSuitesError::InvalidLength);
        }

        let mut cs_iter = bytes.chunks(2);

        while let Some(cs) = cs_iter.next() {
            prc.handle_cipher_suite(&[cs[0], cs[1]]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use rstest::rstest;

    #[derive(Debug, PartialEq)]
    struct Tester {
        suites_encountered: Vec<[u8; 2]>,
    }
    impl ClientHelloProcessor for Tester {
        fn handle_extension(&mut self, _ext_id: u16, _ext_data: &[u8]) -> () {
            unreachable!()
        }
        fn handle_cipher_suite(&mut self, cipher_suite: &[u8; 2]) -> () {
            self.suites_encountered
                .push([cipher_suite[0], cipher_suite[1]]);
        }
    }

    use hex_literal::hex;

    // Firefox as client wants these cipher suites
    #[rstest]
    #[case("130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035",
           Ok(()),
           Tester { suites_encountered: vec![
               hex!("1301"), hex!("1303"), hex!("1302"), hex!("c02b"),
               hex!("c02f"), hex!("cca9"), hex!("cca8"), hex!("c02c"),
               hex!("c030"), hex!("c00a"), hex!("c009"), hex!("c013"),
               hex!("c014"), hex!("009c"), hex!("009d"), hex!("002f"),
               hex!("0035")]
           }    )]
    /// Cipher suites must be % 4 == 0
    #[case("130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f00",
           Err(CipherSuitesError::InvalidLength),
           Tester { suites_encountered: vec![] }
    )]
    fn t_cipher_suites_parsing(
        #[case] input: &'static str,
        #[case] res: Result<(), CipherSuitesError>,
        #[case] exp: Tester,
    ) {
        let mut prc = Tester {
            suites_encountered: vec![],
        };

        let r = CipherSuites::parse_cipher_suites(&mut prc, &hex::decode(input).unwrap());
        assert_eq!(r, res);
        assert_eq!(exp, prc);
    }
}
