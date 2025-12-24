//! yTLS Extension (28) Record Size Limit Handling

use crate::TlsExtError;

/// Downstream Record Size Limit Processor
pub trait ExtRecSizeLimitProcessor {
    // Set the record size limit
    fn record_size_limit(&mut self, _: u16) -> ();
}

/// TLS Server Name Indication (SNI) handling
pub struct TlsExtRecSizeLim {}

impl TlsExtRecSizeLim {
    /// Check with the provided Processor whether
    /// any of the Client Hello provided SNIs matches
    #[inline]
    pub fn client_rec_size_limit_cb<P: ExtRecSizeLimitProcessor>(
        p: &mut P,
        limit_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if limit_raw.len() < 2 {
            return Err(TlsExtError::InvalidLength);
        }
        let rec_size_limit = u16::from_be_bytes([limit_raw[0], limit_raw[1]]);

        p.record_size_limit(rec_size_limit);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;

    #[derive(Debug, Default, PartialEq)]
    struct Tester {
        seen: Vec<u16>,
    }

    impl ExtRecSizeLimitProcessor for Tester {
        fn record_size_limit(&mut self, lim: u16) -> () {
            self.seen.push(lim);
        }
    }

    #[rstest]
    #[case(
        "4001",
        Tester { seen: vec![16385] },
        Ok(())
    )]
    #[case(
        "40",
        Tester { seen: vec![] },
        Err(TlsExtError::InvalidLength)
    )]
    fn client_record_size_limit(
        #[case] raw_t: &str,
        #[case] expected_tester: Tester,
        #[case] expected_res: Result<(), TlsExtError>,
    ) {
        let in_raw = hex::decode(raw_t).unwrap();
        let mut tester = Tester::default();
        let res = TlsExtRecSizeLim::client_rec_size_limit_cb(&mut tester, &in_raw);
        assert_eq!(expected_tester, tester);
        assert_eq!(expected_res, res);
    }
}
