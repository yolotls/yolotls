//! yTLS Extension (27) Compress Certificate support

use crate::TlsExtError;
use ytls_typed::CertificateCompressKind;

/// Downstream Compress Certificate Processor
pub trait ExtCompressCertProcessor {
    /// Client indicates support for a given Certificate Compression algorithm.
    fn compress_certificate(&mut self, _: CertificateCompressKind) -> ();
}

/// TLS Extension 27 Compress Certificate Support
pub struct TlsExtCompressCert {}

impl TlsExtCompressCert {
    /// Parse all the supported certificate compression algorithms.
    #[inline]
    pub fn client_compress_certificate_cb<P: ExtCompressCertProcessor>(
        p: &mut P,
        compress_alg_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if compress_alg_raw.len() < 1 {
            return Err(TlsExtError::InvalidLength);
        }
        let compress_algs_len = compress_alg_raw[0];

        if compress_algs_len == 0 {
            return Err(TlsExtError::NoData);
        }

        if compress_alg_raw.len() < 4
            || compress_algs_len as usize != compress_alg_raw.len() - 1
            || compress_algs_len % 2 != 0
        {
            return Err(TlsExtError::InvalidLength);
        }

        let remaining = &compress_alg_raw[1..];
        let expected_len = remaining.len();

        if compress_algs_len as usize != expected_len {
            return Err(TlsExtError::InvalidLength);
        }

        let mut comp_algs_i = remaining.chunks(2);

        while let Some(comp_alg) = comp_algs_i.next() {
            let comp_alg_id = u16::from_be_bytes([comp_alg[0], comp_alg[1]]);
            p.compress_certificate(comp_alg_id.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;
    use ytls_typed::CertificateCompressKind as Cck;

    #[derive(Debug, Default, PartialEq)]
    struct Tester {
        seen: Vec<Cck>,
    }

    impl ExtCompressCertProcessor for Tester {
        fn compress_certificate(&mut self, comp_alg: Cck) -> () {
            self.seen.push(comp_alg);
        }
    }

    #[rstest]
    #[case(
        "06000100020003",
        Tester { seen: vec![Cck::Zlib, Cck::Brotli, Cck::Zstd] },
        Ok(())
    )]
    #[case(
        "",
        Tester { seen: vec![] },
        Err(TlsExtError::InvalidLength)
    )]
    fn client_compress_certificate(
        #[case] raw_t: &str,
        #[case] expected_tester: Tester,
        #[case] expected_res: Result<(), TlsExtError>,
    ) {
        let in_raw = hex::decode(raw_t).unwrap();
        let mut tester = Tester::default();
        let res = TlsExtCompressCert::client_compress_certificate_cb(&mut tester, &in_raw);
        assert_eq!(expected_tester, tester);
        assert_eq!(expected_res, res);
    }
}
