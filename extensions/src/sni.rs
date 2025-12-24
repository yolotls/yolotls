//! yTLS Extension (0) SNI Handling

use crate::TlsExtError;

/// Currently RFC only defines DNS Hostname type for SNI entries
#[derive(Debug, PartialEq)]
pub enum EntrySniKind {
    DnsHostname,
    Unknown(u8),
}

/// Downstream SNI Processor
pub trait ExtSniProcessor {
    /// Check whether any of the provided SNIs matches.
    /// When any of the entries matches, result will be
    /// true and otherwise false.
    fn sni(&mut self, _: EntrySniKind, _: &[u8]) -> bool;
}

/// TLS Server Name Indication (SNI) handling
pub struct TlsExtSni {}

impl TlsExtSni {
    /// Check with the provided Processor whether
    /// any of the Client Hello provided SNIs matches
    #[inline]
    pub fn client_hello_cb<P: ExtSniProcessor>(
        p: &mut P,
        sni_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if sni_raw.len() < 2 {
            return Err(TlsExtError::InvalidLength);
        }
        let sni_len = u16::from_be_bytes([sni_raw[0], sni_raw[1]]);

        if sni_len == 0 {
            return Err(TlsExtError::NoData);
        }

        let mut remaining = &sni_raw[2..];
        let expected_len = remaining.len();
        if sni_len as usize != expected_len {
            return Err(TlsExtError::InvalidLength);
        }

        let mut processed = 0;

        loop {
            if remaining.len() < 3 {
                return Err(TlsExtError::InvalidLength);
            }

            let entry_len = u16::from_be_bytes([remaining[1], remaining[2]]);
            let entry_kind = match remaining[0] {
                0 => EntrySniKind::DnsHostname,
                _ => EntrySniKind::Unknown(remaining[0]),
            };
            remaining = &remaining[3..];
            processed += 3;

            if entry_len as usize > remaining.len() {
                return Err(TlsExtError::EntryOverflow);
            }

            match p.sni(entry_kind, &remaining[0..entry_len as usize]) {
                true => break,
                false => {}
            }

            processed += entry_len as usize;

            if processed == expected_len {
                break;
            }

            remaining = &remaining[entry_len as usize..];
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;

    #[derive(Debug, PartialEq)]
    struct Tester {
        sni_seen: Vec<(EntrySniKind, Vec<u8>)>,
    }

    impl ExtSniProcessor for Tester {
        fn sni(&mut self, k: EntrySniKind, name: &[u8]) -> bool {
            self.sni_seen.push((k, name.to_vec()));
            true
        }
    }

    #[rstest]
    #[case(
        "0013000010746573742e72757374637279702e746f",
        Tester { sni_seen: vec![(EntrySniKind::DnsHostname, hex!("746573742e72757374637279702e746f").to_vec())] },
        Ok(())
    )]
    fn client_hello_one_ok(
        #[case] sni_raw_t: &str,
        #[case] expected_tester: Tester,
        #[case] expected_res: Result<(), TlsExtError>,
    ) {
        let sni_raw = hex::decode(sni_raw_t).unwrap();
        let mut tester = Tester { sni_seen: vec![] };
        let res = TlsExtSni::client_hello_cb(&mut tester, &sni_raw);
        assert_eq!(expected_tester, tester);
        assert_eq!(expected_res, res);
    }
}
