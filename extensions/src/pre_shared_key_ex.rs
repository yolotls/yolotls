//! yTLS Extension (41) Pre-Shared Key Exchange Modes

use crate::TlsExtError;

/// Pre-Shared Key Exchange Modes
#[derive(Debug, PartialEq)]
pub enum PskeKind {
    /// PSK-only key establishment. In this mode, the server MUST NOT supply a "key_share" value.
    PskKe,
    /// PSK with (EC)DHE key establishment. In this mode, the client and server MUST
    /// supply "key_share" values as described in RFC RFC 8446 bis-14 Section 4.2.8.
    PskDheKe,
    /// Unknown Pre-Shared Key Exchange Mode
    Unknown(u8),
}

impl From<u8> for PskeKind {
    fn from(b: u8) -> Self {
        match b {
            0 => Self::PskKe,
            1 => Self::PskDheKe,
            _ => Self::Unknown(b),
        }
    }
}

/// Downstream Supported Versions Processor
pub trait ExtPskeProcessor {
    /// Signals the Pre-Shared Key Exchange Mode supported
    fn pske_mode(&mut self, _: PskeKind) -> ();
}

/// TLS Extension 41 Pre-Shared Key Exchange mode Handling
pub struct TlsExtPske {}

impl TlsExtPske {
    /// Client Pre-Shared Key Exchange mode callback
    #[inline]
    pub fn client_pske_cb<P: ExtPskeProcessor>(
        p: &mut P,
        pske_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if pske_raw.len() < 1 {
            return Err(TlsExtError::InvalidLength);
        }

        let pske_len = pske_raw[0];

        if pske_len == 0 {
            return Err(TlsExtError::NoData);
        }

        if pske_raw.len() < 1 {
            return Err(TlsExtError::InvalidLength);
        }

        let remaining = &pske_raw[1..];
        let expected_len = remaining.len();

        if expected_len != pske_len as usize {
            return Err(TlsExtError::InvalidLength);
        }

        let mut pske_i = remaining.chunks(1);

        while let Some(entry_pske_raw) = pske_i.next() {
            p.pske_mode(entry_pske_raw[0].into());
        }
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
        seen: Vec<PskeKind>,
    }

    impl ExtPskeProcessor for Tester {
        fn pske_mode(&mut self, k: PskeKind) -> () {
            self.seen.push(k);
        }
    }

    #[rstest]
    #[case(
        "0101",
        Tester { seen: vec![PskeKind::PskDheKe] },
        Ok(())
    )]
    #[case(
        "",
        Tester { seen: vec![] },
        Err(TlsExtError::InvalidLength)
    )]
    fn client_psk_modes(
        #[case] raw_t: &str,
        #[case] expected_tester: Tester,
        #[case] expected_res: Result<(), TlsExtError>,
    ) {
        let in_raw = hex::decode(raw_t).unwrap();
        let mut tester = Tester::default();
        let res = TlsExtPske::client_pske_cb(&mut tester, &in_raw);
        assert_eq!(expected_tester, tester);
        assert_eq!(expected_res, res);
    }
}
