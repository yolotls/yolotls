//! yTLS Extension (51) Key Share
//! https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc8446bis-14#section-4.2.8

use crate::TlsExtError;
use ytls_typed::Group;

/// Downstream Key Share Processor
pub trait ExtKeyShareProcessor {
    fn key_share(&mut self, _: Group, _: &[u8]) -> bool;
}

/// TLS Extension 51 Key Share handling
pub struct TlsExtKeyShare {}

impl TlsExtKeyShare {
    #[inline]
    pub fn client_key_share_cb<P: ExtKeyShareProcessor>(
        p: &mut P,
        key_share_raw: &[u8],
    ) -> Result<(), TlsExtError> {
        if key_share_raw.len() < 2 {
            return Err(TlsExtError::InvalidLength);
        }

        let total_expected_len = u16::from_be_bytes([key_share_raw[0], key_share_raw[1]]);

        let mut remaining = &key_share_raw[2..];
        let expected_len: usize = remaining.len();

        if total_expected_len as usize != expected_len {
            return Err(TlsExtError::InvalidLength);
        }

        let mut processed: usize = 0;

        loop {
            if remaining.len() < 4 {
                return Err(TlsExtError::InvalidLength);
            }

            let ks_id = u16::from_be_bytes([remaining[0], remaining[1]]);
            let ks_data_len = u16::from_be_bytes([remaining[2], remaining[3]]);

            let group: Group = ks_id.into();

            remaining = &remaining[4..];

            if ks_data_len as usize > remaining.len() {
                return Err(TlsExtError::EntryOverflow);
            }

            let (ks_data, remaining_next) = remaining.split_at(ks_data_len as usize);
            remaining = remaining_next;

            processed += ks_data_len as usize + 4;

            p.key_share(group, ks_data);

            if processed >= expected_len {
                break;
            }
        }

        Ok(())
    }
}

//-----------------------------------
// TC1
//-----------------------------------
// 00 69 - 105 len total
//  +36 bytes X25519
//  +69 bytes Secp256r1
// ---------------------
//  105 bytes total
//-----------------------------------
// X25519  - 36 bytes
//-----------------------------------
// 00 1d - X25519 for key exchange
// 00 20 - 32 Bytes folows
// 4a f2 a0 81 b8 a1 28 61 2d a7
// bc fd ab 1d 24 6a 5c f5 c6 38
// 57 aa 9c ea 4b 48 51 b2 6e d0
// d9 07
//-----------------------------------
// Secp256r1 - 69 bytes
//-----------------------------------
// 00 17 - Secp256r1 for key exchange
// 00 41 - 65 bytes follows
// 04 74 d6 f3 d1 0c 10 d2 fb 55
// 45 7e 9b 8f 14 d7 d6 5d e0 ff
// 2d 6b e3 a4 d6 e8 8a fc a9 6b
// 80 e6 86 87 1b f9 1e 18 c5 da
// 72 32 d3 89 70 f4 08 ad fb 0e
// 5c c3 3e 38 d5 36 b1 84 ee 75
// 04 75 4f 97 aa
//-----------------------------------
#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;
    use ytls_typed::Group;

    #[derive(Debug, PartialEq)]
    struct GroupSeen {
        group: Group,
        pk: Vec<u8>,
    }

    #[derive(Debug, Default, PartialEq)]
    struct Tester {
        groups: Vec<GroupSeen>,
    }

    impl ExtKeyShareProcessor for Tester {
        fn key_share(&mut self, g: Group, pk: &[u8]) -> bool {
            self.groups.push(GroupSeen {
                group: g,
                pk: pk.to_vec(),
            });
            false
        }
    }

    #[rstest]
    #[case(
        "0069001d00204af2a081b8a128612da7bcfdab1d246a5cf5c63857aa9cea4b4851b26ed0d907001700410474d6f3d10c10d2fb55457e9b8f14d7d65de0ff2d6be3a4d6e88afca96b80e686871bf91e18c5da7232d38970f408adfb0e5cc33e38d536b184ee7504754f97aa",
        Tester { groups: vec![GroupSeen { group: Group::X25519, pk: vec![74, 242, 160, 129, 184, 161, 40, 97, 45, 167, 188, 253, 171, 29, 36, 106, 92, 245, 198, 56, 87, 170, 156, 234, 75, 72, 81, 178, 110, 208, 217, 7] }, GroupSeen { group: Group::Secp256r1, pk: vec![4, 116, 214, 243, 209, 12, 16, 210, 251, 85, 69, 126, 155, 143, 20, 215, 214, 93, 224, 255, 45, 107, 227, 164, 214, 232, 138, 252, 169, 107, 128, 230, 134, 135, 27, 249, 30, 24, 197, 218, 114, 50, 211, 137, 112, 244, 8, 173, 251, 14, 92, 195, 62, 56, 213, 54, 177, 132, 238, 117, 4, 117, 79, 151, 170] }] },
        Ok(())
    )]
    fn key_share_ok(
        #[case] ks_raw_t: &str,
        #[case] expected_tester: Tester,
        #[case] expected_res: Result<(), TlsExtError>,
    ) {
        let key_share_raw = hex::decode(ks_raw_t).unwrap();
        let mut tester = Tester::default();
        let res = TlsExtKeyShare::client_key_share_cb(&mut tester, &key_share_raw);
        assert_eq!(expected_res, res);
        assert_eq!(expected_tester, tester);
    }
}
