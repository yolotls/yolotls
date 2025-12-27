//! Known yTLS Hashers validation

use rstest::rstest;
use ytls_rustcrypto::Sha384Hasher;
use ytls_traits::CryptoSha384TrancriptProcessor;

#[rstest]
#[case(Sha384Hasher::sha384_init())]
fn sha384_ok<I: CryptoSha384TrancriptProcessor>(#[case] mut h: I) {
    h.sha384_update(b"that foxes thing who cares");

    let expected: [u8; 48] = [
        106, 14, 51, 133, 167, 31, 226, 108, 76, 104, 192, 60, 216, 119, 159, 87, 191, 25, 165, 40,
        249, 59, 225, 9, 80, 40, 238, 192, 45, 206, 182, 85, 153, 148, 23, 110, 109, 136, 40, 45,
        155, 74, 60, 126, 123, 104, 198, 186,
    ];

    assert_eq!(h.sha384_finalize(), expected);
}
