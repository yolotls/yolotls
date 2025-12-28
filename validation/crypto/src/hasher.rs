//! Known yTLS Hashers validation

use rstest::rstest;
use ytls_rustcrypto::Sha256Hasher;
use ytls_rustcrypto::Sha384Hasher;
use ytls_traits::CryptoSha256TranscriptProcessor;
use ytls_traits::CryptoSha384TranscriptProcessor;

#[rstest]
#[case(Sha384Hasher::sha384_init())]
fn sha384_ok<I: CryptoSha384TranscriptProcessor>(#[case] mut h: I) {
    h.sha384_update(b"that foxes thing who cares");

    let expected: [u8; 48] = [
        65, 1, 242, 111, 162, 67, 120, 21, 88, 179, 13, 40, 212, 36, 87, 239, 128, 59, 159, 30, 43,
        180, 174, 27, 247, 112, 71, 75, 33, 125, 59, 54, 109, 240, 181, 166, 49, 24, 250, 58, 145,
        105, 121, 5, 145, 116, 108, 249,
    ];

    assert_eq!(expected, h.sha384_finalize());
}

#[rstest]
#[case(Sha384Hasher::sha384_init())]
fn sha384_empty_ok<I: CryptoSha384TranscriptProcessor>(#[case] mut h: I) {
    h.sha384_update(b"");

    let expected: [u8; 48] = hex_literal::hex!("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");

    assert_eq!(expected, h.sha384_finalize());
}

#[rstest]
#[case(Sha256Hasher::sha256_init())]
fn sha256_ok<I: CryptoSha256TranscriptProcessor>(#[case] mut h: I) {
    h.sha256_update(b"that foxes thing who cares");

    let expected: [u8; 32] = [
        129, 240, 153, 5, 254, 140, 199, 174, 176, 236, 3, 197, 112, 251, 131, 114, 185, 88, 241,
        231, 153, 51, 57, 131, 198, 236, 47, 201, 194, 155, 198, 254,
    ];

    assert_eq!(expected, h.sha256_finalize());
}

#[rstest]
#[case(Sha256Hasher::sha256_init())]
fn sha256_empty_ok<I: CryptoSha256TranscriptProcessor>(#[case] mut h: I) {
    h.sha256_update(b"");

    let expected: [u8; 32] =
        hex_literal::hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    assert_eq!(expected, h.sha256_finalize());
}
