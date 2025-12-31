//! Known yTLS HKDF Processors validation

use hex_literal::hex;
use rstest::rstest;
use ytls_rustcrypto::Sha256Hkdf;
use ytls_traits::CryptoSha256HkdfExtractProcessor;
use ytls_traits::CryptoSha256HkdfGenProcessor;

#[rstest]
#[case(Sha256Hkdf::sha256_hkdf_init())]
fn hkdf_init_ok<I: CryptoSha256HkdfExtractProcessor>(#[case] h: I) {
    // Zero Hashlen IKM & Salt are used when PSK is not in use
    let ikm: [u8; 32] = [0; 32];
    let salt: [u8; 1] = [0; 1];
    let (early_secret, _hk_early) = h.hkdf_sha256_extract(Some(&salt[..]), &ikm);

    // Vector - see https://datatracker.ietf.org/doc/rfc8448/
    assert_eq!(
        early_secret,
        hex!(
            "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c
         e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"
        )
    );
}

use ytls_traits::CryptoConfig;

// Label (info) used in TLS1.3
const fn tls13_label_derived() -> [u8; 49] {
    [
        // Hashlen u16
        0, 32, // Len of of "tls13 derived" (1 byte)
        13, // tls13\s (6 bytes)
        116, 108, 115, 49, 51, 32, // derived (7 bytes)
        100, 101, 114, 105, 118, 101, 100, // Len of "ctx" (1 byte)
        32,  // ctx = empty SHA256("") (32 bytes)
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ]
}

#[rstest]
#[case(Sha256Hkdf::sha256_hkdf_from_prk(&hex!("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")).unwrap())]
fn hkdf_from_psk_expand_ok<I: CryptoSha256HkdfGenProcessor>(#[case] mut h: I) {
    let mut derived_secret: [u8; 32] = [0; 32];
    let label_derived = tls13_label_derived();
    match h.hkdf_sha256_expand(&label_derived, &mut derived_secret) {
        Ok(()) => {}
        Err(_) => panic!("failed."),
    }
    assert_eq!(derived_secret, hex!("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba                                                      
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba"));
}

#[rstest]
#[case(Sha256Hkdf::sha256_hkdf_init())]
fn hkdf_extract_expand_ok<I: CryptoSha256HkdfExtractProcessor>(#[case] h: I) {
    // Zero Hashlen IKM & Salt are used when PSK is not in use
    let ikm: [u8; 32] = [0; 32];
    let salt: [u8; 1] = [0; 1];
    let (_early_secret, mut hk_early) = h.hkdf_sha256_extract(Some(&salt[..]), &ikm);

    let mut derived_secret: [u8; 32] = [0; 32];
    let label_derived = tls13_label_derived();
    match hk_early.hkdf_sha256_expand(&label_derived, &mut derived_secret) {
        Ok(()) => {}
        Err(_) => panic!("failed."),
    }
    assert_eq!(derived_secret, hex!("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba                                                      
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba"));
}
