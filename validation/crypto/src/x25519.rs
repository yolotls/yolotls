//! Known yTLS X25519 Processors validation

use rstest::rstest;
use ytls_rustcrypto::X25519;
use ytls_traits::CryptoX25519Processor;

#[rstest]
#[case(X25519::x25519_init(&mut rand::rng()))]
fn x25519_ok<I: CryptoX25519Processor>(#[case] h: I) {
    let _pk = h.x25519_public_key();

    let other_public_key: [u8; 32] = [0; 32];

    h.x25519_shared_secret(&other_public_key);
}
