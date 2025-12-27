//! yTLS RustCrypto Hashers

use ytls_traits::CryptoX25519Processor;
use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;

use rand_core::CryptoRng;

/// RustCrypto Sha384Hasher
pub struct X25519 {
    ep: EphemeralSecret,
}

impl X25519 {
    pub fn x25519_init<R: CryptoRng>(rng: &mut R) -> Self {
        let ep = EphemeralSecret::random_from_rng(rng);
        Self { ep }
    }
}

impl CryptoX25519Processor for X25519 {
    fn x25519_public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.ep).to_bytes()
    }
    fn x25519_shared_secret(self, pub_key: &[u8; 32]) -> [u8; 32] {
        self.ep.diffie_hellman(&(*pub_key).into()).to_bytes()
    }
}
