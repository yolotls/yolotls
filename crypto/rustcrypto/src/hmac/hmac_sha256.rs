//! yTLS RustCrypto HMAC SHA256

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use ytls_traits::CryptoSha256HmacProcessor;

/// RustCrypto Sha256Hmac
#[derive(Clone)]
pub struct Sha256Hmac {
    hmac: Hmac<Sha256>,
}

impl Sha256Hmac {
    pub fn sha256_hmac_init_with_key(key: &[u8; 32]) -> Self {
        // SAFETY: Safe to unwrap with fixed legth key
        let hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();

        Sha256Hmac { hmac }
    }
}

impl CryptoSha256HmacProcessor for Sha256Hmac {
    fn hmac_sha256_update(&mut self, d: &[u8]) -> () {
        self.hmac.update(d)
    }
    fn hmac_sha256_fork(&self) -> Self {
        self.clone()
    }
    fn hmac_sha256_finalize(self) -> [u8; 32] {
        self.hmac.finalize().into_bytes().into()
    }
}
