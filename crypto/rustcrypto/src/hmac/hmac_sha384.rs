//! yTLS RustCrypto HMAC SHA384

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha384};
use ytls_traits::CryptoSha384HmacProcessor;

/// RustCrypto Sha384Hmac
#[derive(Clone)]
pub struct Sha384Hmac {
    hmac: Hmac<Sha384>,
}

impl Sha384Hmac {
    pub fn sha384_hmac_init_with_key(key: &[u8; 48]) -> Self {
        // SAFETY: Safe to unwrap with fixed legth key
        let hmac = Hmac::<Sha384>::new_from_slice(key).unwrap();

        Sha384Hmac { hmac }
    }
}

impl CryptoSha384HmacProcessor for Sha384Hmac {
    fn hmac_sha384_update(&mut self, d: &[u8]) -> () {
        self.hmac.update(d)
    }
    fn hmac_sha384_fork(&self) -> Self {
        self.clone()
    }
    fn hmac_sha384_finalize(self) -> [u8; 48] {
        self.hmac.finalize().into_bytes().into()
    }
}
