//! yTLS RustCrypto Hashers

use sha2::{Digest, Sha384};
use ytls_traits::CryptoSha384TranscriptProcessor;

/// RustCrypto Sha384Hasher
pub struct Sha384Hasher {
    hasher: Sha384,
}

impl Sha384Hasher {
    pub fn sha384_init() -> Self {
        let hasher = Sha384::new();
        Sha384Hasher { hasher }
    }
}

impl CryptoSha384TranscriptProcessor for Sha384Hasher {
    fn sha384_update(&mut self, d: &[u8]) -> () {
        self.hasher.update(d);
    }
    fn sha384_finalize(self) -> [u8; 48] {
        self.hasher.finalize().into()
    }
}
