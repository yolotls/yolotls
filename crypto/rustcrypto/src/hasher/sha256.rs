//! yTLS RustCrypto Hashers

use sha2::{Digest, Sha256};
use ytls_traits::CryptoSha256TranscriptProcessor;

/// RustCrypto Sha256Hasher
#[derive(Clone)]
pub struct Sha256Hasher {
    hasher: Sha256,
}

impl Sha256Hasher {
    pub fn sha256_init() -> Self {
        let hasher = Sha256::new();
        Sha256Hasher { hasher }
    }
}

impl CryptoSha256TranscriptProcessor for Sha256Hasher {
    fn sha256_update(&mut self, d: &[u8]) -> () {
        self.hasher.update(d);
    }
    fn sha256_fork(&self) -> Self {
        self.clone()
    }
    fn sha256_finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}
