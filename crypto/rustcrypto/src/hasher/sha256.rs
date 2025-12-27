//! yTLS RustCrypto Hashers

use ytls_traits::CryptoSha256TranscriptProcessor;
use sha2::{Digest, Sha256};

/// RustCrypto Sha256Hasher
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
    fn sha256_finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}
