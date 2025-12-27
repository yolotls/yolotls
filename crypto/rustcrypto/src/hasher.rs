//! yTLS RustCrypto Hashers

use ytls_traits::CryptoSha384TrancriptProcessor;
use sha3::{Digest, Sha3_384};

/// RustCrypto Sha384Hasher
pub struct Sha384Hasher {
    hasher: Sha3_384,
}

impl Sha384Hasher {
    pub fn sha384_init() -> Self {
        let hasher = Sha3_384::new();
        Sha384Hasher { hasher }
    }
}

impl CryptoSha384TrancriptProcessor for Sha384Hasher {
    fn sha384_update(&mut self, d: &[u8]) -> () {
        self.hasher.update(d);
    }    
    fn sha384_finalize(self) -> [u8; 48] {
        self.hasher.finalize().into()
    }
}
