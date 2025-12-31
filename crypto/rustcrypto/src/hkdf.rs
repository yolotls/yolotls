//! yTLS RustCrypto Hdkf

use ytls_traits::CryptoSha256HkdfExtractProcessor;
use ytls_traits::CryptoSha256HkdfGenProcessor;

/// yTLS RustCrypto Hdkdf
pub struct Sha256Hkdf;
pub struct Sha256HkdfExtract {
    inner: GenericHkdf<Hmac<Sha256>>,
}

pub use hkdf::{hmac::Hmac, GenericHkdf, Hkdf};
pub use sha2::{Digest, Sha256};

impl Sha256Hkdf {
    pub fn sha256_hkdf_init() -> Self {
        Self {}
    }
    pub fn sha256_hkdf_from_prk(
        prk: &[u8],
    ) -> Result<impl CryptoSha256HkdfGenProcessor, hkdf::InvalidPrkLength> {
        Ok(Sha256HkdfExtract {
            inner: Hkdf::<Sha256>::from_prk(prk)?,
        })
    }
}

impl CryptoSha256HkdfExtractProcessor for Sha256Hkdf {
    fn hkdf_sha256_extract(
        &self,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> ([u8; 32], impl CryptoSha256HkdfGenProcessor) {
        let (handshake_secret, hs_hk) = Hkdf::<Sha256>::extract(salt, ikm);
        (handshake_secret.into(), Sha256HkdfExtract { inner: hs_hk })
    }
}

impl CryptoSha256HkdfGenProcessor for Sha256HkdfExtract {
    type Error = hkdf::InvalidLength;
    fn hkdf_sha256_expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.expand(info, okm)
    }
}
