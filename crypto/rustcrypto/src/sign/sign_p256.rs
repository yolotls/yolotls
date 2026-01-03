//! yTLS RustCrypto ECDSA p256 Signer

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use ytls_traits::CryptoSignerP256Processor;

/// RustCrypto ECDSA p256 Signer
pub struct SignP256 {
    signing_key: SigningKey,
}

impl SignP256 {
    #[inline]
    pub fn sign_p256_init(key: &[u8]) -> Option<Self> {
        // SAFETY: The key input length is guarded to be correct
        let signing_key = match SigningKey::try_from(key) {
            Ok(k) => k,
            Err(_) => return None,
        };
        Some(Self { signing_key })
    }
}

impl CryptoSignerP256Processor for SignP256 {
    #[inline]
    fn sign_p256(&self, content: &[u8], output: &mut [u8]) -> Option<usize> {
        let signature: Signature = self.signing_key.sign(content);
        let der_bytes = signature.to_der();
        let bytes = der_bytes.as_bytes();

        if bytes.len() > output.len() {
            return None;
        }

        output[0..bytes.len()].copy_from_slice(bytes);

        Some(bytes.len())
    }
}
