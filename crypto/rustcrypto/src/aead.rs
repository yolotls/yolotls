//! yTLS RustCrypto AEADs

use ytls_traits::CryptoChaCha20Poly1305Processor;

use chacha20poly1305::{
    aead::{AeadCore, AeadInOut, KeyInit},
    ChaCha20Poly1305, Nonce,
};

pub struct AeadChaCha20Poly1305 {
    cipher: ChaCha20Poly1305,
}

use ytls_traits::AeadError;

impl AeadChaCha20Poly1305 {
    pub fn chacha20poly1305_init(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&(*key).into()),
        }
    }
}

impl CryptoChaCha20Poly1305Processor for AeadChaCha20Poly1305 {
    fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        additional_data: &[u8],
        to_encrypt: &mut [u8],
    ) -> Result<[u8; 16], AeadError> {
        let nonce: Nonce = (*nonce).into();
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, &additional_data, to_encrypt.into())
            .map_err(|_| AeadError::Opaque)?;

        Ok(tag.into())
    }
}
