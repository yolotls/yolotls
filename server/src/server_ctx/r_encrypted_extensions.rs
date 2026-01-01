//! Encrypted Extensions handler for Server Ctx

use crate::{TlsServerCtx, TlsServerCtxConfig, TlsServerCtxError};

use ytls_traits::CryptoChaCha20Poly1305Processor;
use ytls_traits::CryptoSha256TranscriptProcessor;

use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;
use ytls_traits::TlsLeft;

use ytls_record::WrappedStaticRecordBuilder;
use ytls_traits::EncryptedExtensionsBuilder;
use ytls_traits::WrappedHandshakeBuilder;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> EncryptedExtensionsBuilder
    for TlsServerCtx<C, Crypto, Rng>
{
    // Empty for nowx
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> TlsServerCtx<C, Crypto, Rng> {
    #[inline]
    pub(crate) fn do_encrypted_extensions<L: TlsLeft, T: CryptoSha256TranscriptProcessor>(
        &mut self,
        left: &mut L,
        transcript: &mut T,
    ) -> Result<(), TlsServerCtxError> {
        let key: [u8; 32] = match self.handshake_secret_key {
            None => return Err(TlsServerCtxError::MissingHandshakeKey),
            Some(k) => k,
        };

        let nonce: [u8; 12] = match self.handshake_server_iv {
            None => return Err(TlsServerCtxError::MissingHandshakeIv),
            Some(ref mut n) => match n.use_and_incr() {
                Some(cur) => cur,
                None => return Err(TlsServerCtxError::ExhaustedIv),
            },
        };

        let cipher = Crypto::aead_chaha20poly1305(&key);

        let mut encrypted_extensions =
            WrappedStaticRecordBuilder::<8192>::encrypted_extensions(self)
                .map_err(TlsServerCtxError::Builder)?;

        transcript.sha256_update(encrypted_extensions.as_hashing_context_ref());

        let tag = if let Ok([additional_data, encrypt_payload]) =
            encrypted_extensions.as_disjoint_mut_for_aead()
        {
            cipher
                .encrypt_in_place(&nonce, &additional_data, encrypt_payload.as_mut())
                .unwrap()
        } else {
            panic!("No disjoint.");
        };

        encrypted_extensions.set_auth_tag(&tag);

        left.send_record_out(encrypted_extensions.as_encoded_bytes());
        Ok(())
    }
}
