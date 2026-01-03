//! Server handshake finished for Server Ctx

use crate::{TlsServerCtx, TlsServerCtxConfig, TlsServerCtxError};

use ytls_traits::CryptoSha256TranscriptProcessor;

use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;
use ytls_traits::TlsLeft;

use ytls_record::WrappedStaticRecordBuilder;
use ytls_traits::CryptoChaCha20Poly1305Processor;
use ytls_traits::ServerHandshakeFinishedBuilder;
use ytls_traits::WrappedHandshakeBuilder;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ServerHandshakeFinishedBuilder
    for TlsServerCtx<C, Crypto, Rng>
{
    fn hash_finished(&self) -> &[u8] {
        match self.hash_finished {
            Some(ref h) => h,
            None => &[],
        }
    }
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> TlsServerCtx<C, Crypto, Rng> {
    #[inline]
    pub(crate) fn do_server_handshake_finished<L: TlsLeft, T: CryptoSha256TranscriptProcessor>(
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

        // snapshot transcript hash for cert verify
        let ctx_transcript = transcript.sha256_fork();
        let ctx_hash_input = ctx_transcript.sha256_finalize();

        let hs_key = match self.handshake_finished_key {
            Some(ref k) => k,
            None => &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        };

        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(hs_key).expect("HMAC can take key of any size");
        mac.update(&ctx_hash_input);

        let finished_hmac = mac.finalize();

        self.hash_finished = Some(finished_hmac.into_bytes().into());

        let mut server_handshake_finished =
            WrappedStaticRecordBuilder::<8192>::server_handshake_finished(self)
                .map_err(TlsServerCtxError::Builder)?;

        transcript.sha256_update(server_handshake_finished.as_hashing_context_ref());

        let tag = if let Ok([additional_data, encrypt_payload]) =
            server_handshake_finished.as_disjoint_mut_for_aead()
        {
            cipher
                .encrypt_in_place(&nonce, &additional_data, encrypt_payload.as_mut())
                .unwrap()
        } else {
            panic!("No disjoint.");
        };

        server_handshake_finished.set_auth_tag(&tag);

        left.send_record_out(server_handshake_finished.as_encoded_bytes());
        Ok(())
    }
}
