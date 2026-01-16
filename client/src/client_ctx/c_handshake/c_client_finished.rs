//! Client Finished

use crate::CtxError;
use crate::TlsClientCtxConfig;
use ytls_traits::{CryptoConfig, CryptoRng};

use crate::ClientHandshakeCtx;

use ytls_record::WrappedStaticRecordBuilder;
use ytls_traits::CryptoSha256HmacProcessor;
use ytls_traits::CryptoSha256TranscriptProcessor;
use ytls_traits::TlsLeftOut;
use ytls_traits::WrappedHandshakeBuilder;

use ytls_traits::ClientHandshakeFinishedBuilder;
use ytls_traits::CryptoChaCha20Poly1305Processor;

struct Finished {
    finished_hmac: [u8; 32],
}

impl ClientHandshakeFinishedBuilder for Finished {
    fn hash_finished(&self) -> &[u8] {
        &self.finished_hmac
    }
}

impl<Config, Crypto, Rng> ClientHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsClientCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    #[inline]
    pub(crate) fn do_client_handshake_finished<Lo: TlsLeftOut>(
        &mut self,
        left: &mut Lo,
    ) -> Result<(), CtxError> {
        let key: [u8; 32] = match self.handshake_client_key {
            None => return Err(CtxError::MissingHandshakeKey),
            Some(k) => k,
        };

        let nonce: [u8; 12] = match self.handshake_client_iv {
            None => return Err(CtxError::MissingHandshakeIv),
            Some(ref mut n) => match n.use_and_incr() {
                Some(cur) => cur,
                None => return Err(CtxError::ExhaustedIv),
            },
        };

        let cipher = Crypto::aead_chaha20poly1305(&key);
        let ctx_transcript = self.transcript.sha256_fork();
        let ctx_hash_input = ctx_transcript.sha256_finalize();

        let hs_key = match self.handshake_finished_client_key {
            Some(ref k) => k,
            None => &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        };

        let mut mac = Crypto::hmac_sha256_init_with_key(hs_key);
        mac.hmac_sha256_update(&ctx_hash_input);

        let finished_hmac = mac.hmac_sha256_finalize();

        let finished = Finished { finished_hmac };

        let mut client_handshake_finished =
            WrappedStaticRecordBuilder::<8192>::client_handshake_finished(&finished)
                .map_err(CtxError::Builder)?;

        self.transcript
            .sha256_update(client_handshake_finished.as_hashing_context_ref());

        let tag = if let Ok([additional_data, encrypt_payload]) =
            client_handshake_finished.as_disjoint_mut_for_aead()
        {
            cipher
                .encrypt_in_place(&nonce, &additional_data, encrypt_payload.as_mut())
                .map_err(|_| CtxError::Bug("Encrypt failure"))?
        } else {
            return Err(CtxError::Bug(
                "Disjoint for AEAD failed at client finished.",
            ));
        };

        client_handshake_finished.set_auth_tag(&tag);

        left.send_record_out(client_handshake_finished.as_encoded_bytes());
        Ok(())
    }
}
