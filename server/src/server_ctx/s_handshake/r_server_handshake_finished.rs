//! Server handshake finished for Server Handshake Ctx

use crate::{ServerHandshakeCtx, TlsServerCtxConfig, CtxError};

use ytls_traits::CryptoSha256TranscriptProcessor;

use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;
use ytls_traits::TlsLeftOut;

use ytls_record::WrappedStaticRecordBuilder;
use ytls_traits::CryptoChaCha20Poly1305Processor;
use ytls_traits::CryptoSha256HmacProcessor;
use ytls_traits::ServerHandshakeFinishedBuilder;
use ytls_traits::WrappedHandshakeBuilder;

use ytls_traits::Tls13KeyScheduleHandshakeSha256;

impl<Config, Crypto, Rng> ServerHandshakeFinishedBuilder for ServerHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsServerCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    fn hash_finished(&self) -> &[u8] {
        match self.hash_finished {
            Some(ref h) => h,
            None => &[],
        }
    }
}

impl<Config, Crypto, Rng> ServerHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsServerCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    #[inline]
    pub(crate) fn do_server_handshake_finished<
        L: TlsLeftOut,
        T: CryptoSha256TranscriptProcessor,
    >(
        &mut self,
        left: &mut L,
        transcript: &mut T,
    ) -> Result<(), CtxError> {
        let key: [u8; 32] = match self.handshake_server_key {
            None => return Err(CtxError::MissingHandshakeKey),
            Some(k) => k,
        };

        let nonce: [u8; 12] = match self.handshake_server_iv {
            None => return Err(CtxError::MissingHandshakeIv),
            Some(ref mut n) => match n.use_and_incr() {
                Some(cur) => cur,
                None => return Err(CtxError::ExhaustedIv),
            },
        };

        let cipher = Crypto::aead_chaha20poly1305(&key);

        // snapshot transcript hash for cert verify
        let ctx_transcript = transcript.sha256_fork();
        let ctx_hash_input = ctx_transcript.sha256_finalize();

        let hs_key = match self.handshake_finished_server_key {
            Some(ref k) => k,
            None => &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        };

        let mut mac = Crypto::hmac_sha256_init_with_key(hs_key);
        mac.hmac_sha256_update(&ctx_hash_input);

        let finished_hmac = mac.hmac_sha256_finalize();

        self.hash_finished = Some(finished_hmac);

        let mut server_handshake_finished =
            WrappedStaticRecordBuilder::<8192>::server_handshake_finished(self)
                .map_err(CtxError::Builder)?;

        transcript.sha256_update(server_handshake_finished.as_hashing_context_ref());

        let tag = if let Ok([additional_data, encrypt_payload]) =
            server_handshake_finished.as_disjoint_mut_for_aead()
        {
            cipher
                .encrypt_in_place(&nonce, &additional_data, encrypt_payload.as_mut())
                .unwrap()
        } else {
            return Err(CtxError::Bug(
                "Disjoint for AEAD failed at certificate verify.",
            ));
        };

        server_handshake_finished.set_auth_tag(&tag);

        left.send_record_out(server_handshake_finished.as_encoded_bytes());
        Ok(())
    }
}
