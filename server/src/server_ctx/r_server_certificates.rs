//! Encrypted Extensions handler for Server Ctx

use crate::{TlsServerCtx, TlsServerCtxConfig, TlsServerCtxError};

use ytls_traits::CryptoChaCha20Poly1305Processor;
use ytls_traits::CryptoSha256TranscriptProcessor;

use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;
use ytls_traits::TlsLeft;

use ytls_record::WrappedStaticRecordBuilder;
use ytls_traits::ServerCertificatesBuilder;
use ytls_traits::WrappedHandshakeBuilder;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ServerCertificatesBuilder
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn server_certs_list(&self) -> &[u8] {
        self.config.server_cert_chain()
    }
    #[inline]
    fn server_cert_data(&self, id: u8) -> &[u8] {
        self.config.server_cert(id)
    }
    #[inline]
    fn server_cert_extensions(&self, _id: u8) -> &[u8] {
        &[]
    }
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> TlsServerCtx<C, Crypto, Rng> {
    #[inline]
    pub(crate) fn do_server_certificates<L: TlsLeft, T: CryptoSha256TranscriptProcessor>(
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

        let mut server_certificates = WrappedStaticRecordBuilder::<8192>::server_certificates(self)
            .map_err(TlsServerCtxError::Builder)?;

        //transcript.sha256_update(&server_certificates.wrapped_hash_header_ref());
        println!(
            "Server Certificates hash ctx len = {}",
            server_certificates.as_hashing_context_ref().len()
        );
        transcript.sha256_update(server_certificates.as_hashing_context_ref());

        let tag = if let Ok([additional_data, encrypt_payload]) =
            server_certificates.as_disjoint_mut_for_aead()
        {
            cipher
                .encrypt_in_place(&nonce, &additional_data, encrypt_payload.as_mut())
                .unwrap()
        } else {
            panic!("No disjoint.");
        };

        //transcript.sha256_update(&server_certificates.wrapped_hash_header_ref());
        //transcript.sha256_update(server_certificates.as_hashing_context_ref());

        server_certificates.set_auth_tag(&tag);

        left.send_record_out(server_certificates.as_encoded_bytes());
        Ok(())
    }
}
