//! Encrypted Extensions handler for Server Ctx

use crate::{TlsServerCtx, TlsServerCtxConfig, TlsServerCtxError};

use ytls_traits::CryptoChaCha20Poly1305Processor;
use ytls_traits::CryptoSha256TranscriptProcessor;
use ytls_traits::CryptoSignerP256Processor;

use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;
use ytls_traits::TlsLeft;

use ytls_record::WrappedStaticRecordBuilder;
use ytls_traits::ServerCertificateVerifyBuilder;
use ytls_traits::WrappedHandshakeBuilder;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ServerCertificateVerifyBuilder
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn signature_algorithm(&self) -> [u8; 2] {
        // ecdsa_secp256r1_sha256
        [0x04, 0x03]
    }
    #[inline]
    fn sign_cert_verify(&self) -> &[u8] {
        match self.signature_cert_verify {
            Some(ref s) => &s[..self.signature_cert_verify_len],
            None => &[],
        }
    }
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> TlsServerCtx<C, Crypto, Rng> {
    #[inline]
    pub(crate) fn do_server_certificate_verify<L: TlsLeft, T: CryptoSha256TranscriptProcessor>(
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

        //use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        //let signing_key = SigningKey::try_from(raw_signing_key).unwrap();

        // snapshot transcript hash for cert verify
        let ctx_transcript = transcript.sha256_fork();
        let ctx_hash_input = ctx_transcript.sha256_finalize();
        self.cert_verify_hash = Some(ctx_hash_input);

        let h = match self.cert_verify_hash {
            Some(h) => h,
            None => panic!("No hash."),
        };

        // +64 bytes of 0x20 (30)
        // +33 bytes of "Context"
        //  +1 byte content separator
        // +32 bytes of hash
        // ---------------------------
        // 130 bytes total
        let verify: [u8; 130] = [
            // 1     2     3     4     5     6     7     8     9     0
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            //  123456789012345678901234567890123  (33 bytes)
            // "TLS 1.3, server CertificateVerify"
            0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65,
            0x72, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56,
            0x65, 0x72, 0x69, 0x66, 0x79, // content separator \0 (1 byte)
            0x00, // 32 bytes hash
            h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13],
            h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25],
            h[26], h[27], h[28], h[29], h[30], h[31],
        ];

        //let signature: Signature = signing_key.sign(&verify);

        //let der_bytes = signature.to_der();

        //let bytes = der_bytes.as_bytes();

        //c_bytes[0..bytes.len()].copy_from_slice(&bytes);

        let raw_signing_key = self.config.server_private_key();
        let signer = match Crypto::sign_p256_init(raw_signing_key) {
            Some(signer) => signer,
            None => return Err(TlsServerCtxError::PrivateKey),
        };
        let mut c_bytes: [u8; 100] = [0; 100];
        let c_bytes_len = match signer.sign_p256(&verify, &mut c_bytes) {
            None => return Err(TlsServerCtxError::Crypto),
            Some(out_len) => out_len,
        };

        self.signature_cert_verify = Some(c_bytes);
        self.signature_cert_verify_len = c_bytes_len;

        let cipher = Crypto::aead_chaha20poly1305(&key);

        let mut server_certificate_verify =
            WrappedStaticRecordBuilder::<8192>::server_certificate_verify(self)
                .map_err(TlsServerCtxError::Builder)?;

        transcript.sha256_update(server_certificate_verify.as_hashing_context_ref());

        let tag = if let Ok([additional_data, encrypt_payload]) =
            server_certificate_verify.as_disjoint_mut_for_aead()
        {
            cipher
                .encrypt_in_place(&nonce, &additional_data, encrypt_payload.as_mut())
                .unwrap()
        } else {
            panic!("No disjoint.");
        };

        server_certificate_verify.set_auth_tag(&tag);

        left.send_record_out(server_certificate_verify.as_encoded_bytes());
        Ok(())
    }
}
