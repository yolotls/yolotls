//! yTls Server Handshake Context

use ytls_record::Content;
use ytls_record::MsgType;
use ytls_record::Record;

mod r_server_hello;
mod s_client_finished;
mod s_client_hello;

mod r_encrypted_extensions;
mod r_server_certificate_verify;
mod r_server_certificates;
mod r_server_handshake_finished;

use ytls_traits::CryptoConfig;
use ytls_traits::{TlsLeftIn, TlsLeftOut};

use ytls_traits::CryptoSha256HkdfExtractProcessor;
use ytls_traits::CryptoSha256HkdfGenProcessor;
use ytls_traits::CryptoSha256TranscriptProcessor;
use ytls_traits::CryptoSha384TranscriptProcessor;
use ytls_traits::CryptoX25519Processor;

use ytls_keys::Tls13Keys;
use ytls_traits::SecretStore;
use ytls_traits::Tls13KeyScheduleApSha256;
use ytls_traits::Tls13KeyScheduleDerivedSha256;
use ytls_traits::Tls13KeyScheduleHandshakeSha256;
use ytls_traits::Tls13KeyScheduleInit;

use rand_core::CryptoRng;

use crate::TlsServerCtxConfig;
use crate::{Rfc8446Error, TlsServerCtxError};

use ytls_util::Nonce12;

use ytls_keys::Tls13KeysHandshakeSha256;

/// State machine context for yTLS Server
pub struct ServerHandshakeCtx<Config, Crypto, Rng> {
    /// Downstream config implementation
    config: Config,
    /// Downstream crypto implementation
    crypto: Crypto,
    /// Downstream rng implementation
    rng: Rng,
    /// Downstream found host through SNI
    downstream_found_host: bool,
    /// X25519 Group supported
    group_x25519_supported: bool,
    /// TLS_CHACHA20_POLY1305_SHA256 supported
    chacha20_poly1305_sha256_supported: bool,
    /// Ed25519 Signature Algorithm supported
    sig_alg_ed25519_supported: bool,
    /// TLS 1.3 supported
    tls13_supported: bool,
    /// Extended main secret used
    extended_main_secret: bool,
    /// Record size limit
    record_size_limit: u16,
    /// Signed Certificage Timestamps
    signed_cert_ts: bool,
    /// Sig alg RsaPkcs1Sha256 supported ?
    sig_alg_rsa_pkcs1_sha256_supported: bool,

    //--------------------------------------------
    // TODO: Move all of the below away from here
    //       some of these shoul get zeroized too
    //       probably best to do through type state
    //--------------------------------------------
    /// Client supplied random
    client_random: Option<[u8; 32]>,
    /// Client X25519 pk
    client_x25519_pk: Option<[u8; 32]>,
    /// Client Session Id (max 100 bytes)
    // TODO: handle this better.. this is wasteful - protocol is dumb wasting bytes here.
    client_session_id: Option<[u8; 100]>,
    /// Client Session Id len (max 100 bytes)
    client_session_len: usize,
    /// Curve25519 Public Key
    public_key: Option<[u8; 32]>,
    /// Handshake secrets
    // TODO: move these to vault provider and make sure they get zeroized
    /// Shared Secret
    shared_secret: Option<[u8; 32]>,
    /// Key Share for X25519
    key_share: [u8; 36],
    handshake_server_key: Option<[u8; 32]>,
    handshake_client_key: Option<[u8; 32]>,
    handshake_server_iv: Option<Nonce12>,
    handshake_client_iv: Option<Nonce12>,
    handshake_finished_server_key: Option<[u8; 32]>,
    handshake_finished_client_key: Option<[u8; 32]>,

    // TODO: get rid of these (atleast from here)
    signature_cert_verify: Option<[u8; 100]>,
    signature_cert_verify_len: usize,
    /// cert verify ctx hash sha256
    cert_verify_hash: Option<[u8; 32]>,
    /// Client+Server hellos hash
    hello_hash: Option<[u8; 32]>,
    /// Handshake finished hash
    hash_finished: Option<[u8; 32]>,

    is_complete: bool,
}

impl<Config, Crypto, Rng> ServerHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsServerCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    /// New yTLS server context with the given configuration
    pub fn with_required(config: Config, crypto: Crypto, rng: Rng) -> Self {
        Self {
            config,
            crypto,
            rng,
            downstream_found_host: false,
            group_x25519_supported: false,
            chacha20_poly1305_sha256_supported: false,
            sig_alg_ed25519_supported: false,
            tls13_supported: false,
            extended_main_secret: false,
            record_size_limit: 0,
            signed_cert_ts: false,
            sig_alg_rsa_pkcs1_sha256_supported: false,
            client_random: None,
            client_x25519_pk: None,
            client_session_id: None,
            client_session_len: 0,
            public_key: None,
            shared_secret: None,
            key_share: [0; 36],
            handshake_server_key: None,
            handshake_client_key: None,
            handshake_server_iv: None,
            handshake_client_iv: None,
            handshake_finished_server_key: None,
            handshake_finished_client_key: None,

            cert_verify_hash: None,
            hello_hash: None,
            hash_finished: None,
            signature_cert_verify: None,
            signature_cert_verify_len: 0,

            is_complete: false,
        }
    }
}

use ytls_traits::CtxApplicationProcessor;
use ytls_traits::CtxHandshakeProcessor;
use ytls_traits::HandshakeComplete;

impl<Config, Crypto, Rng> CtxHandshakeProcessor for ServerHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsServerCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    type Error = TlsServerCtxError;
    /// Spin yTLS Server Handshake Context
    #[inline]
    fn spin_handshake<Li: TlsLeftIn, Lo: TlsLeftOut, Ks: SecretStore>(
        &mut self,
        li: &mut Li,
        lo: &mut Lo,
        ks: &mut Ks,
    ) -> Result<Option<HandshakeComplete>, Self::Error> {
        if self.is_complete {
            return Ok(Some(HandshakeComplete));
        }

        let init_data = li.left_buf_in();
        let init_len = init_data.len();
        let mut data = init_data;

        #[allow(unused_assignments)]
        let mut consumed = 0;

        loop {
            let (rec, remaining) =
                Record::parse_client(self, data).map_err(|e| TlsServerCtxError::Record(e))?;

            consumed = init_len - remaining.len();
            println!(
                "Handshake consumed {consumed} Remaining len = {} out of initial {init_len}",
                remaining.len()
            );

            if self.shared_secret.is_none() {
                if let Some(pk) = self.client_x25519_pk {
                    let x25519_ctx = self.crypto.x25519_init(&mut self.rng);
                    self.public_key = Some(x25519_ctx.x25519_public_key());
                    self.shared_secret = Some(x25519_ctx.x25519_shared_secret(&pk));
                    self.key_share = self.key_share_x25519();
                    println!("Key Share generated = {}", hex::encode(self.key_share));
                }
            }

            match rec.content() {
                Content::ChangeCipherSpec => {
                    println!("ChangeCipherSpec .. = {}", hex::encode(rec.as_bytes()));
                }
                Content::ApplicationData => {
                    println!(
                        "ApplicationData {} ..  = {}",
                        hex::encode(rec.header_as_bytes()),
                        hex::encode(rec.as_bytes())
                    );

                    let key = match self.handshake_client_key {
                        Some(k) => k,
                        None => panic!("No key."),
                    };

                    let nonce: [u8; 12] = match self.handshake_client_iv {
                        None => return Err(TlsServerCtxError::MissingHandshakeIv),
                        Some(ref mut n) => match n.use_and_incr() {
                            Some(cur) => cur,
                            None => return Err(TlsServerCtxError::ExhaustedIv),
                        },
                    };

                    let cipher = Crypto::aead_chaha20poly1305(&key);

                    let full_payload = rec.as_bytes();
                    let full_payload_len = full_payload.len();

                    let mut tag: [u8; 16] = [0; 16];

                    let body_len = full_payload_len - 16;
                    let mut body: [u8; 200] = [0; 200];
                    body[0..body_len].copy_from_slice(&full_payload[0..body_len]);

                    tag.copy_from_slice(&full_payload[body_len..body_len + 16]);

                    let additional_data = rec.header_as_bytes();

                    use ytls_traits::CryptoChaCha20Poly1305Processor;
                    cipher
                        .decrypt_in_place(&nonce, &additional_data, &mut body[0..body_len], &tag)
                        .map_err(|_| TlsServerCtxError::Rfc8446(Rfc8446Error::Decrypt))?;

                    use ytls_record::{WrappedMsgType, WrappedRecord};
                    let r = WrappedRecord::parse_client(&body[0..body_len])
                        .map_err(|_| TlsServerCtxError::Rfc8446(Rfc8446Error::Unexpected))?;

                    use ytls_record::HandshakeMsg;

                    if let WrappedMsgType::Handshake(HandshakeMsg {
                        msg: MsgType::ClientFinished(f),
                        ..
                    }) = r.msg()
                    {
                        self.check_client_finished(&f)?;
                    } else {
                        return Err(TlsServerCtxError::Rfc8446(Rfc8446Error::Unexpected));
                    };

                    self.is_complete = true;
                }
                Content::Handshake(content) => {
                    let msg = content.msg();
                    match msg {
                        MsgType::ClientFinished(_) => {
                            return Err(TlsServerCtxError::Rfc8446(Rfc8446Error::Unexpected));
                        }
                        MsgType::ClientHello(h) => {
                            let shared_secret = match self.shared_secret {
                                Some(s) => s,
                                None => {
                                    return Err(TlsServerCtxError::Bug(
                                        "Supposed to have shared secret and was not guarded.",
                                    ))
                                }
                            };

                            let mut transcript = Crypto::sha256_init();
                            transcript.sha256_update(rec.as_bytes());
                            println!("ClientHello = {:?}", h);
                            self.do_server_hello(lo, &mut transcript)?;
                            let mut transcript_more = transcript.sha256_fork();
                            let hello_hash = transcript.sha256_finalize();

                            self.hello_hash = Some(hello_hash);

                            let k = Tls13Keys::<Crypto>::no_psk_with_crypto_and_sha256();
                            let hs_k = k.dh_x25519(&shared_secret, &hello_hash);

                            let mut server_handshake_iv: [u8; 12] = [0; 12];
                            let mut server_handshake_key: [u8; 32] = [0; 32];
                            let mut server_handshake_finished_key: [u8; 32] = [0; 32];
                            hs_k.handshake_server_iv(&mut server_handshake_iv);
                            hs_k.handshake_server_key(&mut server_handshake_key);
                            hs_k.handshake_server_finished_key(&mut server_handshake_finished_key);

                            self.handshake_server_key = Some(server_handshake_key);
                            self.handshake_server_iv =
                                Some(Nonce12::from_ks_iv(&server_handshake_iv));
                            self.handshake_finished_server_key =
                                Some(server_handshake_finished_key);

                            let mut client_handshake_iv: [u8; 12] = [0; 12];
                            let mut client_handshake_key: [u8; 32] = [0; 32];
                            let mut client_handshake_finished_key: [u8; 32] = [0; 32];
                            hs_k.handshake_client_iv(&mut client_handshake_iv);
                            hs_k.handshake_client_key(&mut client_handshake_key);
                            hs_k.handshake_client_finished_key(&mut client_handshake_finished_key);
                            self.handshake_client_key = Some(client_handshake_key);
                            self.handshake_client_iv =
                                Some(Nonce12::from_ks_iv(&client_handshake_iv));
                            self.handshake_finished_client_key =
                                Some(client_handshake_finished_key);

                            self.do_encrypted_extensions(lo, &mut transcript_more)?;

                            self.do_server_certificates(lo, &mut transcript_more)?;

                            self.do_server_certificate_verify(lo, &mut transcript_more)?;

                            self.do_server_handshake_finished(lo, &mut transcript_more)?;

                            let finish_handshake_hash =
                                transcript_more.sha256_fork().sha256_finalize();
                            self.hash_finished = Some(finish_handshake_hash);

                            let ap_k = hs_k.finished_handshake(&finish_handshake_hash);

                            let mut server_application_iv: [u8; 12] = [0; 12];
                            let mut server_application_key: [u8; 32] = [0; 32];
                            let mut client_application_iv: [u8; 12] = [0; 12];
                            let mut client_application_key: [u8; 32] = [0; 32];

                            ap_k.application_server_key(&mut server_application_key);
                            ap_k.application_server_iv(&mut server_application_iv);
                            ap_k.application_client_key(&mut client_application_key);

                            ap_k.application_client_iv(&mut client_application_iv);

                            ks.store_ap_client_key(&client_application_key);
                            ks.store_ap_client_iv(&client_application_iv);
                            ks.store_ap_server_key(&server_application_key);
                            ks.store_ap_server_iv(&server_application_iv);
                            /*
                                *ks = super::KeyStoreAp::Complete(
                                    super::KeyStoreApComplete {
                                        application_server_key: server_application_key,
                                        application_client_key: client_application_key,
                                        application_server_iv:
                                        Nonce12::from_ks_iv(&server_application_iv),
                                        application_client_iv:
                                        Nonce12::from_ks_iv(&client_application_iv)
                                    }
                            );
                                */
                        }
                    }
                }
                Content::Alert(alert) => {
                    println!("Alert = {:?}", alert);
                }
            }

            if remaining.len() == 0 {
                break;
            }

            data = remaining;
        }

        li.left_buf_mark_discard_in(consumed);

        if self.is_complete {
            println!("Completion...");
            return Ok(Some(HandshakeComplete));
        }

        Ok(None)
    }
}
