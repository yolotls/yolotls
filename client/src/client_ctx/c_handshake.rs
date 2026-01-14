//! yTls Client Handshake Context

use ytls_record::Content;
use ytls_record::MsgType;
use ytls_record::Record;

use ytls_traits::CryptoConfig;
use ytls_traits::{TlsLeftIn, TlsLeftOut};

use ytls_traits::CryptoSha256TranscriptProcessor;
//use ytls_traits::CryptoSha256HkdfExtractProcessor;
//use ytls_traits::CryptoSha256HkdfGenProcessor;
//use ytls_traits::CryptoSha384TranscriptProcessor;
use ytls_traits::CryptoX25519Processor;

use ytls_keys::Tls13Keys;
use ytls_traits::SecretStore;
use ytls_traits::Tls13KeyScheduleApSha256;
use ytls_traits::Tls13KeyScheduleDerivedSha256;
use ytls_traits::Tls13KeyScheduleHandshakeSha256;
use ytls_traits::Tls13KeyScheduleInit;

use rand_core::CryptoRng;

use crate::TlsClientCtxConfig;
use crate::{CtxError, Rfc8446Error};

use ytls_util::Nonce12;

use ytls_ctx::HandshakeOrder;
use ytls_keys::Tls13KeysHandshakeSha256;

mod c_client_hello;

mod c_client_finished;
mod p_server_hello;
mod p_wrapped;
use p_server_hello::{ServerHello, ServerRecord};

/// State machine context for yTLS CLient
pub struct ClientHandshakeCtx<Config, Crypto: CryptoConfig, Rng> {
    /// Downstream config implementation
    config: Config,
    /// Downstream crypto implementation
    crypto: Crypto,
    /// Downstream rng implementation
    rng: Rng,

    cur: HandshakeOrder,

    transcript: Crypto::Hasher,
    x25519: Option<Crypto::X25519>,

    handshake_client_key: Option<[u8; 32]>,
    handshake_client_iv: Option<Nonce12>,
    handshake_server_key: Option<[u8; 32]>,
    handshake_server_iv: Option<Nonce12>,

    handshake_finished_server_key: Option<[u8; 32]>,
    handshake_finished_client_key: Option<[u8; 32]>,

    key_schedule: Option<([u8; 32], [u8; 32], [u8; 32])>,

    is_complete: bool,
}

impl<Config, Crypto, Rng> ClientHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsClientCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    /// New yTLS server context with the given configuration
    pub fn with_required(config: Config, crypto: Crypto, mut rng: Rng) -> Self {
        let x25519 = Crypto::ecdhe_x25519(&mut rng);

        Self {
            config,
            crypto,
            rng,

            cur: HandshakeOrder::default(),
            transcript: Crypto::hasher_sha256(),
            x25519: Some(x25519),

            handshake_client_key: None,
            handshake_client_iv: None,
            handshake_server_key: None,
            handshake_server_iv: None,

            handshake_finished_server_key: None,
            handshake_finished_client_key: None,

            key_schedule: None,

            is_complete: false,
        }
    }
}

use ytls_traits::CtxHandshakeProcessor;
use ytls_traits::HandshakeComplete;

impl<Config, Crypto, Rng> CtxHandshakeProcessor for ClientHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsClientCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    type Error = CtxError;
    /// Spin yTLS Client Handshake Context
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

        if self.cur.cur_is_created() {
            self.do_client_hello(lo)?;
            self.cur = HandshakeOrder::ClientHello;
        }

        let init_data = li.left_buf_in();
        let init_len = init_data.len();
        let mut data = init_data;

        #[allow(unused_assignments)]
        let mut consumed = 0;

        loop {
            if data.len() == 0 {
                break;
            }

            let mut prc = ServerRecord::default();

            let (rec, remaining) =
                Record::parse_server(&mut prc, data).map_err(|e| CtxError::Record(e))?;

            consumed = init_len - remaining.len();

            match rec.content() {
                Content::ChangeCipherSpec => {
                    // ignore
                    // todo: check the content compliant w/ 8446
                }
                Content::ApplicationData => {
                    match self.cur {
                        HandshakeOrder::ServerHello => {}
                        HandshakeOrder::ServerCertificates => {}
                        HandshakeOrder::ServerCertificateVerify => {}
                        HandshakeOrder::ServerFinished => {}
                        _ => return Err(CtxError::Rfc8446(Rfc8446Error::Unexpected)),
                    }

                    let key = match self.handshake_server_key {
                        Some(k) => k,
                        None => {
                            return Err(CtxError::Bug(
                                "Expected to have Server Key by now and was not guarded.",
                            ))
                        }
                    };

                    let nonce: [u8; 12] = match self.handshake_server_iv {
                        None => {
                            return Err(CtxError::Bug(
                                "Expected to have Server Iv by now and was not guarded.",
                            ))
                        }
                        Some(ref mut n) => match n.use_and_incr() {
                            Some(cur) => cur,
                            None => return Err(CtxError::ExhaustedIv),
                        },
                    };

                    let cipher = Crypto::aead_chaha20poly1305(&key);

                    let full_payload = rec.as_bytes();
                    let full_payload_len = full_payload.len();

                    let mut tag: [u8; 16] = [0; 16];

                    let body_len = full_payload_len - 16;
                    let mut body: [u8; 8192] = [0; 8192];

                    body[0..body_len].copy_from_slice(&full_payload[0..body_len]);

                    tag.copy_from_slice(&full_payload[body_len..body_len + 16]);

                    let additional_data = rec.header_as_bytes();

                    use ytls_traits::CryptoChaCha20Poly1305Processor;
                    cipher
                        .decrypt_in_place(&nonce, &additional_data, &mut body[0..body_len], &tag)
                        .map_err(|_| CtxError::Rfc8446(Rfc8446Error::Decrypt))?;

                    use ytls_record::{WrappedMsgType, WrappedRecord};
                    let r = WrappedRecord::parse_server(self, &body[0..body_len])
                        .map_err(|_| CtxError::Rfc8446(Rfc8446Error::Unexpected))?;

                    let hashing_body = &body[0..body_len - 1];

                    use ytls_record::HandshakeMsg;

                    match r.msg() {
                        WrappedMsgType::Alert(_alert) => {
                            // do nothing with it for now
                        }
                        WrappedMsgType::Handshake(HandshakeMsg {
                            msg: MsgType::EncryptedExtensions,
                            ..
                        }) => {
                            // do nothing with it for now (we ensure it's 00 00)
                            self.transcript.sha256_update(hashing_body);
                        }
                        WrappedMsgType::Handshake(HandshakeMsg {
                            msg: MsgType::ServerCertificate,
                            req_ctx: Some(0),
                        }) => {
                            self.transcript.sha256_update(hashing_body);
                        }
                        WrappedMsgType::Handshake(HandshakeMsg {
                            msg: MsgType::ServerCertificateVerify,
                            ..
                        }) => {
                            self.transcript.sha256_update(hashing_body);
                        }
                        WrappedMsgType::Handshake(HandshakeMsg {
                            msg: MsgType::ServerFinished,
                            ..
                        }) => {
                            self.transcript.sha256_update(hashing_body);

                            let finish_hasher = self.transcript.sha256_fork();

                            self.do_client_handshake_finished(lo)?;

                            let hs_k: Tls13KeysHandshakeSha256<Crypto> = match self.key_schedule {
                                Some(secrets) => Tls13KeysHandshakeSha256::from_secrets(
                                    secrets.0, secrets.1, secrets.2,
                                ),
                                None => {
                                    return Err(CtxError::Bug(
                                        "Key schedule was not guarded for finish.",
                                    ))
                                }
                            };

                            let finish_handshake_hash = finish_hasher.sha256_finalize();

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

                            self.is_complete = true;
                        }
                        _ => {
                            return Err(CtxError::Rfc8446(Rfc8446Error::Unexpected));
                        }
                    }
                }
                Content::Handshake(content) => {
                    let msg = content.msg();

                    match msg {
                        MsgType::ServerHello(_h) => {
                            if self.cur != HandshakeOrder::ClientHello {
                                return Err(CtxError::Rfc8446(Rfc8446Error::Unexpected));
                            }

                            let server_pk = match prc.server_hello.pk_x25519 {
                                Some(pk) => pk,
                                None => return Err(CtxError::Rfc8446(Rfc8446Error::Unexpected)),
                            };

                            let mut x25519: Option<Crypto::X25519> = None;
                            core::mem::swap(&mut x25519, &mut self.x25519);

                            let x25519 = match x25519 {
                                Some(x) => x,
                                None => return Err(CtxError::Rfc8446(Rfc8446Error::Unexpected)),
                            };

                            let shared_secret = x25519.x25519_shared_secret(&server_pk);

                            self.transcript.sha256_update(rec.as_bytes());
                            let hello_transcript = self.transcript.sha256_fork();
                            let hello_hash = hello_transcript.sha256_finalize();

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

                            self.key_schedule = Some(hs_k.into_secrets());

                            self.cur = HandshakeOrder::ServerHello;
                        }
                        _ => {
                            return Err(CtxError::Rfc8446(Rfc8446Error::Unexpected));
                        }
                    }
                }
                Content::Alert(_alert) => {
                    // do nothing with it for now
                }
            }

            if remaining.len() == 0 {
                break;
            }

            data = remaining;
        }

        li.left_buf_mark_discard_in(consumed);

        if self.is_complete {
            return Ok(Some(HandshakeComplete));
        }

        Ok(None)
    }
}
