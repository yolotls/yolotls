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
//use ytls_traits::CryptoX25519Processor;

//use ytls_keys::Tls13Keys;
use ytls_traits::SecretStore;
//use ytls_traits::Tls13KeyScheduleApSha256;
//use ytls_traits::Tls13KeyScheduleDerivedSha256;
//use ytls_traits::Tls13KeyScheduleHandshakeSha256;
//use ytls_traits::Tls13KeyScheduleInit;

use rand_core::CryptoRng;

use crate::TlsClientCtxConfig;
use crate::{CtxError, Rfc8446Error};

use ytls_util::Nonce12;

use ytls_ctx::HandshakeOrder;
use ytls_keys::Tls13KeysHandshakeSha256;

mod c_client_hello;

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

    handshake_client_key: Option<[u8; 32]>,
    handshake_client_iv: Option<Nonce12>,
    handshake_server_key: Option<[u8; 32]>,
    handshake_server_iv: Option<Nonce12>,

    is_complete: bool,
}

impl<Config, Crypto, Rng> ClientHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsClientCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    /// New yTLS server context with the given configuration
    pub fn with_required(config: Config, crypto: Crypto, rng: Rng) -> Self {
        Self {
            config,
            crypto,
            rng,

            cur: HandshakeOrder::default(),
            transcript: Crypto::hasher_sha256(),

            handshake_client_key: None,
            handshake_client_iv: None,
            handshake_server_key: None,
            handshake_server_iv: None,

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
            //            let (rec, remaining) =
            //                Record::parse_server(self, data).map_err(|e| CtxError::Record(e))?;

            println!("Todo: to parse {}", hex::encode(data));

            let remaining = &[];

            consumed = init_len - remaining.len();

            /*
                if self.shared_secret.is_none() {
                    if let Some(pk) = self.client_x25519_pk {
                        let x25519_ctx = self.crypto.x25519_init(&mut self.rng);
                        self.public_key = Some(x25519_ctx.x25519_public_key());
                        self.shared_secret = Some(x25519_ctx.x25519_shared_secret(&pk));
                        self.key_share = self.key_share_x25519();
                    }
            }
                */

            /*
            match rec.content() {
                Content::ChangeCipherSpec => {
                    // ignore
                }
                Content::ApplicationData => {
                    todo!()
                    let key = match self.handshake_server_key {
                        Some(k) => k,
                        None => panic!("No key."),
                    };

                    let nonce: [u8; 12] = match self.handshake_server_iv {
                        None => return Err(CtxError::MissingHandshakeIv),
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

                    println!("Additional data: {}, body: {}", &additional_data, &body[0..body_len]);

                    use ytls_record::{WrappedMsgType, WrappedRecord};
                    let r = WrappedRecord::parse_client(&body[0..body_len])
                        .map_err(|_| CtxError::Rfc8446(Rfc8446Error::Unexpected))?;

                    use ytls_record::HandshakeMsg;

                    match r.msg() {
                        WrappedMsgType::Handshake(HandshakeMsg {
                            msg: MsgType::ClientFinished(f),
                            ..
                        }) => {
                            todo!()
                            self.check_client_finished(&f)?;
                            self.is_complete = true;
                        }
                        WrappedMsgType::Alert(_alert) => {
                            // do nothing with it for now
                        }
                        _ => {
                            return Err(CtxError::Rfc8446(Rfc8446Error::Unexpected));
                        }
                    }
                }
                Content::Handshake(content) => {
                    let msg = content.msg();
                    todo!()
                    /*
                    match msg {
                        MsgType::ServerFinished(_) => {
                            todo!()
                        }
                        MsgType::ServerHello(_h) => {
                            todo!()
                        }
                    }
                     */
                }
                Content::Alert(_alert) => {
                    // do nothing with it for now
                }
            }
            */

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
