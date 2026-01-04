//! yTls Server Context

use ytls_record::Content;
use ytls_record::MsgType;
use ytls_record::Record;

mod r_server_hello;
mod s_client_hello;

mod r_encrypted_extensions;
mod r_server_certificate_verify;
mod r_server_certificates;
mod r_server_handshake_finished;

use ytls_traits::CryptoConfig;
use ytls_traits::TlsLeft;

use ytls_traits::CryptoSha256HkdfExtractProcessor;
use ytls_traits::CryptoSha256HkdfGenProcessor;
use ytls_traits::CryptoSha256TranscriptProcessor;
use ytls_traits::CryptoSha384TranscriptProcessor;
use ytls_traits::CryptoX25519Processor;

use ytls_keys::Tls13Keys;
use ytls_traits::Tls13KeyScheduleDerivedSha256;
use ytls_traits::Tls13KeyScheduleHandshakeSha256;
use ytls_traits::Tls13KeyScheduleInit;

use rand_core::CryptoRng;

use crate::TlsServerCtxConfig;
use crate::TlsServerCtxError;

use ytls_util::Nonce12;

/// State machine context for yTLS Server
pub struct TlsServerCtx<Config, Crypto, Rng> {
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
    /// Shared Secret
    shared_secret: Option<[u8; 32]>,
    /// Key Share for X25519
    key_share: [u8; 36],
    /// Handshake secret key
    handshake_secret_key: Option<[u8; 32]>,
    handshake_server_iv: Option<Nonce12>,
    handshake_finished_key: Option<[u8; 32]>,
    signature_cert_verify: Option<[u8; 100]>,
    signature_cert_verify_len: usize,
    /// cert verify ctx hash sha256
    cert_verify_hash: Option<[u8; 32]>,
    /// Client+Server hellos hash
    hello_hash: Option<[u8; 32]>,
    /// Handshake finished hash
    hash_finished: Option<[u8; 32]>,
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> TlsServerCtx<C, Crypto, Rng> {
    /// New yTLS server context with the given configuration
    pub fn with_config_and_crypto(
        config: C,
        crypto: Crypto,
        rng: Rng,
    ) -> Result<Self, TlsServerCtxError> {
        Ok(Self {
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
            handshake_secret_key: None,
            handshake_server_iv: None,
            handshake_finished_key: None,
            cert_verify_hash: None,
            hello_hash: None,
            hash_finished: None,
            signature_cert_verify: None,
            signature_cert_verify_len: 0,
        })
    }
    /// Process incoming TLS Records
    //    pub fn process_tls_records<L: TlsLeft, R: CryptoRng>(
    pub fn process_tls_records<L: TlsLeft>(
        &mut self,
        l: &mut L,
        //rng: &mut R,
        data: &[u8],
    ) -> Result<(), TlsServerCtxError> {
        let (rec, _remaining) =
            Record::parse_client(self, data).map_err(|e| TlsServerCtxError::Record(e))?;

        println!("---- context spinning");

        //println!("Rec = {:?}", rec);

        /*
            println!("TLS13 Supported = {}", self.tls13_supported);
            println!(
                "chacha20_poly1305_sha256_supported = {}",
                self.chacha20_poly1305_sha256_supported
            );
            println!(
                "sig_alg_ed25519_supported_supported = {}",
                self.sig_alg_ed25519_supported
            );
            println!("extended_main_secret = {}", self.extended_main_secret);
            println!("record_size_limit = {}", self.record_size_limit);
            println!("signed_cert_ts = {}", self.signed_cert_ts);
            println!("group_x25519_supported = {}", self.group_x25519_supported);
            println!("downstream_found_host = {}", self.downstream_found_host);
            println!(
                "sig_alg_rsa_pkcs1_sha256_supported = {}",
                self.sig_alg_rsa_pkcs1_sha256_supported
        );
            */

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
                println!("ApplicationData ..  = {}", hex::encode(rec.as_bytes()));

                // TODO: decrypt
            }
            Content::Handshake(content) => {
                let msg = content.msg();
                match msg {
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
                        self.do_server_hello(l, &mut transcript)?;
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

                        self.handshake_secret_key = Some(server_handshake_key);
                        self.handshake_server_iv = Some(Nonce12::from_ks_iv(&server_handshake_iv));
                        self.handshake_finished_key = Some(server_handshake_finished_key);

                        self.do_encrypted_extensions(l, &mut transcript_more)?;

                        self.do_server_certificates(l, &mut transcript_more)?;

                        self.do_server_certificate_verify(l, &mut transcript_more)?;

                        self.do_server_handshake_finished(l, &mut transcript_more)?;
                    }
                }
            }
            Content::Alert(alert) => {
                println!("Alert = {:?}", alert);
            }
        }

        Ok(())
    }
}
