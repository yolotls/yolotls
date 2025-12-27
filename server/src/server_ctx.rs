//! yTls Server Context

use ytls_record::Content;
use ytls_record::MsgType;
use ytls_record::Record;

mod r_server_hello;
mod s_client_hello;

use ytls_traits::TlsLeft;
use ytls_traits::CryptoConfig;

//use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use ytls_traits::CryptoX25519Processor;

use rand_core::CryptoRng;

use crate::TlsServerCtxConfig;
use crate::TlsServerCtxError;

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
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> TlsServerCtx<C, Crypto, Rng> {
    /// New yTLS server context with the given configuration
    pub fn with_config_and_crypto(config: C, crypto: Crypto, rng: Rng) -> Result<Self, TlsServerCtxError> {
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

        //println!("Rec = {:?}", rec);

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

        if self.shared_secret.is_none() {
            if let Some(pk) = self.client_x25519_pk {
                //let ephemeral_secret = EphemeralSecret::random();
                //let pub_key: PublicKey = pk.clone().into();
                //self.public_key = Some(pub_key.clone());
                //self.shared_secret = Some(ephemeral_secret.diffie_hellman(&pub_key));
                let x25519_ctx = self.crypto.x25519_init(&mut self.rng);
                self.public_key = Some(x25519_ctx.x25519_public_key());
                self.shared_secret = Some(x25519_ctx.x25519_shared_secret(&pk));
                self.key_share = self.key_share_x25519();
                println!("Key Share generated = {}", hex::encode(self.key_share));
            }
        }

        match rec.content() {
            Content::Handshake(content) => {
                let msg = content.msg();
                match msg {
                    MsgType::ClientHello(h) => {
                        println!("ClientHello rec bytes = {}", hex::encode(rec.as_bytes()));
                        println!("ClientHello = {:?}", h);
                        self.do_server_hello(l)?;
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
