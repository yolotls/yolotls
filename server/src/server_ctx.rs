//! yTls Server Context

use ytls_record::Content;
use ytls_record::MsgType;
use ytls_record::Record;

mod r_server_hello;
mod s_client_hello;

use ytls_traits::TlsLeft;
use ytls_traits::CryptoConfig;

use ytls_traits::CryptoX25519Processor;
use ytls_traits::CryptoSha256TranscriptProcessor;
use ytls_traits::CryptoSha384TranscriptProcessor;
use ytls_traits::CryptoSha256HkdfExtractProcessor;
use ytls_traits::CryptoSha256HkdfGenProcessor;

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
    /// Handshake secret key
    handshake_secret_key: Option<[u8; 32]>,
    /// Handshake secret iv
    handshake_secret_iv: Option<[u8; 12]>,    
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
            handshake_secret_key: None,
            handshake_secret_iv: None,
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
            Content::ApplicationData => {
                println!("ApplicationData ..  = {}", hex::encode(rec.as_bytes()));

                let handshake_secret_key = match self.handshake_secret_key {
                    Some(k) => k,
                    None => return Err(TlsServerCtxError::UnexpectedAppData),
                };

                //let tag = cipher.decrypt_inout_detached(&nonce, b"", app_data[5..].as_mut().into()).unwrap();
                
            },
            Content::Handshake(content) => {
                let msg = content.msg();
                match msg {
                    MsgType::ClientHello(h) => {

                        //println!("ClientHello len<{}> bytes = {}", rec.as_bytes().len(), hex::encode(rec.as_bytes()));
                        
                        let shared_secret = match self.shared_secret {
                            Some(s) => s,
                            None => return Err(TlsServerCtxError::Bug("Supposed to have shared secret and was not guarded.")),
                        };
                        
                        let mut transcript = Crypto::sha256_init();
                        transcript.sha256_update(rec.as_bytes());
                        println!("ClientHello = {:?}", h);
                        self.do_server_hello(l, &mut transcript)?;
                        let hello_hash = transcript.sha256_finalize();                        

                        //use hkdf::Hkdf;
                        //use sha2::Sha256;

                        let hkdf = Crypto::hkdf_sha256_init();
                        
                        //*****************************************************
                        //  early_secret = HKDF-Extract(salt: 00, key: 00...)
                        //-----------------------------------------------------
                        let ikm: [u8; 32] = [0; 32];
                        let salt: [u8; 1] = [0; 1];

                        let (early_secret, hk_early) = hkdf.hkdf_sha256_extract(Some(&salt[..]), &ikm);
                        //let (early_secret, hk_early) = Hkdf::<Sha256>::extract(Some(&salt[..]), &ikm);
                        println!("early_secret = {}", hex::encode(early_secret));
                        
                        //*****************************************************                        
                        // empty_hash = SHA256("")
                        // derived_secret = HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 48)
                        //-----------------------------------------------------
                        let label_derived = ytls_util::HkdfLabelSha256::tls13_early_secret();
                        let mut derived_secret: [u8; 32] = [0; 32];
                        hk_early.hkdf_sha256_expand(&label_derived, &mut derived_secret);
                        //hk_early.expand(&label_derived, &mut derived_secret).unwrap();                        

                        //*****************************************************
                        // handshake_secret = HKDF-Extract(salt: derived_secret, key: shared_secret)
                        // client_secret = HKDF-Expand-Label(key: handshake_secret, label: "c hs traffic", ctx: hello_hash, len: 48)
                        // server_secret = HKDF-Expand-Label(key: handshake_secret, label: "s hs traffic", ctx: hello_hash, len: 48)
                        //-----------------------------------------------------
                        let (handshake_secret, mut hs_hk) = hkdf.hkdf_sha256_extract(Some(&derived_secret), &shared_secret);
                        //let (handshake_secret, hs_hk) = Hkdf::<Sha256>::extract(Some(&derived_secret), &shared_secret);

                        let label = ytls_util::HkdfLabelSha256::tls13_client_handshake_traffic(&hello_hash);
                        let mut client_secret: [u8; 32] = [0; 32];
                        hs_hk.hkdf_sha256_expand(&label, &mut client_secret);
                        //hs_hk.expand(&label, &mut client_secret).unwrap();
                        
                        let label = ytls_util::HkdfLabelSha256::tls13_server_handshake_traffic(&hello_hash);
                        let mut server_secret: [u8; 32] = [0; 32];
                        hs_hk.hkdf_sha256_expand(&label, &mut server_secret);
                        //hs_hk.expand(&label, &mut server_secret).unwrap();                        

                        /*
                        println!("Client Hello random = {}", hex::encode(self.client_random.unwrap()));
                        println!("Hello hash = {}", hex::encode(hello_hash));
                        println!("Public key = {}", hex::encode(self.public_key.unwrap()));
                        println!("Derived secret = {}", hex::encode(derived_secret));
                        println!("Shared secret = {}", hex::encode(shared_secret));
                        println!("Client secret = {}", hex::encode(client_secret));
                        */
                        println!("Server secret = {}", hex::encode(server_secret));
                        
                        // server_handshake_key = HKDF-Expand-Label(key: server_secret, label: "key", ctx: "", len: 32)
                        let mut server_handshake_key: [u8; 32] = [0; 32];
                        let mut server_handshake_iv: [u8; 12] = [0; 12];
                        let key_label = ytls_util::HkdfLabelSha256::tls13_server_secret_key(32);
                        let iv_label = ytls_util::HkdfLabelSha256::tls13_server_secret_iv();

                        let mut hk_key = match Crypto::hkdf_sha256_from_prk(&server_secret) {
                            Ok(hk_key) => hk_key,
                            Err(_) => panic!("hk_key"),
                        };
                        //let hk_key = Hkdf::<Sha256>::from_prk(&server_secret).expect("PRK should be large enough");
                        hk_key.hkdf_sha256_expand(&key_label, &mut server_handshake_key);
                        //hk_key.expand(&key_label, &mut server_handshake_key).unwrap();

                        let mut hk_iv = match Crypto::hkdf_sha256_from_prk(&server_secret) {
                            Ok(hk_iv) => hk_iv,
                            Err(_) => panic!("hk_iv"),
                        };
                        //let hk_iv = Hkdf::<Sha256>::from_prk(&server_secret).expect("PRK should be large enough");
                        hk_iv.hkdf_sha256_expand(&iv_label, &mut server_handshake_iv);
                        //hk_iv.expand(&iv_label, &mut server_handshake_iv).unwrap();

                        println!("*** Setting handshake secret key = {}", hex::encode(server_handshake_key));
                        println!("*** Setting handshake secret iv = {}", hex::encode(server_handshake_iv));
                        self.handshake_secret_key = Some(server_handshake_key);
                        self.handshake_secret_iv = Some(server_handshake_iv);
                        
                        use chacha20poly1305::{
                            aead::{AeadCore, AeadInOut, KeyInit},
                            ChaCha20Poly1305, Nonce
                        };
                        
                        let key: [u8; 32] = server_handshake_key;
                        let cipher = ChaCha20Poly1305::new(&key.into());

                        use inout::InOutBuf;

                        let mut app_data: [u8; 28] = [
                            // 5 bytes header (cleartext)
                            0x17, 0x03, 0x03, 0x00, 0x17,
                            // 7 bytes app data (to encrypt)
                            0x08, 0x00, 0x00, 0x02, 0x00, 0x00, 0x16,
                            // 16 bytes (encrypt auth tag)
                            00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
                            00, 00, 00, 00, 00, 00
                        ];

                        let nonce: Nonce = server_handshake_iv.into();

                        let tag = if let Ok([additional_data, encrypt_payload]) = app_data.get_disjoint_mut([0..5, 5..12]) {
                            cipher.encrypt_inout_detached(&nonce, &additional_data, encrypt_payload.as_mut().into()).unwrap()
                        }
                        else {
                            panic!("No disjoint.");
                        };
                        
                        println!("App_data[2] = {}", hex::encode(app_data));                        
                        println!("Tag = {}", hex::encode(tag));
                        
                        app_data[12..28].copy_from_slice(tag.as_slice());

                        l.send_record_out(&app_data);

                        println!("Sending out = {}", hex::encode(app_data));

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
