//! yTls Server Context

use ytls_record::Record;

mod s_client_hello;

use crate::TlsServerCtxConfig;
use crate::TlsServerCtxError;

/// State machine context for yTLS Server
pub struct TlsServerCtx<C> {
    /// Downstream config implementation
    config: C,
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
}

impl<C: TlsServerCtxConfig> TlsServerCtx<C> {
    /// New yTLS server context with the given configuration
    pub fn with_config(config: C) -> Result<Self, TlsServerCtxError> {
        Ok(Self {
            config,
            downstream_found_host: false,
            group_x25519_supported: false,
            chacha20_poly1305_sha256_supported: false,
            sig_alg_ed25519_supported: false,
            tls13_supported: false,
            extended_main_secret: false,
            record_size_limit: 0,
            signed_cert_ts: false,
        })
    }
    /// Process incoming TLS Records
    pub fn process_tls_records(&mut self, data: &[u8]) -> Result<(), TlsServerCtxError> {
        let rec = Record::parse(self, data).map_err(|e| TlsServerCtxError::Record(e))?;
        println!("Rec = {:?}", rec);
        todo!()
    }
}
