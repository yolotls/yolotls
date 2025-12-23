//! yTls Server Context

use ytls_record::Record;

mod s_client_hello;

use crate::TlsServerCtxError;
use crate::TlsServerCtxConfig;

/// State machine context for yTLS Server
pub struct TlsServerCtx;

impl TlsServerCtx {
    /// New yTLS server context with the given configuration
    pub fn with_config(c: TlsServerCtxConfig) -> Result<Self, TlsServerCtxError> {
        Ok(Self {})
    }
    /// Process incoming TLS Records
    pub fn process_tls_records(&mut self, data: &[u8]) -> Result<(), TlsServerCtxError> {
        let rec = Record::parse(self, data)
            .map_err(|e| TlsServerCtxError::Record(e))?;
        println!("Rec = {:?}", rec);
        todo!()
    }
    
}
