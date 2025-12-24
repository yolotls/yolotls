//! yTLS Server Config

use ytls_typed::Alpn;

/// Implement to provide configuration for the Tls Server Context
pub trait TlsServerCtxConfig {
    /// Implement to provide whether indicative host name (SNI) matches intended server name.
    fn dns_host_name(&self, _: &str) -> bool;
    fn alpn<'r>(&self, _: Alpn<'r>) -> bool;
}
