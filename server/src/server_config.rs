//! yTLS Server Config

use ytls_typed::Alpn;

/// Implement to provide configuration for the Tls Server Context
pub trait TlsServerCtxConfig {
    /// Implement to provide whether indicative host name (SNI) matches intended server name.
    fn dns_host_name(&self, _: &str) -> bool;
    /// Implement to provide whether given alpn matches intended alpn
    fn alpn<'r>(&self, _: Alpn<'r>) -> bool;
    /// Implenent to provide Server certificate chain listing certificate internal ids
    fn server_cert_chain(&self) -> &[u8];
    /// Implement to provide Server certificate by id key
    fn server_cert(&self, _id: u8) -> &[u8];
    /// Implement to provide Server private key
    fn server_private_key(&self) -> &[u8];
}
