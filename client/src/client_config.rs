//! yTLS Client Config

/// Implement to provide configuration for the TLS Client Context
pub trait TlsClientCtxConfig {
    /// Implement to provide indicative host name (SNI)
    fn dns_host_name(&self) -> &[u8];
    // Implement to provide ALPN
    //fn alpn<'r>(&self) -> Alpn<'r>;
}
