//! yTLS Server Config

/// Implement to provide configuration for the Tls Server Context
pub trait TlsServerCtxConfig {
    /// Implement to provide whether indicative host name (SNI) matches intended server name.
    fn dns_host_name(&self, _: &str) -> bool;
}
