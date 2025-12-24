//! yTLS Cipher Suites
//! See the list from IANA
//! https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4

#[derive(Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum TlsCipherSuite {
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    /// MTI - draft-ietf-tls-rfc8446bis-14 (MUST)
    TLS_AES_128_GCM_SHA256,
    /// MTI - draft-ietf-tls-rfc8446bis-14 (SHOULD)
    TLS_AES_256_GCM_SHA384,
    /// MTI (SHOULD)
    TLS_CHACHA20_POLY1305_SHA256,
    /// Recommended
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    /// Recommended
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    /// Recommended
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    /// Recommended
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,

    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,

    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
    /// Unknown
    Unknown([u8; 2]),
}

impl From<&[u8; 2]> for TlsCipherSuite {
    fn from(raw: &[u8; 2]) -> TlsCipherSuite {
        match raw {
            [0x00, 0x2F] => Self::TLS_RSA_WITH_AES_128_CBC_SHA,
            [0x00, 0x35] => Self::TLS_RSA_WITH_AES_256_CBC_SHA,
            [0x00, 0x9C] => Self::TLS_RSA_WITH_AES_128_GCM_SHA256,
            [0x00, 0x9D] => Self::TLS_RSA_WITH_AES_256_GCM_SHA384,

            [0x13, 0x01] => Self::TLS_AES_128_GCM_SHA256,
            [0x13, 0x02] => Self::TLS_AES_256_GCM_SHA384,
            [0x13, 0x03] => Self::TLS_CHACHA20_POLY1305_SHA256,

            [0xC0, 0x09] => Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            [0xC0, 0x0A] => Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            [0xC0, 0x13] => Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            [0xC0, 0x14] => Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,

            [0xC0, 0x2B] => Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            [0xC0, 0x2C] => Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            [0xC0, 0x2F] => Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            [0xC0, 0x30] => Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            [0xCC, 0xA8] => Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            [0xCC, 0xA9] => Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            [0xCC, 0xAA] => Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            [0xCC, 0xAC] => Self::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            [0xCC, 0xAD] => Self::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            [0xD0, 0x01] => Self::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
            [0xD0, 0x02] => Self::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
            _ => Self::Unknown([raw[0], raw[1]]),
        }
    }
}
