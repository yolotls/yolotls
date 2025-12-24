//! Typed (EC) Groups

#[derive(Debug, PartialEq)]
pub enum Group {
    /// RFC 8422 s. 5.11.
    Secp256r1,
    /// RFC 8422 s. 5.11.
    Secp384r1,
    /// RFC 8422 s. 5.11.    
    Secp521r1,
    /// RFC 8422 s. 5.11.
    X25519,
    /// RFC 8422 s. 5.11.
    X448,
    /// RFC 8422 s. 5.11.
    Ffdhe2048,
    /// RFC 7919 s. 8.3    
    Ffdhe3072,
    /// RFC 7919 s. 8.3    
    Ffdhe4096,
    /// RFC 7919 s. 8.3    
    Ffdhe6144,
    /// RFC 7919 s. 8.3
    Ffdhe8192,
    /// draft-kwiatkowski-tls-ecdhe-mlkem-03 s. 5
    SecP256r1Mlkem768,
    /// draft-kwiatkowski-tls-ecdhe-mlkem-03 s. 5
    X25519Mlkem768,
    /// draft-kwiatkowski-tls-ecdhe-mlkem-03 s. 5
    SecP384r1Mlkem1024,
    /// Unknown Group (may be in future RFC / drafts)
    Unknown(u16),
}

impl From<u16> for Group {
    #[inline]
    fn from(d: u16) -> Self {
        match d {
            // RFC 8422 s. 5.11.
            23 => Self::Secp256r1,
            // RFC 8422 s. 5.11.
            24 => Self::Secp384r1,
            // RFC 8422 s. 5.11.
            25 => Self::Secp521r1,
            // RFC 8422 s. 5.11.
            29 => Self::X25519,
            // RFC 8422 s. 5.11.
            30 => Self::X448,
            // RFC 7919 s. 8.3
            256 => Self::Ffdhe2048,
            // RFC 7919 s. 8.3
            257 => Self::Ffdhe3072,
            // RFC 7919 s. 8.3
            258 => Self::Ffdhe4096,
            // RFC 7919 s. 8.3
            259 => Self::Ffdhe6144,
            // RFC 7919 s. 8.3
            260 => Self::Ffdhe8192,
            // draft-ietf-tls-hybrid-design-16 & draft-kwiatkowski-tls-ecdhe-mlkem-03
            4587 => Self::SecP256r1Mlkem768,
            // draft-kwiatkowski-tls-ecdhe-mlkem-03 s. 5.2
            4588 => Self::X25519Mlkem768,
            // draft-kwiatkowski-tls-ecdhe-mlkem-03 s. 5.3
            4589 => Self::SecP384r1Mlkem1024,
            // draft-kwiatkowski-tls-ecdhe-mlkem-03 Obsoletes 25497 and 25498
            _ => Self::Unknown(d),
        }
    }
}
