//! Hybrid Public Key Encryption types

/// Key Derivation Functions (KDFs)
#[derive(Debug, PartialEq)]
pub enum HkdfKind {
    /// 0x0001, Nh 32, RFC 5869
    HkdfSha256,
    /// 0x0002, Nh 48, RFC 5869
    HkdfSha384,
    /// 0x0003, Nh 64, RFC 5869
    HkdfSha512,
    /// Unknown
    Unknown(u16),
}

impl From<u16> for HkdfKind {
    fn from(r: u16) -> Self {
        match r {
            1 => Self::HkdfSha256,
            2 => Self::HkdfSha384,
            3 => Self::HkdfSha512,
            _ => Self::Unknown(r),
        }
    }
}

/// Authenticated Encryption with Associated Data (AEAD) Functions
#[derive(Debug, PartialEq)]
pub enum HaeadKind {
    /// 0x0001, Nk 16, Nn 12, Nt 16, RFC 9180 #GCM
    Aes128Gcm,
    /// 0x0002, Nk 32, Nn 12, Nt 16, RFC 9180 #GCM
    Aes256Gcm,
    /// 0x0003, NK 32, Nn 12, Nt 16, RFC 8349
    ChaCha20Poly1305,
    /// Unknown
    Unknown(u16),
}

impl From<u16> for HaeadKind {
    fn from(r: u16) -> Self {
        match r {
            1 => Self::Aes128Gcm,
            2 => Self::Aes256Gcm,
            3 => Self::ChaCha20Poly1305,
            _ => Self::Unknown(r),
        }
    }
}
