//! TLS Versions

#[derive(Debug, PartialEq)]
pub enum Version {
    Tls12,
    Tls13,
    Unknown(u16),
}

impl From<u16> for Version {
    #[inline]
    fn from(r: u16) -> Self {
        match r {
            0x0303 => Self::Tls12,
            0x0304 => Self::Tls13,
            _ => Self::Unknown(r),
        }
    }
}
