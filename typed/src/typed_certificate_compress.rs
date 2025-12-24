//! Certificate Compressor types

#[derive(Debug, PartialEq)]
pub enum CertificateCompressKind {
    Zlib,
    Brotli,
    Zstd,
    Unknown(u16),
}

impl From<u16> for CertificateCompressKind {
    #[inline]
    fn from(r: u16) -> Self {
        match r {
            1 => Self::Zlib,
            2 => Self::Brotli,
            3 => Self::Zstd,
            _ => Self::Unknown(r),
        }
    }
}
