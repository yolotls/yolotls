//! yTLS Common Handshake

#[derive(Default, Debug, PartialEq)]
pub enum HandshakeOrder {
    #[default]
    Created,
    ClientHello,
    ServerHello,
    EncryptedExtensions,
    ServerCertificates,
    ServerCertificateVerify,
    ServerFinished,
    ClientFinished,
}

impl HandshakeOrder {
    /// Is current at Created stage
    #[inline]
    pub fn cur_is_created(&self) -> bool {
        match self {
            Self::Created => true,
            _ => false,
        }
    }
}
