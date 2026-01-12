//! yTLS Common Handshake

#[derive(Default, Debug)]
pub enum HandshakeOrder {
    #[default]
    Created,
    ClientHello,
    ServerHello,
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
