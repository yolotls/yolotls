//! Signature Algorithms
//! https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc8446bis-14#appendix-B.3.1.3

#[derive(Debug, PartialEq)]
pub enum SignatureAlgorithm {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
    EcdsaSecp521r1Sha512,
    RsaPssRsaeSha256,
    RsaPssRsaeSha384,
    RsaPssRsaeSha512,
    Ed25519,
    Ed448,
    RsaPssPssSha256,
    RsaPssPssSha384,
    RsaPssPssSha512,
    RsaPkcs1Sha1,
    EcdsaSha1,
    Unknown(u16),
}

impl From<u16> for SignatureAlgorithm {
    fn from(r: u16) -> Self {
        match r {
            0x0401 => Self::RsaPkcs1Sha256,
            0x0501 => Self::RsaPkcs1Sha384,
            0x0601 => Self::RsaPkcs1Sha512,
            0x0403 => Self::EcdsaSecp256r1Sha256,
            0x0503 => Self::EcdsaSecp384r1Sha384,
            0x0603 => Self::EcdsaSecp521r1Sha512,
            0x0804 => Self::RsaPssRsaeSha256,
            0x0805 => Self::RsaPssRsaeSha384,
            0x0806 => Self::RsaPssRsaeSha512,
            0x0807 => Self::Ed25519,
            0x0808 => Self::Ed448,
            0x0809 => Self::RsaPssPssSha256,
            0x080a => Self::RsaPssPssSha384,
            0x080b => Self::RsaPssPssSha512,
            0x0201 => Self::RsaPkcs1Sha1,
            0x0203 => Self::EcdsaSha1,
            _ => Self::Unknown(r),
        }
    }
}
