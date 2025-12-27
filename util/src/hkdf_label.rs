//! HKDF Label utility for TLS

struct HkdfLabel {
}


impl HkdfLabel {
    #[inline]
    fn tls13_early_secret() -> &'static [u8] {
        b"tls13 derived e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
}
