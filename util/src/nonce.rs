use crypto_bigint::Encoding;

use crypto_bigint::U128;

/// Running 12-byte (U96) Nonce for ChaCha20Poly1305 / AES GCM AEADs
pub struct Nonce12 {
    iv: U128,
    seq_id: u64,
}

impl Nonce12 {
    /// Start Nonce12 with TLS1.2 Key Schedule derived 12-byte "IV"
    #[inline]
    pub fn from_ks_iv(i: &[u8; 12]) -> Self {
        let iv = U128::from_be_bytes([
            0, 0, 0, 0, i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8], i[9], i[10], i[11],
        ]);
        let seq_id = 0u64;

        Self { iv, seq_id }
    }
    /// Use current and return it whilst incrementing the packet sequence counter.
    #[inline]
    pub fn use_and_incr(&mut self) -> Option<[u8; 12]> {
        let seq_id = U128::from_u64(self.seq_id);
        let nonce_u128 = self.iv.wrapping_xor(&seq_id);
        let b: [u8; 16] = nonce_u128.to_be_bytes();

        if self.seq_id == u64::MAX {
            return None;
        }

        self.seq_id += 1;

        Some([
            b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
        ])
    }
    /// Through fast forward to X for testing purposes
    #[inline]
    #[cfg(test)]
    pub fn hazmat_fast_forward_with_incr(&mut self, fast_forward: u64) -> Option<[u8; 12]> {
        self.seq_id = fast_forward;
        self.use_and_incr()
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use hex_literal::hex;

    #[test]
    fn cur() {
        let iv_bytes: [u8; 12] = hex!("6fac81d4f2c3bebe02b8b375");
        let mut running_nonce = Nonce12::from_ks_iv(&iv_bytes);
        let cur = running_nonce.use_and_incr();

        assert_eq!(cur, Some(iv_bytes));
    }

    #[test]
    fn packet_seq_1() {
        let iv_bytes: [u8; 12] = hex!("6fac81d4f2c3bebe02b8b375");
        let mut running_nonce = Nonce12::from_ks_iv(&iv_bytes);
        let _cur = running_nonce.use_and_incr();
        let seq_1 = running_nonce.use_and_incr();

        assert_eq!(seq_1, Some(hex!("6fac81d4f2c3bebe02b8b374")));
    }

    // Wrapping u64 is not allowed, ensure it returns None
    #[test]
    fn packet_seq_max() {
        let iv_bytes: [u8; 12] = hex!("6fac81d4f2c3bebe02b8b375");
        let mut running_nonce = Nonce12::from_ks_iv(&iv_bytes);
        let cur = running_nonce.hazmat_fast_forward_with_incr(u64::MAX);

        assert_eq!(cur, None);
    }
}
