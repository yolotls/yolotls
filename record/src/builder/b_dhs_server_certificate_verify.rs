//! Server Certificate Builder Buffer

use crate::error::BuilderError;

use ytls_traits::ServerCertificateVerifyBuilder;

#[derive(Debug, PartialEq)]
pub struct BufStaticServerCertificateVerify<const N: usize> {
    bytes_buf: [u8; N],
    bytes_len: usize,
    cipher_start: usize,
    cipher_end: usize,
    auth_tag_start: usize,
    auth_tag_end: usize,
}

use super::formatter::EncoderU16;

impl<const N: usize> BufStaticServerCertificateVerify<N> {
    pub(crate) fn set_auth_tag(&mut self, new_tag: &[u8; 16]) -> () {
        self.bytes_buf[self.auth_tag_start..self.auth_tag_end].copy_from_slice(new_tag);
    }
    pub(crate) fn as_disjoint_mut_for_aead(&mut self) -> Result<[&mut [u8]; 2], BuilderError> {
        match self
            .bytes_buf
            .get_disjoint_mut([0..5, self.cipher_start..self.cipher_end])
        {
            Ok(r) => Ok(r),
            Err(_) => Err(BuilderError::DisjointMutError),
        }
    }
    pub(crate) fn as_ciphertext_mut(&mut self) -> &mut [u8] {
        &mut self.bytes_buf[self.cipher_start..self.cipher_end]
    }
    pub(crate) fn as_hashing_context_ref(&self) -> &[u8] {
        &self.bytes_buf[self.cipher_start..self.cipher_end]
    }
    pub(crate) fn as_encoded_bytes(&self) -> &[u8] {
        &self.bytes_buf[0..self.bytes_len]
    }
    #[inline]
    pub(crate) fn static_from_untyped<S: ServerCertificateVerifyBuilder>(
        s: &S,
    ) -> Result<Self, BuilderError> {
        let mut cursor = EncoderU16::<N>::new();
        let mut buffer: [u8; N] = [0; N];

        //-------------------------------
        // AppData Record header +5 bytes
        // Bytes 0..4
        //-------------------------------
        cursor.try_skip_only(5)?;
        buffer[0] = 0x17;
        buffer[1] = 3;
        buffer[2] = 3;
        // ,4
        let idx_appdata_len_start = 3;
        //-------------------------------
        // Cleartext <> Ciphertext Start
        // Bytes 0..4 Cleartext
        // Bytes 5..X Ciphertext
        // Bytes X.+16 Auth Tag
        //-------------------------------
        let idx_encrypt_start = 5;

        //-----------------------------------
        // Handshake record metadata +4 bytes
        // Bytes 5..9
        //-----------------------------------
        cursor.try_skip_only(4)?;
        // 0x0b = Handshake type certificate verify
        buffer[5] = 0x0f;
        let idx_hs_payload_len_start = 6;
        // ,7,8 (u24 BE) cont idx_payload_len_start

        // 9, 10
        let algorithm: [u8; 2] = s.signature_algorithm();
        cursor.try_fill_with(&mut buffer, &algorithm)?;

        let signature = s.sign_cert_verify();
        if signature.len() > u16::MAX as usize {
            return Err(BuilderError::Overflow);
        }
        let s_len_bytes: [u8; 2] = (signature.len() as u16).to_be_bytes();

        // 11, 12
        cursor.try_fill_with(&mut buffer, &s_len_bytes)?;
        // 13..
        cursor.try_fill_with(&mut buffer, &signature)?;

        //----------------------------------------
        // Total handshake length
        // =  + signature length  2 bytes
        //    + signature type    2 bytes
        //    + signature lenghth X bytes
        //------------------ ---------------------
        let hs_total_len_u32_b: [u8; 4] = ((signature.len() + 4) as u32).to_be_bytes();
        if hs_total_len_u32_b[0] != 0 {
            return Err(BuilderError::Overflow);
        }
        buffer[idx_hs_payload_len_start..idx_hs_payload_len_start + 3]
            .copy_from_slice(&hs_total_len_u32_b[1..4]);

        //----------------------------------------
        // Total appdata length (for ciphertext)
        //    + handshake headers 8 bytes     +8
        //    + auth tag (aead) 16 bytes     +16
        //    + record type is handshake      +1
        //   ------------------------------------
        //                          totals    25
        //    + signature.length              +X
        //------------------ ---------------------
        let total_app_data_len = 25 + signature.len();

        if total_app_data_len > u16::MAX as usize {
            return Err(BuilderError::Overflow);
        }
        let appdata_total_len_u16_b: [u8; 2] = (total_app_data_len as u16).to_be_bytes();
        buffer[idx_appdata_len_start..idx_appdata_len_start + 2]
            .copy_from_slice(&appdata_total_len_u16_b[0..2]);

        cursor.try_skip_only(1)?;
        // Handshake record type at end
        buffer[cursor.cur_as_usize() - 1] = 0x16;
        let idx_encrypt_end = cursor.cur_as_usize();

        let auth_tag_start = cursor.cur_as_usize();
        let auth_tag_end = cursor.cur_as_usize() + 16;

        cursor.try_skip_only(16)?;

        Ok(Self {
            bytes_buf: buffer,
            bytes_len: cursor.cur_as_usize(),
            cipher_start: idx_encrypt_start,
            cipher_end: idx_encrypt_end,
            auth_tag_start,
            auth_tag_end,
        })
    }
}

#[cfg(test)]
mod test_ok_basic_1cert_verify {
    use super::*;
    use hex_literal::hex;
    use ytls_traits::ServerCertificateVerifyBuilder;

    struct Tester;

    impl ServerCertificateVerifyBuilder for Tester {
        fn signature_algorithm(&self) -> [u8; 2] {
            [0x04, 0x03]
        }
        fn sign_cert_verify(&self) -> &[u8] {
            &[0x69, 0x69, 0x69]
        }
    }

    // 001c - 28
    //  1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
    // 0f
    // 00 00 0b length (11)
    //  1  2  3  4  5  6  7
    // 04 03 00 03 69 69 69
    // 1600000000000000000000000000000000

    // 0f
    // 00 00 44
    // 04 03
    // 00 40 - 64
    //  1  2  3  4  5  6  7  8  9  0
    // e3 31 06 54 d7 85 92 b5 c4 61
    // 84 25 01 73 38 0e d5 67 94 f7
    // ff c5 26 bc 81 87 b8 98 0d 26
    // 24 c1 ad 62 5b 81 85 c8 cf c8
    // 4a cc ad 2f 65 45 a7 9a 00 73
    // 97 db 5d 34 3a 95 f6 bb 8c a2
    // d7 a4 c3 e4

    // 17
    // 0303
    // 0024 24 bytes follows
    // 0f - Certificateverify         + 1 byte
    // 00 00 0b  length (11)          + 3 bytes
    // 04 03     sign type            + 2 bytes
    // 00 03     length sign          + 2 bytes
    // 69 69 69  signature            + 3 bytes
    // 16        handhsake (wrapped)  + 1 bytes
    // 00000000000000000000000000000000

    //----------------------------------------------
    // Expected Wrapped Record header +5 bytes
    //----------------------------------------------
    // 17    - AppData record type (Wrapped)
    // 03 03 - Legacy TLS 1.2
    // XX XX - Length X follows
    //----------------------------------------------
    // Handshake headers +8 bytes
    //----------------------------------------------
    // 0f       - Handshake message type: CertificateVerify
    // 00 XX XX - Length: X bytes Certificate message payload
    //----------------------------------------------
    // Certificate Verify Lengths
    //
    // ---------------------
    // X total
    //---------------------------------------------
    // Certificate Verify
    //---------------------------------------------
    // 04 03    - ecdsa_secp256r1_sha256
    //---------------------------------------------
    // Wrapped inner record type +1 byte
    //---------------------------------------------
    // 16       - Wrapped record inner is type Handshake record
    //---------------------------------------------
    // AEAD Placeholder +16 bytes
    //---------------------------------------------
    // 00..     - [aead auth tag placeholder 16 bytes]
    //---------------------------------------------
    #[test]
    fn static_8192_basic() {
        let tester = Tester;

        let b = BufStaticServerCertificateVerify::<8192>::static_from_untyped(&tester).unwrap();

        let h = hex::encode(b.as_encoded_bytes());

        let expected_lit = hex!("17 03 03 03 43");

        assert_eq!(hex::encode(expected_lit), h);
    }
}
