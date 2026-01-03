//! EncryptedExtensions Builder Buffer

use crate::error::BuilderError;

use ytls_traits::EncryptedExtensionsBuilder;

#[derive(Debug, PartialEq)]
pub struct BufStaticEncryptedExtensions<const N: usize> {
    bytes_buf: [u8; N],
    bytes_len: usize,
    cipher_start: usize,
    cipher_end: usize,
    auth_tag_start: usize,
    auth_tag_end: usize,
}

use super::formatter::EncoderU16;

impl<const N: usize> BufStaticEncryptedExtensions<N> {
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
    pub(crate) fn wrapped_hash_header_ref(&self) -> [u8; 5] {
        let len = self.cipher_end - 1 - self.cipher_start;
        let len_u32_b: [u8; 4] = (len as u32).to_be_bytes();
        [0x16, 3, 3, len_u32_b[2], len_u32_b[3]]
    }
    pub(crate) fn as_hashing_context_ref(&self) -> &[u8] {
        &self.bytes_buf[self.cipher_start..self.cipher_end - 1]
    }
    pub(crate) fn as_encoded_bytes(&self) -> &[u8] {
        &self.bytes_buf[0..self.bytes_len]
    }
    #[inline]
    pub(crate) fn static_from_untyped<S: EncryptedExtensionsBuilder>(
        _s: &S,
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
        // Handshake record metadata +8 bytes
        // Bytes 5..12
        //-----------------------------------
        cursor.try_skip_only(6)?;
        // 0x0b = Handshake type Encrypted Extensions
        buffer[5] = 0x08;
        let idx_hs_payload_len_start = 6;
        // ,7,8 (u24 BE) cont idx_payload_len_start
        // 9 = 0 bytes of request context
        let idx_extensions_total_len_start = 10;
        // ,11,12 (u24 BE) cont idx_certs_total_len_start

        // TODO: empty.
        let total_extensions_len = 0;

        //--------------------------------------
        // Total Extensions Length including headers
        //--------------------------------------
        let extensions_total_len_u32_b: [u8; 4] = (total_extensions_len as u32).to_be_bytes();
        if extensions_total_len_u32_b[0] != 0 {
            return Err(BuilderError::Overflow);
        }
        buffer[idx_extensions_total_len_start..idx_extensions_total_len_start + 3]
            .copy_from_slice(&extensions_total_len_u32_b[1..4]);

        //----------------------------------------
        // Total handshake length
        // = total extensions length
        //    + handshake headers 2 bytes
        //------------------ ---------------------
        let hs_total_len_u32_b: [u8; 4] = ((total_extensions_len + 2) as u32).to_be_bytes();
        if hs_total_len_u32_b[0] != 0 {
            return Err(BuilderError::Overflow);
        }
        buffer[idx_hs_payload_len_start..idx_hs_payload_len_start + 3]
            .copy_from_slice(&hs_total_len_u32_b[1..4]);

        //----------------------------------------
        // Total appdata length (for ciphertext)
        //    + handshake headers 6 bytes     +6
        //    + auth tag (aead) 16 bytes     +16
        //    + record type is handshake      +1
        //   ------------------------------------
        //                          totals    23
        //    + total certs w/ hdrs length    +X
        //------------------ ---------------------
        let total_app_data_len = 23 + total_extensions_len;

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
mod test_ok_smol_barebones {
    use super::*;
    use hex_literal::hex;
    use ytls_traits::EncryptedExtensionsBuilder;

    struct Tester;

    impl EncryptedExtensionsBuilder for Tester {}

    //----------------------------------------------
    // Expected Wrapped Record header +5 bytes
    //----------------------------------------------
    // 17    - AppData record type (Wrapped)
    // 03 03 - Legacy TLS 1.2
    // 00 17 - Length 23 bytes follows
    //----------------------------------------------
    // Handshake headers +6 bytes
    //----------------------------------------------
    // 08       - Handshake: Encrypted Extensions
    // 00 00 02 - 2 bytes follows
    // 00 00    - Zero length encrypted extensions
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

        let b = BufStaticEncryptedExtensions::<8192>::static_from_untyped(&tester).unwrap();

        let h = hex::encode(b.as_encoded_bytes());

        let expected_lit = hex!(
            "17 03 03 00 17 08 00 00 02 00 00 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        );

        assert_eq!(hex::encode(expected_lit), h);
    }
}
