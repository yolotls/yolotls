//! Server Handshake Finished Builder Buffer

use crate::error::BuilderError;

use ytls_traits::ServerHandshakeFinishedBuilder;

#[derive(Debug, PartialEq)]
pub struct BufStaticServerHandshakeFinished<const N: usize> {
    bytes_buf: [u8; N],
    bytes_len: usize,
    cipher_start: usize,
    cipher_end: usize,
    auth_tag_start: usize,
    auth_tag_end: usize,
}

use super::formatter::EncoderU16;

impl<const N: usize> BufStaticServerHandshakeFinished<N> {
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
    pub(crate) fn static_from_untyped<S: ServerHandshakeFinishedBuilder>(
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
        // Handshake type server handshake finished
        buffer[5] = 0x14;
        let idx_hs_payload_len_start = 6;
        // ,7,8 (u24 BE) cont idx_payload_len_start

        let hash_finished = s.hash_finished();
        if hash_finished.len() > u16::MAX as usize {
            return Err(BuilderError::Overflow);
        }
        // 9..
        cursor.try_fill_with(&mut buffer, &hash_finished)?;

        //----------------------------------------
        // Total handshake length
        // =  + finished length  2 bytes
        //    + finished lenghth X bytes
        //------------------ ---------------------
        let hs_total_len_u32_b: [u8; 4] = ((hash_finished.len()) as u32).to_be_bytes();
        if hs_total_len_u32_b[0] != 0 {
            return Err(BuilderError::Overflow);
        }
        buffer[idx_hs_payload_len_start..idx_hs_payload_len_start + 3]
            .copy_from_slice(&hs_total_len_u32_b[1..4]);

        //----------------------------------------
        // Total appdata length (for ciphertext)
        //    + handshake headers 8 bytes     +6
        //    + auth tag (aead) 16 bytes     +16
        //    + record type is handshake      +1
        //   ------------------------------------
        //                          totals    23
        //    + signature.length              +X
        //------------------ ---------------------
        let total_app_data_len = 21 + hash_finished.len();

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
mod test_ok_basic_hash_finished {
    use super::*;
    use hex_literal::hex;
    use ytls_traits::ServerHandshakeFinishedBuilder;

    struct Tester;

    impl ServerHandshakeFinishedBuilder for Tester {
        fn hash_finished(&self) -> &[u8] {
            &[42, 42]
        }
    }

    // 14
    // 00 00 22
    // 00 20 85 22 95 90 9d 12 d6 1e 3f 30
    //dd fe 9c 82 eb 98 c3 6a 19 47 0d 22 a3 f6 15 fb
    //ae 13 74 1d ff 8b

    //----------------------------------------------
    // Expected Wrapped Record header +5 bytes
    //----------------------------------------------
    // 17    - AppData record type (Wrapped)
    // 03 03 - Legacy TLS 1.2
    // XX XX - Length X follows
    //----------------------------------------------
    // Handshake headers +4 bytes
    //----------------------------------------------
    // 14       - Handshake message type: Finished
    // 00 XX XX - Length: X bytes of hashlen
    //----------------------------------------------
    // Certificate Verify Lengths
    //
    // ---------------------
    // X total
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

        let b = BufStaticServerHandshakeFinished::<8192>::static_from_untyped(&tester).unwrap();

        let h = hex::encode(b.as_encoded_bytes());

        let expected_lit = hex!("17030300191400000400022a2a1600000000000000000000000000000000");

        assert_eq!(hex::encode(expected_lit), h);
    }
}
