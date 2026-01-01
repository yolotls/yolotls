//! Server Certificate Builder Buffer

use crate::error::BuilderError;

use ytls_traits::ServerCertificatesBuilder;

#[derive(Debug, PartialEq)]
pub struct BufStaticServerCertificates<const N: usize> {
    bytes_buf: [u8; N],
    bytes_len: usize,
    cipher_start: usize,
    cipher_end: usize,
    auth_tag_start: usize,
    auth_tag_end: usize,
}

use super::formatter::EncoderU16;

impl<const N: usize> BufStaticServerCertificates<N> {
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
    pub(crate) fn static_from_untyped<S: ServerCertificatesBuilder>(
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
        let idx_appdata_len_start = 3; // ,4
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
        cursor.try_skip_only(8)?;
        // 0x0b = Handshake type certificate
        buffer[5] = 0x0b;
        let idx_hs_payload_len_start = 6;
        // ,7,8 (u24 BE) cont idx_payload_len_start
        // 9 = 0 bytes of request context
        let idx_certs_total_len_start = 10;
        // ,11,12 (u24 BE) cont idx_certs_total_len_start

        let cert_list = s.server_certs_list();
        let mut all_certs_payload_len = 0;

        for cert_id in cert_list {
            let cert_data = s.server_cert_data(*cert_id);
            let cert_ext_data = s.server_cert_extensions(*cert_id);

            let cert_len = cert_data.len();

            // Cert length is annoyingly u24
            let len_u32_b: [u8; 4] = (cert_len as u32).to_be_bytes();
            if len_u32_b[0] != 0 {
                return Err(BuilderError::Overflow);
            }

            let ext_cert_len = cert_ext_data.len();
            if ext_cert_len > u16::MAX as usize {
                return Err(BuilderError::Overflow);
            }
            let ext_len_u16_b: [u8; 2] = (ext_cert_len as u16).to_be_bytes();

            cursor.try_fill_with(&mut buffer, &len_u32_b[1..4])?;
            cursor.try_fill_with(&mut buffer, cert_data)?;
            cursor.try_fill_with(&mut buffer, &ext_len_u16_b[0..2])?;
            if cert_ext_data.len() > 0 {
                cursor.try_fill_with(&mut buffer, cert_ext_data)?;
            }

            all_certs_payload_len += 3 + cert_len + 2 + cert_ext_data.len();
        }

        //--------------------------------------
        // Total Certs Length including headers
        //--------------------------------------
        let certs_total_len_u32_b: [u8; 4] = (all_certs_payload_len as u32).to_be_bytes();
        if certs_total_len_u32_b[0] != 0 {
            return Err(BuilderError::Overflow);
        }
        buffer[idx_certs_total_len_start..idx_certs_total_len_start + 3]
            .copy_from_slice(&certs_total_len_u32_b[1..4]);

        //----------------------------------------
        // Total handshake length
        // = total certs length
        //    + handshake headers 4 bytes
        //------------------ ---------------------
        let hs_total_len_u32_b: [u8; 4] = ((all_certs_payload_len + 4) as u32).to_be_bytes();
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
        //                          totals    21
        //    + total certs w/ hdrs length    +X
        //------------------ ---------------------
        let total_app_data_len = 25 + all_certs_payload_len;

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
mod test_ok_basic_1cert_extensions {
    use super::*;
    use hex_literal::hex;
    use ytls_traits::ServerCertificatesBuilder;

    struct Tester;

    impl ServerCertificatesBuilder for Tester {
        fn server_certs_list(&self) -> &[u8] {
            &[42]
        }
        fn server_cert_data(&self, id: u8) -> &[u8] {
            match id {
                42 => &hex!("30 82 03 21 30 82 02 09 a0 03 02 01 02 02 08 15 5a 92 ad c2 04 8f 90 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 22 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04 0a 13 0a 45 78 61 6d 70 6c 65 20 43 41 30 1e 17 0d 31 38 31 30 30 35 30 31 33 38 31 37 5a 17 0d 31 39 31 30 30 35 30 31 33 38 31 37 5a 30 2b 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 1c 30 1a 06 03 55 04 03 13 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 c4 80 36 06 ba e7 47 6b 08 94 04 ec a7 b6 91 04 3f f7 92 bc 19 ee fb 7d 74 d7 a8 0d 00 1e 7b 4b 3a 4a e6 0f e8 c0 71 fc 73 e7 02 4c 0d bc f4 bd d1 1d 39 6b ba 70 46 4a 13 e9 4a f8 3d f3 e1 09 59 54 7b c9 55 fb 41 2d a3 76 52 11 e1 f3 dc 77 6c aa 53 37 6e ca 3a ec be c3 aa b7 3b 31 d5 6c b6 52 9c 80 98 bc c9 e0 28 18 e2 0b f7 f8 a0 3a fd 17 04 50 9e ce 79 bd 9f 39 f1 ea 69 ec 47 97 2e 83 0f b5 ca 95 de 95 a1 e6 04 22 d5 ee be 52 79 54 a1 e7 bf 8a 86 f6 46 6d 0d 9f 16 95 1a 4c f7 a0 46 92 59 5c 13 52 f2 54 9e 5a fb 4e bf d7 7a 37 95 01 44 e4 c0 26 87 4c 65 3e 40 7d 7d 23 07 44 01 f4 84 ff d0 8f 7a 1f a0 52 10 d1 f4 f0 d5 ce 79 70 29 32 e2 ca be 70 1f df ad 6b 4b b7 11 01 f4 4b ad 66 6a 11 13 0f e2 ee 82 9e 4d 02 9d c9 1c dd 67 16 db b9 06 18 86 ed c1 ba 94 21 02 03 01 00 01 a3 52 30 50 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 05 a0 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 01 30 1f 06 03 55 1d 23 04 18 30 16 80 14 89 4f de 5b cc 69 e2 52 cf 3e a3 00 df b1 97 b8 1d e1 c1 46 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 59 16 45 a6 9a 2e 37 79 e4 f6 dd 27 1a ba 1c 0b fd 6c d7 55 99 b5 e7 c3 6e 53 3e ff 36 59 08 43 24 c9 e7 a5 04 07 9d 39 e0 d4 29 87 ff e3 eb dd 09 c1 cf 1d 91 44 55 87 0b 57 1d d1 9b df 1d 24 f8 bb 9a 11 fe 80 fd 59 2b a0 39 8c de 11 e2 65 1e 61 8c e5 98 fa 96 e5 37 2e ef 3d 24 8a fd e1 74 63 eb bf ab b8 e4 d1 ab 50 2a 54 ec 00 64 e9 2f 78 19 66 0d 3f 27 cf 20 9e 66 7f ce 5a e2 e4 ac 99 c7 c9 38 18 f8 b2 51 07 22 df ed 97 f3 2e 3e 93 49 d4 c6 6c 9e a6 39 6d 74 44 62 a0 6b 42 c6 d5 ba 68 8e ac 3a 01 7b dd fc 8e 2c fc ad 27 cb 69 d3 cc dc a2 80 41 44 65 d3 ae 34 8c e0 f3 4a b2 fb 9c 61 83 71 31 2b 19 10 41 64 1c 23 7f 11 a5 d6 5c 84 4f 04 04 84 99 38 71 2b 95 9e d6 85 bc 5c 5d d6 45 ed 19 90 94 73 40 29 26 dc b4 0e 34 69 a1 59 41 e8 e2 cc a8 4b b6 08 46 36 a0"),
                _ => unreachable!(),
            }
        }
        fn server_cert_extensions(&self, _id: u8) -> &[u8] {
            &[]
        }
    }

    //----------------------------------------------
    // Expected Wrapped Record header +5 bytes
    //----------------------------------------------
    // 17    - AppData record type (Wrapped)
    // 03 03 - Legacy TLS 1.2
    // 03 43 - Length 835 follows
    //----------------------------------------------
    // Handshake headers +8 bytes
    //----------------------------------------------
    // 0b       - Handshake message type: Certificate
    // 00 03 2e - Length: 814 bytes Certificate message payload
    // 00       - Request context (not a response)
    // 00 03 2a - Length: 810 bytes of certificates follow
    //----------------------------------------------
    // Certificate Chains enumeration
    // ---- Certificate Chain 1
    //  +3 bytes    - Length of it
    //  +805 bytes  - Payload of certs data of certificates 1
    //  +2 bytes    - Extension length
    //  +0 bytes    - Payload of extensions
    // ---------------------
    // 810 bytes total
    //---------------------------------------------
    // Certificate Chain 1 +810 bytes
    //---------------------------------------------
    // 00 03 25 - Length: 805 bytes of certificate follow
    // 30 82 03 .. [certificate payload 805 bytes]
    // 00 00    - Certification extensions length - 0 bytes
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

        let b = BufStaticServerCertificates::<8192>::static_from_untyped(&tester).unwrap();

        let h = hex::encode(b.as_encoded_bytes());

        let expected_lit = hex!("17 03 03 03 43 0b 00 03 2e 00 00 03 2a 00 03 25 30 82 03 21 30 82 02 09 a0 03 02 01 02 02 08 15 5a 92 ad c2 04 8f 90 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 22 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04 0a 13 0a 45 78 61 6d 70 6c 65 20 43 41 30 1e 17 0d 31 38 31 30 30 35 30 31 33 38 31 37 5a 17 0d 31 39 31 30 30 35 30 31 33 38 31 37 5a 30 2b 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 1c 30 1a 06 03 55 04 03 13 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 c4 80 36 06 ba e7 47 6b 08 94 04 ec a7 b6 91 04 3f f7 92 bc 19 ee fb 7d 74 d7 a8 0d 00 1e 7b 4b 3a 4a e6 0f e8 c0 71 fc 73 e7 02 4c 0d bc f4 bd d1 1d 39 6b ba 70 46 4a 13 e9 4a f8 3d f3 e1 09 59 54 7b c9 55 fb 41 2d a3 76 52 11 e1 f3 dc 77 6c aa 53 37 6e ca 3a ec be c3 aa b7 3b 31 d5 6c b6 52 9c 80 98 bc c9 e0 28 18 e2 0b f7 f8 a0 3a fd 17 04 50 9e ce 79 bd 9f 39 f1 ea 69 ec 47 97 2e 83 0f b5 ca 95 de 95 a1 e6 04 22 d5 ee be 52 79 54 a1 e7 bf 8a 86 f6 46 6d 0d 9f 16 95 1a 4c f7 a0 46 92 59 5c 13 52 f2 54 9e 5a fb 4e bf d7 7a 37 95 01 44 e4 c0 26 87 4c 65 3e 40 7d 7d 23 07 44 01 f4 84 ff d0 8f 7a 1f a0 52 10 d1 f4 f0 d5 ce 79 70 29 32 e2 ca be 70 1f df ad 6b 4b b7 11 01 f4 4b ad 66 6a 11 13 0f e2 ee 82 9e 4d 02 9d c9 1c dd 67 16 db b9 06 18 86 ed c1 ba 94 21 02 03 01 00 01 a3 52 30 50 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 05 a0 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 01 30 1f 06 03 55 1d 23 04 18 30 16 80 14 89 4f de 5b cc 69 e2 52 cf 3e a3 00 df b1 97 b8 1d e1 c1 46 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 59 16 45 a6 9a 2e 37 79 e4 f6 dd 27 1a ba 1c 0b fd 6c d7 55 99 b5 e7 c3 6e 53 3e ff 36 59 08 43 24 c9 e7 a5 04 07 9d 39 e0 d4 29 87 ff e3 eb dd 09 c1 cf 1d 91 44 55 87 0b 57 1d d1 9b df 1d 24 f8 bb 9a 11 fe 80 fd 59 2b a0 39 8c de 11 e2 65 1e 61 8c e5 98 fa 96 e5 37 2e ef 3d 24 8a fd e1 74 63 eb bf ab b8 e4 d1 ab 50 2a 54 ec 00 64 e9 2f 78 19 66 0d 3f 27 cf 20 9e 66 7f ce 5a e2 e4 ac 99 c7 c9 38 18 f8 b2 51 07 22 df ed 97 f3 2e 3e 93 49 d4 c6 6c 9e a6 39 6d 74 44 62 a0 6b 42 c6 d5 ba 68 8e ac 3a 01 7b dd fc 8e 2c fc ad 27 cb 69 d3 cc dc a2 80 41 44 65 d3 ae 34 8c e0 f3 4a b2 fb 9c 61 83 71 31 2b 19 10 41 64 1c 23 7f 11 a5 d6 5c 84 4f 04 04 84 99 38 71 2b 95 9e d6 85 bc 5c 5d d6 45 ed 19 90 94 73 40 29 26 dc b4 0e 34 69 a1 59 41 e8 e2 cc a8 4b b6 08 46 36 a0 00 00 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

        assert_eq!(hex::encode(expected_lit), h);
    }
}

#[cfg(test)]
mod test_ok_smol_barebones_1cert {
    use super::*;
    use hex_literal::hex;
    use ytls_traits::ServerCertificatesBuilder;

    struct Tester;

    impl ServerCertificatesBuilder for Tester {
        fn server_certs_list(&self) -> &[u8] {
            &[42]
        }
        fn server_cert_data(&self, id: u8) -> &[u8] {
            match id {
                42 => &[0x69, 0x42, 0x69, 0x42],
                _ => unreachable!(),
            }
        }
        fn server_cert_extensions(&self, _id: u8) -> &[u8] {
            &[]
        }
    }

    //----------------------------------------------
    // Expected Wrapped Record header +5 bytes
    //----------------------------------------------
    // 17    - AppData record type (Wrapped)
    // 03 03 - Legacy TLS 1.2
    // 00 22 - Length 34 bytes follows
    //----------------------------------------------
    // Handshake headers +8 bytes
    //----------------------------------------------
    // 0b       - Handshake message type: Certificate
    // 00 00 0d - Length: 13 bytes Certificate message payload
    // 00       - Request context (not a response)
    // 00 00 09 - Length: 9 bytes of certificates follow
    //----------------------------------------------
    // Certificate Chains enumeration
    // ---- Certificate Chain 1
    //  +3 bytes    - Length of it
    //  +4 bytes    - Payload of certs data of certificates 1
    //  +2 bytes    - Extension length
    //  +0 bytes    - Payload of extensions
    // ---------------------
    // 9 bytes total
    //---------------------------------------------
    // Certificate Chain 1 +
    //---------------------------------------------
    // 00 00 04    - Length: 4 bytes of certificate follow
    // 69 42 69 42 .. [certificate payload 4 bytes]
    // 00 00        - Certification extensions length - 0 bytes
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

        let b = BufStaticServerCertificates::<8192>::static_from_untyped(&tester).unwrap();

        let h = hex::encode(b.as_encoded_bytes());

        let expected_lit = hex!("17 03 03 00 22 0b 00 00 0d 00 00 00 09 00 00 04 69 42 69 42 00 00 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

        assert_eq!(hex::encode(expected_lit), h);
    }
}

#[cfg(test)]
mod test_ok_smol_barebones_2certs {
    use super::*;
    use hex_literal::hex;
    use ytls_traits::ServerCertificatesBuilder;

    struct Tester;

    impl ServerCertificatesBuilder for Tester {
        fn server_certs_list(&self) -> &[u8] {
            &[42, 69]
        }
        fn server_cert_data(&self, id: u8) -> &[u8] {
            match id {
                42 => &[0x69, 0x42, 0x69, 0x42],
                69 => &[0x76, 0x77, 0x78, 0x89],
                _ => unreachable!(),
            }
        }
        fn server_cert_extensions(&self, _id: u8) -> &[u8] {
            &[]
        }
    }

    #[test]
    fn static_8192_basic() {
        let tester = Tester;

        let b = BufStaticServerCertificates::<8192>::static_from_untyped(&tester).unwrap();

        let h = hex::encode(b.as_encoded_bytes());

        let expected_lit = hex!("170303002b0b000016000000120000046942694200000000047677788900001600000000000000000000000000000000");

        assert_eq!(hex::encode(expected_lit), h);
    }
}
