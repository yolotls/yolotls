//! ClientHello Builder Buffer

use crate::error::BuilderError;

use ytls_traits::ClientHelloBuilder;

#[derive(Debug, PartialEq)]
pub struct BufStaticClientHello<const N: usize> {
    bytes_buf: [u8; N],
    bytes_len: usize,
}

use super::formatter::EncoderU16;

impl<const N: usize> BufStaticClientHello<N> {
    pub(crate) fn as_hashing_context(&self) -> &[u8] {
        &self.bytes_buf[5..self.bytes_len]
    }
    pub(crate) fn as_encoded_bytes(&self) -> &[u8] {
        &self.bytes_buf[0..self.bytes_len]
    }
    // Construct static Buffered ClientHello
    #[inline]
    pub(crate) fn static_from_untyped<S: ClientHelloBuilder>(s: &S) -> Result<Self, BuilderError> {
        let mut cursor = EncoderU16::<N>::new();
        let mut buffer: [u8; N] = [0; N];
        //-----------------------
        // Record header +5 bytes
        //-----------------------
        cursor.try_skip_only(5)?;
        buffer[0] = 0x16; // Handshake Record
        let version_b = s.legacy_version();
        buffer[1] = version_b[0];
        buffer[2] = version_b[1];
        let pos_rec_len_start = 3;
        // bytes 3..5 length of the whole record
        //-----------------------
        // Handshake header +4 bytes
        //-----------------------
        cursor.try_skip_only(4)?;
        // Client Hello == 0x01
        buffer[5] = 0x01;
        // Leaving one byte zero due to this being u24
        // and we only have u16
        let pos_client_hello_len_start = 7;
        // bytes 6,7,8 length of the ClientHello
        //-----------------------
        // ClientHello follows
        //-----------------------
        cursor.try_fill_with(&mut buffer, s.legacy_client_version())?;
        cursor.try_fill_with(&mut buffer, s.client_random())?;

        let session_id = s.legacy_session_id();
        if session_id.len() > 255 {
            return Err(BuilderError::SessionIdOverflow);
        }
        let cur = cursor.cur_as_usize();
        cursor.try_skip_only(1)?;
        buffer[cur] = session_id.len() as u8;
        cursor.try_fill_with(&mut buffer, session_id)?;

        let cipher_suites = s.cipher_suites();
        let cipher_suites_len_b16 = ((cipher_suites.len() * 2) as u16).to_be_bytes();
        cursor.try_fill_with(&mut buffer, &cipher_suites_len_b16)?;
        for cipher_suite in cipher_suites {
            cursor.try_fill_with(&mut buffer, cipher_suite)?;
        }

        let cur = cursor.cur_as_usize();
        cursor.try_skip_only(1)?;
        let compression_methods = s.supported_legacy_insecure_compression_methods();
        if compression_methods.len() > 255 {
            return Err(BuilderError::Overflow);
        }
        cursor.try_fill_with(&mut buffer, compression_methods)?;
        buffer[cur] = compression_methods.len() as u8;

        //------------------------
        // Extensions
        //-----------------------
        let pos_extension_len_start = cursor.cur_as_usize();
        cursor.try_skip_only(2)?;

        let mut extensions_total_len = 0_u16;

        let extensions = s.extensions_list();

        for ext in extensions {
            cursor.try_fill_with(&mut buffer, &ext.to_be_bytes())?;
            let ext_data = s.extension_data(*ext);
            if ext_data.len() > u16::MAX as usize {
                return Err(BuilderError::Overflow);
            }
            let ext_u16_b = (ext_data.len() as u16).to_be_bytes();
            cursor.try_fill_with(&mut buffer, &ext_u16_b)?;
            cursor.try_fill_with(&mut buffer, ext_data)?;

            extensions_total_len += 4_u16 + ext_data.len() as u16;
        }

        // Write Extensions len
        buffer[pos_extension_len_start..pos_extension_len_start + 2]
            .copy_from_slice(&extensions_total_len.to_be_bytes());

        // Write Record Len
        let record_len = cursor.cur_as_u16() - 5;
        buffer[pos_rec_len_start..pos_rec_len_start + 2]
            .copy_from_slice(&(record_len.to_be_bytes()));

        // Write Hello Len
        let hello_len = record_len - 4;
        buffer[pos_client_hello_len_start..pos_client_hello_len_start + 2]
            .copy_from_slice(&hello_len.to_be_bytes());

        Ok(Self {
            bytes_buf: buffer,
            bytes_len: cursor.cur_as_usize(),
        })
    }
}

#[cfg(test)]
mod test_ok_no_extensions {
    use super::*;
    use hex_literal::hex;
    use ytls_traits::ClientHelloBuilder;
    use ytls_traits::HandshakeBuilder;

    struct Tester;

    impl ClientHelloBuilder for Tester {
        fn legacy_version(&self) -> &[u8; 2] {
            &[3, 1]
        }
        fn legacy_client_version(&self) -> &[u8; 2] {
            &[3, 3]
        }
        fn client_random(&self) -> &[u8; 32] {
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]
        }
        fn legacy_session_id(&self) -> &[u8] {
            &[
                50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
                71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
            ]
        }
        fn cipher_suites(&self) -> &[[u8; 2]] {
            &[[0x13, 0x03]]
        }
        fn supported_legacy_insecure_compression_methods(&self) -> &[u8] {
            &[00]
        }
        fn extensions_list(&self) -> &[u16] {
            &[]
        }
        fn extension_data(&self, _id: u16) -> &[u8] {
            unreachable!()
        }
    }

    //----------------------------------------------
    // Record Header - 5 bytes
    //----------------------------------------------
    // 16 - Handshake Record identifier 0x16
    // 03 01 - Legacy TLS Version (TLS 1.0)
    // 00 XX - Record length X bytes follows
    //      +4 handshake header
    //    ------- ClientHello ------
    //      +2 legacy Client version
    //     +33 random
    //     +33 session ID
    //      +2 cipher suite
    //      +1 compression methods
    //      +2 extensions length
    //   ----------------------------
    //      XX total in which XX is ClientHello
    //----------------------------------------------
    // Handshake Header - 4 bytes
    //----------------------------------------------
    //

    #[test]
    fn static_8192_basic() {
        let tester = Tester;

        let b = BufStaticClientHello::<8192>::static_from_untyped(&tester)
            .expect("Test: Builder: StaticClientHello failure");

        let h = hex::encode(b.as_encoded_bytes());

        let expected = hex!(
            "16
                             03 01
                             00 4F
                             01
                             00 00 4b 
                             03 03
                             01 02 03 04 05 06 07 08 09 0a
                             0b 0c 0d 0e 0f 10 11 12 13 14
                             15 16 17 18 19 1a 1b 1c 1d 1e
                             1f 20
                             20
                             32 33 34 35 36 37 38 39 3a 3b
                             3c 3d 3e 3f 40 41 42 43 44 45
                             46 47 48 49 4a 4b 4c 4d 4e 4f
                             50 51
                             00 02 13 03
                             01 00
                             00 00
                             "
        );

        assert_eq!(hex::encode(expected), h);
    }
}
