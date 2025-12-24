//! ServerHello Builder Buffer

use crate::error::BuilderError;

use ytls_traits::UntypedServerHelloBuilder;

#[derive(Debug, PartialEq)]
pub struct BufStaticServerHello<const N: usize> {
    bytes_buf: [u8; N],
    bytes_len: usize,
}

struct WriteCursor<const N: usize> {
    written: usize,
}

impl<const N: usize> WriteCursor<N> {
    #[inline]
    fn new() -> Self {
        Self { written: 0 }
    }
    fn cur_as_usize(&self) -> usize {
        self.written
    }
    fn cur_as_u16(&self) -> u16 {
        self.written as u16
    }
    #[inline]
    fn try_incr(&mut self, i: usize) -> Result<usize, BuilderError> {
        if self.written + i > N {
            return Err(BuilderError::Overflow);
        }
        if self.written + i > u16::MAX as usize {
            return Err(BuilderError::Overflow);
        }

        self.written += i;
        Ok(self.written)
    }
}

impl<const N: usize> BufStaticServerHello<N> {
    pub(crate) fn as_ref(&self) -> &[u8] {
        &self.bytes_buf[0..self.bytes_len]
    }
    // Construct static Buffered ServerHello
    #[inline]
    pub(crate) fn static_from_untyped<S: UntypedServerHelloBuilder>(
        s: &S,
    ) -> Result<Self, BuilderError> {
        let mut cursor = WriteCursor::<N>::new();
        let mut buffer: [u8; N] = [0; N];
        //-----------------------
        // Record header +6 bytes
        //-----------------------
        cursor.try_incr(5)?;
        buffer[0] = 0x16; // Handshake Record
        let version_b = s.legacy_version();
        buffer[1] = version_b[0];
        buffer[2] = version_b[1];
        let pos_rec_len_start = 3;
        // bytes 3..5 length of the whole record
        //-----------------------
        // Handshake header +4 bytes
        //-----------------------
        cursor.try_incr(4)?;
        buffer[5] = 0x02; // Server Hello
        let pos_server_hello_len_start = 7; // u16 -> u24
                                            // bytes 6,7,8 length of the ServerHello
                                            //-----------------------
                                            // ServerHello follows
                                            //-----------------------
        cursor.try_incr(34)?;
        buffer[9..11].copy_from_slice(s.legacy_version());
        buffer[11..43].copy_from_slice(s.server_random());
        let session_id = s.legacy_session_id();
        if session_id.len() > 255 {
            return Err(BuilderError::SessionIdOverflow);
        }
        cursor.try_incr(1 + session_id.len())?;
        buffer[43] = session_id.len() as u8;
        let end_session_id = 44 + session_id.len();
        buffer[44..end_session_id].copy_from_slice(&session_id[0..session_id.len()]);

        cursor.try_incr(2)?;
        let mut pos = end_session_id;
        buffer[pos..pos + 2].copy_from_slice(s.selected_cipher_suite());
        pos += 2;

        //------------------------
        // Compression method +1
        //------------------------
        cursor.try_incr(1)?;
        let compression_method: u8 = match s.selected_legacy_insecure_compression_method() {
            None => 0,
            Some(x) => x,
        };
        buffer[pos] = compression_method;
        pos += 1;

        //------------------------
        // Extensions Length +2
        //------------------------
        cursor.try_incr(2)?;
        let pos_extension_len_start = pos;
        pos += 2;

        let mut extensions_total_len = 0_u16;

        let mut ext_pos = pos;

        let extensions = s.extensions_list();

        for ext in extensions {
            let ext_data = s.extension_data(*ext);
            let ext_data_len_usize = ext_data.len();

            if ext_data_len_usize + 4 > u16::MAX as usize {
                return Err(BuilderError::Overflow);
            }
            let ext_data_len: u16 = ext_data_len_usize as u16;

            cursor.try_incr(ext_data_len_usize + 4)?;
            extensions_total_len += 4 + ext_data_len;

            buffer[ext_pos..ext_pos + 2].copy_from_slice(&ext.to_be_bytes());
            buffer[ext_pos + 2..ext_pos + 4].copy_from_slice(&ext_data_len.to_be_bytes());
            let data_start_pos = ext_pos + 4;
            let data_end_pos = data_start_pos + ext_data.len();
            buffer[data_start_pos..data_end_pos].copy_from_slice(ext_data);
            ext_pos = data_end_pos;
        }

        if extensions.len() > 0 {
            let extensions_total_len_u16 = extensions_total_len as u16;
            buffer[pos_extension_len_start..pos_extension_len_start + 2]
                .copy_from_slice(&extensions_total_len_u16.to_be_bytes());
        }

        // Write Record Len
        let record_len = cursor.cur_as_u16() - 5;
        buffer[pos_rec_len_start..pos_rec_len_start + 2].copy_from_slice(&record_len.to_be_bytes());

        // Write Hello Len
        let hello_len = record_len - 4;
        buffer[pos_server_hello_len_start..pos_server_hello_len_start + 2]
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
    use ytls_traits::UntypedHandshakeBuilder;
    use ytls_traits::UntypedServerHelloBuilder;

    struct Tester;

    impl UntypedServerHelloBuilder for Tester {
        /// This should return [3, 3] for TLS 1.3
        fn legacy_version(&self) -> &[u8; 2] {
            &[3, 3]
        }
        /// Generate 32 bytes server random for the Hello                                                           
        fn server_random(&self) -> &[u8; 32] {
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]
        }
        /// In TLS 1.3 provide the ClientHello session id (if any) back                                             
        fn legacy_session_id(&self) -> &[u8] {
            &[
                62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42,
                41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31,
            ]
        }
        /// Server selected the cipher suite from client's list.                                                    
        fn selected_cipher_suite(&self) -> &[u8; 2] {
            // TLS_CHACHA20_POLY1305_SHA256
            &[0x13, 0x03]
        }
        /// Server selected compression list. This must be None for TLS 1.3.
        fn selected_legacy_insecure_compression_method(&self) -> Option<u8> {
            None
        }
        /// Extensions used list                                            
        fn extensions_list(&self) -> &[u16] {
            &[]
        }
        /// Given extension relevant encoded data. See [`ytls_extensions`] to encode.
        fn extension_data(&self, _ext: u16) -> &[u8] {
            todo!()
        }
    }

    //----------------------------------------------
    // Record Header - 5 bytes
    //----------------------------------------------
    // 16 - Handshake Record identifier 0x16
    // 03 03 - Legacy TLS Version (TLS 1.2)
    // 00 4c - Record length 76 bytes follows
    //      +4 handshake header
    //    ------- ServerHello ------
    //      +2 legacy server version
    //     +32 random
    //     +33 session ID
    //      +2 cipher suite
    //      +1 compression method
    //      +2 extensions length
    //   ----------------------------
    //      76 total in which 72 is ServerHello
    //----------------------------------------------
    // Handshake Header - 4 bytes
    //----------------------------------------------
    // 02 - Handshake type ServerHello = 0x02
    // 00 00 48 - Server Hello length 72 bytes follows
    //----------------------------------------------
    // Legacy Server Version - 2 bytes
    //----------------------------------------------
    // 03 03
    //----------------------------------------------
    // Random - 32 bytes
    //----------------------------------------------
    // 01 02 03 04 05 06 07 08 09 0a
    // 0b 0c 0d 0e 0f 10 11 12 13 14
    // 15 16 17 18 19 1a 1b 1c 1d 1e
    // 1f 20
    //----------------------------------------------
    // Session id - 33 bytes
    //----------------------------------------------
    // 20 - Opaque Session id length (u8)
    // 3e 3d 3c 3b 3a 39 38 37 36 35 - 10 bytes
    // 34 33 32 31 30 2f 2e 2d 2c 2b - 20 bytes
    // 2a 29 28 27 26 25 24 23 22 21 - 30 bytes
    // 20 1f - 32 bytes
    //----------------------------------------------
    // Cipher Suite - 2 bytes
    //----------------------------------------------
    // 13 03
    //----------------------------------------------
    // Compression Method - 1 bytes
    //----------------------------------------------
    // 00
    //----------------------------------------------
    // Extensions length - 2 bytes
    //----------------------------------------------
    // 00 00
    #[test]
    fn static_8192_basic() {
        let tester = Tester;

        let b = BufStaticServerHello::<8192>::static_from_untyped(&tester).unwrap();

        let h = hex::encode(b.as_ref());

        assert_eq!(h, "160303004c0200004803030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20203e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f1303000000");
    }
}

#[cfg(test)]
mod test_ok_yes_two_extensions {
    use super::*;
    use ytls_traits::UntypedHandshakeBuilder;
    use ytls_traits::UntypedServerHelloBuilder;

    struct Tester;

    impl UntypedServerHelloBuilder for Tester {
        /// This should return [3, 3] for TLS 1.3
        fn legacy_version(&self) -> &[u8; 2] {
            &[3, 3]
        }
        /// Generate 32 bytes server random for the Hello                                                           
        fn server_random(&self) -> &[u8; 32] {
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]
        }
        /// In TLS 1.3 provide the ClientHello session id (if any) back                                             
        fn legacy_session_id(&self) -> &[u8] {
            &[
                62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42,
                41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31,
            ]
        }
        /// Server selected the cipher suite from client's list.                                                    
        fn selected_cipher_suite(&self) -> &[u8; 2] {
            // TLS_CHACHA20_POLY1305_SHA256
            &[0x13, 0x03]
        }
        /// Server selected compression list. This must be None for TLS 1.3.
        fn selected_legacy_insecure_compression_method(&self) -> Option<u8> {
            None
        }
        /// Extensions used list                                            
        fn extensions_list(&self) -> &[u16] {
            // 28 = Record Size Limit
            // 43 = Supported Versions
            &[28, 43]
        }
        /// Given extension relevant encoded data. See [`ytls_extensions`] to encode.
        fn extension_data(&self, ext: u16) -> &[u8] {
            match ext {
                // 16385 (u16) = 2 bytes
                28 => &[0x40, 0x01],
                // Len 4B + Tls13, Tls12 = 5 bytes
                43 => &[0x04, 0x03, 0x04, 0x03, 0x03],
                _ => unreachable!(),
            }
        }
    }

    //----------------------------------------------
    // Record Header - 5 bytes
    //----------------------------------------------
    // 16 - Handshake Record identifier 0x16
    // 03 03 - Legacy TLS Version (TLS 1.2)
    // 00 5b - Record length 91 bytes follows
    //      +4 handshake header
    //    ------- ServerHello ------
    //      +2 legacy server version
    //     +32 random
    //     +33 session ID
    //      +2 cipher suite
    //      +1 compression method
    //      +2 extensions length
    //      +6 extension (28)
    //      +9 extension (43)
    //   ----------------------------
    //      91 total in which 87 is ServerHello
    //----------------------------------------------
    // Handshake Header - 4 bytes
    //----------------------------------------------
    // 02 - Handshake type ServerHello = 0x02
    // 00 00 57 - Server Hello length 87 bytes follows
    //----------------------------------------------
    // Legacy Server Version - 2 bytes
    //----------------------------------------------
    // 03 03
    //----------------------------------------------
    // Random - 32 bytes
    //----------------------------------------------
    // 01 02 03 04 05 06 07 08 09 0a
    // 0b 0c 0d 0e 0f 10 11 12 13 14
    // 15 16 17 18 19 1a 1b 1c 1d 1e
    // 1f 20
    //----------------------------------------------
    // Session id - 33 bytes
    //----------------------------------------------
    // 20 - Opaque Session id length (u8)
    // 3e 3d 3c 3b 3a 39 38 37 36 35 - 10 bytes
    // 34 33 32 31 30 2f 2e 2d 2c 2b - 20 bytes
    // 2a 29 28 27 26 25 24 23 22 21 - 30 bytes
    // 20 1f - 32 bytes
    //----------------------------------------------
    // Cipher Suite - 2 bytes
    //----------------------------------------------
    // 13 03
    //----------------------------------------------
    // Compression Method - 1 bytes
    //----------------------------------------------
    // 00
    //----------------------------------------------
    // Extensions length - 2 bytes
    //----------------------------------------------
    // 00 0F - 15 bytes total extensions
    //----------------------------------------------
    // Extension (28) Record Length Limit - 6 bytes
    //----------------------------------------------
    // 00 1c - Header Id for 28
    // 00 02 - Length 2 bytes
    // 40 01 - payload for 28
    //----------------------------------------------
    // Extension (43) Supported Versions - 9 bytes
    //----------------------------------------------
    // 00 2b - Header Id for 43
    // 00 05 - Length 5 bytes
    // 04 - 4 bytes version length
    // 03 04 - TLS 1.3
    // 03 03 - TLS 1.2
    #[test]
    fn static_8192_extensions_basic() {
        let tester = Tester;

        let b = BufStaticServerHello::<8192>::static_from_untyped(&tester).unwrap();

        let h = hex::encode(b.as_ref());

        assert_eq!(h, "160303005b0200005703030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20203e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f130300000f001c00024001002b00050403040303");
    }
}
