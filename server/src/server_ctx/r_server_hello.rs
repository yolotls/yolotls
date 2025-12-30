//! Respond with Server Hello

use crate::TlsServerCtx;
use crate::TlsServerCtxConfig;

use crate::TlsServerCtxError;
use ytls_record::StaticRecordBuilder;
use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;
use ytls_traits::UntypedServerHelloBuilder;

use ytls_traits::TlsLeft;
use ytls_traits::UntypedHandshakeBuilder;

use ytls_traits::CryptoSha256TranscriptProcessor;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> TlsServerCtx<C, Crypto, Rng> {
    #[inline]
    pub(crate) fn do_server_hello<L: TlsLeft, T: CryptoSha256TranscriptProcessor>(
        &mut self,
        l: &mut L,
        t: &mut T,
    ) -> Result<(), TlsServerCtxError> {
        let b = StaticRecordBuilder::<8192>::server_hello_untyped(self)
            .map_err(TlsServerCtxError::Builder)?;

        //println!("ServerHello/w<{}> = {}", b.as_encoded_bytes().len(), hex::encode(b.as_encoded_bytes()));
        //println!("ServerHello/p<{}> = {}", b.without_header_as_bytes().len(), hex::encode(b.without_header_as_bytes()));
        t.sha256_update(b.without_header_as_bytes());

        l.send_record_out(b.as_encoded_bytes());
        Ok(())
    }
    #[inline]
    pub(crate) fn key_share_x25519(&self) -> [u8; 36] {
        let mut r: [u8; 36] = [0; 36];
        r[0..4].copy_from_slice(&[0x00, 0x1d, 0x00, 0x20]);
        match &self.public_key {
            Some(ref s) => {
                r[4..36].copy_from_slice(s);
            }
            None => {}
        }
        r
    }
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> UntypedServerHelloBuilder
    for TlsServerCtx<C, Crypto, Rng>
{
    fn legacy_version(&self) -> &[u8; 2] {
        &[3, 3]
    }
    fn server_random(&self) -> &[u8; 32] {
        &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]
    }
    fn legacy_session_id(&self) -> &[u8] {
        match &self.client_session_id {
            Some(ref s) => &s[0..self.client_session_len],
            None => &[],
        }
    }
    fn selected_cipher_suite(&self) -> &[u8; 2] {
        // TLS_CHACHA20_POLY1305_SHA256
        &[0x13, 0x03]
    }
    fn selected_legacy_insecure_compression_method(&self) -> Option<u8> {
        None
    }
    fn extensions_list(&self) -> &[u16] {
        // 28 = Record Size Limit
        // 43 = Supported Versions
        // 51 = Key Share
        // 41 = pre-shared_key
        &[43, 51]
    }
    fn extension_data(&self, ext: u16) -> &[u8] {
        match ext {
            // Len 2B + Tls13 = 3 bytes
            43 => &[0x03, 0x04],
            // 1d = X25519 pub key 32b len (0x20)
            51 => &self.key_share,
            //41 => &[0x00, 0x00],
            _ => unreachable!(),
        }
    }
}
