//! yTLS ClientHello submission

use crate::{ClientHandshakeCtx, CtxError, TlsClientCtxConfig};
use ytls_traits::TlsLeftOut;
use ytls_traits::{CryptoConfig, CryptoRng};

use ytls_traits::CryptoSha256TranscriptProcessor;

use ytls_record::StaticRecordBuilder;

use ytls_traits::CryptoX25519Processor;

impl<Config, Crypto, Rng> ClientHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsClientCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    #[inline]
    pub(crate) fn do_client_hello<Lo: TlsLeftOut>(&mut self, lo: &mut Lo) -> Result<(), CtxError> {
        let x25519_ctx = self.crypto.x25519_init(&mut self.rng);
        let pk: [u8; 32] = x25519_ctx.x25519_public_key();

        let key_share: [u8; 38] = [
            0, 0x24, 0, 0x1d, 0, 0x20, pk[0], pk[1], pk[2], pk[3], pk[4], pk[5], pk[6], pk[7],
            pk[8], pk[9], pk[10], pk[11], pk[12], pk[13], pk[14], pk[15], pk[16], pk[17], pk[18],
            pk[19], pk[20], pk[21], pk[22], pk[23], pk[24], pk[25], pk[26], pk[27], pk[28], pk[29],
            pk[30], pk[31],
        ];

        let ch = ClientHello { key_share };

        let hello =
            StaticRecordBuilder::<8192>::client_hello_untyped(&ch).map_err(CtxError::Builder)?;

        self.transcript.sha256_update(hello.as_hashing_context());
        lo.send_record_out(hello.as_encoded_bytes());

        Ok(())
    }
}

use ytls_traits::ClientHelloBuilder;
use ytls_traits::HandshakeBuilder;

struct ClientHello {
    key_share: [u8; 38],
}

impl ClientHelloBuilder for ClientHello {
    fn legacy_version(&self) -> &[u8; 2] {
        &[3, 3]
    }
    fn legacy_client_version(&self) -> &[u8; 2] {
        &[3, 1]
    }
    fn client_random(&self) -> &[u8; 32] {
        &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]
    }
    fn legacy_session_id(&self) -> &[u8] {
        &[
            50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
            72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
        ]
    }
    fn cipher_suites(&self) -> &[[u8; 2]] {
        &[[0x13, 0x03]]
    }
    fn supported_legacy_insecure_compression_methods(&self) -> &[u8] {
        &[00]
    }
    fn extensions_list(&self) -> &[u16] {
        &[13, 43, 51, 10]
    }
    fn extension_data(&self, id: u16) -> &[u8] {
        match id {
            // supported groups: X25519
            10 => &[0, 2, 0, 29],
            // Signature algorithms: ECDSA-Secp256r1-SHA256
            13 => &[0, 2, 4, 3],
            // supported_versions: TLS 1.3
            43 => &[2, 3, 4],
            // key_share: X25519 32 bytes
            51 => &self.key_share,
            _ => unreachable!(),
        }
    }
}
