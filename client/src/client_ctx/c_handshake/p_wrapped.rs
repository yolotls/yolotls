//! yTLS Wrapped Record (Handshake) Processor

use crate::TlsClientCtxConfig;
use ytls_ctx::CtxError;
use ytls_traits::{CryptoConfig, CryptoRng};

use crate::ClientHandshakeCtx;

use ytls_traits::ServerCertificateProcessor;
use ytls_traits::ServerCertificateVerifyProcessor;
use ytls_traits::ServerFinishedProcessor;
use ytls_traits::ServerWrappedRecordProcessor;

impl<Config, Crypto, Rng> ServerWrappedRecordProcessor for ClientHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsClientCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    type ServerCertificateHandler = Self;
    type ServerCertificateVerifyHandler = Self;
    type ServerFinishedHandler = Self;

    #[inline]
    fn server_certificate(&mut self) -> &mut Self::ServerCertificateHandler {
        self
    }
    #[inline]
    fn server_certificate_verify(&mut self) -> &mut Self::ServerCertificateVerifyHandler {
        self
    }
    #[inline]
    fn server_finished(
        &mut self,
    ) -> &mut <Self as ServerWrappedRecordProcessor>::ServerFinishedHandler {
        self
    }
}

impl<Config, Crypto, Rng> ServerCertificateProcessor for ClientHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsClientCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    #[inline]
    fn handle_server_certificate(&mut self, _cert_data: &[u8], _ext_data: &[u8]) -> () {
        //println!("Handle server certificate cert_data: {}, ext_data: {}", hex::encode(cert_data), hex::encode(ext_data));
    }
}

impl<Config, Crypto, Rng> ServerCertificateVerifyProcessor
    for ClientHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsClientCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    #[inline]
    fn handle_server_certificate_verify(&mut self, _algorithm: [u8; 2], _signature: &[u8]) -> () {
        //println!("Handle server certificate verify signature: {}", hex::encode(signature));
    }
}

impl<Config, Crypto, Rng> ServerFinishedProcessor for ClientHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsClientCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    #[inline]
    fn handle_server_finished(&mut self, _hash_finished: &[u8]) -> () {
        //println!("Handle server finished: {}", hex::encode(hash_finished));
    }
}
