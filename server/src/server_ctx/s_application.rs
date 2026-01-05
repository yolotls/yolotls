//! yTLS Server Application Ctx

use crate::{TlsServerCtxConfig, TlsServerCtxError};
use ytls_traits::CtxApplicationProcessor;
use ytls_traits::ShutdownComplete;
use ytls_traits::{TlsLeftIn, TlsLeftOut, TlsRight};

use ytls_traits::{CryptoConfig, CryptoRng};

use ytls_util::Nonce12;

/// yTLS Server Application Ctx
pub struct ServerApplicationCtx<Config, Crypto, Rng> {
    config: Config,
    crypto: Crypto,
    rng: Rng,
    // TODO: move these to vault or something and make sure
    // they get zeroize'd
    // Also handle different length depending on cipher suites
    application_server_key: [u8; 32],
    application_client_key: [u8; 32],
    application_server_iv: Nonce12,
    application_client_iv: Nonce12,
}

impl<Config, Crypto, Rng> ServerApplicationCtx<Config, Crypto, Rng>
where
    Config: TlsServerCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
}

impl<Config, Crypto, Rng> CtxApplicationProcessor for ServerApplicationCtx<Config, Crypto, Rng>
where
    Config: TlsServerCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    type Error = TlsServerCtxError;

    fn spin_application<Li: TlsLeftIn, Lo: TlsLeftOut, R: TlsRight>(
        &mut self,
        _li: &mut Li,
        _lo: &mut Lo,
        _right: &mut R,
    ) -> Result<Option<ShutdownComplete>, Self::Error> {
        todo!()
    }
}
