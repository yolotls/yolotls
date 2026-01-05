//! yTLS Server Application Ctx

use crate::{TlsServerCtxConfig, TlsServerCtxError};
use ytls_traits::CtxApplicationProcessor;
use ytls_traits::ShutdownComplete;
use ytls_traits::{TlsLeftIn, TlsLeftOut, TlsRight};

use ytls_traits::{CryptoConfig, CryptoRng};

/// yTLS Server Application Ctx
pub struct ServerApplicationCtx<Config, Crypto, Rng> {
    /// Downstream config implementation
    config: Config,
    /// Downstream crypto implementation
    crypto: Crypto,
    /// Downstream rng implementation
    rng: Rng,
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
