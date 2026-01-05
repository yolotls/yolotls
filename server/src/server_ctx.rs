//! Server Ctx

use crate::TlsServerCtxError;

use ytls_traits::CtxHandshakeProcessor;
use ytls_traits::CtxApplicationProcessor;
use ytls_traits::{TlsLeftIn, TlsLeftOut, TlsRight};

mod s_handshake;
#[doc(inline)]
pub use s_handshake::*;

mod s_application;
#[doc(inline)]
pub use s_application::*;

pub struct TlsServerCtx<Config, Crypto, Rng> {
    cur: CurCtx<Config, Crypto, Rng>,
}

use crate::TlsServerCtxConfig;
use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;

enum CurCtx<Config, Crypto, Rng> {
    Handshake(ServerHandshakeCtx<Config, Crypto, Rng>),
    Application(ServerApplicationCtx<Config, Crypto, Rng>),
}

impl<Config, Crypto, Rng> TlsServerCtx<Config, Crypto, Rng>
where
    Config: TlsServerCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    #[inline]
    pub fn with_required(config: Config, crypto: Crypto, rng: Rng) -> Self {
        Self { cur: CurCtx::Handshake(ServerHandshakeCtx::with_required(config, crypto, rng)) }
    }
    #[inline]
    pub fn advance_with<Li: TlsLeftIn, Lo: TlsLeftOut, R: TlsRight>(&mut self, li: &mut Li, lo: &mut Lo, r: &mut R) -> Result<(), TlsServerCtxError> {
        match self.cur {
            CurCtx::Handshake(ref mut h) => { h.spin_handshake(li, lo)?; } ,
            CurCtx::Application(ref mut h) => { h.spin_application(li, lo, r)?; },
        }
        Ok(())
    }
}
