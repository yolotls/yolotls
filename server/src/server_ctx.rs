//! Server Ctx

use crate::CtxError;
use crate::TlsServerCtxConfig;

use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;

pub use ytls_traits::CtxApplicationProcessor;
pub use ytls_traits::CtxHandshakeProcessor;
use ytls_traits::{TlsLeftIn, TlsLeftOut, TlsRight};

pub use ytls_traits::HandshakeComplete;

use ytls_keys::KeyStoreAp;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

mod s_handshake;
#[doc(inline)]
pub use s_handshake::*;

mod s_application;
#[doc(inline)]
pub use s_application::*;

enum CurCtx<Config, Crypto, Rng> {
    Handshake(ServerHandshakeCtx<Config, Crypto, Rng>),
    Application(ServerApplicationCtx<Crypto>),
}

/// yTLS Server Context
pub struct TlsServerCtx<Config, Crypto, Rng> {
    crypto: Crypto,
    cur: CurCtx<Config, Crypto, Rng>,
    ks: KeyStoreAp,
    hs_complete: bool,
}

impl<Config, Crypto, Rng> TlsServerCtx<Config, Crypto, Rng>
where
    Config: TlsServerCtxConfig,
    Crypto: CryptoConfig + Clone,
    Rng: CryptoRng,
{
    #[inline]
    pub fn with_required(config: Config, crypto: Crypto, rng: Rng) -> Self {
        Self {
            crypto: crypto.clone(),
            ks: KeyStoreAp::default(),
            cur: CurCtx::Handshake(ServerHandshakeCtx::with_required(config, crypto, rng)),
            hs_complete: false,
        }
    }
    /// Indicates Server Ctx is not ready for application data
    #[inline]
    pub fn is_handshaking(&self) -> bool {
        match self.cur {
            CurCtx::Application(_) => false,
            _ => true,
        }
    }
    #[inline]
    pub fn advance_with<Li: TlsLeftIn, Lo: TlsLeftOut, R: TlsRight>(
        &mut self,
        li: &mut Li,
        lo: &mut Lo,
        r: &mut R,
    ) -> Result<(), CtxError> {
        let sw_ap = if let CurCtx::Handshake(ref mut h) = self.cur {
            match h.spin_handshake(li, lo, &mut self.ks)? {
                Some(HandshakeComplete) => {
                    self.hs_complete = true;
                    true
                }
                _ => false,
            }
        } else {
            false
        };

        if sw_ap {
            self.cur = CurCtx::Application(ServerApplicationCtx::with_required(
                self.crypto.clone(),
                &self.ks,
            ));
            self.ks = KeyStoreAp::default();
        }

        if let CurCtx::Application(ref mut a) = self.cur {
            a.spin_application(li, lo, r)?;
        }

        Ok(())
    }
}
