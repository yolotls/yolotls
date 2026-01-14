//! Client Ctx

use crate::CtxError;
use crate::TlsClientCtxConfig;

use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;

pub use ytls_traits::CtxApplicationProcessor;
pub use ytls_traits::CtxHandshakeProcessor;
use ytls_traits::{TlsLeftIn, TlsLeftOut, TlsRight};

use ytls_traits::CryptoSha256TranscriptProcessor;

pub use ytls_traits::HandshakeComplete;

use ytls_keys::KeyStoreAp;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

mod c_handshake;
#[doc(inline)]
pub use c_handshake::*;

mod c_application;
#[doc(inline)]
pub use c_application::*;

enum CurCtx<Config, Crypto: CryptoConfig, Rng> {
    Handshake(ClientHandshakeCtx<Config, Crypto, Rng>),
    Application(ClientApplicationCtx<Crypto>),
}

/// Combined client context with handshake and application.
pub struct TlsClientCtx<Config, Crypto: CryptoConfig, Rng> {
    crypto: Crypto,
    cur: CurCtx<Config, Crypto, Rng>,
    ks: KeyStoreAp,
    hs_complete: bool,
}

impl<Config, Crypto, Rng> TlsClientCtx<Config, Crypto, Rng>
where
    Config: TlsClientCtxConfig,
    Crypto: CryptoConfig + Clone,
    Rng: CryptoRng,
{
    #[inline]
    pub fn with_required(config: Config, crypto: Crypto, rng: Rng) -> Self {
        Self {
            crypto: crypto.clone(),
            ks: KeyStoreAp::default(),
            cur: CurCtx::Handshake(ClientHandshakeCtx::with_required(config, crypto, rng)),
            hs_complete: false,
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
            self.cur = CurCtx::Application(ClientApplicationCtx::with_required(
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
