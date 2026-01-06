//! Server Ctx

use crate::TlsServerCtxError;

pub use ytls_traits::CtxApplicationProcessor;
pub use ytls_traits::CtxHandshakeProcessor;
use ytls_traits::{TlsLeftIn, TlsLeftOut, TlsRight};

pub use ytls_traits::HandshakeComplete;

mod s_handshake;
#[doc(inline)]
pub use s_handshake::*;

mod s_application;
#[doc(inline)]
pub use s_application::*;

use crate::TlsServerCtxConfig;
use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;

enum CurCtx<Config, Crypto, Rng> {
    Handshake(ServerHandshakeCtx<Config, Crypto, Rng>),
    Application(ServerApplicationCtx<Crypto>),
}

pub struct TlsServerCtx<Config, Crypto, Rng> {
    crypto: Crypto,
    cur: CurCtx<Config, Crypto, Rng>,
    ks: KeyStoreAp,
    hs_complete: bool,
}

pub(crate) struct KeyStoreAp {
    application_server_key: [u8; 32],
    application_client_key: [u8; 32],
    application_server_iv: [u8; 12],
    application_client_iv: [u8; 12],
}

impl Default for KeyStoreAp {
    fn default() -> Self {
        Self {
            application_server_key: [0; 32],
            application_client_key: [0; 32],
            application_server_iv: [0; 12],
            application_client_iv: [0; 12],
        }
    }
}

use ytls_traits::SecretStore;

impl SecretStore for KeyStoreAp {
    fn store_ap_client_key(&mut self, k: &[u8]) -> () {
        assert_eq!(k.len(), 32);
        self.application_client_key.copy_from_slice(k);
    }
    fn store_ap_client_iv(&mut self, n: &[u8]) -> () {
        assert_eq!(n.len(), 12);
        self.application_client_iv.copy_from_slice(n);
    }
    fn store_ap_server_key(&mut self, k: &[u8]) -> () {
        assert_eq!(k.len(), 32);
        self.application_server_key.copy_from_slice(k);
    }
    fn store_ap_server_iv(&mut self, n: &[u8]) -> () {
        assert_eq!(n.len(), 12);
        self.application_server_iv.copy_from_slice(n);
    }

    fn load_ap_client_key(&self) -> &[u8] {
        &self.application_client_key
    }
    fn load_ap_client_iv(&self) -> &[u8] {
        &self.application_client_iv
    }
    fn load_ap_server_key(&self) -> &[u8] {
        &self.application_server_key
    }
    fn load_ap_server_iv(&self) -> &[u8] {
        &self.application_server_iv
    }
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
    #[inline]
    pub fn advance_with<Li: TlsLeftIn, Lo: TlsLeftOut, R: TlsRight>(
        &mut self,
        li: &mut Li,
        lo: &mut Lo,
        r: &mut R,
    ) -> Result<(), TlsServerCtxError> {
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
        }

        if let CurCtx::Application(ref mut a) = self.cur {
            a.spin_application(li, lo, r)?;
        }

        Ok(())
    }
}
