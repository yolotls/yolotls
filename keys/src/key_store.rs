//! keystore

use ytls_traits::SecretStore;

/// KeyStore Application
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct KeyStoreAp {
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
