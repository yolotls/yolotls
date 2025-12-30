//! TLS1.3 Key Schedule implementing
//! [`Tls13KeyScheduleInit`] for initializing the Key Schedule,

use ytls_traits::CryptoConfig;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use ytls_traits::Tls13KeyScheduleApSha256;
use ytls_traits::Tls13KeyScheduleDerivedSha256;
use ytls_traits::Tls13KeyScheduleHandshakeSha256;
use ytls_traits::Tls13KeyScheduleInit;

use ytls_traits::CryptoSha256HkdfExtractProcessor;
use ytls_traits::CryptoSha256HkdfGenProcessor;

use ytls_util::HkdfLabelSha256;

/// TLS 1.3 Key Schedule implemented in type state.
/// See the trait [`Tls13KeyScheduleInit`] for more.
pub struct Tls13Keys;

impl Tls13KeyScheduleInit for Tls13Keys {
    fn no_psk_with_crypto_and_sha256<Crypto: CryptoConfig>(
        crypto: Crypto,
    ) -> impl Tls13KeyScheduleDerivedSha256 {
        let ikm: [u8; 32] = [0; 32];
        let salt: [u8; 1] = [0; 1];

        let hkdf = Crypto::hkdf_sha256_init();

        //*****************************************************
        //  early_secret = HKDF-Extract(salt: 00, key: 00...)
        //-----------------------------------------------------
        let (_early_secret, hk_early) = hkdf.hkdf_sha256_extract(Some(&salt[..]), &ikm);
        let label_derived = HkdfLabelSha256::tls13_early_secret_sha256();
        let mut derived_secret: [u8; 32] = [0; 32];
        //*****************************************************
        // empty_hash = SHA256("")
        // derived_secret = HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 32)
        //----------------------------------------------------
        let _ = hk_early.hkdf_sha256_expand(&label_derived, &mut derived_secret);
        Tls13KeysDerivedSha256 {
            crypto,
            derived_secret,
        }
    }
}

/// Key Schedule in early secret derived state which can proceed to handshake.
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Tls13KeysDerivedSha256<C> {
    crypto: C,
    derived_secret: [u8; 32],
}

impl<C: CryptoConfig> Tls13KeyScheduleDerivedSha256 for Tls13KeysDerivedSha256<C> {
    fn dh_x25519(
        self,
        shared_secret: &[u8; 32],
        hellos_hash: &[u8; 32],
    ) -> impl Tls13KeyScheduleHandshakeSha256 {
        let mut client_secret: [u8; 32] = [0; 32];
        let mut server_secret: [u8; 32] = [0; 32];

        let hkdf = C::hkdf_sha256_init();

        //*****************************************************
        // handshake_secret = HKDF-Extract(salt: derived_secret, key: shared_secret)
        let (_handshake_secret, hs_hk) =
            hkdf.hkdf_sha256_extract(Some(&self.derived_secret), shared_secret);

        //*****************************************************
        // client_secret = HKDF-Expand-Label(key: handshake_secret, label: "c hs traffic", ctx: hello_hash, len: 32)
        let label = HkdfLabelSha256::tls13_client_handshake_traffic(&hellos_hash);
        let _ = hs_hk.hkdf_sha256_expand(&label, &mut client_secret);

        //*****************************************************
        // server_secret = HKDF-Expand-Label(key: handshake_secret, label: "s hs traffic", ctx: hello_hash, len: 32)
        let label = HkdfLabelSha256::tls13_server_handshake_traffic(&hellos_hash);
        let _ = hs_hk.hkdf_sha256_expand(&label, &mut server_secret);

        Tls13KeysHandshakeSha256 {
            crypto: self.crypto,
            client_secret,
            server_secret,
        }
    }
}

/// Key Schedule in handshake secret derived state which can proceed to application secret once finished.
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Tls13KeysHandshakeSha256<C> {
    crypto: C,
    client_secret: [u8; 32],
    server_secret: [u8; 32],
}

impl<C: CryptoConfig> Tls13KeysHandshakeSha256<C> {
    fn _client_prk(&self) -> impl CryptoSha256HkdfGenProcessor + use<'_, C> {
        let hk = C::hkdf_sha256_from_prk(&self.client_secret);
        match hk {
            Ok(i) => i,
            // SAFETY: This should not happen given secrets are hard-sized
            Err(_) => panic!("tls13_key_schedule has incorrect length."),
        }
    }
    fn _server_prk(&self) -> impl CryptoSha256HkdfGenProcessor + use<'_, C> {
        let hk = C::hkdf_sha256_from_prk(&self.server_secret);
        match hk {
            Ok(i) => i,
            // SAFETY: This should not happen given secrets are hard-sized
            Err(_) => panic!("tls13_key_schedule has incorrect length."),
        }
    }
}

impl<C: CryptoConfig> Tls13KeyScheduleHandshakeSha256 for Tls13KeysHandshakeSha256<C> {
    fn handshake_server_key(&self, out_key: &mut [u8]) -> () {
        let hk = self._server_prk();
        let key_label = HkdfLabelSha256::tls13_secret_key(out_key.len() as u8);
        let _ = hk.hkdf_sha256_expand(&key_label, out_key);
    }
    fn handshake_client_key(&self, out_key: &mut [u8]) -> () {
        let hk = self._client_prk();
        let key_label = HkdfLabelSha256::tls13_secret_key(out_key.len() as u8);
        let _ = hk.hkdf_sha256_expand(&key_label, out_key);
    }
    fn handshake_server_iv(&self, out_iv: &mut [u8]) -> () {
        let hk = self._server_prk();
        let key_label = HkdfLabelSha256::tls13_secret_iv(out_iv.len() as u8);
        let _ = hk.hkdf_sha256_expand(&key_label, out_iv);
    }
    fn handshake_client_iv(&self, out_iv: &mut [u8]) -> () {
        let hk = self._client_prk();
        let key_label = HkdfLabelSha256::tls13_secret_iv(out_iv.len() as u8);
        let _ = hk.hkdf_sha256_expand(&key_label, out_iv);
    }
    #[allow(unreachable_code)]
    fn finished_handshake(self, _handshakes_hash: &[u8; 32]) -> impl Tls13KeyScheduleApSha256 {
        let _main_secret: [u8; 32] = [0; 32];
        todo!();
        Tls13KeysApSha256 {
            crypto: self.crypto,
            main_secret: _main_secret,
        }
    }
}

/// Key Schedule in final main secret derived state from which application keys and ivs can be derived.
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Tls13KeysApSha256<C> {
    crypto: C,
    main_secret: [u8; 32],
}

impl<C: CryptoConfig> Tls13KeyScheduleApSha256 for Tls13KeysApSha256<C> {
    fn application_server_key(&self, _out_key: &mut [u8]) -> () {
        todo!()
    }
    fn application_client_key(&self, _out_key: &mut [u8]) -> () {
        todo!()
    }
    fn application_server_iv(&self, _out_iv: &mut [u8]) -> () {
        todo!()
    }
    fn application_client_iv(&self, _out_iv: &mut [u8]) -> () {
        todo!()
    }
}

// https://datatracker.ietf.org/doc/rfc8448/
#[cfg(test)]
mod test_sha256_rfc8448 {
    use super::*;
    use hex_literal::hex;
    use ytls_rustcrypto::RustCrypto;

    const fn shared_secret() -> &'static [u8; 32] {
        &hex!(
            "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
              35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d"
        )
    }

    const fn handshake_hash() -> &'static [u8; 32] {
        &hex!(
            "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
              d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8"
        )
    }

    #[test]
    fn handshake_server_key_ok() {
        let c = RustCrypto;
        let k = Tls13Keys::no_psk_with_crypto_and_sha256(c);
        let hs_k = k.dh_x25519(shared_secret(), handshake_hash());
        let mut server_handshake_key: [u8; 16] = [0; 16];
        hs_k.handshake_server_key(&mut server_handshake_key);
        assert_eq!(
            &server_handshake_key,
            &hex!("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc")
        );
    }

    #[test]
    fn handshake_server_iv_ok() {
        let c = RustCrypto;
        let k = Tls13Keys::no_psk_with_crypto_and_sha256(c);
        let hs_k = k.dh_x25519(shared_secret(), handshake_hash());
        let mut server_handshake_iv: [u8; 12] = [0; 12];
        hs_k.handshake_server_iv(&mut server_handshake_iv);
        assert_eq!(
            &server_handshake_iv,
            &hex!("5d 31 3e b2 67 12 76 ee 13 00 0b 30")
        );
    }
}
