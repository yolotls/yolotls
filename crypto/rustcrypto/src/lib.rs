#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![warn(
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
#![doc = include_str!("../README.md")]
#![allow(missing_docs)]
#![allow(unused_imports)]
#![allow(dead_code)]

//***********************************************
// Re-Exports
//***********************************************

//-----------------------------------------------
// All Errors
//-----------------------------------------------
mod error;
pub use error::*;

//-----------------------------------------------
//
//-----------------------------------------------

mod dh;
#[doc(inline)]
pub use dh::*;

mod hasher;
#[doc(inline)]
pub use hasher::*;

mod hmac;
#[doc(inline)]
pub use hmac::*;

mod hkdf;
#[doc(inline)]
pub use hkdf::*;

mod aead;
#[doc(inline)]
pub use aead::*;

mod sign;
#[doc(inline)]
pub use sign::*;

/// Use this together with yTLS by providing this struct into the
/// client or server contextes.
#[derive(Copy, Clone)]
pub struct RustCrypto;

impl RustCrypto {
    pub fn init() -> Self {
        Self {}
    }
}

use ytls_traits::CryptoConfig;
//---------------
// Hashers
//---------------
use ytls_traits::CryptoSha256TranscriptProcessor;
use ytls_traits::CryptoSha384TranscriptProcessor;
//---------------
// HMAC
//---------------
use ytls_traits::CryptoSha256HmacProcessor;
use ytls_traits::CryptoSha384HmacProcessor;
//---------------
// HDKF
//---------------
use ytls_traits::CryptoSha256HkdfExtractProcessor;
use ytls_traits::CryptoSha256HkdfGenProcessor;
//---------------
// ECDHE
//---------------
use ytls_traits::CryptoX25519Processor;
//---------------
// AEAD
//---------------
use ytls_traits::CryptoChaCha20Poly1305Processor;
//---------------
// Signers
//---------------
use ytls_traits::CryptoSignerP256Processor;

use rand_core::CryptoRng;

use ::hkdf::InvalidPrkLength;

impl CryptoConfig for RustCrypto {
    type PrkError = InvalidPrkLength;
    #[inline]
    fn sign_p256_init(key: &[u8]) -> Option<impl CryptoSignerP256Processor> {
        SignP256::sign_p256_init(key)
    }
    #[inline]
    fn aead_chaha20poly1305(key: &[u8; 32]) -> impl CryptoChaCha20Poly1305Processor {
        AeadChaCha20Poly1305::chacha20poly1305_init(key)
    }
    #[inline]
    fn hkdf_sha256_from_prk(
        prk: &[u8],
    ) -> Result<impl CryptoSha256HkdfGenProcessor, Self::PrkError> {
        Sha256Hkdf::sha256_hkdf_from_prk(prk)
    }
    #[inline]
    fn hkdf_sha256_init() -> impl CryptoSha256HkdfExtractProcessor {
        Sha256Hkdf::sha256_hkdf_init()
    }
    #[inline]
    fn hmac_sha384_init_with_key(key: &[u8; 48]) -> impl CryptoSha384HmacProcessor {
        Sha384Hmac::sha384_hmac_init_with_key(key)
    }
    #[inline]
    fn hmac_sha256_init_with_key(key: &[u8; 32]) -> impl CryptoSha256HmacProcessor {
        Sha256Hmac::sha256_hmac_init_with_key(key)
    }
    #[inline]
    fn sha256_init() -> impl CryptoSha256TranscriptProcessor {
        Sha256Hasher::sha256_init()
    }
    #[inline]
    fn sha384_init() -> impl CryptoSha384TranscriptProcessor {
        Sha384Hasher::sha384_init()
    }
    #[inline]
    fn x25519_init<R: CryptoRng>(&mut self, rng: &mut R) -> impl CryptoX25519Processor {
        X25519::x25519_init(rng)
    }
}
