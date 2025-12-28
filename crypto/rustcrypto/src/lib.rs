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

mod hkdf;
#[doc(inline)]
pub use hkdf::*;

/// Use this together with yTLS by providing this struct into the
/// client or server contextes.
pub struct RustCrypto;

impl RustCrypto {
    pub fn init() -> Self {        
        Self {}
    }
}

use ytls_traits::CryptoConfig;
use ytls_traits::CryptoSha256TranscriptProcessor;
use ytls_traits::CryptoSha384TranscriptProcessor;
use ytls_traits::CryptoX25519Processor;
use ytls_traits::CryptoSha256HkdfExtractProcessor;
use ytls_traits::CryptoSha256HkdfGenProcessor;
use rand_core::CryptoRng;

use ::hkdf::InvalidPrkLength;

impl CryptoConfig for RustCrypto {
    type PrkError = InvalidPrkLength;
    fn hkdf_sha256_from_prk(prk: &[u8]) -> Result<impl CryptoSha256HkdfGenProcessor, Self::PrkError> {
        Sha256Hkdf::sha256_hkdf_from_prk(prk)
    }
    fn hkdf_sha256_init() -> impl CryptoSha256HkdfExtractProcessor {
        Sha256Hkdf::sha256_hkdf_init()
    }
    fn sha256_init() -> impl CryptoSha256TranscriptProcessor {
        Sha256Hasher::sha256_init()
    }
    fn sha384_init() -> impl CryptoSha384TranscriptProcessor {
        Sha384Hasher::sha384_init()
    }
    fn x25519_init<R: CryptoRng>(&mut self, rng: &mut R) -> impl CryptoX25519Processor {
        X25519::x25519_init(rng)
    }
}
