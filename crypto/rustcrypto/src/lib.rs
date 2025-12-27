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
pub use dh::*;

mod hasher;
pub use hasher::*;

/// Use this together with yTLS by providing this struct into the
/// client or server contextes.
pub struct RustCrypto;

impl RustCrypto {
    pub fn init() -> Self {        
        Self {}
    }
}

use ytls_traits::CryptoConfig;
use ytls_traits::CryptoSha384TrancriptProcessor;
use ytls_traits::CryptoX25519Processor;
use rand_core::CryptoRng;

impl CryptoConfig for RustCrypto {
    fn sha384_init(&mut self) -> impl CryptoSha384TrancriptProcessor {
        Sha384Hasher::sha384_init()
    }
    fn x25519_init<R: CryptoRng>(&mut self, rng: &mut R) -> impl CryptoX25519Processor {
        X25519::x25519_init(rng)
    }
}
