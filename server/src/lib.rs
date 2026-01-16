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
// Public Re-Exports
//***********************************************
#[doc(inline)]
pub use ytls_ctx::{CtxError, Rfc8446Error};

#[doc(inline)]
pub use ytls_traits::{TlsLeftIn, TlsLeftOut, TlsRight};

//-----------------------------------------------
// Public API
//-----------------------------------------------

mod server_config;
#[doc(inline)]
pub use server_config::*;

mod server_ctx;
#[doc(inline)]
pub use server_ctx::*;
