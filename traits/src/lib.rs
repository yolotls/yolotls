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

mod t_io;
#[doc(inline)]
pub use t_io::*;

mod t_crypto;
#[doc(inline)]
pub use t_crypto::*;

mod t_builder;
#[doc(inline)]
pub use t_builder::*;

mod t_parser;
#[doc(inline)]
pub use t_parser::*;
