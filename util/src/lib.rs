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

mod byte_slices;
#[doc(inline)]
pub use byte_slices::*;
