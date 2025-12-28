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

#[cfg(test)]
mod hasher;
#[cfg(test)]
pub use hasher::*;

#[cfg(test)]
mod x25519;
#[cfg(test)]
pub use x25519::*;

#[cfg(test)]
mod hkdf;
#[cfg(test)]
pub use hkdf::*;
