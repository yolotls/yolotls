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
// 0 - Server Name Indicator
//-----------------------------------------------
mod sni;
#[doc(inline)]
pub use sni::*;

//-----------------------------------------------
// 10 - Supported (EC) Groups
//-----------------------------------------------
mod supported_groups;
#[doc(inline)]
pub use supported_groups::*;

//-----------------------------------------------
// 11 - Supported (EC) Point Formats - DEPRECATED
//-----------------------------------------------
// point formats = all but uncompressed now supported
// https://datatracker.ietf.org/doc/html/rfc8422#section-5.1.2
// add it if needed to support deprecated point formats

//-----------------------------------------------
// 13 - Signature Algorithms
//-----------------------------------------------
mod signature_algorithms;
#[doc(inline)]
pub use signature_algorithms::*;

//-----------------------------------------------
// 16 - Application Layer Protocol Negotiation (ALPN)
//-----------------------------------------------
mod alpns;
#[doc(inline)]
pub use alpns::*;

//-----------------------------------------------
// 27 - Compress Certificate
//-----------------------------------------------
mod compress_certificate;
#[doc(inline)]
pub use compress_certificate::*;

//-----------------------------------------------
// 28 - Record Size Limit
//-----------------------------------------------
mod rec_size_limit;
#[doc(inline)]
pub use rec_size_limit::*;

//-----------------------------------------------
// 34 - Delegated Credential
//-----------------------------------------------
mod delegated_credential;
#[doc(inline)]
pub use delegated_credential::*;

//-----------------------------------------------
// 41 - Supported Versions
//-----------------------------------------------
mod pre_shared_key_ex;
#[doc(inline)]
pub use pre_shared_key_ex::*;

//-----------------------------------------------
// 43 - Supported Versions
//-----------------------------------------------
mod supported_versions;
#[doc(inline)]
pub use supported_versions::*;

//-----------------------------------------------
// 51 - Key Share
//-----------------------------------------------
mod key_share;
#[doc(inline)]
pub use key_share::*;

//-----------------------------------------------
// 65037 - encrypted_client_hello
//-----------------------------------------------
mod encrypted_client_hello;
#[doc(inline)]
pub use encrypted_client_hello::*;
